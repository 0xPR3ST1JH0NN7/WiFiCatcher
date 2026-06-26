import asyncio
import pathlib

from fastapi.testclient import TestClient

from wifihound.capture import ReplaySource
from wifihound.capture.controller import CaptureController, diff_elements
from wifihound.parsers.airodump_csv import AirodumpCsvParser
from wifihound.server import create_app

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
SAMPLE = FIXTURES / "sample-airodump.csv"
SAMPLE_TEXT = SAMPLE.read_text()


def test_replay_source_reveals_progressively():
    scan = AirodumpCsvParser().parse(SAMPLE_TEXT, "s.csv")
    src = ReplaySource(scan, steps=4)
    counts = []

    async def collect():
        for _ in range(8):
            snap = await src.read()
            counts.append(len(snap.access_points) + len(snap.clients))

    asyncio.run(collect())
    # Non-decreasing reveal, ending at the full set (4 APs + 4 clients = 8).
    assert counts == sorted(counts)
    assert counts[-1] == 8
    assert counts[0] < counts[-1]


def test_airodump_command_includes_filters():
    from wifihound.capture.sources import AirodumpSource
    src = AirodumpSource("wlan0mon", channel="6", encrypt="WPA2", wps=True,
                         essid="HomeNet", bssid="DC:A6:32:11:22:33")
    cmd = src.build_command("/tmp/cap")
    assert cmd[:2] == ["airodump-ng", "--output-format"]
    assert "-c" in cmd and "6" in cmd
    assert "--encrypt" in cmd and "WPA2" in cmd
    assert "--wps" in cmd
    assert "--essid" in cmd and "HomeNet" in cmd
    assert "--bssid" in cmd and "DC:A6:32:11:22:33" in cmd
    assert cmd[-1] == "wlan0mon"


def test_diff_elements():
    g_prev = {}
    cyto1 = {"elements": {"nodes": [{"data": {"id": "a", "label": "A"}}], "edges": []}}
    patch, idx = diff_elements(g_prev, cyto1)
    assert len(patch["add"]) == 1 and patch["add"][0]["group"] == "nodes"

    cyto2 = {"elements": {"nodes": [{"data": {"id": "a", "label": "A2"}},
                                     {"data": {"id": "b", "label": "B"}}], "edges": []}}
    patch2, idx2 = diff_elements(idx, cyto2)
    assert [u["id"] for u in patch2["update"]] == ["a"]
    assert [a["data"]["id"] for a in patch2["add"]] == ["b"]
    assert patch2["remove"] == []

    cyto3 = {"elements": {"nodes": [{"data": {"id": "b", "label": "B"}}], "edges": []}}
    patch3, _ = diff_elements(idx2, cyto3)
    assert patch3["remove"] == ["a"]


def test_controller_streams_patches():
    scan = AirodumpCsvParser().parse(SAMPLE_TEXT, "s.csv")
    ctrl = CaptureController(interval=0.02)
    received = []

    async def run():
        q = ctrl.subscribe()
        await ctrl.start(ReplaySource(scan, steps=4), mode="replay", interval=0.02)
        # Drain a few patches as the replay reveals nodes.
        for _ in range(4):
            msg = await asyncio.wait_for(q.get(), timeout=2)
            received.append(msg)
        await ctrl.stop()

    asyncio.run(run())
    assert any(m["type"] == "patch" for m in received)
    assert any(m.get("add") for m in received)


# ------------------------------------------------------------------- REST / WS
def client():
    return TestClient(create_app())


def import_sample(c):
    with open(SAMPLE, "rb") as fh:
        return c.post("/api/import", files={"file": ("sample.csv", fh, "text/csv")})


def test_replay_requires_loaded_capture():
    c = client()
    res = c.post("/api/live/start", json={"mode": "replay"})
    assert res.status_code == 400


def test_replay_start_stop_status():
    c = client()
    import_sample(c)
    assert c.post("/api/live/start", json={"mode": "replay"}).json()["status"] == "running"
    assert c.get("/api/live/status").json()["running"] is True
    assert c.post("/api/live/stop").json()["status"] == "stopped"
    assert c.get("/api/live/status").json()["running"] is False


def test_airodump_blocked_when_disabled():
    c = client()
    res = c.post("/api/live/start",
                 json={"mode": "airodump", "interface": "wlan0mon", "acknowledged": True})
    assert res.status_code == 403


def test_websocket_sends_init():
    c = client()
    import_sample(c)
    c.post("/api/live/start", json={"mode": "replay", "interval": 0.05})
    try:
        with c.websocket_connect("/api/live/ws") as ws:
            msg = ws.receive_json()
            assert msg["type"] == "init"
            assert "elements" in msg
    finally:
        c.post("/api/live/stop")
