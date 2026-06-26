import pathlib

from fastapi.testclient import TestClient

from wifihound.server import create_app

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
SAMPLE = FIXTURES / "sample-airodump.csv"


def client():
    return TestClient(create_app())


def import_sample(c):
    with open(SAMPLE, "rb") as fh:
        return c.post("/api/import", files={"file": ("sample.csv", fh, "text/csv")})


def test_health():
    c = client()
    assert c.get("/health").json()["status"] == "ok"


def test_import_and_graph():
    c = client()
    res = import_sample(c)
    assert res.status_code == 200
    body = res.json()
    assert body["summary"]["access_points"] == 4
    assert len(body["elements"]["nodes"]) == 8

    graph = c.get("/api/graph").json()
    assert len(graph["elements"]["edges"]) == 3


def test_node_endpoint():
    c = client()
    import_sample(c)
    res = c.get("/api/node/DC:A6:32:11:22:33")
    assert res.status_code == 200
    assert res.json()["essid"] == "HomeNet"


def test_node_404():
    c = client()
    import_sample(c)
    assert c.get("/api/node/00:00:00:00:00:00").status_code == 404


def test_search_endpoint():
    c = client()
    import_sample(c)
    results = c.get("/api/search", params={"q": "office"}).json()["results"]
    assert any(r["id"] == "B8:27:EB:AA:BB:CC" for r in results)


def test_parsers_endpoint():
    c = client()
    ids = [p["id"] for p in c.get("/api/parsers").json()]
    assert "airodump-csv" in ids


def test_unsupported_format():
    c = client()
    res = c.post(
        "/api/import",
        files={"file": ("notes.txt", b"just some random text", "text/plain")},
    )
    assert res.status_code == 415


def test_deauth_blocked_when_disabled():
    c = client()
    import_sample(c)
    res = c.post(
        "/api/operations/deauth",
        json={"bssid": "DC:A6:32:11:22:33", "acknowledged": True},
    )
    # Offensive ops are off by default -> forbidden
    assert res.status_code == 403


def test_deauth_requires_active_capture(monkeypatch):
    from wifihound.api import routes
    # Pass the authorization gate, but no live capture is running.
    monkeypatch.setattr(routes, "require_authorization", lambda ack: None)
    c = client()
    res = c.post(
        "/api/operations/deauth",
        json={"bssid": "DC:A6:32:11:22:33", "acknowledged": True},
    )
    assert res.status_code == 409  # needs a fixed-channel airodump capture


def test_deauth_runs_with_fixed_channel_capture(monkeypatch):
    from wifihound.api import routes
    from wifihound.capture.controller import CaptureController

    monkeypatch.setattr(routes, "require_authorization", lambda ack: None)

    # Fake an active airodump capture locked on channel 6.
    fake = CaptureController()
    fake.running = True
    fake.mode = "airodump"

    class _Src:
        interface = "wlan0mon"
        channel = "6"

    fake._source = _Src()
    monkeypatch.setattr(routes, "CAPTURE", fake)
    monkeypatch.setattr(routes.deauth_op, "deauth",
                        lambda **kw: {"status": "dry-run",
                                      "command": ["aireplay-ng", "--deauth",
                                                  str(kw["count"]), "-a", kw["bssid"],
                                                  kw["interface"]]})

    c = client()
    res = c.post("/api/operations/deauth",
                 json={"bssid": "DC:A6:32:11:22:33", "client": "5C:F3:70:01:02:03",
                       "count": 3, "acknowledged": True, "dry_run": True})
    assert res.status_code == 200
    assert res.json()["command"][0] == "aireplay-ng"
