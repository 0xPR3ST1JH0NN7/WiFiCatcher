"""End-to-end wiring: API routes / capture source <-> a fake privileged helper.

A real helper daemon runs on a temp socket with *fake* operations (no radio),
so the whole path — route -> client -> socket -> daemon -> op -> back — is
exercised without hardware.
"""

from __future__ import annotations

import asyncio
import os
import socket
import threading
import time
import types

import pytest
from fastapi.testclient import TestClient

import WiFiCatcher.api.routes as routes
from WiFiCatcher.privileged import ops, server
from WiFiCatcher.server import app

AIRODUMP_CSV = (
    "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, "
    "Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
    "AA:BB:CC:DD:EE:FF, 2026-01-01 00:00:00, 2026-01-01 00:01:00, 6, 130, WPA2, "
    "CCMP, PSK, -40, 10, 0, 0.0.0.0, 8, TestNet, \n"
)


def _wait(path: str) -> None:
    for _ in range(100):
        try:
            socket.socket(socket.AF_UNIX).connect(path)
            return
        except OSError:
            time.sleep(0.02)


@pytest.fixture()
def daemon(tmp_path, monkeypatch):
    """A daemon with fake deauth + capture.stream ops, wired via the env var."""
    sock_path = str(tmp_path / "priv.sock")
    monkeypatch.setitem(ops.HANDLERS, "deauth",
                        lambda p: {"status": "ok", "echo": p})

    def _cap(params):
        yield {"monitor_interface": "wlan0mon", "enabled": True}
        while True:
            yield {"csv": AIRODUMP_CSV}
            time.sleep(0.05)
    monkeypatch.setitem(ops.STREAMERS, "capture.stream", _cap)

    srv = server._bind_socket(sock_path)
    threading.Thread(target=server.serve, args=(srv, {os.getuid()}, 0),
                     daemon=True).start()
    _wait(sock_path)
    monkeypatch.setenv("WIFICATCHER_PRIV_SOCKET", sock_path)
    yield sock_path
    srv.close()


# ------------------------------------------------------------- deauth route
def test_deauth_requires_acknowledgement() -> None:
    c = TestClient(app)
    r = c.post("/api/operations/deauth",
               json={"bssid": "AA:BB:CC:DD:EE:FF", "acknowledged": False})
    assert r.status_code == 403


def test_deauth_requires_active_capture(daemon) -> None:
    # acknowledged, but no live airodump capture => 409
    c = TestClient(app)
    r = c.post("/api/operations/deauth",
               json={"bssid": "AA:BB:CC:DD:EE:FF", "acknowledged": True})
    assert r.status_code == 409


def test_deauth_routes_to_helper(daemon, monkeypatch) -> None:
    fake_cap = types.SimpleNamespace(can_deauth=True, interface="wlan0mon")
    monkeypatch.setattr(routes, "CAPTURE", fake_cap)
    c = TestClient(app)
    r = c.post("/api/operations/deauth",
               json={"bssid": "AA:BB:CC:DD:EE:FF", "count": 5, "acknowledged": True})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["echo"]["bssid"] == "AA:BB:CC:DD:EE:FF"
    # The helper op reads the interface under 'iface'; the route must send it by
    # that name (a mismatch caused a real "iface required" 400).
    assert body["echo"]["iface"] == "wlan0mon"


def test_deauth_helper_unavailable(monkeypatch) -> None:
    fake_cap = types.SimpleNamespace(can_deauth=True, interface="wlan0mon")
    monkeypatch.setattr(routes, "CAPTURE", fake_cap)
    monkeypatch.setenv("WIFICATCHER_PRIV_SOCKET", "/run/nope-not-here.sock")
    c = TestClient(app)
    r = c.post("/api/operations/deauth",
               json={"bssid": "AA:BB:CC:DD:EE:FF", "acknowledged": True})
    assert r.status_code == 503


# -------------------------------------------------------------- config gate
def test_config_reports_helper_reachable(daemon) -> None:
    assert TestClient(app).get("/api/config").json()["offensive_available"] is True


def test_config_reports_helper_absent(monkeypatch) -> None:
    monkeypatch.setenv("WIFICATCHER_PRIV_SOCKET", "/run/nope-not-here.sock")
    assert TestClient(app).get("/api/config").json()["offensive_available"] is False


# ------------------------------------------------ HelperAirodumpSource stream
def test_helper_source_streams_csv(daemon) -> None:
    from WiFiCatcher.capture import HelperAirodumpSource

    src = HelperAirodumpSource("wlan0", channel="6")

    async def drive():
        await src.start()
        assert src.interface == "wlan0mon"          # from the helper's first event
        scan = None
        for _ in range(100):
            scan = await src.read()
            if scan is not None:
                break
            await asyncio.sleep(0.02)
        await src.stop()
        return scan

    scan = asyncio.run(drive())
    assert scan is not None
    assert any(ap.bssid == "AA:BB:CC:DD:EE:FF" for ap in scan.access_points)
