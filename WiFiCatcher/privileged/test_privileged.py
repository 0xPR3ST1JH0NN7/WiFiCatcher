"""Tests for the privilege-separation subsystem (protocol, server, client, ops).

These exercise the full plumbing over a real unix socket with fake operations;
the radio tools themselves are not invoked.
"""

from __future__ import annotations

import os
import socket
import threading
import time

import pytest

from WiFiCatcher.privileged import client as client_mod
from WiFiCatcher.privileged import ops, server
from WiFiCatcher.privileged.client import PrivClient, PrivError
from WiFiCatcher.privileged.protocol import recv_message, send_message


# ------------------------------------------------------------- protocol
def test_protocol_round_trip() -> None:
    a, b = socket.socketpair()
    send_message(a, {"op": "x", "params": {"n": [1, 2, 3]}})
    assert recv_message(b) == {"op": "x", "params": {"n": [1, 2, 3]}}
    a.close()
    b.close()


# ------------------------------------------------------------------ ops
def test_dispatch_unknown_op() -> None:
    with pytest.raises(ops.OpError):
        ops.dispatch("nope.nope", {})


def test_deauth_validation_rejects_bad_mac(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ops.OpError):
        ops.dispatch("deauth", {"iface": "wlan0mon", "bssid": "not-a-mac"})


def test_iface_validation_rejects_metachars() -> None:
    with pytest.raises(ops.OpError):
        ops.dispatch("monitor.start", {"iface": "wlan0; rm -rf /"})


# --------------------------------------------------- server <-> client e2e
@pytest.fixture()
def helper(tmp_path, monkeypatch):
    """A running daemon on a temp socket, accepting this process's uid."""
    sock_path = str(tmp_path / "priv.sock")
    monkeypatch.setitem(ops.HANDLERS, "test.echo", lambda p: {"echo": p})

    def _stream(params):
        for i in range(int(params.get("n", 3))):
            yield {"i": i}
    monkeypatch.setitem(ops.STREAMERS, "test.stream", _stream)

    srv = server._bind_socket(sock_path)
    t = threading.Thread(
        target=server.serve, args=(srv, {os.getuid()}, 0), daemon=True)
    t.start()
    # wait for the socket to accept
    for _ in range(50):
        try:
            socket.socket(socket.AF_UNIX).connect(sock_path)
            break
        except OSError:
            time.sleep(0.02)
    yield PrivClient(sock_path)
    srv.close()


def test_unary_call(helper: PrivClient) -> None:
    echoed = helper.call("test.echo", a=1, b="x")["echo"]
    assert echoed["a"] == 1 and echoed["b"] == "x"
    # The server injects the authenticated peer uid into every op's params.
    assert echoed["_peer_uid"] == os.getuid()


def test_unknown_op_returns_error(helper: PrivClient) -> None:
    with pytest.raises(PrivError):
        helper.call("does.not.exist")


def test_streaming(helper: PrivClient) -> None:
    events = list(helper.stream("test.stream", n=4))
    assert events == [{"i": 0}, {"i": 1}, {"i": 2}, {"i": 3}]


def test_available(helper: PrivClient) -> None:
    assert helper.available() is True


def test_unreachable_helper_is_reported() -> None:
    c = PrivClient("/run/definitely-not-a-socket.sock")
    assert c.available() is False
    with pytest.raises(PrivError):
        c.call("test.echo")


def test_peer_uid_rejected(tmp_path) -> None:
    """A daemon that only allows a *different* uid rejects our connection."""
    sock_path = str(tmp_path / "priv2.sock")
    srv = server._bind_socket(sock_path)
    wrong_uid = os.getuid() + 12345
    threading.Thread(target=server.serve, args=(srv, {wrong_uid}, 0),
                     daemon=True).start()
    for _ in range(50):
        try:
            socket.socket(socket.AF_UNIX).connect(sock_path)
            break
        except OSError:
            time.sleep(0.02)
    try:
        with pytest.raises(PrivError):
            PrivClient(sock_path).call("test.echo")
    finally:
        srv.close()


# ------------------------------------------------------------ idle logic
def test_idle_expires_only_when_quiet_and_free() -> None:
    idle = server._Idle(timeout=0.05)
    idle.enter()
    time.sleep(0.1)
    assert idle.expired() is False        # a connection is active
    idle.leave()
    assert idle.expired() is False        # just became free
    time.sleep(0.1)
    assert idle.expired() is True         # quiet long enough


def test_helper_available_uses_configured_socket(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("WIFICATCHER_PRIV_SOCKET", str(tmp_path / "nope.sock"))
    assert client_mod.helper_available() is False
