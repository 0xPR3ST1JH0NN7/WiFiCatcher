"""App-side client for the privileged warden.

The unprivileged app never runs radio tools itself; it asks the warden over the
unix socket. This module is the only thing that talks to that socket.
"""

from __future__ import annotations

import os
import socket
from typing import Any, Iterator

from WiFiCatcher.privileged.protocol import ProtocolError, recv_message, send_message

DEFAULT_SOCKET = "/run/wc-privwarden.sock"


def socket_path() -> str:
    return os.environ.get("WIFICATCHER_PRIV_SOCKET", DEFAULT_SOCKET)


class PrivError(RuntimeError):
    """The warden refused or failed an operation."""


class PrivUnavailable(PrivError):
    """The warden socket could not be reached (not installed / not running)."""


class PrivClient:
    """Thin request/response (and streaming) client over the warden socket."""

    def __init__(self, path: str | None = None, timeout: float = 10.0) -> None:
        self.path = path or socket_path()
        self.timeout = timeout

    def _connect(self, timeout: float | None = None) -> socket.socket:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout if timeout is None else timeout)
        try:
            sock.connect(self.path)
        except OSError as exc:
            sock.close()
            raise PrivUnavailable(
                f"privileged warden unreachable at {self.path}: {exc}")
        return sock

    def available(self) -> bool:
        """True if the warden socket accepts a connection (systemd starts it)."""
        try:
            self._connect(timeout=1.0).close()
            return True
        except PrivError:
            return False

    def call(self, op: str, **params: Any) -> dict:
        """Run a unary operation; return its result dict or raise PrivError."""
        sock = self._connect()
        try:
            send_message(sock, {"op": op, "params": params})
            resp = recv_message(sock)
        except (ProtocolError, OSError) as exc:
            raise PrivError(f"warden communication failed: {exc}") from exc
        finally:
            sock.close()
        if not isinstance(resp, dict) or not resp.get("ok"):
            raise PrivError(resp.get("error", "unknown warden error")
                            if isinstance(resp, dict) else "malformed response")
        return resp.get("result", {})

    def stream(self, op: str, **params: Any) -> Iterator[dict]:
        """Run a streaming operation, yielding each event dict until it ends.

        Closing the iterator disconnects, telling the warden to stop the
        underlying work (e.g. kill airodump-ng).
        """
        sock = self._connect(timeout=None)
        sock.settimeout(None)                     # long-lived stream, no read timeout
        try:
            send_message(sock, {"op": op, "params": params})
            while True:
                try:
                    msg = recv_message(sock)
                except (ProtocolError, OSError) as exc:
                    raise PrivError(f"stream failed: {exc}") from exc
                if not isinstance(msg, dict):
                    raise PrivError("malformed stream frame")
                if "event" in msg:
                    yield msg["event"]
                    continue
                if msg.get("done"):
                    return
                if not msg.get("ok", True):
                    raise PrivError(msg.get("error", "stream error"))
                return
        finally:
            sock.close()


def warden_available() -> bool:
    """Convenience: is the privileged warden reachable right now?"""
    return PrivClient().available()
