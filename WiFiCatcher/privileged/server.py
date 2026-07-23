"""The privileged warden daemon (``wc-privwarden``).

Runs as root. Gets its listening socket either from **systemd socket
activation** (the ``.socket`` unit passes fd 3) or from ``--socket PATH`` for
local development, authenticates each peer with ``SO_PEERCRED``, dispatches
validated operations, and exits after an idle period so systemd can re-launch it
on the next connection.

Run it:
    python -m WiFiCatcher.privileged --socket /tmp/wc-priv.sock   # dev
    (systemd sets $LISTEN_FDS and passes the socket as fd 3 in production)
"""

from __future__ import annotations

import argparse
import logging
import os
import socket
import struct
import threading
import time

from WiFiCatcher.privileged import ops
from WiFiCatcher.privileged.protocol import ProtocolError, recv_message, send_message

logger = logging.getLogger("WiFiCatcher.privileged")

SYSTEMD_LISTEN_FDS_START = 3        # sd_listen_fds(3) convention
_UCRED = struct.Struct("iII")      # struct ucred: pid_t, uid_t, gid_t


class _Idle:
    """Tracks activity so the daemon can exit when nothing is happening."""

    def __init__(self, timeout: float) -> None:
        self.timeout = timeout
        self._active = 0
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def enter(self) -> None:
        with self._lock:
            self._active += 1

    def leave(self) -> None:
        with self._lock:
            self._active -= 1
            self._last = time.monotonic()

    def expired(self) -> bool:
        with self._lock:
            return self._active == 0 and (time.monotonic() - self._last) > self.timeout


def _listen_socket_from_systemd() -> socket.socket | None:
    """Return the socket systemd passed us (fd 3), or None if not activated."""
    if os.environ.get("LISTEN_PID") != str(os.getpid()):
        return None
    if int(os.environ.get("LISTEN_FDS", "0")) < 1:
        return None
    return socket.socket(fileno=SYSTEMD_LISTEN_FDS_START,
                         family=socket.AF_UNIX, type=socket.SOCK_STREAM)


def _bind_socket(path: str) -> socket.socket:
    """Create and bind a unix socket at ``path`` (dev / on-demand mode)."""
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    old = os.umask(0o177)                      # socket => 0600
    try:
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(path)
    finally:
        os.umask(old)
    srv.listen(8)
    return srv


def _peer_uid(conn: socket.socket) -> int:
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _UCRED.size)
    _pid, uid, _gid = _UCRED.unpack(raw)
    return uid


def _handle(conn: socket.socket, allowed_uids: set[int], idle: _Idle) -> None:
    idle.enter()
    try:
        peer = _peer_uid(conn)
        if allowed_uids and peer not in allowed_uids:
            logger.warning("rejected peer uid %s", peer)
            send_message(conn, {"ok": False, "error": "peer not authorized"})
            return
        req = recv_message(conn)
        if not isinstance(req, dict):
            send_message(conn, {"ok": False, "error": "malformed request"})
            return
        op = req.get("op")
        # Carry the *authenticated* peer uid to the op (e.g. to chown saved
        # captures to the caller); overwrite any client-supplied value.
        params = {**(req.get("params") or {}), "_peer_uid": peer}
        logger.info("op %s", op)

        if op in ops.STREAMERS:
            _run_stream(conn, op, params)
        else:
            try:
                result = ops.dispatch(op, params)
                send_message(conn, {"ok": True, "result": result})
            except ops.OpError as exc:
                send_message(conn, {"ok": False, "error": str(exc)})
            except Exception as exc:                     # tool failure, etc.
                logger.exception("op %s failed", op)
                send_message(conn, {"ok": False, "error": str(exc)})
    except (ProtocolError, OSError) as exc:
        logger.debug("connection ended: %s", exc)
    finally:
        idle.leave()
        try:
            conn.close()
        except OSError:
            pass


def _run_stream(conn: socket.socket, op: str, params: dict) -> None:
    """Drive a streaming op: emit {"event": ...} frames until it ends or the
    client disconnects (which closes the generator and runs its cleanup)."""
    gen = ops.STREAMERS[op](params)
    try:
        for event in gen:
            send_message(conn, {"event": event})
        send_message(conn, {"ok": True, "done": True})
    except ops.OpError as exc:
        send_message(conn, {"ok": False, "error": str(exc)})
    except (ProtocolError, OSError):
        pass                                             # client went away
    finally:
        close = getattr(gen, "close", None)              # cleanup (e.g. stop airodump)
        if callable(close):
            close()


def serve(srv: socket.socket, allowed_uids: set[int], idle_timeout: float) -> None:
    idle = _Idle(idle_timeout)
    srv.settimeout(1.0)

    def _reaper() -> None:
        while True:
            time.sleep(1.0)
            if idle.expired():
                logger.info("idle for %.0fs, exiting", idle_timeout)
                os._exit(0)                              # systemd restarts on next connect

    if idle_timeout > 0:
        threading.Thread(target=_reaper, daemon=True).start()

    logger.info("privileged warden ready")
    while True:
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        threading.Thread(target=_handle, args=(conn, allowed_uids, idle),
                         daemon=True).start()


def _parse_uids(spec: str | None) -> set[int]:
    if not spec:
        return set()
    out: set[int] = set()
    for part in spec.replace(",", " ").split():
        try:
            out.add(int(part))
        except ValueError:
            continue
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="wc-privwarden",
                                     description="WiFiCatcher privileged warden daemon.")
    parser.add_argument("--socket", help="bind this unix socket path "
                        "(dev/on-demand; omit under systemd socket activation)")
    parser.add_argument("--peer-uid", default=os.environ.get("WIFICATCHER_PEER_UID"),
                        help="only accept these uid(s) (comma/space separated)")
    parser.add_argument("--idle", type=float,
                        default=float(os.environ.get("WIFICATCHER_IDLE", "300")),
                        help="exit after this many idle seconds (0 = never)")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s wc-privwarden %(levelname)s %(message)s")

    if os.geteuid() != 0:
        logger.warning("not running as root; privileged operations will fail")

    srv = _listen_socket_from_systemd()
    if srv is None:
        if not args.socket:
            parser.error("no systemd socket and no --socket given")
        srv = _bind_socket(args.socket)

    allowed = _parse_uids(args.peer_uid)
    if not allowed:
        logger.warning("no --peer-uid set: relying on socket permissions only")

    try:
        serve(srv, allowed, args.idle)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
