"""Wire protocol for the privileged helper socket.

Messages are length-prefixed JSON frames: a 4-byte big-endian unsigned length
followed by that many bytes of UTF-8 JSON. Small, self-describing, and easy to
validate.

Request  (app -> helper):  {"op": "<name>", "params": {...}}
Response (helper -> app):
  * unary:      {"ok": true, "result": {...}}  |  {"ok": false, "error": "..."}
  * streaming:  zero or more {"event": {...}} frames, then a terminal
                {"ok": true, "done": true}  |  {"ok": false, "error": "..."}
"""

from __future__ import annotations

import json
import socket
import struct
from typing import Any

_HEADER = struct.Struct(">I")           # 4-byte big-endian length prefix
MAX_FRAME = 8 * 1024 * 1024             # 8 MiB hard cap per frame (anti-DoS)


class ProtocolError(Exception):
    """A malformed or oversized frame, or a closed connection mid-message."""


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    chunks: list[bytes] = []
    remaining = n
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ProtocolError("connection closed mid-frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def send_message(sock: socket.socket, obj: Any) -> None:
    """Serialise ``obj`` to a length-prefixed JSON frame and send it."""
    payload = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_FRAME:
        raise ProtocolError(f"frame too large ({len(payload)} bytes)")
    sock.sendall(_HEADER.pack(len(payload)) + payload)


def recv_message(sock: socket.socket) -> Any:
    """Read one length-prefixed JSON frame. Raises on EOF/oversize/bad JSON."""
    (length,) = _HEADER.unpack(_recv_exactly(sock, _HEADER.size))
    if length > MAX_FRAME:
        raise ProtocolError(f"declared frame too large ({length} bytes)")
    raw = _recv_exactly(sock, length)
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"invalid JSON frame: {exc}") from exc
