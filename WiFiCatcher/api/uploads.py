"""Validation for user-uploaded files.

Uploads are attacker-controlled, so every upload is validated before it touches
the filesystem or an external tool. Checks, weakest to strongest:

* **Size** — a hard cap so a huge body can't exhaust memory or disk.
* **Content-Type** — advisory only; the client can forge it (a real upload
  arrived as ``image/CAP``), so it is checked but never trusted on its own.
* **Extension / filename** — allow-list. The client filename is *never* used to
  build a filesystem path; only a whitelisted extension is derived from it, so
  path separators, ``..`` and shell metacharacters in the name can't leak
  through (see :func:`safe_capture_suffix`).
* **Magic bytes / content sniff** — authoritative. Content can't lie: a capture
  must start with a pcap/pcapng signature, a CSV import must be text.

Failures raise ``HTTPException`` (415 for a bad format, 413 for oversize).
"""

from __future__ import annotations

import os

from fastapi import HTTPException

# Hard ceiling on an accepted upload. Enterprise handshakes are tiny and CSV
# exports are small; a bounded cap keeps a giant body from being buffered and
# processed. Override with WIFICATCHER_MAX_UPLOAD_MB.
try:
    _MAX_MB = int(os.environ.get("WIFICATCHER_MAX_UPLOAD_MB", "50"))
except ValueError:
    _MAX_MB = 50
MAX_UPLOAD_BYTES = max(1, _MAX_MB) * 1024 * 1024

# --- capture files (.cap / .pcap / .pcapng) --------------------------------
# pcap: 32-bit magic in either endianness, microsecond or nanosecond stamps.
_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1",  # microseconds, little-endian
    b"\xa1\xb2\xc3\xd4",  # microseconds, big-endian
    b"\x4d\x3c\xb2\xa1",  # nanoseconds, little-endian
    b"\xa1\xb2\x3c\x4d",  # nanoseconds, big-endian
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"  # pcapng Section Header Block start

_CAPTURE_EXTS = {".cap", ".pcap", ".pcapng"}
_CAPTURE_CTYPES = {
    "", "application/octet-stream", "application/vnd.tcpdump.pcap",
    "application/x-pcapng", "application/cap", "application/x-pcap",
}

# --- CSV imports ------------------------------------------------------------
_CSV_EXTS = {"", ".csv", ".txt", ".log"}
_CSV_CTYPES = {
    "", "text/csv", "text/plain", "application/vnd.ms-excel",
    "application/octet-stream",
}


def _reject(detail: str) -> None:
    raise HTTPException(status_code=415, detail=detail)


def _check_size(raw: bytes) -> None:
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large ({len(raw)} bytes); limit is "
                   f"{MAX_UPLOAD_BYTES} bytes "
                   f"(WIFICATCHER_MAX_UPLOAD_MB={_MAX_MB}).")


def _ext(filename: str) -> str:
    return os.path.splitext(filename or "")[1].lower()


def _ctype(content_type: str | None) -> str:
    # Strip any ";charset=..." parameter and normalise.
    return (content_type or "").split(";")[0].strip().lower()


def safe_capture_suffix(filename: str) -> str:
    """Return a temp-file suffix from a *validated* extension only.

    Never derive a filesystem path from the raw client filename: a name like
    ``x.cap;ls > b;`` or ``a.c/../../etc/x`` would otherwise flow into the temp
    path. Only a whitelisted extension is ever used; anything else falls back to
    ``.cap``.
    """
    ext = _ext(filename)
    return ext if ext in _CAPTURE_EXTS else ".cap"


def validate_capture(raw: bytes, filename: str, content_type: str | None) -> None:
    """Reject anything that is not a genuine pcap/pcapng capture."""
    _check_size(raw)
    ext = _ext(filename)
    if ext and ext not in _CAPTURE_EXTS:
        _reject(f"Unsupported extension '{ext}'. Allowed: "
                + ", ".join(sorted(_CAPTURE_EXTS)) + ".")
    ctype = _ctype(content_type)
    if ctype and ctype not in _CAPTURE_CTYPES:
        _reject(f"Unexpected Content-Type '{ctype}' for a capture file.")
    head = raw[:4]
    if head not in _PCAP_MAGICS and head != _PCAPNG_MAGIC:
        _reject("Not a pcap/pcapng capture: file signature (magic bytes) "
                "does not match.")


def validate_csv(raw: bytes, filename: str, content_type: str | None) -> None:
    """Reject anything that is not a plausible text CSV import.

    There is no binary magic for CSV, so the authoritative check is a content
    sniff: the payload must be text (no NUL bytes). Format is confirmed
    downstream by the parser's own header detection.
    """
    _check_size(raw)
    ext = _ext(filename)
    if ext and ext not in _CSV_EXTS:
        _reject(f"Unsupported extension '{ext}'. Expected an airodump .csv "
                "export.")
    ctype = _ctype(content_type)
    if ctype and ctype not in _CSV_CTYPES:
        _reject(f"Unexpected Content-Type '{ctype}' for a CSV import.")
    if b"\x00" in raw[:8192]:
        _reject("File looks binary, not a text CSV.")
