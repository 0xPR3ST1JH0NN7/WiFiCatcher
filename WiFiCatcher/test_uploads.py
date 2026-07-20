"""Tests for upload validation (size, extension, content-type, magic bytes)."""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from WiFiCatcher.api import uploads

# Minimal valid signatures.
PCAP = b"\xd4\xc3\xb2\xa1" + b"\x00" * 20          # pcap, microsec, LE
PCAP_BE = b"\xa1\xb2\xc3\xd4" + b"\x00" * 20       # pcap, big-endian
PCAP_NS = b"\x4d\x3c\xb2\xa1" + b"\x00" * 20       # pcap, nanosec
PCAPNG = b"\x0a\x0d\x0d\x0a" + b"\x00" * 20        # pcapng SHB
CSV = b"BSSID, First time seen, Last time seen, channel\n" + b"AA:BB, x, y, 6\n"


# --------------------------------------------------------------- captures
@pytest.mark.parametrize("blob", [PCAP, PCAP_BE, PCAP_NS, PCAPNG])
def test_capture_accepts_valid_signatures(blob: bytes) -> None:
    uploads.validate_capture(blob, "scan.cap", "application/octet-stream")  # no raise


def test_capture_rejects_wrong_magic_even_when_ext_and_ctype_spoofed() -> None:
    # Attacker forges a valid extension AND a whitelisted content-type; the
    # magic-byte check is authoritative and still rejects the PHP payload.
    with pytest.raises(HTTPException) as exc:
        uploads.validate_capture(
            b"<?php system($_GET[0]); ?>", "x.cap", "application/octet-stream")
    assert exc.value.status_code == 415
    assert "magic" in exc.value.detail.lower()


def test_capture_rejects_spoofed_content_type() -> None:
    # The real-world attack used Content-Type: image/CAP — rejected outright.
    with pytest.raises(HTTPException) as exc:
        uploads.validate_capture(PCAP, "x.cap", "image/CAP")
    assert exc.value.status_code == 415


def test_capture_rejects_bad_extension() -> None:
    with pytest.raises(HTTPException) as exc:
        uploads.validate_capture(PCAP, "payload.php", "application/octet-stream")
    assert exc.value.status_code == 415
    assert "extension" in exc.value.detail.lower()


def test_capture_rejects_unexpected_content_type() -> None:
    with pytest.raises(HTTPException) as exc:
        uploads.validate_capture(PCAP, "scan.cap", "text/html")
    assert exc.value.status_code == 415


def test_capture_size_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(uploads, "MAX_UPLOAD_BYTES", 10)
    with pytest.raises(HTTPException) as exc:
        uploads.validate_capture(PCAP + b"x" * 100, "scan.cap", "")
    assert exc.value.status_code == 413


def test_capture_content_type_is_advisory_when_generic() -> None:
    # Empty/octet-stream content-types are allowed; content still decides.
    uploads.validate_capture(PCAP, "scan.pcapng", "")           # no raise
    uploads.validate_capture(PCAPNG, "scan.pcapng", None)       # no raise


# ------------------------------------------------- filename sanitisation
def test_safe_suffix_neutralises_shell_metacharacters() -> None:
    # The reported "x.cap;ls > b;" no longer reaches the temp path.
    assert uploads.safe_capture_suffix("x.cap;ls > b;") == ".cap"


def test_safe_suffix_neutralises_path_traversal() -> None:
    assert uploads.safe_capture_suffix("a.c/../../../etc/passwd") == ".cap"
    assert "/" not in uploads.safe_capture_suffix("evil/../x.pcap")
    assert ".." not in uploads.safe_capture_suffix("a.cap/../..")


@pytest.mark.parametrize("name,expected", [
    ("scan.cap", ".cap"),
    ("scan.PCAP", ".pcap"),
    ("scan.pcapng", ".pcapng"),
    ("noext", ".cap"),
    ("weird.exe", ".cap"),
])
def test_safe_suffix_whitelists_extensions(name: str, expected: str) -> None:
    assert uploads.safe_capture_suffix(name) == expected


# ------------------------------------------------------------------- csv
def test_csv_accepts_text() -> None:
    uploads.validate_csv(CSV, "scan.csv", "text/csv")  # no raise


def test_csv_rejects_binary_payload() -> None:
    with pytest.raises(HTTPException) as exc:
        uploads.validate_csv(b"MZ\x00\x00\x90binary", "scan.csv", "text/csv")
    assert exc.value.status_code == 415


def test_csv_rejects_bad_extension() -> None:
    with pytest.raises(HTTPException):
        uploads.validate_csv(CSV, "scan.php", "text/csv")


def test_csv_size_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(uploads, "MAX_UPLOAD_BYTES", 5)
    with pytest.raises(HTTPException) as exc:
        uploads.validate_csv(CSV, "scan.csv", "text/csv")
    assert exc.value.status_code == 413
