"""WPS detection over a live pcap.

WPS-enabled access points advertise a WPS information element in their beacons
and probe responses. airodump-ng's CSV does not carry it, but the pcap it writes
alongside does, so we read the WPS version and AP-setup-locked state per BSSID
with ``tshark`` (already used for handshake detection).

:func:`parse_wps` is pure and unit-tested; the ``tshark`` call is best-effort and
degrades to "no detection" when tshark is absent or the capture has no WPS APs.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import Optional

from WiFiCatcher.models import normalize_mac

# tshark fields, joined by this separator so values with commas stay intact.
_SEP = "|"
_FIELDS = ["wlan.bssid", "wps.version", "wps.version2", "wps.ap_setup_locked"]

# Match any frame that carries a WPS element. Keying only on the legacy Version
# attribute (0x104A) misses APs that advertise WPS solely via Version2 (0x1049)
# or only expose the setup-state attribute, so include all three.
WPS_FILTER = "wps.version || wps.version2 || wps.wifi_protected_setup_state"


def _decode_version(raw: str) -> Optional[str]:
    """Turn a raw WPS version byte into airodump-ng's ``major.minor`` string.

    tshark prints the WPS version attributes as a hex byte (``0x10``, ``0x20``),
    with the high nibble the major and the low nibble the minor, exactly how
    airodump-ng derives the ``2.0`` / ``1.0`` it shows with ``--wps``. Returns
    ``None`` only when the field is empty or unparseable.
    """
    raw = raw.strip().lower()
    if not raw:
        return None
    try:
        val = int(raw, 16)
    except ValueError:
        return None
    return f"{val >> 4}.{val & 0x0F}"


def parse_wps(tshark_output: str) -> dict[str, dict]:
    """Parse ``tshark`` WPS field rows into ``{bssid: {version, locked}}``.

    Each row is ``bssid|version|version2|ap_setup_locked`` (see ``_FIELDS``).
    The WPS 2.0 attribute (``wps.version2``) wins over the legacy one when both
    are present, matching what airodump-ng shows. A row only exists when a frame
    carried a WPS element, so the AP has WPS even if no version byte decodes; in
    that case the version is reported as ``"0.0"`` rather than dropped.
    ap_setup_locked is truthy when tshark prints ``1`` / ``True``.
    """
    found: dict[str, dict] = {}
    for line in tshark_output.splitlines():
        cols = line.split(_SEP)
        bssid = normalize_mac(cols[0]) if cols else ""
        if not bssid:
            continue
        version1 = cols[1] if len(cols) > 1 else ""
        version2 = cols[2] if len(cols) > 2 else ""
        locked = cols[3].strip().lower() if len(cols) > 3 else ""
        version = _decode_version(version2) or _decode_version(version1) or "0.0"
        found[bssid] = {
            "version": version,
            "locked": locked in ("1", "true", "0x01"),
        }
    return found


class WpsWatcher:
    """Poll a source's pcap for WPS info; accumulate the latest per BSSID."""

    def __init__(self, source):
        self._source = source
        self._wps: dict[str, dict] = {}

    @staticmethod
    def available() -> bool:
        return shutil.which("tshark") is not None

    def _cap_path(self) -> Optional[str]:
        getter = getattr(self._source, "latest_cap", None)
        return getter() if callable(getter) else None

    def poll(self) -> dict[str, dict]:
        """Return the cumulative ``{bssid: {version, locked}}`` seen so far."""
        cap = self._cap_path()
        if not cap or not self.available():
            return dict(self._wps)
        try:
            out = subprocess.run(
                ["tshark", "-r", cap, "-n", "-Y", WPS_FILTER, "-T", "fields"]
                + [arg for field in _FIELDS for arg in ("-e", field)]
                + ["-E", f"separator={_SEP}"],
                capture_output=True, text=True, timeout=25, check=False,
            ).stdout
        except (OSError, subprocess.SubprocessError):
            return dict(self._wps)
        self._wps.update(parse_wps(out))
        return dict(self._wps)
