"""WPS detection over a live pcap.

WPS-enabled access points advertise a WPS information element in their beacons
and probe responses. airodump-ng's CSV does not carry it, but the pcap it writes
alongside does, so we read the WPS version and AP-setup-locked state per BSSID
with ``tshark`` (already used for handshake detection).

:func:`parse_wps` is pure and unit-tested; the ``tshark`` call is best-effort and
degrades to "no detection" when tshark is absent or the capture has no WPS APs.
"""

from __future__ import annotations

import functools
import shutil
import subprocess
from typing import Optional

from WiFiCatcher.models import normalize_mac

# tshark fields, joined by this separator so values with commas stay intact.
_SEP = "|"

# WPS attribute fields. The WPS 2.0 marker lives in the WFA vendor extension and
# is exposed by tshark as ``wps.ext.version2`` (NOT ``wps.version2``, a name no
# tshark build registers). A single unknown ``-e`` field or filter term makes
# tshark reject the whole command and print nothing, which silently disables
# detection, so the field names below are probed against the local tshark and
# any it does not know are dropped rather than passed through blindly.
_BSSID = "wlan.bssid"
_V1 = "wps.version"            # legacy Version attribute (0x10 even on WPS 2.0)
_V2 = "wps.ext.version2"       # WFA extension Version2 attribute (0x20 = WPS 2.0)
_LOCKED = "wps.ap_setup_locked"
_STATE = "wps.wifi_protected_setup_state"

# Desired extraction columns, in order (BSSID first). parse_wps maps by name, so
# dropping an unknown field just shortens the row without misaligning it.
_DESIRED = (_BSSID, _V2, _V1, _LOCKED)


@functools.lru_cache(maxsize=1)
def _known_fields() -> frozenset[str]:
    """Filter names the local tshark registers, or empty when it cannot be run.

    ``tshark -G fields`` prints one tab-separated row per field; ``F`` rows carry
    the filter name in the third column. An empty result means "could not probe",
    which callers treat as "assume every desired field is valid".
    """
    try:
        out = subprocess.run(
            ["tshark", "-G", "fields"],
            capture_output=True, text=True, timeout=30, check=False,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return frozenset()
    return frozenset(
        parts[2]
        for parts in (line.split("\t") for line in out.splitlines())
        if len(parts) > 2 and parts[0] == "F"
    )


def wps_fields() -> list[str]:
    """Ordered ``-e`` fields for the tshark WPS pass, limited to known ones.

    Always begins with the BSSID; a version / locked field is dropped only when
    the probe succeeded and the name is genuinely absent.
    """
    known = _known_fields()
    return [f for f in _DESIRED if f == _BSSID or not known or f in known]


def wps_filter() -> str:
    """Display filter selecting any WPS-bearing frame, from valid fields only.

    Keying only on the legacy Version attribute misses APs that advertise WPS
    solely via Version2 or expose just the setup-state attribute, so all three
    are OR'd together (minus any the local tshark does not know).
    """
    known = _known_fields()
    terms = [f for f in (_V1, _V2, _STATE) if not known or f in known]
    return " || ".join(terms) if terms else _V1


def _decode_version(raw: str) -> Optional[str]:
    """Turn a raw WPS version byte into airodump-ng's ``major.minor`` string.

    tshark prints the version attributes as a byte whose high nibble is the major
    and low nibble the minor, exactly how airodump-ng derives the ``2.0`` / ``1.0``
    it shows with ``--wps``. Both the hex form (``0x20``) and a bare decimal
    (``32``) are accepted. Returns ``None`` only when empty or unparseable.
    """
    raw = raw.strip().lower()
    if not raw:
        return None
    try:
        val = int(raw, 16) if raw.startswith("0x") else int(raw)
    except ValueError:
        return None
    return f"{val >> 4}.{val & 0x0F}"


def parse_wps(tshark_output: str, fields: list[str]) -> dict[str, dict]:
    """Parse ``tshark`` WPS field rows into ``{bssid: {version, locked}}``.

    ``fields`` is the same ordered ``-e`` list handed to tshark, so columns are
    located by name and a probed-away field simply reads as empty. The Version2
    attribute wins over the legacy one when both are present, matching airodump-ng.
    A row only exists when a frame carried a WPS element, so the AP has WPS even if
    no version byte decodes; in that case the version is reported as ``"0.0"``
    rather than dropped. ap_setup_locked is truthy when tshark prints ``1`` / ``True``.
    """
    index = {name: i for i, name in enumerate(fields)}

    def col(cols: list[str], name: str) -> str:
        i = index.get(name)
        return cols[i] if i is not None and i < len(cols) else ""

    found: dict[str, dict] = {}
    for line in tshark_output.splitlines():
        cols = line.split(_SEP)
        bssid = normalize_mac(col(cols, _BSSID))
        if not bssid:
            continue
        version = (
            _decode_version(col(cols, _V2))
            or _decode_version(col(cols, _V1))
            or "0.0"
        )
        locked = col(cols, _LOCKED).strip().lower()
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
        fields = wps_fields()
        try:
            out = subprocess.run(
                ["tshark", "-r", cap, "-n", "-Y", wps_filter(), "-T", "fields"]
                + [arg for field in fields for arg in ("-e", field)]
                + ["-E", f"separator={_SEP}"],
                capture_output=True, text=True, timeout=25, check=False,
            ).stdout
        except (OSError, subprocess.SubprocessError):
            return dict(self._wps)
        self._wps.update(parse_wps(out, fields))
        return dict(self._wps)
