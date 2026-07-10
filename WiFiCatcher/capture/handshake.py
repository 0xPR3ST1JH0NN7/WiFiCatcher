"""WPA handshake detection over a live pcap.

During a deauth, a reconnecting client performs the WPA 4-way handshake. A full
handshake is four EAPOL frames between one AP and one client. We let airodump-ng
write a pcap alongside the CSV and periodically count EAPOL frames per BSSID with
``tshark``; a BSSID reaching the frame threshold is reported as "handshake
captured".

The frame-counting logic (:func:`parse_handshakes`) is pure and unit-tested; the
``tshark`` call is best-effort and degrades to "no detection" when tshark is
absent.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import Optional

from WiFiCatcher.models import normalize_mac

# A complete 4-way handshake is 4 EAPOL frames; default threshold is lenient
# enough to also flag a captured handshake when a frame or two is missed.
DEFAULT_MIN_FRAMES = 4


def parse_handshakes(tshark_output: str, min_frames: int = DEFAULT_MIN_FRAMES) -> set[str]:
    """Return BSSIDs whose EAPOL frame count reaches ``min_frames``.

    Input is one BSSID per line (``tshark -e wlan.bssid`` over an EAPOL filter).
    """
    counts: dict[str, int] = {}
    for line in tshark_output.splitlines():
        bssid = normalize_mac(line.strip())
        if bssid:
            counts[bssid] = counts.get(bssid, 0) + 1
    return {bssid for bssid, n in counts.items() if n >= min_frames}


class HandshakeWatcher:
    """Poll a source's pcap for WPA handshakes; report each BSSID once."""

    def __init__(self, source, min_frames: int = DEFAULT_MIN_FRAMES):
        self._source = source
        self._min_frames = min_frames
        self._seen: set[str] = set()

    @staticmethod
    def available() -> bool:
        return shutil.which("tshark") is not None

    def _cap_path(self) -> Optional[str]:
        getter = getattr(self._source, "latest_cap", None)
        return getter() if callable(getter) else None

    def poll(self) -> set[str]:
        """Return the cumulative set of BSSIDs with a captured handshake."""
        cap = self._cap_path()
        if not cap or not self.available():
            return set(self._seen)
        try:
            out = subprocess.run(
                ["tshark", "-r", cap, "-Y", "eapol",
                 "-T", "fields", "-e", "wlan.bssid"],
                capture_output=True, text=True, timeout=20, check=False,
            ).stdout
        except (OSError, subprocess.SubprocessError):
            return set(self._seen)
        self._seen |= parse_handshakes(out, self._min_frames)
        return set(self._seen)
