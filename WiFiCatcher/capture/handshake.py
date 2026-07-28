"""WPA handshake detection from ``tshark`` EAPOL output.

A full 4-way handshake is 4 EAPOL frames. ``parse_handshakes`` is the pure,
tested core: it takes the EAPOL rows a source watcher extracts from airodump-ng's
pcap with ``tshark`` and reports each BSSID that reached a crackable pair. The
tshark invocation itself lives with the capture sources.
"""

from __future__ import annotations

from WiFiCatcher.models import normalize_mac

# The four messages of a WPA 4-way handshake are EAPOL-Key frames (eapol.type
# == 3), tagged by Wireshark with a message number 1..4. A capture is usable
# for offline auditing with any adjacent pair (M1+M2, M2+M3 or M3+M4), not only
# with a clean set of all four, which is often incomplete in the field: a frame
# is lost, or airodump-ng is off-channel for part of the exchange. Flagging on a
# crackable pair rather than on four raw frames is what makes detection reliable.
_CRACKABLE_PAIRS = ({1, 2}, {2, 3}, {3, 4})

# Fallback threshold used only when the message number is unavailable (older
# tshark leaves it blank): count EAPOL-Key frames and flag once a couple appear.
DEFAULT_MIN_FRAMES = 2


def parse_handshakes(tshark_output: str, min_frames: int = DEFAULT_MIN_FRAMES) -> set[str]:
    """Return BSSIDs that show a captured WPA 4-way handshake.

    Input is the output of ``tshark -Y 'eapol.type == 3' -T fields
    -e wlan.bssid -e wlan_rsna_eapol.keydes.msgnr``: one EAPOL-Key frame per
    line, BSSID and 4-way message number tab-separated. A BSSID is reported when
    its captured messages contain a crackable adjacent pair (M1+M2, M2+M3 or
    M3+M4). When the message number is missing, fall back to counting frames and
    flag at ``min_frames``.
    """
    seen_msgs: dict[str, set[int]] = {}
    counts: dict[str, int] = {}
    for line in tshark_output.splitlines():
        parts = line.split("\t")
        bssid = normalize_mac(parts[0].strip())
        if not bssid:
            continue
        counts[bssid] = counts.get(bssid, 0) + 1
        if len(parts) > 1 and parts[1].strip():
            try:
                seen_msgs.setdefault(bssid, set()).add(int(parts[1].strip()))
            except ValueError:
                pass

    found: set[str] = set()
    for bssid, count in counts.items():
        msgs = seen_msgs.get(bssid)
        if msgs:
            if any(pair <= msgs for pair in _CRACKABLE_PAIRS):
                found.add(bssid)
        elif count >= min_frames:
            found.add(bssid)
    return found
