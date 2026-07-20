"""Deauth / disassoc detection over a live pcap.

802.11 deauthentication (management subtype 0x0c) and disassociation (0x0a)
frames mark the end of a client-AP association. airodump-ng's CSV lags and keeps
reporting the old association for a while, so we read these frames from the pcap
airodump writes and use them to drop the association immediately.

:func:`parse_deauth` is pure and unit-tested; the ``tshark`` call is best-effort.
"""

from __future__ import annotations

from WiFiCatcher.models import normalize_mac

_SEP = "|"
# A deauthentication (0x0c) or disassociation (0x0a) management frame.
DEAUTH_FILTER = "wlan.fc.type_subtype == 0x0c || wlan.fc.type_subtype == 0x0a"
FIELDS = ["frame.time_epoch", "wlan.sa", "wlan.da", "wlan.bssid"]
_BROADCAST = "FF:FF:FF:FF:FF:FF"


def parse_deauth(tshark_output: str, since: float = 0.0) -> list[dict]:
    """Parse ``tshark`` deauth/disassoc rows into disconnection events.

    Each row is ``time_epoch|sa|da|bssid`` (see :data:`FIELDS`). Returns, for
    frames strictly newer than ``since`` (epoch seconds), a list of
    ``{"client": mac|None, "bssid": mac, "broadcast": bool, "ts": float}``. The
    client is whichever of sa/da is not the BSSID; a destination of
    ``ff:ff:ff:ff:ff:ff`` is a broadcast deauth that hits every client of the
    BSSID, reported with ``client=None`` and ``broadcast=True``. MACs are
    normalized (upper-case) so they compare equal to the parsed scan.
    """
    events: list[dict] = []
    for line in tshark_output.splitlines():
        cols = line.split(_SEP)
        if len(cols) < 4:
            continue
        try:
            ts = float(cols[0])
        except ValueError:
            continue
        if ts <= since:
            continue
        bssid = normalize_mac(cols[3])
        if not bssid:
            continue
        da = normalize_mac(cols[2])
        if da == _BROADCAST:
            events.append({"client": None, "bssid": bssid,
                           "broadcast": True, "ts": ts})
            continue
        sa = normalize_mac(cols[1])
        if sa and sa != bssid:
            client = sa
        elif da and da != bssid:
            client = da
        else:
            continue
        events.append({"client": client, "bssid": bssid,
                       "broadcast": False, "ts": ts})
    return events
