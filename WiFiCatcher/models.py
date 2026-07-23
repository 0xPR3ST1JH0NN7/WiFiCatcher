"""Core data model: :class:`AccessPoint` (AP / BSSID) and :class:`Client` (station)
are the graph node types; a :class:`Scan` is one parsed capture and is what every
parser returns.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional


def normalize_mac(mac: str) -> str:
    """Return an upper-cased MAC in colon form, empty if invalid. Hyphen-separated
    MACs (``AA-BB-CC-DD-EE-FF``) are accepted and converted.
    """
    mac = (mac or "").strip().upper().replace("-", ":")
    return mac if len(mac) == 17 and mac.count(":") == 5 else ""


@dataclass
class AccessPoint:
    bssid: str
    essid: str = "<Hidden>"
    channel: Optional[str] = None
    privacy: Optional[str] = None          # WPA2 / WPA3 / WEP / OPN ...
    cipher: Optional[str] = None           # CCMP / TKIP ...
    authentication: Optional[str] = None   # PSK / MGT / SAE ...
    power: Optional[int] = None            # signal strength (dBm), often negative
    beacons: Optional[int] = None
    data: Optional[int] = None             # # data frames / IVs
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    vendor: Optional[str] = None           # resolved from OUI
    wps: Optional[bool] = None             # WPS advertised in beacons (live only)
    wps_version: Optional[str] = None      # "1.0" / "2.0"
    wps_locked: Optional[bool] = None      # AP setup locked
    lat: Optional[float] = None
    lon: Optional[float] = None

    @property
    def is_hidden(self) -> bool:
        return not self.essid or self.essid == "<Hidden>"


@dataclass
class Client:
    mac: str
    associated_bssid: Optional[str] = None  # None / "(not associated)" -> unassociated
    power: Optional[int] = None
    packets: Optional[int] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    probed_essids: list[str] = field(default_factory=list)
    vendor: Optional[str] = None

    @property
    def is_associated(self) -> bool:
        return bool(self.associated_bssid) and self.associated_bssid != "(not associated)"


@dataclass
class Scan:
    """Parsed output of a single capture file."""

    access_points: list[AccessPoint] = field(default_factory=list)
    clients: list[Client] = field(default_factory=list)
    source: Optional[str] = None   # original filename
    format: Optional[str] = None   # parser id that produced it

    def summary(self) -> dict:
        associated = sum(1 for c in self.clients if c.is_associated)
        return {
            "source": self.source,
            "format": self.format,
            "access_points": len(self.access_points),
            "clients": len(self.clients),
            "associated_clients": associated,
            "hidden_aps": sum(1 for ap in self.access_points if ap.is_hidden),
        }

    def to_dict(self) -> dict:
        return {
            "access_points": [asdict(ap) for ap in self.access_points],
            "clients": [asdict(c) for c in self.clients],
            "summary": self.summary(),
        }
