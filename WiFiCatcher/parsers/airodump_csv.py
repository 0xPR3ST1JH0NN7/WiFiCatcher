"""Parser for airodump-ng CSV files.

airodump-ng writes two CSV sections in one file:

  BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher,
  Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key

  (blank line)

  Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs

Quoting matters (ESSIDs and probe lists can contain commas), so we use the
``csv`` module rather than a naive ``str.split(',')``.
"""

from __future__ import annotations

import csv
import io

from WiFiCatcher.models import AccessPoint, Client, Scan, normalize_mac
from WiFiCatcher.parsers.base import Parser, register


def _to_int(value: str):
    value = (value or "").strip()
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


class AirodumpCsvParser(Parser):
    id = "airodump-csv"
    name = "airodump-ng CSV"
    extensions = (".csv",)

    def detect(self, text: str, filename: str = "") -> bool:
        head = text[:2048]
        return "BSSID" in head and ("Station MAC" in text or "# beacons" in head)

    def parse(self, text: str, filename: str = "") -> Scan:
        aps: list[AccessPoint] = []
        clients: list[Client] = []

        reader = csv.reader(io.StringIO(text))
        in_clients = False

        for row in reader:
            if not row or all(not cell.strip() for cell in row):
                continue
            cells = [c.strip() for c in row]
            first = cells[0]

            # Section switch / header rows.
            if first == "Station MAC":
                in_clients = True
                continue
            if first == "BSSID":
                in_clients = False
                continue

            if not in_clients:
                ap = self._parse_ap(cells)
                if ap:
                    aps.append(ap)
            else:
                client = self._parse_client(cells)
                if client:
                    clients.append(client)

        return Scan(access_points=aps, clients=clients,
                    source=filename or None, format=self.id)

    @staticmethod
    def _parse_ap(cells: list[str]):
        if len(cells) < 14:
            return None
        bssid = normalize_mac(cells[0])
        if not bssid:
            return None
        essid = cells[13] if len(cells) > 13 and cells[13] else "<Hidden>"
        return AccessPoint(
            bssid=bssid,
            essid=essid,
            first_seen=cells[1] or None,
            last_seen=cells[2] or None,
            channel=cells[3] or None,
            privacy=cells[5] or None,
            cipher=cells[6] or None,
            authentication=cells[7] or None,
            power=_to_int(cells[8]),
            beacons=_to_int(cells[9]),
            data=_to_int(cells[10]),
        )

    @staticmethod
    def _parse_client(cells: list[str]):
        if len(cells) < 6:
            return None
        mac = normalize_mac(cells[0])
        if not mac:
            return None
        bssid_raw = cells[5].strip()
        associated = normalize_mac(bssid_raw) or (
            bssid_raw if bssid_raw == "(not associated)" else None)
        probes = [p.strip() for p in cells[6:] if p.strip()] if len(cells) > 6 else []
        return Client(
            mac=mac,
            first_seen=cells[1] or None,
            last_seen=cells[2] or None,
            power=_to_int(cells[3]),
            packets=_to_int(cells[4]),
            associated_bssid=associated,
            probed_essids=probes,
        )


register(AirodumpCsvParser())
