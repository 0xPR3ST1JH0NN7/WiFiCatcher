"""OUI -> vendor resolution.

The first 3 octets of a MAC (the OUI) identify the hardware vendor. We ship a
small built in table of common vendors so the tool works offline with zero
setup, and allow loading a fuller IEEE/Wireshark ``manuf`` file when available
(``WIFICATCHER_OUI_FILE`` env var or :func:`load_oui_file`).
"""

from __future__ import annotations

import os
import re
from typing import Optional

# A compact, offline-friendly seed list. Extend via an external OUI file.
_BUILTIN_OUI: dict[str, str] = {
    "00:00:0C": "Cisco",
    "00:1A:11": "Google",
    "3C:5A:B4": "Google",
    "F4:F5:E8": "Google",
    "00:03:93": "Apple",
    "00:05:02": "Apple",
    "00:0A:27": "Apple",
    "00:17:F2": "Apple",
    "AC:DE:48": "Apple",
    "F0:18:98": "Apple",
    "DC:A6:32": "Raspberry Pi",
    "B8:27:EB": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "00:50:F2": "Microsoft",
    "00:1D:D8": "Microsoft",
    "00:24:D7": "Intel",
    "00:1B:77": "Intel",
    "3C:A9:F4": "Intel",
    "00:18:4D": "Netgear",
    "A0:40:A0": "Netgear",
    "00:14:6C": "Netgear",
    "00:1F:33": "Netgear",
    "C0:3F:0E": "Netgear",
    "00:0F:B5": "Netgear",
    "00:25:9C": "Cisco-Linksys",
    "00:1A:70": "Cisco-Linksys",
    "C8:D7:19": "Cisco Meraki",
    "00:18:0A": "Cisco Meraki",
    "00:1C:10": "Cisco-Linksys",
    "00:90:4C": "Epigram",
    "00:26:5A": "D-Link",
    "1C:7E:E5": "D-Link",
    "00:1E:58": "D-Link",
    "00:24:01": "D-Link",
    "00:0C:F1": "Intel",
    "00:13:46": "D-Link",
    "00:1D:7E": "Cisco-Linksys",
    "00:23:69": "Cisco-Linksys",
    "00:21:29": "Cisco-Linksys",
    "00:14:BF": "Cisco-Linksys",
    "C4:3D:C7": "Netgear",
    "20:4E:7F": "Netgear",
    "84:1B:5E": "Netgear",
    "00:1F:3F": "AVM (FRITZ!Box)",
    "00:04:0E": "AVM (FRITZ!Box)",
    "38:10:D5": "AVM (FRITZ!Box)",
    "C0:25:06": "AVM (FRITZ!Box)",
    "E0:28:6D": "AVM (FRITZ!Box)",
    "00:1C:DF": "Belkin",
    "08:86:3B": "Belkin",
    "94:10:3E": "Belkin",
    "EC:1A:59": "Belkin",
    "00:24:B2": "Netgear",
    "5C:F3:70": "Samsung",
    "00:12:FB": "Samsung",
    "00:15:99": "Samsung",
    "34:23:BA": "Samsung",
    "F0:08:F1": "Samsung",
    "00:1A:8A": "Samsung",
    "8C:77:12": "Samsung",
    "00:26:37": "Samsung",
    "00:E0:4C": "Realtek",
    "52:54:00": "QEMU/KVM (virtual)",
    "08:00:27": "VirtualBox (virtual)",
    "00:0C:29": "VMware (virtual)",
    "00:50:56": "VMware (virtual)",
    "00:16:3E": "Xen (virtual)",
    "00:1D:0F": "TP-Link",
    "14:CC:20": "TP-Link",
    "50:C7:BF": "TP-Link",
    "A4:2B:B0": "TP-Link",
    "EC:08:6B": "TP-Link",
    "00:27:19": "TP-Link",
    "30:B5:C2": "TP-Link",
    "F4:EC:38": "TP-Link",
    "C0:4A:00": "TP-Link",
    "00:1F:5B": "Apple",
    "BC:92:6B": "Apple",
    "D0:23:DB": "Apple",
    "A4:5E:60": "Apple",
}

# Loaded OUI map (built in, merged with any external file).
_OUI: dict[str, str] = dict(_BUILTIN_OUI)


def _oui_key(mac: str) -> str:
    return (mac or "").upper().replace("-", ":")[:8]


def lookup(mac: str) -> Optional[str]:
    """Return the vendor for a MAC, or None if unknown."""
    return _OUI.get(_oui_key(mac))


# IEEE ``oui.txt`` hex rows look like: ``D0-65-78   (hex)   Intel Corporate``.
_IEEE_HEX_RE = re.compile(
    r"^([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$")


def load_oui_file(path: str) -> int:
    """Load an OUI table from a Wireshark ``manuf`` file, an IEEE ``oui.txt``
    (the ``ieee-data`` package / aircrack-ng), or an nmap prefixes file.

    Handles ``00:11:22  Vendor``, ``001122 Vendor`` and the IEEE
    ``D0-65-78   (hex)   Intel Corporate`` form. Comments, blanks, the IEEE
    ``(base 16)`` duplicate rows and indented address lines are ignored. Only
    three-octet prefixes are kept. Returns the number of entries added.
    """
    added = 0
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = _IEEE_HEX_RE.match(line)
            if m:
                prefix, vendor = m.group(1), m.group(2).strip()
            else:
                if "(base 16)" in line or "(hex)" in line:
                    continue  # IEEE duplicate row / stray marker line
                parts = line.split(None, 1)
                if len(parts) < 2:
                    continue
                prefix, vendor = parts[0], parts[1].strip()
            prefix = prefix.upper().replace("-", ":")
            if "/" in prefix:  # netmask form, skip non-/24 oddities
                prefix = prefix.split("/")[0]
            if ":" not in prefix and len(prefix) >= 6:  # bare hex
                prefix = ":".join(prefix[i:i + 2] for i in range(0, 6, 2))
            key = prefix[:8]
            if len(key) == 8 and vendor:
                _OUI[key] = vendor
                added += 1
    return added


def enrich_scan(scan) -> int:
    """Fill the ``vendor`` field on every AP and client in a scan.

    Returns the number of nodes for which a vendor was resolved.
    """
    resolved = 0
    for ap in scan.access_points:
        vendor = lookup(ap.bssid)
        if vendor:
            ap.vendor = vendor
            resolved += 1
    for client in scan.clients:
        vendor = lookup(client.mac)
        if vendor:
            client.vendor = vendor
            resolved += 1
    return resolved


# System OUI databases, in preference order. The IEEE ``oui.txt`` shipped by the
# ``ieee-data`` package (also used by aircrack-ng) is the common one on Linux, so
# vendors resolve out of the box without setting anything.
_SYSTEM_OUI_PATHS = (
    "/var/lib/ieee-data/oui.txt",
    "/usr/share/ieee-data/oui.txt",
    "/var/lib/misc/oui.txt",
    "/usr/share/aircrack-ng/oui.txt",
    "/etc/aircrack-ng/airodump-ng-oui.txt",
    "/usr/share/wireshark/manuf",
    "/usr/share/nmap/nmap-mac-prefixes",
)


def _autoload() -> None:
    """Load a fuller OUI table so vendors resolve beyond the built-in seed list.

    Priority: the ``WIFICATCHER_OUI_FILE`` env var, else the first system OUI
    database found. Best-effort: a missing or unreadable file just leaves the
    built-in table in place.
    """
    env_file = os.environ.get("WIFICATCHER_OUI_FILE")
    candidates = ([env_file] if env_file else []) + list(_SYSTEM_OUI_PATHS)
    for path in candidates:
        if path and os.path.exists(path):
            try:
                if load_oui_file(path):
                    return
            except OSError:
                continue


_autoload()
