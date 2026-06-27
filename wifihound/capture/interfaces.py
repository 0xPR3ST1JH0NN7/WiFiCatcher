"""Wireless interface discovery and monitor-mode management.

Listing the wireless interfaces and reading their current mode is done straight
from ``sysfs`` (``/sys/class/net``), so it needs no privileges and no external
tools — handy for letting the user *pick* an interface instead of typing a name.

Switching an interface into monitor mode shells out to ``airmon-ng`` and so
carries the same guardrails as the rest of the offensive subsystem: it requires
root and the aircrack-ng suite on PATH.
"""

from __future__ import annotations

import os
import re
import subprocess
from typing import Callable, Optional

from wifihound.operations.base import (
    OperationError,
    require_authorization,
    require_tools,
)

SYSFS_NET = "/sys/class/net"

# Values reported by /sys/class/net/<iface>/type (Linux ARPHRD_* constants).
ARPHRD_ETHER = 1                  # managed-mode Wi-Fi presents as ethernet
ARPHRD_IEEE80211_RADIOTAP = 803   # monitor mode (radiotap headers)


def _read(path: str) -> Optional[str]:
    try:
        with open(path, "r") as fh:
            return fh.read().strip()
    except OSError:
        return None


def is_wireless(name: str, sysfs: str = SYSFS_NET) -> bool:
    """True if ``name`` is an 802.11 interface (has a phy / wireless node)."""
    base = os.path.join(sysfs, name)
    return (os.path.exists(os.path.join(base, "phy80211"))
            or os.path.isdir(os.path.join(base, "wireless")))


def interface_exists(name: str, sysfs: str = SYSFS_NET) -> bool:
    """True if a network interface called ``name`` exists on this host."""
    return bool(name) and os.path.isdir(os.path.join(sysfs, name))


def interface_mode(name: str, sysfs: str = SYSFS_NET) -> str:
    """Return ``"monitor"``, ``"managed"`` or ``"unknown"`` for ``name``."""
    raw = _read(os.path.join(sysfs, name, "type"))
    if raw is None:
        return "unknown"
    try:
        kind = int(raw)
    except ValueError:
        return "unknown"
    if kind == ARPHRD_IEEE80211_RADIOTAP:
        return "monitor"
    return "managed"


def is_monitor(name: str, sysfs: str = SYSFS_NET) -> bool:
    return interface_mode(name, sysfs) == "monitor"


def list_wireless_interfaces(sysfs: str = SYSFS_NET) -> list[dict]:
    """List the wireless interfaces with their mode. No privileges required.

    Returns ``[{"name": str, "mode": "monitor"|"managed"|"unknown",
    "monitor": bool}, ...]`` sorted by name.
    """
    out: list[dict] = []
    try:
        names = sorted(os.listdir(sysfs))
    except OSError:
        return out
    for name in names:
        if name == "lo" or not is_wireless(name, sysfs):
            continue
        mode = interface_mode(name, sysfs)
        out.append({"name": name, "mode": mode, "monitor": mode == "monitor"})
    return out


# --------------------------------------------------------- monitor switching
Runner = Callable[[list], "subprocess.CompletedProcess"]


def _run(cmd: list) -> "subprocess.CompletedProcess":
    return subprocess.run(cmd, capture_output=True, text=True,
                          timeout=30, check=False)


def _parse_monitor_iface(stdout: str) -> Optional[str]:
    """Pull the resulting monitor interface name out of airmon-ng's output.

    airmon-ng phrasing varies by version, e.g.::

        (monitor mode enabled on wlan0mon)
        (mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon)
        (monitor mode vif enabled on [phy0]wlan0mon)
    """
    patterns = (
        r"monitor mode (?:vif )?enabled (?:for \S+ )?on (?:\[[^\]]*\])?(\w+)",
        r"monitor mode enabled on (?:\[[^\]]*\])?(\w+)",
        r"enabled on (?:\[[^\]]*\])?(\w+)",
    )
    for pat in patterns:
        match = re.search(pat, stdout)
        if match:
            return match.group(1)
    return None


def ensure_monitor_mode(iface: str, acknowledged: bool = True,
                        run: Runner = _run, sysfs: str = SYSFS_NET) -> str:
    """Ensure ``iface`` is in monitor mode, enabling it with airmon-ng if not.

    Returns the interface to capture on, which may differ from ``iface`` when
    airmon-ng creates a separate monitor vif (e.g. ``wlan0`` -> ``wlan0mon``).
    An interface already in monitor mode is returned untouched.

    Raises :class:`~wifihound.operations.base.OperationError` (or its
    :class:`OperationNotAuthorized` subclass) if the interface is missing, the
    privilege/tool guardrails fail, or airmon-ng does not produce a usable
    monitor interface.
    """
    if not interface_exists(iface, sysfs):
        raise OperationError(f"Interface '{iface}' was not found on this system.")
    if is_monitor(iface, sysfs):
        return iface

    # Changing the radio's mode is privileged: enforce the offensive guardrails.
    require_authorization(acknowledged)
    require_tools("airmon-ng")

    before = {i["name"] for i in list_wireless_interfaces(sysfs)}
    proc = run(["airmon-ng", "start", iface])
    stdout = (getattr(proc, "stdout", "") or "")
    if getattr(proc, "returncode", 1) != 0:
        detail = stdout.strip() or (getattr(proc, "stderr", "") or "").strip()
        raise OperationError(
            f"airmon-ng could not enable monitor mode on '{iface}'."
            + (f" {detail}" if detail else ""))

    # Resolve the resulting monitor interface, most reliable signal first.
    named = _parse_monitor_iface(stdout)
    if named and is_monitor(named, sysfs):
        return named
    if is_monitor(iface, sysfs):           # some drivers switch in place
        return iface
    if is_monitor(iface + "mon", sysfs):   # common wlan0 -> wlan0mon convention
        return iface + "mon"
    for info in list_wireless_interfaces(sysfs):   # any new monitor vif
        if info["monitor"] and info["name"] not in before:
            return info["name"]
    if named:                              # sysfs lagged but airmon-ng named it
        return named
    raise OperationError(
        f"Monitor mode was enabled but the monitor interface for '{iface}' "
        "could not be determined. Check `airmon-ng` / `iw dev`.")
