"""Wireless interface discovery and monitor-mode management.

Discovery reads ``sysfs`` (no privileges); switching to monitor mode shells out
to ``airmon-ng`` and carries the offensive guardrails (root, aircrack-ng suite).
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from typing import Callable, Optional

from WiFiCatcher.operations.base import (
    OperationError,
    require_authorization,
    require_tools,
)

SYSFS_NET = "/sys/class/net"

# Value reported by /sys/class/net/<iface>/type for monitor mode (radiotap).
ARPHRD_IEEE80211_RADIOTAP = 803


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
    """List wireless interfaces with their mode (no privileges).

    Returns ``[{"name", "mode": monitor|managed|unknown, "monitor": bool}, ...]``
    sorted by name.
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


@dataclass
class MonitorHandle:
    """What :func:`ensure_monitor_mode` set up, so teardown can undo it.

    ``interface`` is the capture (monitor) iface, ``original`` the user's pick,
    and ``enabled`` records whether *we* switched it — restoration only touches
    interfaces we changed ourselves.
    """

    interface: str
    original: str
    enabled: bool


def _run(cmd: list) -> "subprocess.CompletedProcess":
    return subprocess.run(cmd, capture_output=True, text=True,
                          timeout=30, check=False)


def _parse_monitor_iface(stdout: str) -> Optional[str]:
    """Pull the monitor interface name out of airmon-ng's output.

    airmon-ng phrasing varies by version (e.g. "monitor mode enabled on wlan0mon"
    vs "... vif enabled for [phy0]wlan0 on [phy0]wlan0mon"), so several patterns.
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
                        kill_interferers: bool = True,
                        run: Runner = _run, sysfs: str = SYSFS_NET) -> MonitorHandle:
    """Ensure ``iface`` is in monitor mode, enabling it with airmon-ng if needed.

    ``airmon-ng check kill`` first clears interferers (NetworkManager,
    wpa_supplicant) so capture is reliable. The returned :class:`MonitorHandle`'s
    capture iface may differ from ``iface`` (airmon-ng may make a vif, wlan0 ->
    wlan0mon); an iface already in monitor mode is returned untouched and not
    restored. Raises OperationError if the iface is missing, the guardrails fail,
    or no usable monitor interface results.
    """
    if not interface_exists(iface, sysfs):
        raise OperationError(f"Interface '{iface}' was not found on this system.")
    if is_monitor(iface, sysfs):
        return MonitorHandle(interface=iface, original=iface, enabled=False)

    # Changing the radio's mode is privileged: enforce the offensive guardrails.
    require_authorization(acknowledged)
    require_tools("airmon-ng", hint="Install the aircrack-ng suite.")

    # Clear interfering processes first so monitor mode actually sticks. This is
    # best-effort: a failure here must not block enabling monitor mode.
    if kill_interferers:
        try:
            run(["airmon-ng", "check", "kill"])
        except Exception:
            pass

    before = {i["name"] for i in list_wireless_interfaces(sysfs)}
    proc = run(["airmon-ng", "start", iface])
    stdout = (getattr(proc, "stdout", "") or "")
    if getattr(proc, "returncode", 1) != 0:
        detail = stdout.strip() or (getattr(proc, "stderr", "") or "").strip()
        raise OperationError(
            f"airmon-ng could not enable monitor mode on '{iface}'."
            + (f" {detail}" if detail else ""))

    cap = _resolve_capture_iface(iface, stdout, before, sysfs)
    return MonitorHandle(interface=cap, original=iface, enabled=True)


def _resolve_capture_iface(iface: str, stdout: str, before: set,
                           sysfs: str) -> str:
    """Pick the monitor interface airmon-ng produced, most reliable cue first."""
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


def restore_managed_mode(handle: Optional[MonitorHandle], run: Runner = _run) -> None:
    """Return an interface we switched into monitor mode back to managed mode.

    Best-effort: a no-op when ``handle`` is ``None`` or we did not enable monitor
    mode, and never raises (cleanup must not crash stop). Note: airmon-ng does not
    restart the NetworkManager / wpa_supplicant it killed — that happens elsewhere.
    """
    if handle is None or not handle.enabled:
        return
    try:
        run(["airmon-ng", "stop", handle.interface])
    except Exception:
        pass


def restart_network_services(run: Runner = _run) -> None:
    """(Re)start NetworkManager on shutdown if it is not already running.

    Capture kills NetworkManager so monitor mode sticks; without a restart Wi-Fi
    stays down after exit. Checks the live service state (not bookkeeping) so it
    works whichever warden stopped it, and leaves a running NM alone so a replay
    session isn't bounced. Best-effort: root, systemctl then service, never raises.
    """
    if not (hasattr(os, "geteuid") and os.geteuid() == 0):
        return
    try:
        active = run(["systemctl", "is-active", "NetworkManager"])
        if (getattr(active, "stdout", "") or "").strip() == "active":
            return  # already up: don't bounce a working connection
    except Exception:
        pass  # can't tell (no systemctl?): fall through and try to (re)start it
    for cmd in (["systemctl", "restart", "NetworkManager"],
                ["service", "NetworkManager", "restart"]):
        try:
            proc = run(cmd)
            if getattr(proc, "returncode", 1) == 0:
                break
        except Exception:
            continue
