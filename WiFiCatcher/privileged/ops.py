"""Validated privileged operations, executed helper-side (as root).

Each handler receives the request ``params`` (an untrusted dict from the app),
validates every field, then calls the existing WiFiCatcher operation. Building
the argv from validated fields — never from raw client strings — is what keeps
a compromised app from injecting arguments or reaching other binaries.

Handlers here are **unary** (request in, result out). Live capture is a stream
and is handled in :mod:`WiFiCatcher.privileged.server`.
"""

from __future__ import annotations

import re
import time
from typing import Any, Callable

from WiFiCatcher.models import normalize_mac

# Interface names: short, from a known charset — reject anything odd before it
# ever reaches a tool. Real wireless ifaces are additionally checked against
# /sys/class/net by ensure_monitor_mode / the capture code.
_IFACE_RE = re.compile(r"^[A-Za-z0-9._-]{1,32}$")
_MAX_ESSID = 32          # 802.11 SSID max length
_MAX_COUNT = 64          # mirrors operations.deauth.MAX_COUNT


class OpError(Exception):
    """A request that fails validation or execution."""


def _iface(params: dict, key: str = "iface", required: bool = True) -> str:
    val = (params.get(key) or "").strip()
    if not val:
        if required:
            raise OpError(f"'{key}' is required.")
        return ""
    if not _IFACE_RE.match(val):
        raise OpError(f"Invalid interface name for '{key}'.")
    return val


def _mac(params: dict, key: str, required: bool = True) -> str | None:
    raw = params.get(key)
    if not raw:
        if required:
            raise OpError(f"'{key}' is required.")
        return None
    mac = normalize_mac(raw)
    if not mac:
        raise OpError(f"Invalid MAC for '{key}'.")
    return mac


# --------------------------------------------------------------- handlers
def _monitor_start(params: dict) -> dict:
    from WiFiCatcher.capture.interfaces import ensure_monitor_mode
    handle = ensure_monitor_mode(_iface(params))
    return {"interface": handle.interface, "original": handle.original,
            "enabled": handle.enabled}


def _monitor_stop(params: dict) -> dict:
    from WiFiCatcher.capture.interfaces import MonitorHandle, restore_managed_mode
    handle = MonitorHandle(
        interface=_iface(params, "interface"),
        original=_iface(params, "original"),
        enabled=bool(params.get("enabled")),
    )
    restore_managed_mode(handle)
    return {"restored": handle.enabled}


def _deauth(params: dict) -> dict:
    from WiFiCatcher.operations.deauth import deauth
    count = params.get("count", 5)
    try:
        count = int(count)
    except (TypeError, ValueError):
        raise OpError("'count' must be an integer.")
    return deauth(
        interface=_iface(params),
        bssid=_mac(params, "bssid"),
        client=_mac(params, "client", required=False),
        count=max(1, min(count, _MAX_COUNT)),
        acknowledged=bool(params.get("acknowledged")),
        dry_run=bool(params.get("dry_run")),
    )


def _eap_enumerate(params: dict) -> dict:
    from WiFiCatcher.operations.enterprise import enumerate_eap_methods
    essid = (params.get("essid") or "").strip()
    if not essid or len(essid) > _MAX_ESSID:
        raise OpError("A valid ESSID (1-32 chars) is required.")
    identity = (params.get("identity") or "").strip()
    if not identity:
        raise OpError("An EAP identity is required.")
    return enumerate_eap_methods(
        interface=_iface(params),
        essid=essid,
        identity=identity,
        acknowledged=bool(params.get("acknowledged")),
        dry_run=bool(params.get("dry_run")),
    )


def _network_restart(params: dict) -> dict:
    from WiFiCatcher.capture.interfaces import restart_network_services
    restart_network_services()
    return {"restarted": True}


# op name -> handler. Anything not listed here is rejected by the server.
HANDLERS: dict[str, Callable[[dict], dict]] = {
    "monitor.start": _monitor_start,
    "monitor.stop": _monitor_stop,
    "deauth": _deauth,
    "eap.enumerate": _eap_enumerate,
    "network.restart": _network_restart,
}


def dispatch(op: str, params: dict[str, Any] | None) -> dict:
    """Validate + run one unary op. Raises :class:`OpError` on any problem."""
    handler = HANDLERS.get(op)
    if handler is None:
        raise OpError(f"Unknown operation: {op!r}")
    return handler(params or {})


# ----------------------------------------------------------- streaming ops
_BAND_FLAGS = {"2.4": "bg", "5": "a", "both": "abg"}


def _build_airodump(params: dict, iface: str, prefix: str) -> list[str]:
    cmd = ["airodump-ng", "--output-format", "csv", "-w", prefix]
    channel = params.get("channel")
    if channel:
        try:
            cmd += ["-c", str(int(channel))]
        except (TypeError, ValueError):
            raise OpError("'channel' must be an integer.")
    elif params.get("band") in _BAND_FLAGS:
        cmd += ["--band", _BAND_FLAGS[params["band"]]]
    if params.get("encrypt"):
        cmd += ["--encrypt", str(params["encrypt"])[:8]]
    bssid = _mac(params, "bssid", required=False)
    if bssid:
        cmd += ["--bssid", bssid]
    essid = params.get("essid")
    if essid:
        cmd += ["--essid", str(essid)[:_MAX_ESSID]]
    cmd.append(iface)
    return cmd


def _capture_stream(params: dict):
    """Own a live capture end-to-end (as root) and stream CSV snapshots.

    Ensures monitor mode, emits a first ``{"monitor_interface": ...}`` event so
    the app knows which interface to deauth on, then yields ``{"csv": ...}`` each
    time airodump rewrites its CSV. When the caller closes the generator (client
    disconnect / stop), airodump is killed and the interface is restored to
    managed mode — so cleanup happens even if the app crashes.

    NOTE: radio-dependent path; needs real hardware + aircrack-ng to run for
    real. The streaming/cleanup plumbing is covered by tests with a fake.
    """
    import glob
    import shutil
    import subprocess
    import tempfile

    from WiFiCatcher.capture.interfaces import ensure_monitor_mode, restore_managed_mode

    handle = ensure_monitor_mode(
        _iface(params), acknowledged=bool(params.get("acknowledged", True)))
    yield {"monitor_interface": handle.interface, "enabled": handle.enabled}

    workdir = tempfile.mkdtemp(prefix="wc-cap-")
    prefix = f"{workdir}/cap"
    proc = subprocess.Popen(
        _build_airodump(params, handle.interface, prefix),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    last = ""
    try:
        while True:
            csvs = sorted(glob.glob(f"{prefix}-*.csv"))
            if csvs:
                try:
                    text = open(csvs[-1], encoding="utf-8", errors="ignore").read()
                except OSError:
                    text = last
                if text and text != last:
                    last = text
                    yield {"csv": text}
            time.sleep(1.0)
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        shutil.rmtree(workdir, ignore_errors=True)
        try:
            restore_managed_mode(handle)
        except Exception:
            pass


# op name -> generator yielding event dicts.
STREAMERS: dict[str, Callable[[dict], Any]] = {
    "capture.stream": _capture_stream,
}
