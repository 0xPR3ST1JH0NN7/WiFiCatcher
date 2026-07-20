"""Validated privileged operations, executed helper-side (as root).

Each handler receives the request ``params`` (an untrusted dict from the app),
validates every field, then calls the existing WiFiCatcher operation. Building
the argv from validated fields — never from raw client strings — is what keeps
a compromised app from injecting arguments or reaching other binaries.

Handlers here are **unary** (request in, result out). Live capture is a stream
and is handled in :mod:`WiFiCatcher.privileged.server`.
"""

from __future__ import annotations

import os
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


def _chown_tree(path: str, uid: int) -> None:
    """Give ``path`` and everything under it to ``uid`` (best effort)."""
    try:
        os.chown(path, uid, -1)
    except OSError:
        return
    for root, dirs, files in os.walk(path):
        for name in dirs + files:
            try:
                os.chown(os.path.join(root, name), uid, -1)
            except OSError:
                pass


def _build_airodump(params: dict, iface: str, prefix: str) -> list[str]:
    # pcap alongside csv so handshakes can be detected and the capture saved.
    cmd = ["airodump-ng", "--output-format", "pcap,csv", "-w", prefix]
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
    """Own a live capture end-to-end (as root) and stream it back.

    Ensures monitor mode, emits a first event with the monitor interface (and the
    save path when saving), then yields ``{"csv": ...}`` as airodump rewrites its
    CSV and ``{"handshake": {"bssid": ...}}`` when a WPA handshake is detected in
    the pcap. When the caller closes the generator (stop / disconnect), airodump
    is killed and the interface restored to managed mode; a requested capture is
    kept and chowned to the caller, otherwise it is deleted. Cleanup happens even
    if the app crashes.

    NOTE: radio-dependent path; needs real hardware + aircrack-ng to run for
    real. The streaming/save/cleanup plumbing is covered by tests with a fake.
    """
    import glob
    import shutil
    import subprocess
    import tempfile

    from WiFiCatcher.capture.handshake import parse_handshakes
    from WiFiCatcher.capture.interfaces import ensure_monitor_mode, restore_managed_mode
    from WiFiCatcher.capture.wps import parse_wps

    handle = ensure_monitor_mode(
        _iface(params), acknowledged=bool(params.get("acknowledged", True)))

    save = bool(params.get("save"))
    save_dir = params.get("save_dir")
    peer_uid = params.get("_peer_uid")
    if save and save_dir and os.path.isdir(save_dir):
        workdir = tempfile.mkdtemp(
            prefix="wificatcher-" + time.strftime("%Y%m%d-%H%M%S") + "-", dir=save_dir)
        save_path = workdir
    else:
        workdir = tempfile.mkdtemp(prefix="wc-cap-")
        save, save_path = False, None

    first = {"monitor_interface": handle.interface, "enabled": handle.enabled}
    if save_path:
        first["save_path"] = save_path
    yield first

    prefix = os.path.join(workdir, "cap")
    proc = subprocess.Popen(
        _build_airodump(params, handle.interface, prefix),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    last = ""
    seen_hs: set[str] = set()
    wps_prev: dict = {}
    tick = 0
    have_tshark = shutil.which("tshark") is not None
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
            tick += 1
            caps = sorted(glob.glob(f"{prefix}-*.cap")) if have_tshark else []
            if caps and tick % 4 == 0:
                try:
                    out = subprocess.run(
                        ["tshark", "-r", caps[-1], "-Y", "eapol",
                         "-T", "fields", "-e", "wlan.bssid"],
                        capture_output=True, text=True, timeout=15,
                        check=False).stdout
                    for bssid in parse_handshakes(out) - seen_hs:
                        seen_hs.add(bssid)
                        yield {"handshake": {"bssid": bssid}}
                except (OSError, subprocess.SubprocessError):
                    pass
            if caps and tick % 6 == 0:
                try:
                    out = subprocess.run(
                        ["tshark", "-r", caps[-1], "-n", "-Y", "wps.version",
                         "-T", "fields", "-e", "wlan.bssid", "-e", "wps.version",
                         "-e", "wps.version2", "-e", "wps.ap_setup_locked",
                         "-E", "separator=|"],
                        capture_output=True, text=True, timeout=20,
                        check=False).stdout
                    delta = {b: v for b, v in parse_wps(out).items()
                             if wps_prev.get(b) != v}
                    if delta:
                        wps_prev.update(delta)
                        yield {"wps": delta}
                except (OSError, subprocess.SubprocessError):
                    pass
            time.sleep(1.0)
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        if save and save_path and peer_uid is not None:
            _chown_tree(save_path, int(peer_uid))     # hand the files to the user
        elif not save:
            shutil.rmtree(workdir, ignore_errors=True)
        try:
            restore_managed_mode(handle)
        except Exception:
            pass


# op name -> generator yielding event dicts.
STREAMERS: dict[str, Callable[[dict], Any]] = {
    "capture.stream": _capture_stream,
}
