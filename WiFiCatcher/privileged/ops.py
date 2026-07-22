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


def _as_list(value) -> list[str]:
    """Normalise a filter param (missing / single string / list) to a str list."""
    if value is None:
        return []
    items = value if isinstance(value, (list, tuple)) else [value]
    return [str(v).strip() for v in items if str(v).strip()]


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
    # pcap alongside csv so handshakes can be detected and the capture saved.
    cmd = ["airodump-ng", "--output-format", "pcap,csv", "-w", prefix]
    channel = params.get("channel")
    if channel:
        # Accept a single channel or a comma list (e.g. "1,6,11"); airodump-ng
        # takes them as -c 1,6,11 and hops among them.
        try:
            chans = [str(int(t)) for t in str(channel).split(",") if t.strip()]
        except (TypeError, ValueError):
            raise OpError("'channel' must be a number or comma list, e.g. 1,6,11.")
        if not chans:
            raise OpError("'channel' must be a number or comma list, e.g. 1,6,11.")
        cmd += ["-c", ",".join(chans)]
    elif params.get("band") in _BAND_FLAGS:
        cmd += ["--band", _BAND_FLAGS[params["band"]]]
    # Protocol / ESSID / BSSID may each carry several values; airodump-ng takes
    # one flag per value (repeated --encrypt / --essid / --bssid).
    for enc in _as_list(params.get("encrypt")):
        cmd += ["--encrypt", enc[:8]]
    for raw in _as_list(params.get("bssid")):
        mac = normalize_mac(raw)
        if not mac:
            raise OpError(f"Invalid BSSID: {raw!r}.")
        cmd += ["--bssid", mac]
    for essid in _as_list(params.get("essid")):
        cmd += ["--essid", essid[:_MAX_ESSID]]
    cmd.append(iface)
    return cmd


def _safe_capture_name(name) -> str:
    """A safe capture filename base from user input: no path, tame chars only."""
    name = os.path.basename((name or "").strip())
    name = re.sub(r"[^A-Za-z0-9._-]", "", name)
    return name[:64]


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
    from WiFiCatcher.capture.wps import parse_wps, wps_fields, wps_filter
    from WiFiCatcher.operations.enterprise import (
        EAP_ID_FIELDS, EAP_ID_FILTER, hexfields_to_der,
        parse_certificates_from_der_list, parse_eap_identities)

    handle = ensure_monitor_mode(
        _iface(params), acknowledged=bool(params.get("acknowledged", True)))

    save = bool(params.get("save"))
    save_dir = params.get("save_dir")
    peer_uid = params.get("_peer_uid")
    if save and save_dir and os.path.isdir(save_dir):
        # Write straight into the folder the user chose (no subfolder). airodump
        # uses this as the filename prefix, so files land as
        # <folder>/<name>-01.cap / -01.csv. Use the user's name if given
        # (sanitized to a safe basename), else a timestamped default.
        workdir = None
        name = _safe_capture_name(params.get("save_name")) or (
            "wificatcher-" + time.strftime("%Y%m%d-%H%M%S"))
        prefix = os.path.join(save_dir, name)
        save_path = save_dir
    else:
        workdir = tempfile.mkdtemp(prefix="wc-cap-")
        prefix = os.path.join(workdir, "cap")
        save, save_path = False, None

    first = {"monitor_interface": handle.interface, "enabled": handle.enabled}
    if save_path:
        first["save_path"] = save_path
    yield first

    proc = subprocess.Popen(
        _build_airodump(params, handle.interface, prefix),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    last = ""
    seen_hs: set[str] = set()
    wps_prev: dict = {}
    seen_certs: set[str] = set()
    eap_prev: dict = {}
    tick = 0
    have_tshark = shutil.which("tshark") is not None
    # Resolve the WPS filter / fields once against the local tshark; names it
    # does not know are dropped so one bad field can't void the whole pass.
    wps_flds = wps_fields() if have_tshark else []
    wps_filt = wps_filter() if have_tshark else ""
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
                        ["tshark", "-r", caps[-1], "-n", "-Y", wps_filt,
                         "-T", "fields"]
                        + [arg for f in wps_flds for arg in ("-e", f)]
                        + ["-E", "separator=|"],
                        capture_output=True, text=True, timeout=20,
                        check=False).stdout
                    delta = {b: v for b, v in parse_wps(out, wps_flds).items()
                             if wps_prev.get(b) != v}
                    if delta:
                        wps_prev.update(delta)
                        yield {"wps": delta}
                except (OSError, subprocess.SubprocessError):
                    pass
            # Enterprise RADIUS certificate: pull the server cert out of the EAP
            # handshake so it can be read live. Done once per BSSID (it costs a
            # full TLS-reassembly pass), keyed by the AP that sent it (wlan.sa).
            if caps and tick % 8 == 0:
                try:
                    out = subprocess.run(
                        ["tshark", "-r", caps[-1], "-n",
                         "-Y", "tls.handshake.type == 11", "-T", "fields",
                         "-e", "wlan.sa", "-e", "tls.handshake.certificate",
                         "-o", "tls.desegment_ssl_records:TRUE",
                         "-o", "tls.desegment_ssl_application_data:TRUE",
                         "-E", "separator=|"],
                        capture_output=True, text=True, timeout=30,
                        check=False).stdout
                    by_bssid: dict = {}
                    for line in out.splitlines():
                        sa, _, cert_hex = line.partition("|")
                        bssid = normalize_mac(sa)
                        if bssid and cert_hex.strip():
                            by_bssid.setdefault(bssid, []).append(cert_hex)
                    fresh = {}
                    for bssid, hexes in by_bssid.items():
                        if bssid in seen_certs:
                            continue
                        try:
                            certs = parse_certificates_from_der_list(
                                hexfields_to_der(" ".join(hexes)))
                        except Exception:
                            certs = []
                        if certs:
                            seen_certs.add(bssid)
                            fresh[bssid] = certs
                    if fresh:
                        yield {"cert": fresh}
                except (OSError, subprocess.SubprocessError):
                    pass
            # Enterprise EAP identity: the username a client presents in its EAP
            # Response/Identity (often DOMAIN\user when not tunnelled), keyed by AP.
            if caps and tick % 5 == 2:
                try:
                    out = subprocess.run(
                        ["tshark", "-r", caps[-1], "-n", "-Y", EAP_ID_FILTER,
                         "-T", "fields"]
                        + [arg for f in EAP_ID_FIELDS for arg in ("-e", f)]
                        + ["-E", "separator=|"],
                        capture_output=True, text=True, timeout=20,
                        check=False).stdout
                    by_bssid: dict = {}
                    for row in parse_eap_identities(out):
                        if not row["bssid"]:
                            continue
                        entry = {"identity": row["identity"], "client": row["client"]}
                        ids = by_bssid.setdefault(row["bssid"], [])
                        if entry not in ids:
                            ids.append(entry)
                    delta = {b: v for b, v in by_bssid.items() if eap_prev.get(b) != v}
                    if delta:
                        eap_prev.update(delta)
                        yield {"eap_identity": delta}
                except (OSError, subprocess.SubprocessError):
                    pass
            time.sleep(1.0)
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        if save and peer_uid is not None:
            # Hand the capture files (prefix-*.cap/.csv) to the user.
            for f in glob.glob(prefix + "*"):
                try:
                    os.chown(f, int(peer_uid), -1)
                except OSError:
                    pass
        elif workdir:
            shutil.rmtree(workdir, ignore_errors=True)
        try:
            restore_managed_mode(handle)
        except Exception:
            pass


def _eap_stream(params: dict):
    """Stream EAP_buster output line by line for live per-method progress."""
    from WiFiCatcher.operations.enterprise import stream_eap_methods
    essid = (params.get("essid") or "").strip()
    if not essid or len(essid) > _MAX_ESSID:
        raise OpError("A valid ESSID (1-32 chars) is required.")
    identity = (params.get("identity") or "").strip()
    if not identity:
        raise OpError("An EAP identity is required.")
    yield from stream_eap_methods(
        interface=_iface(params), essid=essid, identity=identity,
        acknowledged=bool(params.get("acknowledged")))


# op name -> generator yielding event dicts.
STREAMERS: dict[str, Callable[[dict], Any]] = {
    "capture.stream": _capture_stream,
    "eap.stream": _eap_stream,
}
