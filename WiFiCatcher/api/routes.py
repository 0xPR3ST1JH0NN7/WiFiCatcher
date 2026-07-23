"""REST API for WiFiCatcher."""

from __future__ import annotations

import asyncio
import os
import signal
import tempfile
import threading
import time

from fastapi import (
    APIRouter,
    File,
    Form,
    HTTPException,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
)
from pydantic import BaseModel

from WiFiCatcher import parsers
from WiFiCatcher.api import uploads
from WiFiCatcher.capture import (
    CaptureController,
    WardenAirodumpSource,
    WardenHandshakeWatcher,
    WardenWpsWatcher,
    ReplaySource,
    interface_exists,
    list_wireless_interfaces,
)
from WiFiCatcher.privileged import PrivClient, PrivError, PrivUnavailable
from WiFiCatcher.enrichment import oui
from WiFiCatcher.graph import WifiGraph
from WiFiCatcher.models import normalize_mac
from WiFiCatcher.operations import OperationError, enterprise

router = APIRouter(prefix="/api")

# Single in-memory graph for the running session.
STATE = WifiGraph()

# Single live-capture controller for the running session.
CAPTURE = CaptureController()


# --------------------------------------------------------------------- import
class LocalFileRequest(BaseModel):
    # An absolute path chosen with the in-app file browser; the server reads it.
    path: str
    ap_bssid: str | None = None


def _load_capture(raw: bytes, filename: str, content_type: str | None) -> dict:
    """Validate, parse and load capture bytes into STATE; shared by upload + local."""
    uploads.validate_csv(raw, filename, content_type)
    text = raw.decode("utf-8-sig", errors="ignore")
    parser = parsers.detect_parser(text, filename)
    if parser is None:
        raise HTTPException(
            status_code=415,
            detail="Unrecognized capture format. Supported: "
            + ", ".join(p.name for p in parsers.all_parsers()),
        )
    scan = parser.parse(text, filename)
    oui.enrich_scan(scan)  # vendors are cheap and offline, so do it on import
    STATE.load(scan)
    return {
        "summary": STATE.stats(),
        "parser": parser.id,
        **STATE.to_cytoscape(),
    }


@router.post("/import/local")
def import_local(req: LocalFileRequest):
    """Import a capture the user picked with the in-app browser, read from disk."""
    path = _validate_local_path(req.path)
    try:
        with open(path, "rb") as fh:
            raw = fh.read(uploads.MAX_UPLOAD_BYTES + 1)
    except OSError as exc:
        raise HTTPException(status_code=400, detail="Cannot read that file.") from exc
    return _load_capture(raw, os.path.basename(path), None)


# ---------------------------------------------------------------------- reads
@router.get("/graph")
def get_graph():
    return {"summary": STATE.stats(), **STATE.to_cytoscape()}


@router.get("/stats")
def get_stats():
    return STATE.stats()


@router.get("/parsers")
def get_parsers():
    return [{"id": p.id, "name": p.name, "extensions": list(p.extensions)}
            for p in parsers.all_parsers()]


@router.get("/node/{node_id}")
def get_node(node_id: str):
    # While a live capture runs, prefer its graph: a stale imported STATE node
    # with the same BSSID (which carries no live WPS/handshake data) must not
    # shadow the live one. Otherwise fall back to STATE for imported/replay data.
    if CAPTURE.running:
        info = CAPTURE.node(node_id) or STATE.node(node_id)
    else:
        info = STATE.node(node_id) or CAPTURE.node(node_id)
    if info is None:
        raise HTTPException(status_code=404, detail="Node not found")
    # Attach any RADIUS certificate captured live for this AP, so the details
    # panel can offer to read it in real time without a separate file.
    if CAPTURE.running:
        certs = CAPTURE.radius_certs(node_id)
        if certs:
            info = {**info, "radius_certs": certs}
        eap_ids = CAPTURE.eap_identities(node_id)
        if eap_ids:
            info = {**info, "eap_identities": eap_ids}
    return info


@router.get("/search")
def search(q: str = ""):
    results = STATE.search(q) or CAPTURE.search(q)
    return {"query": q, "results": results}


@router.get("/config")
def config():
    # Live-radio features are available when the privileged warden is reachable
    # (systemd starts it on demand); the app itself never runs as root.
    from WiFiCatcher.privileged import warden_available
    return {"offensive_available": warden_available()}


@router.post("/clear")
def clear_state():
    """Drop the loaded capture so a reload or an explicit Clear starts fresh."""
    STATE.clear()
    return {"status": "cleared", "summary": STATE.stats()}


# --------------------------------------------------------------- server control
@router.post("/shutdown")
def shutdown_server():
    """Stop the server gracefully, so there is no need to Ctrl+C the terminal.

    A SIGTERM is scheduled just after this response is sent; uvicorn handles it
    as a clean shutdown (running the app's shutdown hook, which stops any live
    capture and restores the wireless interface to managed mode). Reachable from
    the CLI with ``python -m WiFiCatcher stop``.
    """
    def _terminate() -> None:
        os.kill(os.getpid(), signal.SIGTERM)

    # Fire just after the HTTP response flushes, so the caller gets an ack first.
    threading.Timer(0.4, _terminate).start()
    return {"status": "stopping"}


# ------------------------------------------------------------------ offensive
class DeauthRequest(BaseModel):
    bssid: str
    client: str | None = None      # set -> deauth one client off the AP
    count: int = 5
    acknowledged: bool = False
    dry_run: bool = False


@router.post("/operations/deauth")
def operations_deauth(req: DeauthRequest):
    # 1) Explicit per-request authorization acknowledgement.
    if not req.acknowledged:
        raise HTTPException(status_code=403,
                            detail="Authorization not acknowledged for this action.")

    # 2) Deauth reuses the live airodump capture, which must be locked on one
    #    channel (aireplay-ng can only reach APs on the interface's channel).
    if not CAPTURE.can_deauth:
        raise HTTPException(
            status_code=409,
            detail="Deauth requires an active airodump capture started on a "
                   "specific channel. Start a live capture with a channel first.",
        )

    # 3) The privileged warden runs aireplay-ng (as root); the app never does.
    try:
        return PrivClient().call(
            "deauth", iface=CAPTURE.interface, bssid=req.bssid,
            client=req.client, count=req.count,
            acknowledged=req.acknowledged, dry_run=req.dry_run)
    except PrivUnavailable as exc:
        raise HTTPException(status_code=503,
                            detail=f"Privileged warden unavailable: {exc}") from exc
    except PrivError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ------------------------------------------------------------- WPA2-Enterprise
# EAP enumeration seizes the radio for minutes; only allow one at a time.
_EAP_LOCK = threading.Lock()

# Live state for a streaming EAP enumeration, updated by a background consumer of
# the warden's eap.stream. A long-held HTTP request would time out (the fetch
# fails with a NetworkError while EAP_buster keeps running), so the frontend
# starts the run then polls this state and shows methods as they resolve.
_EAP_STATE_LOCK = threading.Lock()
_EAP_STATE: dict = {"running": False, "done": False, "stdout": "", "methods": [],
                    "error": None, "essid": None, "interface": None}


def _run_eap_stream(iface: str, essid: str, identity: str) -> None:
    """Consume the warden's eap.stream in a background thread, updating _EAP_STATE."""
    try:
        stream = PrivClient(timeout=None).stream(
            "eap.stream", iface=iface, essid=essid, identity=identity,
            acknowledged=True)
        for event in stream:
            if "line" in event:
                with _EAP_STATE_LOCK:
                    _EAP_STATE["stdout"] += event["line"] + "\n"
            elif event.get("done"):
                with _EAP_STATE_LOCK:
                    _EAP_STATE["methods"] = event.get("methods", [])
    except (PrivError, PrivUnavailable) as exc:
        with _EAP_STATE_LOCK:
            _EAP_STATE["error"] = str(exc)
    except Exception as exc:                       # never leave the lock held
        with _EAP_STATE_LOCK:
            _EAP_STATE["error"] = str(exc)
    finally:
        with _EAP_STATE_LOCK:
            _EAP_STATE["running"] = False
            _EAP_STATE["done"] = True
        _EAP_LOCK.release()


class CertRequest(BaseModel):
    cap_path: str | None = None     # defaults to the live capture's pcap
    ap_bssid: str | None = None     # scope to one AP (wlan.sa == BSSID)
    dry_run: bool = False


@router.post("/operations/enterprise/cert")
def operations_enterprise_cert(req: CertRequest):
    """Extract the RADIUS server certificate from a capture. Read-only, no root.

    Uses the running live-capture pcap when ``cap_path`` is omitted (the deauth
    "reuse the live capture" pattern). Returns ``status: "empty"`` (HTTP 200)
    when the capture holds no certificate.
    """
    cap = req.cap_path or CAPTURE.latest_cap()
    if not cap:
        raise HTTPException(
            status_code=400,
            detail="No capture file. Start a live airodump capture, or pass "
                   "cap_path to a .cap/.pcap.")
    try:
        return enterprise.extract_radius_cert(
            cap_path=cap, ap_bssid=req.ap_bssid, dry_run=req.dry_run)
    except OperationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/operations/enterprise/cert/upload")
async def operations_enterprise_cert_upload(
        file: UploadFile = File(...), ap_bssid: str | None = Form(None)):
    """Inspect the RADIUS certificate in an uploaded .cap/.pcap. Read-only.

    The upload is written to a temporary file, scanned, then deleted.
    """
    raw = await file.read(uploads.MAX_UPLOAD_BYTES + 1)
    uploads.validate_capture(raw, file.filename or "", file.content_type)
    suffix = uploads.safe_capture_suffix(file.filename or "")
    fd, path = tempfile.mkstemp(prefix="WiFiCatcher-up-", suffix=suffix)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(raw)
        return enterprise.extract_radius_cert(
            cap_path=path, ap_bssid=(ap_bssid or None))
    except OperationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


@router.post("/operations/enterprise/cert/local")
def operations_enterprise_cert_local(req: LocalFileRequest):
    """Inspect the RADIUS certificate in a locally-picked .cap/.pcap. Read-only."""
    path = _validate_local_path(req.path)
    try:
        return enterprise.extract_radius_cert(
            cap_path=path, ap_bssid=(req.ap_bssid or None))
    except OperationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/operations/enterprise/eap-identity/local")
def operations_enterprise_eap_identity_local(req: LocalFileRequest):
    """Read EAP Response/Identity usernames from a locally-picked capture. Read-only."""
    path = _validate_local_path(req.path)
    try:
        return enterprise.extract_eap_identities(
            cap_path=path, ap_bssid=(req.ap_bssid or None))
    except OperationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/operations/enterprise/eap-identity/upload")
async def operations_enterprise_eap_identity_upload(
        file: UploadFile = File(...), ap_bssid: str | None = Form(None)):
    """Read EAP Response/Identity usernames (DOMAIN\\user) from an uploaded capture.

    Read-only. The upload is written to a temp file, scanned with tshark, deleted.
    """
    raw = await file.read(uploads.MAX_UPLOAD_BYTES + 1)
    uploads.validate_capture(raw, file.filename or "", file.content_type)
    suffix = uploads.safe_capture_suffix(file.filename or "")
    fd, path = tempfile.mkstemp(prefix="WiFiCatcher-up-", suffix=suffix)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(raw)
        return enterprise.extract_eap_identities(
            cap_path=path, ap_bssid=(ap_bssid or None))
    except OperationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


class EapMethodsRequest(BaseModel):
    essid: str
    identity: str                   # legitimate 802.1X id, e.g. "DOMAIN\\user"
    interface: str | None = None


@router.post("/operations/enterprise/eap-methods/start")
def operations_enterprise_eap_start(req: EapMethodsRequest):
    """Begin a live EAP enumeration in the background; poll /status for progress.

    Returns immediately so the HTTP request is never held for the minutes the run
    takes (which would fail the fetch). The background thread streams EAP_buster
    output into _EAP_STATE, which /status reports (methods resolve one by one).
    """
    interface = (req.interface or "").strip()
    if not interface:
        raise HTTPException(status_code=400,
                            detail="A wireless interface is required.")
    if not _EAP_LOCK.acquire(blocking=False):
        raise HTTPException(status_code=409,
                            detail="An EAP enumeration is already running.")
    with _EAP_STATE_LOCK:
        _EAP_STATE.update({"running": True, "done": False, "stdout": "",
                           "methods": [], "error": None, "essid": req.essid,
                           "interface": interface})
    threading.Thread(target=_run_eap_stream,
                     args=(interface, req.essid, req.identity),
                     daemon=True).start()
    return {"status": "started", "essid": req.essid, "interface": interface}


@router.get("/operations/enterprise/eap-identities")
def operations_enterprise_eap_identities_all():
    """Every EAP identity captured live so far, for the enumeration dialog."""
    ids = CAPTURE.all_eap_identities() if CAPTURE.running else []
    return {"identities": ids}


class MonitorRequest(BaseModel):
    interface: str


@router.post("/live/monitor")
def live_monitor(req: MonitorRequest):
    """Put an interface into monitor mode (already-monitor is left as-is), for EAP.

    Returns the monitor interface name (airmon-ng may create a vif, wlan0 ->
    wlan0mon). Does not touch a capture; the caller stops that first if needed.
    """
    iface = (req.interface or "").strip()
    if not iface:
        raise HTTPException(status_code=400,
                            detail="A wireless interface is required.")
    try:
        mon = PrivClient().call("monitor.start", iface=iface)
    except PrivUnavailable as exc:
        raise HTTPException(status_code=503,
                            detail=f"Privileged warden unavailable: {exc}") from exc
    except PrivError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"interface": mon.get("interface")}


@router.get("/operations/enterprise/eap-methods/status")
def operations_enterprise_eap_status():
    """Current EAP enumeration progress: methods resolved so far, running/done."""
    with _EAP_STATE_LOCK:
        st = dict(_EAP_STATE)
    # While running, parse the partial output for methods decided so far; once
    # done, use the tool's final parse (which also marks untested methods).
    if st["done"] and st["methods"]:
        methods = st["methods"]
    else:
        methods = enterprise.parse_eap_buster(
            st["stdout"], mark_untested_as_maybe=False) if st["stdout"] else []
    return {
        "running": st["running"], "done": st["done"], "error": st["error"],
        "essid": st["essid"], "interface": st["interface"], "methods": methods,
    }


# ----------------------------------------------------------------- live capture
@router.get("/live/interfaces")
def live_interfaces():
    """Wireless interfaces detected on this host, with their current mode.

    Lets the UI offer a pick-list instead of a free-text interface name. Reads
    sysfs only, so it works unprivileged (mode switching still needs root).
    """
    return {"interfaces": list_wireless_interfaces()}


def _validate_local_path(path: str) -> str:
    """Resolve and check a file path chosen with the in-app picker for reading.

    WiFiCatcher runs locally, so the server can read a file the user pointed it at
    (no re-upload). Guards: it must be an existing regular file within the upload
    size limit.
    """
    p = os.path.abspath(os.path.expanduser((path or "").strip()))
    if not p or not os.path.isfile(p):
        raise HTTPException(status_code=400, detail="File not found.")
    try:
        if os.path.getsize(p) > uploads.MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="File is too large.")
    except OSError as exc:
        raise HTTPException(status_code=400, detail="Cannot read that file.") from exc
    return p


@router.get("/fs/list")
def fs_list(path: str | None = None):
    """List a directory for the in-app save-location picker. Read-only.

    Returns the resolved ``path``, its ``parent`` (``None`` at the root),
    whether it is ``writable`` (so the UI can gate "save here"), and its visible
    entries (dot-entries hidden) with directories first. WiFiCatcher runs locally
    and the user already chooses arbitrary save paths, so browsing their own
    filesystem is in the same trust model; it only ever lists names, never reads
    file contents. Defaults to the user's home directory.
    """
    base = os.path.abspath(os.path.expanduser(path or "~"))
    if not os.path.isdir(base):
        raise HTTPException(status_code=400, detail="Not a directory.")
    try:
        names = os.listdir(base)
    except PermissionError as exc:
        raise HTTPException(status_code=403,
                            detail="Permission denied for that folder.") from exc
    except OSError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    entries = []
    for name in names:
        if name.startswith("."):
            continue
        try:
            is_dir = os.path.isdir(os.path.join(base, name))
        except OSError:
            continue
        entries.append({"name": name, "is_dir": is_dir})
    # Directories first, then files, each case-insensitively sorted.
    entries.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
    parent = None if base == "/" else (os.path.dirname(base) or "/")
    return {
        "path": base,
        "parent": parent,
        "writable": os.access(base, os.W_OK),
        "entries": entries,
    }


class LiveStartRequest(BaseModel):
    mode: str = "replay"            # "replay" | "airodump"
    interface: str | None = None
    channel: str | None = None      # fixed channel; required to allow deauth
    band: str | None = None         # "2.4" | "5" | "both" (ignored if channel set)
    # Each accepts a single value or a list; every value becomes its own
    # airodump-ng flag (e.g. two BSSIDs -> --bssid X --bssid Y).
    encrypt: str | list[str] | None = None   # WEP | WPA2 | WPA3 | OPN ...
    essid: str | list[str] | None = None     # capture these ESSIDs only
    bssid: str | list[str] | None = None     # capture these BSSIDs only
    interval: float | None = None
    save: bool = False              # keep the capture files (default ./captures)
    save_path: str | None = None    # folder + base name for the saved capture
    acknowledged: bool = False


@router.post("/live/start")
async def live_start(req: LiveStartRequest):
    # Clamp the poll/reveal interval to a sane range (seconds).
    interval = max(0.2, min(req.interval or 1.5, 10.0))
    if req.mode == "replay":
        # Re-feed the currently loaded capture as if it were being discovered.
        if STATE.scan is None:
            raise HTTPException(
                status_code=400,
                detail="Load a capture first, then replay it live.",
            )
        source = ReplaySource(STATE.scan)
    elif req.mode == "airodump":
        # Real radio capture runs in the privileged warden; the app is
        # unprivileged and never touches the radio itself.
        if not req.acknowledged:
            raise HTTPException(status_code=403,
                                detail="Authorization not acknowledged for this action.")
        if not req.interface:
            raise HTTPException(status_code=400,
                                detail="Select a wireless interface to capture on.")
        # Verify the chosen interface exists (sysfs read, unprivileged).
        if not interface_exists(req.interface):
            available = ", ".join(i["name"] for i in list_wireless_interfaces())
            raise HTTPException(
                status_code=404,
                detail=f"Interface '{req.interface}' was not found. "
                       f"Available: {available or 'none detected'}.",
            )
        # When saving, require a folder that exists and this user can write to, so
        # the capture is not silently lost after the run.
        save_dir = save_name = None
        if req.save:
            path = (req.save_path or "").strip()
            save_dir, save_name = os.path.dirname(path), os.path.basename(path)
            if not path or not os.path.isdir(save_dir) or not os.access(save_dir, os.W_OK):
                raise HTTPException(
                    status_code=400,
                    detail="Choose an existing, writable folder and file name "
                           "(use Save as…) before starting.")
        # Validate every optional BSSID filter up front: an invalid one would
        # otherwise fail deep in the warden after the capture "started", leaving
        # an empty graph with no explanation.
        bssids = req.bssid if isinstance(req.bssid, list) else ([req.bssid] if req.bssid else [])
        if any(b and not normalize_mac(b) for b in bssids):
            raise HTTPException(
                status_code=400,
                detail="Invalid BSSID; use the AA:BB:CC:DD:EE:FF form.")
        # The warden enables monitor mode, runs airodump-ng and streams CSV +
        # handshake events back; source.interface / saved_path come from its
        # first event.
        source = WardenAirodumpSource(
            req.interface, channel=req.channel, band=req.band,
            encrypt=req.encrypt, essid=req.essid, bssid=req.bssid,
            save=req.save, save_dir=save_dir, save_name=save_name,
            acknowledged=req.acknowledged)
        handshakes = WardenHandshakeWatcher(source)
        # WPS detection is always on (cheap: one tshark pass every few seconds),
        # like handshake detection, so the user never has to enable it.
        wps = WardenWpsWatcher(source)
        try:
            await CAPTURE.start(source, mode=req.mode, interval=interval,
                                handshakes=handshakes, wps=wps)
        except PrivUnavailable as exc:
            raise HTTPException(status_code=503,
                                detail=f"Privileged warden unavailable: {exc}") from exc
        except PrivError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"status": "running", "mode": req.mode,
                "channel": req.channel, "interface": source.interface,
                "save_path": source.saved_path}
    else:
        raise HTTPException(status_code=400, detail=f"Unknown mode '{req.mode}'.")

    await CAPTURE.start(source, mode=req.mode, interval=interval)
    return {"status": "running", "mode": req.mode, "channel": req.channel}


@router.post("/live/stop")
async def live_stop():
    await CAPTURE.stop()
    return {"status": "stopped", "saved_path": CAPTURE.last_saved_path}


class EapHandoffRequest(BaseModel):
    interface: str          # the base adapter the capture is running on (e.g. wlan0)


@router.post("/live/stop-for-eap")
async def live_stop_for_eap(req: EapHandoffRequest):
    """Stop the live capture and re-establish a monitor vif for EAP_buster.

    EAP_buster takes the interface into managed mode itself but needs it free of
    NetworkManager, so we stop airodump and put the adapter back into monitor mode
    (airmon-ng kills the interfering services). The warden restores managed
    asynchronously after we disconnect, so monitor.start is retried until the base
    interface has settled. Returns the monitor interface name to run EAP on.
    """
    iface = (req.interface or "").strip()
    if not iface:
        raise HTTPException(status_code=400,
                            detail="A wireless interface is required.")
    await CAPTURE.stop()

    def _reenable_monitor():
        last: Exception | None = None
        for _ in range(8):   # ~8s for the warden's airodump kill + managed restore
            try:
                return PrivClient().call("monitor.start", iface=iface)
            except PrivUnavailable:
                raise                 # warden down: not transient, do not retry
            except PrivError as exc:
                last = exc            # base iface not back yet; wait and retry
                time.sleep(1.0)
        if last:
            raise last
        raise PrivError("Could not enable monitor mode.")

    try:
        mon = await asyncio.get_event_loop().run_in_executor(None, _reenable_monitor)
    except PrivUnavailable as exc:
        raise HTTPException(status_code=503,
                            detail=f"Privileged warden unavailable: {exc}") from exc
    except PrivError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"status": "stopped", "saved_path": CAPTURE.last_saved_path,
            "monitor_interface": mon.get("interface")}


@router.get("/live/status")
def live_status():
    return CAPTURE.status()


@router.websocket("/live/ws")
async def live_ws(ws: WebSocket):
    await ws.accept()
    queue = CAPTURE.subscribe()
    try:
        await ws.send_json(CAPTURE.snapshot())  # initial full graph
        while True:
            message = await queue.get()
            await ws.send_json(message)
    except WebSocketDisconnect:
        pass
    finally:
        CAPTURE.unsubscribe(queue)
