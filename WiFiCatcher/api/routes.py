"""REST API for WiFiCatcher."""

from __future__ import annotations

import asyncio
import os
import signal
import tempfile
import threading

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
    HelperAirodumpSource,
    HelperHandshakeWatcher,
    HelperWpsWatcher,
    ReplaySource,
    interface_exists,
    list_wireless_interfaces,
)
from WiFiCatcher.privileged import PrivClient, PrivError, PrivUnavailable
from WiFiCatcher.enrichment import oui
from WiFiCatcher.graph import WifiGraph
from WiFiCatcher.operations import OperationError, enterprise

router = APIRouter(prefix="/api")

# Single in-memory graph for the running session.
STATE = WifiGraph()

# Single live-capture controller for the running session.
CAPTURE = CaptureController()


# --------------------------------------------------------------------- import
@router.post("/import")
async def import_capture(file: UploadFile = File(...)):
    raw = await file.read(uploads.MAX_UPLOAD_BYTES + 1)
    uploads.validate_csv(raw, file.filename or "", file.content_type)
    text = raw.decode("utf-8-sig", errors="ignore")
    parser = parsers.detect_parser(text, file.filename or "")
    if parser is None:
        raise HTTPException(
            status_code=415,
            detail="Unrecognized capture format. Supported: "
            + ", ".join(p.name for p in parsers.all_parsers()),
        )
    scan = parser.parse(text, file.filename or "")
    oui.enrich_scan(scan)  # vendors are cheap and offline, so do it on import
    STATE.load(scan)
    return {
        "summary": STATE.stats(),
        "parser": parser.id,
        **STATE.to_cytoscape(),
    }


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
    return info


@router.get("/search")
def search(q: str = ""):
    results = STATE.search(q) or CAPTURE.search(q)
    return {"query": q, "results": results}


@router.get("/config")
def config():
    # Live-radio features are available when the privileged helper is reachable
    # (systemd starts it on demand); the app itself never runs as root.
    from WiFiCatcher.privileged import helper_available
    return {"offensive_available": helper_available()}


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

    # 3) The privileged helper runs aireplay-ng (as root); the app never does.
    try:
        return PrivClient().call(
            "deauth", iface=CAPTURE.interface, bssid=req.bssid,
            client=req.client, count=req.count,
            acknowledged=req.acknowledged, dry_run=req.dry_run)
    except PrivUnavailable as exc:
        raise HTTPException(status_code=503,
                            detail=f"Privileged helper unavailable: {exc}") from exc
    except PrivError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ------------------------------------------------------------- WPA2-Enterprise
# EAP enumeration seizes the radio for minutes; only allow one at a time.
_EAP_LOCK = threading.Lock()


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


class EapMethodsRequest(BaseModel):
    essid: str
    identity: str                   # legitimate 802.1X id, e.g. "DOMAIN\\user"
    interface: str | None = None
    acknowledged: bool = False
    dry_run: bool = False


@router.post("/operations/enterprise/eap-methods")
def operations_enterprise_eap(req: EapMethodsRequest):
    """Enumerate supported EAP methods via EAP_buster.sh.

    Active 802.1X auth against the AP, so it needs root and an acknowledgement.
    The tool takes the interface to managed mode itself, so pass a free
    interface (not one mid airodump capture). Runs for several minutes.
    """
    interface = (req.interface or "").strip()
    if not interface:
        raise HTTPException(status_code=400,
                            detail="A wireless interface is required.")

    def _run():
        # The privileged helper runs EAP_buster.sh / wpa_supplicant (as root).
        try:
            return PrivClient(timeout=max(60.0, enterprise.EAP_BUSTER_TIMEOUT)).call(
                "eap.enumerate", iface=interface, essid=req.essid,
                identity=req.identity, acknowledged=req.acknowledged,
                dry_run=req.dry_run)
        except PrivUnavailable as exc:
            raise HTTPException(status_code=503,
                                detail=f"Privileged helper unavailable: {exc}") from exc
        except PrivError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    if req.dry_run:
        return _run()
    if not _EAP_LOCK.acquire(blocking=False):
        raise HTTPException(status_code=409,
                            detail="An EAP enumeration is already running.")
    try:
        return _run()
    finally:
        _EAP_LOCK.release()


# ----------------------------------------------------------------- live capture
@router.get("/live/interfaces")
def live_interfaces():
    """Wireless interfaces detected on this host, with their current mode.

    Lets the UI offer a pick-list instead of a free-text interface name. Reads
    sysfs only, so it works unprivileged (mode switching still needs root).
    """
    return {"interfaces": list_wireless_interfaces()}


def _pick_directory() -> str:
    """Open a native "choose folder" dialog on the host and return the selected
    absolute path (``""`` if cancelled, or if no dialog / desktop is available).

    A browser can't hand a real filesystem path to the server, but WiFiCatcher
    runs locally, so we pop the OS folder picker on the user's own desktop. Tries
    GTK (``zenity``), then KDE (``kdialog``), then a Tk fallback in its own
    process so it owns the main thread. Blocking, so callers run it in a thread.
    """
    import shutil
    import subprocess
    import sys

    for cmd in (["zenity", "--file-selection", "--directory",
                 "--title=Choose where to save captures"],
                ["kdialog", "--getexistingdirectory", os.path.expanduser("~")]):
        if not shutil.which(cmd[0]):
            continue
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        except (OSError, subprocess.SubprocessError):
            continue
        return res.stdout.strip() if res.returncode == 0 else ""

    tk = ("import tkinter as tk\n"
          "from tkinter import filedialog\n"
          "r = tk.Tk(); r.withdraw(); r.attributes('-topmost', True)\n"
          "print(filedialog.askdirectory(title='Choose where to save captures') or '')\n")
    try:
        res = subprocess.run([sys.executable, "-c", tk],
                             capture_output=True, text=True, timeout=180)
        if res.returncode == 0:
            return res.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return ""


@router.post("/live/choose-dir")
async def live_choose_dir():
    """Open a native folder picker on the host; return ``{"path": <dir or "">}``."""
    path = await asyncio.get_event_loop().run_in_executor(None, _pick_directory)
    if path and not os.path.isdir(path):
        raise HTTPException(status_code=400,
                            detail="The selected path is not a directory.")
    return {"path": path}


class LiveStartRequest(BaseModel):
    mode: str = "replay"            # "replay" | "airodump"
    interface: str | None = None
    channel: str | None = None      # fixed channel; required to allow deauth
    band: str | None = None         # "2.4" | "5" | "both" (ignored if channel set)
    encrypt: str | None = None      # WEP | WPA2 | WPA3 | OPN ...
    essid: str | None = None        # capture one ESSID only
    bssid: str | None = None        # capture one BSSID only
    interval: float | None = None
    save: bool = False              # keep the capture files (default ./captures)
    save_dir: str | None = None     # folder chosen for the saved capture
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
        # Real radio capture runs in the privileged helper; the app is
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
        if req.save:
            folder = (req.save_dir or "").strip()
            if not folder or not os.path.isdir(folder) or not os.access(folder, os.W_OK):
                raise HTTPException(
                    status_code=400,
                    detail="Choose an existing, writable folder to save the "
                           "capture into before starting.")
        # The helper enables monitor mode, runs airodump-ng and streams CSV +
        # handshake events back; source.interface / saved_path come from its
        # first event.
        source = HelperAirodumpSource(
            req.interface, channel=req.channel, band=req.band,
            encrypt=req.encrypt, essid=req.essid, bssid=req.bssid,
            save=req.save, save_dir=(req.save_dir or None),
            acknowledged=req.acknowledged)
        handshakes = HelperHandshakeWatcher(source)
        # WPS detection is always on (cheap: one tshark pass every few seconds),
        # like handshake detection, so the user never has to enable it.
        wps = HelperWpsWatcher(source)
        try:
            await CAPTURE.start(source, mode=req.mode, interval=interval,
                                handshakes=handshakes, wps=wps)
        except PrivUnavailable as exc:
            raise HTTPException(status_code=503,
                                detail=f"Privileged helper unavailable: {exc}") from exc
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
