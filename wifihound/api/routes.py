"""REST API for WiFiHound."""

from __future__ import annotations

import os
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

from wifihound import parsers
from wifihound.capture import (
    AirodumpSource,
    CaptureController,
    HandshakeWatcher,
    ReplaySource,
    ensure_monitor_mode,
    interface_exists,
    list_wireless_interfaces,
)
from wifihound.enrichment import oui
from wifihound.graph import WifiGraph
from wifihound.operations import (
    OperationError,
    deauth as deauth_op,
    enterprise,
    offensive_available,
)
from wifihound.operations.base import (
    OperationError as _OpError,
    OperationNotAuthorized,
    require_authorization,
    require_tools,
)

router = APIRouter(prefix="/api")

# Single in-memory graph for the running session.
STATE = WifiGraph()

# Single live-capture controller for the running session.
CAPTURE = CaptureController()


# --------------------------------------------------------------------- import
@router.post("/import")
async def import_capture(file: UploadFile = File(...)):
    raw = await file.read()
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
    info = STATE.node(node_id)
    if info is None:
        raise HTTPException(status_code=404, detail="Node not found")
    return info


@router.get("/search")
def search(q: str = ""):
    return {"query": q, "results": STATE.search(q)}


@router.get("/path")
def path(source: str, target: str):
    return {"source": source, "target": target,
            "path": STATE.path(source, target)}


@router.get("/config")
def config():
    # Offensive / live-radio features are unlocked by running as root (sudo).
    return {"offensive_available": offensive_available()}


@router.post("/clear")
def clear_state():
    """Drop the loaded capture so a reload or an explicit Clear starts fresh."""
    STATE.clear()
    return {"status": "cleared", "summary": STATE.stats()}


# ------------------------------------------------------------------ enrichment
@router.post("/enrich/oui")
def enrich_oui():
    if STATE.scan is None:
        raise HTTPException(status_code=400, detail="No capture loaded")
    resolved = oui.enrich_scan(STATE.scan)
    STATE.load(STATE.scan)  # rebuild so vendor flows into the graph elements
    return {"resolved": resolved, **STATE.to_cytoscape()}


# ------------------------------------------------------------------ offensive
class DeauthRequest(BaseModel):
    bssid: str
    client: str | None = None      # set -> deauth one client off the AP
    count: int = 5
    acknowledged: bool = False
    dry_run: bool = False


@router.post("/operations/deauth")
def operations_deauth(req: DeauthRequest):
    # 1) Authorization gate (offensive enabled + root + acknowledgement).
    try:
        require_authorization(req.acknowledged)
    except _OpError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    # 2) Deauth reuses the live airodump capture, which must be locked on one
    #    channel (aireplay-ng can only reach APs on the interface's channel).
    if not CAPTURE.can_deauth:
        raise HTTPException(
            status_code=409,
            detail="Deauth requires an active airodump capture started on a "
                   "specific channel. Start a live capture with a channel first.",
        )

    try:
        return deauth_op.deauth(
            interface=CAPTURE.interface,
            bssid=req.bssid,
            client=req.client,
            count=req.count,
            acknowledged=req.acknowledged,
            dry_run=req.dry_run,
        )
    except OperationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


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
    raw = await file.read()
    suffix = os.path.splitext(file.filename or "")[1] or ".cap"
    fd, path = tempfile.mkstemp(prefix="wifihound-up-", suffix=suffix)
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
        try:
            return enterprise.enumerate_eap_methods(
                interface=interface, essid=req.essid, identity=req.identity,
                acknowledged=req.acknowledged, dry_run=req.dry_run)
        except OperationNotAuthorized as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except OperationError as exc:
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


class LiveStartRequest(BaseModel):
    mode: str = "replay"            # "replay" | "airodump"
    interface: str | None = None
    channel: str | None = None      # fixed channel; required to allow deauth
    band: str | None = None         # "2.4" | "5" | "both" (ignored if channel set)
    encrypt: str | None = None      # WEP | WPA2 | WPA3 | OPN ...
    wps: bool = False               # show WPS info (--wps)
    essid: str | None = None        # capture one ESSID only
    bssid: str | None = None        # capture one BSSID only
    interval: float | None = None
    save: bool = False              # keep the capture files under ./captures
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
        # Real radio capture: same guardrails as the offensive subsystem.
        try:
            require_authorization(req.acknowledged)
            require_tools("airodump-ng", hint="Install the aircrack-ng suite.")
        except _OpError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        if not req.interface:
            raise HTTPException(status_code=400,
                                detail="Select a wireless interface to capture on.")
        # 1) Verify the chosen interface actually exists on this host.
        if not interface_exists(req.interface):
            available = ", ".join(i["name"] for i in list_wireless_interfaces())
            raise HTTPException(
                status_code=404,
                detail=f"Interface '{req.interface}' was not found. "
                       f"Available: {available or 'none detected'}.",
            )
        # 2) Make sure it is in monitor mode, enabling it with airmon-ng if
        #    needed (clearing interfering processes first). Capture on whatever
        #    interface monitor mode lands on; the handle restores managed mode
        #    automatically when the capture stops.
        try:
            monitor = ensure_monitor_mode(req.interface,
                                          acknowledged=req.acknowledged)
        except OperationNotAuthorized as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except _OpError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        source = AirodumpSource(
            monitor.interface, channel=req.channel, band=req.band,
            encrypt=req.encrypt, wps=req.wps, essid=req.essid, bssid=req.bssid,
            monitor=monitor, save=req.save,
        )
        # Watch the live pcap for WPA handshakes (e.g. captured during a deauth).
        handshakes = HandshakeWatcher(source)
        await CAPTURE.start(source, mode=req.mode,
                            interval=interval, handshakes=handshakes)
        return {"status": "running", "mode": req.mode,
                "channel": req.channel, "interface": monitor.interface}
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
