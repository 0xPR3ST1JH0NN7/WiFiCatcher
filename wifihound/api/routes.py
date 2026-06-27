"""REST API for WiFiHound."""

from __future__ import annotations

from fastapi import (
    APIRouter,
    File,
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
from wifihound.operations import OperationError, deauth as deauth_op, offensive_available
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
    encrypt: str | None = None      # WEP | WPA2 | WPA3 | OPN ...
    wps: bool = False               # show WPS info (--wps)
    essid: str | None = None        # capture one ESSID only
    bssid: str | None = None        # capture one BSSID only
    interval: float | None = None
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
            require_tools("airodump-ng")
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
        #    needed; capture on whatever interface monitor mode lands on.
        try:
            cap_iface = ensure_monitor_mode(req.interface,
                                            acknowledged=req.acknowledged)
        except OperationNotAuthorized as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except _OpError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        source = AirodumpSource(
            cap_iface, channel=req.channel, encrypt=req.encrypt,
            wps=req.wps, essid=req.essid, bssid=req.bssid,
        )
        # Watch the live pcap for WPA handshakes (e.g. captured during a deauth).
        handshakes = HandshakeWatcher(source)
        await CAPTURE.start(source, mode=req.mode,
                            interval=interval, handshakes=handshakes)
        return {"status": "running", "mode": req.mode,
                "channel": req.channel, "interface": cap_iface}
    else:
        raise HTTPException(status_code=400, detail=f"Unknown mode '{req.mode}'.")

    await CAPTURE.start(source, mode=req.mode, interval=interval)
    return {"status": "running", "mode": req.mode, "channel": req.channel}


@router.post("/live/stop")
async def live_stop():
    await CAPTURE.stop()
    return {"status": "stopped"}


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
