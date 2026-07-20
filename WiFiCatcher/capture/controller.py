"""Capture controller: poll a source, diff the graph, broadcast patches.

The controller owns a single live session. Each tick it asks the source for a
fresh :class:`Scan`, rebuilds the graph with the existing :class:`WifiGraph`,
computes a minimal diff against what it last sent, and pushes a patch to every
subscribed WebSocket queue.
"""

from __future__ import annotations

import asyncio
import datetime
import os
from typing import Optional

from WiFiCatcher.capture.sources import Source
from WiFiCatcher.enrichment import oui
from WiFiCatcher.graph import WifiGraph
from WiFiCatcher.models import Scan

# A live station not heard within this many seconds of the newest sighting is
# dropped from the graph, so clients that leave disappear instead of lingering.
try:
    STALE_AFTER = float(os.environ.get("WIFICATCHER_STALE_SECONDS", "30"))
except ValueError:
    STALE_AFTER = 30.0


def _parse_ts(value: Optional[str]) -> Optional[datetime.datetime]:
    try:
        return datetime.datetime.strptime((value or "").strip(), "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return None


def prune_stale(scan: Scan, max_age: float) -> Scan:
    """Drop APs/clients not seen within ``max_age`` seconds of the newest sighting.

    airodump-ng's CSV keeps every station it has ever seen, so without this a
    client that has left stays on the map forever. Entries are aged out relative
    to the most recent ``last seen`` in the scan (robust to clock skew); an entry
    whose timestamp cannot be parsed is kept.
    """
    stamps = [t for t in (_parse_ts(x.last_seen)
                          for x in (*scan.access_points, *scan.clients)) if t]
    if not stamps:
        return scan
    cutoff = max(stamps) - datetime.timedelta(seconds=max_age)

    def fresh(x) -> bool:
        ts = _parse_ts(x.last_seen)
        return ts is None or ts >= cutoff

    return Scan(
        access_points=[a for a in scan.access_points if fresh(a)],
        clients=[c for c in scan.clients if fresh(c)],
        source=scan.source, format=scan.format,
    )


def _index(cyto: dict) -> dict:
    """Map element id -> ("nodes"|"edges", data) for diffing."""
    idx: dict = {}
    for node in cyto["elements"]["nodes"]:
        idx[node["data"]["id"]] = ("nodes", node["data"])
    for edge in cyto["elements"]["edges"]:
        idx[edge["data"]["id"]] = ("edges", edge["data"])
    return idx


def diff_elements(prev: dict, cyto: dict) -> tuple[dict, dict]:
    """Return (patch, new_index).

    patch = {"add": [{group, data}], "update": [data], "remove": [id]}
    """
    new = _index(cyto)
    add, update, remove = [], [], []
    for el_id, (group, data) in new.items():
        if el_id not in prev:
            add.append({"group": group, "data": data})
        elif prev[el_id][1] != data:
            update.append(data)
    for el_id in prev:
        if el_id not in new:
            remove.append(el_id)
    return {"add": add, "update": update, "remove": remove}, new


class CaptureController:
    def __init__(self, interval: float = 1.5):
        self._interval = interval
        self._source: Optional[Source] = None
        self._task: Optional[asyncio.Task] = None
        self._graph = WifiGraph()
        self._subscribers: set[asyncio.Queue] = set()
        self._index: dict = {}
        self._handshakes = None
        self._seen_handshakes: set[str] = set()
        self._wps_watcher = None
        self._wps: dict = {}
        self._wps_tick = 0
        self.running = False
        self.mode: Optional[str] = None
        # Where the most recent capture was kept, if "save" was requested.
        self.last_saved_path: Optional[str] = None

    # ----------------------------------------------------------- lifecycle
    async def start(self, source: Source, mode: str,
                    interval: Optional[float] = None, handshakes=None,
                    wps=None) -> None:
        await self.stop()
        self._source = source
        self.mode = mode
        self._index = {}
        self._graph = WifiGraph()
        self._handshakes = handshakes
        self._seen_handshakes = set()
        self._wps_watcher = wps
        self._wps = {}
        self._wps_tick = 0
        self.last_saved_path = None
        if interval:
            self._interval = interval
        await source.start()
        self.running = True
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self.running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None
        if self._source:
            try:
                await self._source.stop()
            except Exception:
                pass
            # Surface where a "saved" capture was kept, if any, before we drop it.
            self.last_saved_path = getattr(self._source, "saved_path", None)
            self._source = None
        self.mode = None
        await self._broadcast({"type": "stopped"})

    # ------------------------------------------------------------- polling
    async def _loop(self) -> None:
        while self.running:
            scan = None
            try:
                scan = await self._source.read()
            except Exception:
                scan = None
            if scan is not None:
                # Live radio: age out stations that stopped being heard, so a
                # client that disconnected leaves the graph. Replay keeps all.
                if self.mode == "airodump":
                    scan = prune_stale(scan, STALE_AFTER)
                # Resolve vendors (live capture parses raw CSV, which has none).
                oui.enrich_scan(scan)
                self._apply_wps(scan)
                self._graph.load(scan)
                cyto = self._graph.to_cytoscape()
                patch, self._index = diff_elements(self._index, cyto)
                if patch["add"] or patch["update"] or patch["remove"]:
                    await self._broadcast({
                        "type": "patch",
                        "summary": self._graph.stats(),
                        **patch,
                    })
            await self._poll_handshakes()
            await self._poll_wps()
            await asyncio.sleep(self._interval)

    def _apply_wps(self, scan) -> None:
        """Merge accumulated WPS info into the scan's APs before the graph loads."""
        if not self._wps:
            return
        for ap in scan.access_points:
            info = self._wps.get(ap.bssid)
            if info:
                ap.wps = True
                ap.wps_version = info.get("version")
                ap.wps_locked = info.get("locked")

    async def _poll_wps(self) -> None:
        # tshark over the whole pcap is not free, so refresh WPS every few ticks.
        if not self._wps_watcher:
            return
        self._wps_tick += 1
        if self._wps_tick % 3 != 1:
            return
        try:
            self._wps = self._wps_watcher.poll()
        except Exception:
            pass

    async def _poll_handshakes(self) -> None:
        if not self._handshakes:
            return
        try:
            found = self._handshakes.poll()
        except Exception:
            return
        for bssid in found - self._seen_handshakes:
            self._seen_handshakes.add(bssid)
            node = self._graph.node(bssid)
            essid = node.get("essid") if node else None
            await self._broadcast({"type": "handshake", "bssid": bssid, "essid": essid})

    # --------------------------------------------------------- subscribers
    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    async def _broadcast(self, message: dict) -> None:
        for q in list(self._subscribers):
            try:
                q.put_nowait(message)
            except asyncio.QueueFull:
                pass

    # --------------------------------------------------------------- source
    @property
    def interface(self):
        return getattr(self._source, "interface", None)

    @property
    def channel(self):
        return getattr(self._source, "channel", None)

    def latest_cap(self):
        """Newest pcap of the live capture (for certificate inspection), if any."""
        getter = getattr(self._source, "latest_cap", None)
        return getter() if callable(getter) else None

    # ----------------------------------------------------------- live lookups
    def node(self, node_id: str):
        """Node detail from the live capture graph (mid-capture lookups)."""
        return self._graph.node(node_id)

    def search(self, query: str):
        """Search the live capture graph (mid-capture)."""
        return self._graph.search(query)

    @property
    def can_deauth(self) -> bool:
        """Deauth needs a live airodump capture locked on one channel."""
        return bool(self.running and self.mode == "airodump" and self.channel)

    def snapshot(self) -> dict:
        """Full current graph, used as the init message for a new subscriber."""
        return {
            "type": "init",
            "running": self.running,
            "mode": self.mode,
            "channel": self.channel,
            "can_deauth": self.can_deauth,
            "summary": self._graph.stats(),
            **self._graph.to_cytoscape(),
        }

    def status(self) -> dict:
        return {
            "running": self.running,
            "mode": self.mode,
            "channel": self.channel,
            "can_deauth": self.can_deauth,
            "interval": self._interval,
            "summary": self._graph.stats(),
        }
