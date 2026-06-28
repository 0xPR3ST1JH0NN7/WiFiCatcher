"""Capture controller: poll a source, diff the graph, broadcast patches.

The controller owns a single live session. Each tick it asks the source for a
fresh :class:`Scan`, rebuilds the graph with the existing :class:`WifiGraph`,
computes a minimal diff against what it last sent, and pushes a patch to every
subscribed WebSocket queue.
"""

from __future__ import annotations

import asyncio
from typing import Optional

from wifihound.capture.sources import Source
from wifihound.graph import WifiGraph


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
        self.running = False
        self.mode: Optional[str] = None
        # Where the most recent capture was kept, if "save" was requested.
        self.last_saved_path: Optional[str] = None

    # ----------------------------------------------------------- lifecycle
    async def start(self, source: Source, mode: str,
                    interval: Optional[float] = None, handshakes=None) -> None:
        await self.stop()
        self._source = source
        self.mode = mode
        self._index = {}
        self._graph = WifiGraph()
        self._handshakes = handshakes
        self._seen_handshakes = set()
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
            await asyncio.sleep(self._interval)

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
