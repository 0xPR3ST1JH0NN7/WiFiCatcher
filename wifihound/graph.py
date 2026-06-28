"""Graph model built on top of networkx.

The :class:`WifiGraph` holds the current scan, exposes search / neighbour /
path queries, and serialises to Cytoscape.js element JSON for the frontend.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Optional

import networkx as nx

from wifihound.models import AccessPoint, Client, Scan


def _is_enterprise(data: dict) -> bool:
    """WPA-Enterprise (802.1X) APs report MGT in airodump's Authentication."""
    return "MGT" in (data.get("authentication") or "").upper()


class WifiGraph:
    def __init__(self) -> None:
        self.graph = nx.Graph()
        self.scan: Optional[Scan] = None

    # ------------------------------------------------------------------ build
    def load(self, scan: Scan) -> None:
        """Replace the current graph with the contents of ``scan``."""
        self.scan = scan
        g = nx.Graph()

        for ap in scan.access_points:
            g.add_node(ap.bssid, kind="ap", data=asdict(ap))

        for client in scan.clients:
            if client.mac not in g:
                g.add_node(client.mac, kind="client", data=asdict(client))
            bssid = client.associated_bssid
            if bssid and bssid in g and g.nodes[bssid].get("kind") == "ap":
                g.add_edge(client.mac, bssid, kind="assoc")

        self.graph = g

    def clear(self) -> None:
        """Drop the current scan and graph, returning to an empty session."""
        self.graph = nx.Graph()
        self.scan = None

    # ----------------------------------------------------------------- access
    def node(self, node_id: str) -> Optional[dict]:
        if node_id not in self.graph:
            return None
        n = self.graph.nodes[node_id]
        info = dict(n["data"])
        info["id"] = node_id
        info["kind"] = n["kind"]
        info["degree"] = self.graph.degree(node_id)
        info["neighbors"] = list(self.graph.neighbors(node_id))
        info["enterprise"] = n["kind"] == "ap" and _is_enterprise(n["data"])
        return info

    def neighbors(self, node_id: str) -> list[str]:
        if node_id not in self.graph:
            return []
        return list(self.graph.neighbors(node_id))

    def search(self, query: str) -> list[dict]:
        """Case-insensitive match over id, essid, vendor and probed essids."""
        q = (query or "").strip().lower()
        if not q:
            return []
        results = []
        for node_id, attrs in self.graph.nodes(data=True):
            data = attrs.get("data", {})
            haystack = [node_id, data.get("essid"), data.get("vendor")]
            haystack += data.get("probed_essids", []) or []
            if any(q in str(h).lower() for h in haystack if h):
                results.append({
                    "id": node_id,
                    "kind": attrs.get("kind"),
                    "label": data.get("essid") or node_id,
                })
        return results

    def path(self, source: str, target: str) -> list[str]:
        """Shortest path between two nodes, or [] if none."""
        if source not in self.graph or target not in self.graph:
            return []
        try:
            return nx.shortest_path(self.graph, source, target)
        except nx.NetworkXNoPath:
            return []

    # -------------------------------------------------------------- serialise
    def to_cytoscape(self) -> dict:
        """Return ``{"elements": {"nodes": [...], "edges": [...]}}``."""
        nodes = []
        for node_id, attrs in self.graph.nodes(data=True):
            data = attrs.get("data", {})
            kind = attrs.get("kind")
            if kind == "ap":
                label = data.get("essid") or "<Hidden>"
            else:
                label = node_id
            nodes.append({"data": {
                "id": node_id,
                "label": label,
                "kind": kind,
                "essid": data.get("essid"),
                "privacy": data.get("privacy"),
                "channel": data.get("channel"),
                "vendor": data.get("vendor"),
                "power": data.get("power"),
                "degree": self.graph.degree(node_id),
                "enterprise": kind == "ap" and _is_enterprise(data),
            }})

        edges = []
        for src, dst, attrs in self.graph.edges(data=True):
            edges.append({"data": {
                "id": f"{src}__{dst}",
                "source": src,
                "target": dst,
                "kind": attrs.get("kind", "assoc"),
            }})

        return {"elements": {"nodes": nodes, "edges": edges}}

    def stats(self) -> dict:
        if self.scan is None:
            return {"access_points": 0, "clients": 0, "associated_clients": 0,
                    "hidden_aps": 0, "loaded": False}
        s = self.scan.summary()
        s["loaded"] = True
        return s
