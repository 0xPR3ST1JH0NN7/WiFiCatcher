"""Graph model on networkx: holds the current scan, exposes search/neighbour
queries, and serialises to Cytoscape.js element JSON for the frontend.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Optional

import networkx as nx

from WiFiCatcher.models import AccessPoint, Client, Scan


def _is_enterprise(data: dict) -> bool:
    """WPA-Enterprise (802.1X) APs report MGT in airodump's Authentication."""
    return "MGT" in (data.get("authentication") or "").upper()


def _phantom_ap(ap: AccessPoint) -> bool:
    """True if this AP row is likely a station airodump mislisted as a BSSID.

    A real access point beacons; a client that only ever sends data frames can
    still show up in airodump's AP table with no ESSID and no beacons. Left as an
    AP it renders as a white "hidden" node wired to the real AP, when it is really
    the client that is connecting.
    """
    essid = (ap.essid or "").strip()
    return essid in ("", "<Hidden>") and not (ap.beacons or 0)


class WifiGraph:
    def __init__(self) -> None:
        self.graph = nx.Graph()
        self.scan: Optional[Scan] = None

    # ------------------------------------------------------------------ build
    def load(self, scan: Scan) -> None:
        """Replace the current graph with the contents of ``scan``."""
        self.scan = scan
        g = nx.Graph()

        # A station that airodump also mislisted as a phantom BSSID must stay a
        # client, or the node that is connecting shows as a white "hidden" AP and
        # its association is drawn as an AP-to-AP edge.
        assoc_clients = {c.mac for c in scan.clients if c.mac and c.associated_bssid}

        for ap in scan.access_points:
            if ap.bssid in assoc_clients and _phantom_ap(ap):
                continue
            g.add_node(ap.bssid, kind="ap", data=asdict(ap))

        for client in scan.clients:
            if client.mac not in g:
                g.add_node(client.mac, kind="client", data=asdict(client))
            bssid = client.associated_bssid
            # Only ever wire a client to an AP: never an AP-to-AP edge.
            if (bssid and bssid in g
                    and g.nodes[bssid].get("kind") == "ap"
                    and g.nodes[client.mac].get("kind") == "client"):
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
                "cipher": data.get("cipher"),
                "authentication": data.get("authentication"),
                "channel": data.get("channel"),
                "vendor": data.get("vendor"),
                "power": data.get("power"),
                "degree": self.graph.degree(node_id),
                "enterprise": kind == "ap" and _is_enterprise(data),
                "wps": bool(data.get("wps")),
                "wps_version": data.get("wps_version"),
                "wps_locked": data.get("wps_locked"),
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
