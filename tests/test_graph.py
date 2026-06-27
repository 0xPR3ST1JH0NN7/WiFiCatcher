import pathlib

from wifihound.enrichment import oui
from wifihound.graph import WifiGraph
from wifihound.parsers.airodump_csv import AirodumpCsvParser

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
SAMPLE = (FIXTURES / "sample-airodump.csv").read_text()


def build_graph():
    scan = AirodumpCsvParser().parse(SAMPLE, "sample.csv")
    g = WifiGraph()
    g.load(scan)
    return g, scan


def test_load_and_elements():
    g, _ = build_graph()
    cyto = g.to_cytoscape()
    # 4 APs + 4 clients = 8 nodes
    assert len(cyto["elements"]["nodes"]) == 8
    # 3 associated clients -> 3 edges
    assert len(cyto["elements"]["edges"]) == 3


def test_node_lookup():
    g, _ = build_graph()
    info = g.node("DC:A6:32:11:22:33")
    assert info["kind"] == "ap"
    assert info["essid"] == "HomeNet"
    assert info["degree"] == 1


def test_search_matches_essid_and_probe():
    g, _ = build_graph()
    assert any(r["id"] == "B8:27:EB:AA:BB:CC" for r in g.search("office"))
    # probe-only essid is searchable on the client node
    assert any(r["id"] == "AC:DE:48:0A:0B:0C" for r in g.search("starbucks"))


def test_path_between_client_and_ap():
    g, _ = build_graph()
    path = g.path("5C:F3:70:01:02:03", "DC:A6:32:11:22:33")
    assert path == ["5C:F3:70:01:02:03", "DC:A6:32:11:22:33"]


def test_oui_enrichment():
    g, scan = build_graph()
    resolved = oui.enrich_scan(scan)
    assert resolved > 0
    # DC:A6:32 -> Raspberry Pi in the built in OUI table
    ap = next(a for a in scan.access_points if a.bssid == "DC:A6:32:11:22:33")
    assert ap.vendor == "Raspberry Pi"
