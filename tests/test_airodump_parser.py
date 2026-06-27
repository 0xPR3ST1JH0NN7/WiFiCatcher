import pathlib

from wifihound.parsers import detect_parser, get
from wifihound.parsers.airodump_csv import AirodumpCsvParser

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
SAMPLE = (FIXTURES / "sample-airodump.csv").read_text()


def test_parser_registered():
    assert get("airodump-csv") is not None


def test_detect():
    parser = detect_parser(SAMPLE, "scan-01.csv")
    assert isinstance(parser, AirodumpCsvParser)


def test_counts():
    scan = AirodumpCsvParser().parse(SAMPLE, "sample.csv")
    assert len(scan.access_points) == 4
    assert len(scan.clients) == 4
    summary = scan.summary()
    assert summary["associated_clients"] == 3
    assert summary["hidden_aps"] == 1  # the OPN AP has an empty ESSID


def test_ap_fields():
    scan = AirodumpCsvParser().parse(SAMPLE, "sample.csv")
    ap = next(a for a in scan.access_points if a.bssid == "DC:A6:32:11:22:33")
    assert ap.essid == "HomeNet"
    assert ap.channel == "6"
    assert ap.privacy == "WPA2"
    assert ap.cipher == "CCMP"
    assert ap.power == -42
    assert ap.beacons == 120


def test_quoted_essid_with_space():
    scan = AirodumpCsvParser().parse(SAMPLE, "sample.csv")
    ap = next(a for a in scan.access_points if a.bssid == "A4:2B:B0:CA:FE:99")
    assert ap.essid == "Cafe Guest"


def test_unassociated_client_with_probes():
    scan = AirodumpCsvParser().parse(SAMPLE, "sample.csv")
    client = next(c for c in scan.clients if c.mac == "AC:DE:48:0A:0B:0C")
    assert not client.is_associated
    assert client.probed_essids == ["HomeNet", "FreeWiFi", "Starbucks"]


def test_associated_client_links_to_ap():
    scan = AirodumpCsvParser().parse(SAMPLE, "sample.csv")
    client = next(c for c in scan.clients if c.mac == "5C:F3:70:01:02:03")
    assert client.associated_bssid == "DC:A6:32:11:22:33"
