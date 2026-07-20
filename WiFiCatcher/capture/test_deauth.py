"""Tests for deauth/disassoc parsing and controller-side suppression."""

from WiFiCatcher.capture.controller import CaptureController
from WiFiCatcher.capture.deauth import parse_deauth
from WiFiCatcher.models import Client, Scan

AP = "AA:BB:CC:DD:EE:FF"
CLIENT = "11:22:33:44:55:66"


# --------------------------------------------------------------- parse_deauth
def test_parse_deauth_ap_deauthing_client():
    # AP -> client: sa is the AP (bssid), da is the client.
    out = f"1000.0|{AP}|{CLIENT}|{AP}"
    assert parse_deauth(out) == [
        {"client": CLIENT, "bssid": AP, "broadcast": False, "ts": 1000.0}]


def test_parse_deauth_client_leaving():
    # client -> AP: sa is the client, da is the AP.
    out = f"1000.0|{CLIENT}|{AP}|{AP}"
    ev = parse_deauth(out)[0]
    assert ev["client"] == CLIENT and ev["bssid"] == AP and ev["broadcast"] is False


def test_parse_deauth_broadcast():
    out = f"1000.0|{AP}|FF:FF:FF:FF:FF:FF|{AP}"
    assert parse_deauth(out) == [
        {"client": None, "bssid": AP, "broadcast": True, "ts": 1000.0}]


def test_parse_deauth_since_filters_old_frames():
    out = f"100.0|{CLIENT}|{AP}|{AP}\n200.0|{CLIENT}|{AP}|{AP}"
    events = parse_deauth(out, since=150.0)
    assert len(events) == 1 and events[0]["ts"] == 200.0


def test_parse_deauth_normalizes_case():
    out = f"1000.0|{CLIENT.lower()}|{AP.lower()}|{AP.lower()}"
    ev = parse_deauth(out)[0]
    assert ev["bssid"] == AP and ev["client"] == CLIENT


def test_parse_deauth_ignores_bad_and_clientless_rows():
    out = "\n".join([
        "garbage",
        f"notime|{CLIENT}|{AP}|{AP}",   # unparseable timestamp
        f"300.0||{AP}|{AP}",            # no client (sa empty, da == bssid)
    ])
    assert parse_deauth(out) == []


# ------------------------------------------------------ controller suppression
class _FakeSource:
    def __init__(self, events):
        self._events = events

    def drain_deauth(self):
        out, self._events = self._events, []
        return out


def _scan():
    return Scan(access_points=[],
                clients=[Client(mac=CLIENT, associated_bssid=AP)],
                source="live.csv", format="csv")


def test_apply_deauth_drops_matching_association():
    c = CaptureController()
    c._source = _FakeSource(
        [{"client": CLIENT, "bssid": AP, "broadcast": False}])
    scan = _scan()
    c._apply_deauth(scan)
    assert scan.clients[0].associated_bssid is None


def test_apply_deauth_broadcast_drops_all_of_bssid():
    c = CaptureController()
    c._source = _FakeSource([{"client": None, "bssid": AP, "broadcast": True}])
    scan = _scan()
    c._apply_deauth(scan)
    assert scan.clients[0].associated_bssid is None


def test_apply_deauth_leaves_other_clients_alone():
    c = CaptureController()
    c._source = _FakeSource(
        [{"client": "99:99:99:99:99:99", "bssid": AP, "broadcast": False}])
    scan = _scan()
    c._apply_deauth(scan)
    assert scan.clients[0].associated_bssid == AP
