"""Unit tests for WPS parsing (:mod:`WiFiCatcher.capture.wps`)."""

from WiFiCatcher.capture.wps import _decode_version, parse_wps, wps_fields

# The ordered -e field list parse_wps expects, matching wps.py's _DESIRED.
FIELDS = ["wlan.bssid", "wps.ext.version2", "wps.version", "wps.ap_setup_locked"]


def test_decode_version_from_hex_and_decimal():
    assert _decode_version("0x20") == "2.0"
    assert _decode_version("0x10") == "1.0"
    assert _decode_version("0x00") == "0.0"
    assert _decode_version("32") == "2.0"   # bare decimal byte
    assert _decode_version("16") == "1.0"
    assert _decode_version("") is None
    assert _decode_version("junk") is None


def test_version2_wins_over_legacy_version():
    # A WPS 2.0 AP keeps Version=0x10 for compat and adds ext.version2=0x20.
    out = "1C:49:7B:9C:28:9E|0x20|0x10|0x00"
    parsed = parse_wps(out, FIELDS)
    assert parsed["1C:49:7B:9C:28:9E"] == {"version": "2.0", "locked": False}


def test_legacy_only_and_locked():
    out = "AA:BB:CC:DD:EE:01||0x10|0x01"
    parsed = parse_wps(out, FIELDS)
    assert parsed["AA:BB:CC:DD:EE:01"] == {"version": "1.0", "locked": True}


def test_wps_present_without_version_reports_zero():
    # A frame matched the WPS filter (row exists) but carried no version byte.
    out = "AA:BB:CC:DD:EE:02|||0"
    parsed = parse_wps(out, FIELDS)
    assert parsed["AA:BB:CC:DD:EE:02"]["version"] == "0.0"


def test_bssid_is_normalized_and_blank_rows_skipped():
    out = "aa-bb-cc-dd-ee-03|0x20|0x10|0\n|0x20|0x10|0\n"
    parsed = parse_wps(out, FIELDS)
    assert list(parsed) == ["AA:BB:CC:DD:EE:03"]


def test_columns_located_by_name_when_a_field_is_dropped():
    # If tshark lacked ext.version2, the -e list (and rows) omit that column;
    # parse_wps maps by name, so the legacy version is still read correctly.
    fields = ["wlan.bssid", "wps.version", "wps.ap_setup_locked"]
    parsed = parse_wps("AA:BB:CC:DD:EE:04|0x10|0x01", fields)
    assert parsed["AA:BB:CC:DD:EE:04"] == {"version": "1.0", "locked": True}


def test_wps_fields_starts_with_bssid():
    assert wps_fields()[0] == "wlan.bssid"
