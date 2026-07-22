"""Unit tests for EAP Response/Identity parsing."""

from WiFiCatcher.operations.enterprise import parse_eap_identities


def test_parses_bssid_client_identity():
    out = ("1c:49:7b:9c:28:9e|aa:bb:cc:11:22:33|HTB\\jdoe\n"
           "1c:49:7b:9c:28:9e|aa:bb:cc:44:55:66|anonymous\n")
    rows = parse_eap_identities(out)
    assert rows == [
        {"bssid": "1C:49:7B:9C:28:9E", "client": "AA:BB:CC:11:22:33",
         "identity": "HTB\\jdoe"},
        {"bssid": "1C:49:7B:9C:28:9E", "client": "AA:BB:CC:44:55:66",
         "identity": "anonymous"},
    ]


def test_deduplicates_repeated_frames():
    out = ("1c:49:7b:9c:28:9e|aa:bb:cc:11:22:33|CORP\\user\n"
           "1c:49:7b:9c:28:9e|aa:bb:cc:11:22:33|CORP\\user\n")
    assert len(parse_eap_identities(out)) == 1


def test_skips_empty_identity_and_short_rows():
    out = ("1c:49:7b:9c:28:9e|aa:bb:cc:11:22:33|\n"
           "junk-without-separators\n"
           "\n")
    assert parse_eap_identities(out) == []


def test_normalizes_macs_and_keeps_identity_verbatim():
    out = "AA-BB-CC-DD-EE-FF|11-22-33-44-55-66|dom\\User.Name\n"
    rows = parse_eap_identities(out)
    assert rows[0]["bssid"] == "AA:BB:CC:DD:EE:FF"
    assert rows[0]["client"] == "11:22:33:44:55:66"
    assert rows[0]["identity"] == "dom\\User.Name"


def test_collapses_doubled_backslash():
    # Some tshark builds escape the backslash; LAB\\test must read as LAB\test.
    out = "1c:49:7b:9c:28:9e|aa:bb:cc:11:22:33|LAB\\\\test\n"
    assert parse_eap_identities(out)[0]["identity"] == "LAB\\test"
