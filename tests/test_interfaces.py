"""Tests for wireless interface discovery and monitor-mode switching.

sysfs is faked under ``tmp_path`` and ``airmon-ng`` is replaced with an injected
runner, so these run with no hardware, no root and no aircrack-ng installed.
"""

import types

import pytest

from wifihound.capture import interfaces as ifaces
from wifihound.operations.base import OperationError, OperationNotAuthorized


def _make_iface(root, name, *, wireless=True, type_val=None):
    d = root / name
    d.mkdir()
    if wireless:
        (d / "phy80211").mkdir()
    if type_val is not None:
        (d / "type").write_text(f"{type_val}\n")


def _proc(returncode=0, stdout="", stderr=""):
    return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


# --------------------------------------------------------------- listing/mode
def test_list_wireless_interfaces(tmp_path):
    _make_iface(tmp_path, "lo", wireless=False, type_val=772)
    _make_iface(tmp_path, "eth0", wireless=False, type_val=1)
    _make_iface(tmp_path, "wlan0", type_val=ifaces.ARPHRD_ETHER)
    _make_iface(tmp_path, "wlan1mon", type_val=ifaces.ARPHRD_IEEE80211_RADIOTAP)

    out = ifaces.list_wireless_interfaces(sysfs=str(tmp_path))
    assert [i["name"] for i in out] == ["wlan0", "wlan1mon"]  # sorted, wired excluded
    by = {i["name"]: i for i in out}
    assert by["wlan0"]["mode"] == "managed" and by["wlan0"]["monitor"] is False
    assert by["wlan1mon"]["mode"] == "monitor" and by["wlan1mon"]["monitor"] is True


def test_list_wireless_interfaces_missing_sysfs(tmp_path):
    assert ifaces.list_wireless_interfaces(sysfs=str(tmp_path / "nope")) == []


def test_interface_exists_and_mode(tmp_path):
    _make_iface(tmp_path, "wlan0", type_val=ifaces.ARPHRD_ETHER)
    assert ifaces.interface_exists("wlan0", sysfs=str(tmp_path))
    assert not ifaces.interface_exists("wlan9", sysfs=str(tmp_path))
    assert not ifaces.interface_exists("", sysfs=str(tmp_path))
    assert ifaces.interface_mode("wlan0", sysfs=str(tmp_path)) == "managed"
    assert ifaces.is_monitor("wlan0", sysfs=str(tmp_path)) is False


def test_interface_mode_unknown_without_type(tmp_path):
    _make_iface(tmp_path, "wlan0", type_val=None)
    assert ifaces.interface_mode("wlan0", sysfs=str(tmp_path)) == "unknown"


@pytest.mark.parametrize("text,expected", [
    ("(monitor mode enabled on wlan0mon)", "wlan0mon"),
    ("(mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon)", "wlan0mon"),
    ("(monitor mode vif enabled on [phy1]wlp3s0mon)", "wlp3s0mon"),
    ("nothing useful here", None),
])
def test_parse_monitor_iface(text, expected):
    assert ifaces._parse_monitor_iface(text) == expected


# ------------------------------------------------------- monitor-mode switching
@pytest.fixture
def rooted(monkeypatch):
    """Pass the root + tool guardrails so the airmon-ng path can be exercised."""
    import wifihound.operations.base as base
    monkeypatch.setattr(base, "_is_root", lambda: True)
    monkeypatch.setattr(ifaces, "require_tools", lambda *a: None)


def test_ensure_monitor_already_monitor_skips_airmon(tmp_path):
    _make_iface(tmp_path, "wlan0", type_val=ifaces.ARPHRD_IEEE80211_RADIOTAP)
    calls = []

    def run(cmd):
        calls.append(cmd)
        return _proc()

    out = ifaces.ensure_monitor_mode("wlan0", run=run, sysfs=str(tmp_path))
    assert out == "wlan0"
    assert calls == []  # already in monitor mode -> airmon-ng is not invoked


def test_ensure_monitor_missing_interface(tmp_path):
    with pytest.raises(OperationError):
        ifaces.ensure_monitor_mode("wlan9", run=lambda c: _proc(), sysfs=str(tmp_path))


def test_ensure_monitor_creates_vif_named_in_stdout(tmp_path, rooted):
    _make_iface(tmp_path, "wlan0", type_val=ifaces.ARPHRD_ETHER)

    def run(cmd):
        assert cmd == ["airmon-ng", "start", "wlan0"]
        _make_iface(tmp_path, "wlan0mon", type_val=ifaces.ARPHRD_IEEE80211_RADIOTAP)
        return _proc(stdout="(monitor mode enabled on wlan0mon)")

    assert ifaces.ensure_monitor_mode("wlan0", run=run, sysfs=str(tmp_path)) == "wlan0mon"


def test_ensure_monitor_switches_in_place(tmp_path, rooted):
    _make_iface(tmp_path, "wlan0", type_val=ifaces.ARPHRD_ETHER)

    def run(cmd):
        (tmp_path / "wlan0" / "type").write_text(str(ifaces.ARPHRD_IEEE80211_RADIOTAP))
        return _proc(stdout="no parseable name here")

    assert ifaces.ensure_monitor_mode("wlan0", run=run, sysfs=str(tmp_path)) == "wlan0"


def test_ensure_monitor_falls_back_to_mon_convention(tmp_path, rooted):
    _make_iface(tmp_path, "wlan0", type_val=ifaces.ARPHRD_ETHER)

    def run(cmd):
        _make_iface(tmp_path, "wlan0mon", type_val=ifaces.ARPHRD_IEEE80211_RADIOTAP)
        return _proc(stdout="chatty but unparseable output")

    assert ifaces.ensure_monitor_mode("wlan0", run=run, sysfs=str(tmp_path)) == "wlan0mon"


def test_ensure_monitor_airmon_failure_raises(tmp_path, rooted):
    _make_iface(tmp_path, "wlan0", type_val=ifaces.ARPHRD_ETHER)
    with pytest.raises(OperationError):
        ifaces.ensure_monitor_mode(
            "wlan0", run=lambda c: _proc(returncode=1, stdout="airmon-ng failed"),
            sysfs=str(tmp_path))


def test_ensure_monitor_requires_root(tmp_path, monkeypatch):
    import wifihound.operations.base as base
    monkeypatch.setattr(base, "_is_root", lambda: False)
    monkeypatch.setattr(ifaces, "require_tools", lambda *a: None)
    _make_iface(tmp_path, "wlan0", type_val=ifaces.ARPHRD_ETHER)
    with pytest.raises(OperationNotAuthorized):
        ifaces.ensure_monitor_mode("wlan0", run=lambda c: _proc(), sysfs=str(tmp_path))
