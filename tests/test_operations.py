import pytest

import wifihound.operations.base as base
import wifihound.operations.deauth as deauth_mod
from wifihound.operations.base import OperationNotAuthorized


def _as_root(monkeypatch, is_root=True):
    monkeypatch.setattr(base, "_is_root", lambda: is_root)


def test_deauth_blocked_without_root(monkeypatch):
    _as_root(monkeypatch, False)
    with pytest.raises(OperationNotAuthorized):
        deauth_mod.deauth("wlan0mon", "DC:A6:32:11:22:33", acknowledged=True)


def test_deauth_requires_acknowledgement(monkeypatch):
    _as_root(monkeypatch, True)
    monkeypatch.setattr(deauth_mod, "require_tools", lambda *a: None)
    with pytest.raises(OperationNotAuthorized):
        deauth_mod.deauth("wlan0mon", "DC:A6:32:11:22:33", acknowledged=False)


def test_deauth_dry_run(monkeypatch):
    _as_root(monkeypatch, True)
    monkeypatch.setattr(deauth_mod, "require_tools", lambda *a: None)
    result = deauth_mod.deauth(
        "wlan0mon", "dc:a6:32:11:22:33", count=5,
        acknowledged=True, dry_run=True,
    )
    assert result["status"] == "dry-run"
    assert result["command"][:3] == ["aireplay-ng", "--deauth", "5"]
    assert "DC:A6:32:11:22:33" in result["command"]


def test_deauth_client_targets_one_station(monkeypatch):
    _as_root(monkeypatch, True)
    monkeypatch.setattr(deauth_mod, "require_tools", lambda *a: None)
    result = deauth_mod.deauth(
        "wlan0mon", "DC:A6:32:11:22:33", client="5C:F3:70:01:02:03",
        count=3, acknowledged=True, dry_run=True,
    )
    cmd = result["command"]
    assert cmd[:3] == ["aireplay-ng", "--deauth", "3"]
    assert "-a" in cmd and "DC:A6:32:11:22:33" in cmd
    assert "-c" in cmd and "5C:F3:70:01:02:03" in cmd
