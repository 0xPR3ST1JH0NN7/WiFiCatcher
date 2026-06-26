import wifihound.operations.deauth as deauth_mod
from wifihound.operations.base import (
    OperationNotAuthorized,
    set_offensive_enabled,
)


def test_deauth_disabled_by_default():
    set_offensive_enabled(False)
    try:
        with __import__("pytest").raises(OperationNotAuthorized):
            deauth_mod.deauth("wlan0mon", "DC:A6:32:11:22:33", acknowledged=True)
    finally:
        set_offensive_enabled(False)


def test_deauth_requires_acknowledgement(monkeypatch):
    set_offensive_enabled(True)
    monkeypatch.setattr(deauth_mod, "require_tools", lambda *a: None)
    # Pretend we are root so we reach the acknowledgement check.
    import wifihound.operations.base as base
    monkeypatch.setattr(base, "_is_root", lambda: True)
    try:
        with __import__("pytest").raises(OperationNotAuthorized):
            deauth_mod.deauth("wlan0mon", "DC:A6:32:11:22:33", acknowledged=False)
    finally:
        set_offensive_enabled(False)


def test_deauth_dry_run(monkeypatch):
    set_offensive_enabled(True)
    monkeypatch.setattr(deauth_mod, "require_tools", lambda *a: None)
    import wifihound.operations.base as base
    monkeypatch.setattr(base, "_is_root", lambda: True)
    try:
        result = deauth_mod.deauth(
            "wlan0mon", "dc:a6:32:11:22:33", count=5,
            acknowledged=True, dry_run=True,
        )
        assert result["status"] == "dry-run"
        assert result["command"][:3] == ["aireplay-ng", "--deauth", "5"]
        assert "DC:A6:32:11:22:33" in result["command"]
    finally:
        set_offensive_enabled(False)


def test_deauth_client_targets_one_station(monkeypatch):
    set_offensive_enabled(True)
    monkeypatch.setattr(deauth_mod, "require_tools", lambda *a: None)
    import wifihound.operations.base as base
    monkeypatch.setattr(base, "_is_root", lambda: True)
    try:
        result = deauth_mod.deauth(
            "wlan0mon", "DC:A6:32:11:22:33", client="5C:F3:70:01:02:03",
            count=3, acknowledged=True, dry_run=True,
        )
        cmd = result["command"]
        assert cmd[:3] == ["aireplay-ng", "--deauth", "3"]
        assert "-a" in cmd and "DC:A6:32:11:22:33" in cmd
        assert "-c" in cmd and "5C:F3:70:01:02:03" in cmd
    finally:
        set_offensive_enabled(False)
