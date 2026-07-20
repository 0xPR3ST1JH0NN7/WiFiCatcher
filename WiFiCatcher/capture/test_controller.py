"""Tests for the capture controller helpers (stale-station pruning)."""

from __future__ import annotations

from WiFiCatcher.capture.controller import prune_stale
from WiFiCatcher.models import AccessPoint, Client, Scan


def test_prune_drops_stations_not_seen_recently() -> None:
    scan = Scan(
        access_points=[
            AccessPoint(bssid="AA:AA:AA:AA:AA:AA", last_seen="2026-01-01 00:05:00"),
        ],
        clients=[
            Client(mac="11:11:11:11:11:11", last_seen="2026-01-01 00:04:50"),  # 10s
            Client(mac="22:22:22:22:22:22", last_seen="2026-01-01 00:00:00"),  # 5m
        ],
    )
    out = prune_stale(scan, max_age=60)
    macs = {c.mac for c in out.clients}
    assert "11:11:11:11:11:11" in macs        # heard 10s before newest -> kept
    assert "22:22:22:22:22:22" not in macs    # 5 min old -> dropped
    assert len(out.access_points) == 1        # the newest sighting -> kept


def test_prune_keeps_unparseable_timestamps() -> None:
    scan = Scan(
        access_points=[AccessPoint(bssid="AA:AA:AA:AA:AA:AA",
                                   last_seen="2026-01-01 00:05:00")],
        clients=[Client(mac="33:33:33:33:33:33", last_seen="")],  # unknown -> kept
    )
    out = prune_stale(scan, max_age=60)
    assert len(out.clients) == 1


def test_prune_noop_without_any_timestamps() -> None:
    scan = Scan(clients=[Client(mac="44:44:44:44:44:44", last_seen=None)])
    out = prune_stale(scan, max_age=60)
    assert len(out.clients) == 1
