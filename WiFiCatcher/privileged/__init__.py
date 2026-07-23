"""Privilege separation for WiFiCatcher.

Root-only operations run in a small warden daemon
(:mod:`WiFiCatcher.privileged.server`) that listens on a unix socket and
validates every request; the app talks to it via :class:`PrivClient`. The daemon
gets root + its socket from systemd socket activation (prod) or ``--socket`` (dev).
"""

from WiFiCatcher.privileged.client import (
    PrivClient,
    PrivError,
    PrivUnavailable,
    warden_available,
)

__all__ = ["PrivClient", "PrivError", "PrivUnavailable", "warden_available"]
