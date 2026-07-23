"""Privilege separation for WiFiCatcher.

The web app runs unprivileged. The few operations that need root (monitor mode,
airodump-ng, aireplay-ng, EAP enumeration, restoring NetworkManager) are carried
out by a small **warden daemon** (:mod:`WiFiCatcher.privileged.server`) that
listens on a unix socket and validates every request before acting. The app
talks to it through :class:`WiFiCatcher.privileged.client.PrivClient`.

Launch models (the daemon code is identical; only how it gets root + the socket
differs):

* **systemd socket activation** (production): systemd owns the socket and starts
  the daemon on demand, passing it the listening fd. See ``packaging/systemd``.
* **on-demand / dev**: run ``python -m WiFiCatcher.privileged --socket PATH``
  (as root) and point the app at ``PATH`` via ``WIFICATCHER_PRIV_SOCKET``.
"""

from WiFiCatcher.privileged.client import (
    PrivClient,
    PrivError,
    PrivUnavailable,
    warden_available,
)

__all__ = ["PrivClient", "PrivError", "PrivUnavailable", "warden_available"]
