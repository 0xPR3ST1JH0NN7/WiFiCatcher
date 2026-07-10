"""Deauthentication operation via aireplay-ng (authorized testing only).

This sends 802.11 deauth frames toward an AP (optionally targeting a single
client). It is a standard, well known technique used in *authorized* WiFi
penetration tests, for example to capture a WPA handshake for offline auditing
of a network you own or are contracted to assess.

All guardrails in :mod:`WiFiCatcher.operations.base` apply.
"""

from __future__ import annotations

import logging
import subprocess

from WiFiCatcher.models import normalize_mac
from WiFiCatcher.operations.base import (
    OperationError,
    require_authorization,
    require_tools,
)

logger = logging.getLogger("WiFiCatcher.operations.deauth")

# Cap the burst so a single API call can never become a sustained flood.
MAX_COUNT = 64


def deauth(
    interface: str,
    bssid: str,
    client: str | None = None,
    count: int = 5,
    acknowledged: bool = False,
    dry_run: bool = False,
) -> dict:
    """Send ``count`` deauth bursts at ``bssid`` (optionally one ``client``).

    Returns a dict describing what was run. Raises :class:`OperationError`
    (or its subclasses) if any guardrail or validation fails.
    """
    require_authorization(acknowledged)
    require_tools("aireplay-ng", hint="Install the aircrack-ng suite.")

    bssid = normalize_mac(bssid)
    if not bssid:
        raise OperationError("Invalid BSSID.")
    if not interface or not interface.strip():
        raise OperationError("A monitor-mode interface is required.")
    interface = interface.strip()

    target_client = normalize_mac(client) if client else None
    if client and not target_client:
        raise OperationError("Invalid client MAC.")

    count = max(1, min(int(count), MAX_COUNT))

    cmd = ["aireplay-ng", "--deauth", str(count), "-a", bssid]
    if target_client:
        cmd += ["-c", target_client]
    cmd.append(interface)

    # Audit at INFO so it stays off the default terminal (shown with --debug).
    logger.info("Deauth requested: %s", " ".join(cmd))

    if dry_run:
        return {"status": "dry-run", "command": cmd}

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60, check=False
        )
    except FileNotFoundError as exc:  # tool vanished between check and run
        raise OperationError(str(exc)) from exc
    except subprocess.TimeoutExpired as exc:
        raise OperationError("aireplay-ng timed out.") from exc

    return {
        "status": "ok" if proc.returncode == 0 else "error",
        "command": cmd,
        "returncode": proc.returncode,
        "stdout": proc.stdout[-4000:],
        "stderr": proc.stderr[-4000:],
    }
