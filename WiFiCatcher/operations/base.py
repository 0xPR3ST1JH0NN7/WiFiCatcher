"""Offensive-operation framework with hard guardrails.

Live-radio operations require root, an explicit per-request acknowledgement, and
present tools; every call is logged. Authorized use only.
"""

from __future__ import annotations

import logging
import os
import shutil

logger = logging.getLogger("WiFiCatcher.operations")


class OperationError(RuntimeError):
    """Raised when an operation is refused or fails."""


class OperationNotAuthorized(OperationError):
    """Raised when the per-request gate or privilege check blocks a call."""


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def offensive_available() -> bool:
    """Offensive / live-radio features are available only when running as root."""
    return _is_root()


def require_authorization(acknowledged: bool) -> None:
    """Enforce every guardrail before an offensive operation may run."""
    if not _is_root():
        raise OperationNotAuthorized(
            "This action needs root privileges (radio access). "
            "Start WiFiCatcher with sudo."
        )
    if not acknowledged:
        raise OperationNotAuthorized(
            "Authorization not acknowledged for this action."
        )


def require_tools(*tools: str, hint: str = "") -> None:
    missing = [t for t in tools if shutil.which(t) is None]
    if missing:
        detail = f"Required tool(s) not found on PATH: {', '.join(missing)}."
        raise OperationError(f"{detail} {hint}".strip())
