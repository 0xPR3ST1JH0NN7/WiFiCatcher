"""Offensive operations (guardrailed, authorized testing only)."""

from WiFiCatcher.operations.base import (  # noqa: F401
    OperationError,
    OperationNotAuthorized,
    offensive_available,
)
from WiFiCatcher.operations import enterprise  # noqa: F401

__all__ = [
    "OperationError",
    "OperationNotAuthorized",
    "offensive_available",
    "enterprise",
]
