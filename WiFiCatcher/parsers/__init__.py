"""Parser package. Importing it registers all built in parsers."""

from WiFiCatcher.parsers.base import (  # noqa: F401
    Parser,
    all_parsers,
    detect_parser,
    get,
    register,
)

# Importing the modules runs their register() calls.
from WiFiCatcher.parsers import airodump_csv  # noqa: F401,E402

__all__ = ["Parser", "all_parsers", "detect_parser", "get", "register"]
