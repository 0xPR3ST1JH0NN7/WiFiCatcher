"""Parser interface and registry.

A parser turns raw capture bytes/text into a :class:`~WiFiCatcher.models.Scan`.
New formats (Kismet netxml, pcap, JSON ...) only need to subclass :class:`Parser`
and register themselves via :func:`register`.
"""

from __future__ import annotations

from typing import Callable, Optional

from WiFiCatcher.models import Scan


class Parser:
    """Base class for capture-file parsers."""

    #: short, stable identifier used in the API (e.g. "airodump-csv")
    id: str = "base"
    #: human-readable name shown in the UI
    name: str = "Base parser"
    #: file extensions this parser typically handles (lower-case, with dot)
    extensions: tuple[str, ...] = ()

    def detect(self, text: str, filename: str = "") -> bool:
        """Return True if this parser can likely handle the given content."""
        raise NotImplementedError

    def parse(self, text: str, filename: str = "") -> Scan:
        """Parse ``text`` into a :class:`Scan`."""
        raise NotImplementedError


_REGISTRY: dict[str, Parser] = {}


def register(parser: Parser) -> Parser:
    _REGISTRY[parser.id] = parser
    return parser


def get(parser_id: str) -> Optional[Parser]:
    return _REGISTRY.get(parser_id)


def all_parsers() -> list[Parser]:
    return list(_REGISTRY.values())


def detect_parser(text: str, filename: str = "") -> Optional[Parser]:
    """Pick the first registered parser that claims it can handle ``text``."""
    # Prefer an extension match, then fall back to content sniffing.
    lower = filename.lower()
    ext_matches = [p for p in _REGISTRY.values()
                   if any(lower.endswith(e) for e in p.extensions)]
    for parser in ext_matches:
        if parser.detect(text, filename):
            return parser
    for parser in _REGISTRY.values():
        if parser.detect(text, filename):
            return parser
    return None
