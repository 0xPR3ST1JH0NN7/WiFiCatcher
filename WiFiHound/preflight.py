"""Startup preflight: verify the Python packages and external tools are present.

WiFiHound shells out to the aircrack-ng suite and ``tshark``. This module
resolves each dependency, prints a checklist to the terminal, and reports
whether they are all present so the CLI can refuse to start when something
mandatory is missing.

Every tool in the checklist is required and blocks startup when missing. A few
extras are resolved at runtime instead of here: ``wpa_supplicant`` (EAP
enumeration) and ``pcapFilter.sh`` (a faster RADIUS cert extractor that falls
back to ``tshark``); ``EAP_buster`` is bundled with WiFiHound. Run with
``--skip-checks`` to bypass the gate entirely.
"""

from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass
from importlib import metadata

# ANSI colors, used only when writing to a real terminal.
_GREEN = "\033[92m"
_RED = "\033[91m"
_DIM = "\033[2m"
_RESET = "\033[0m"


def _c(text: str, code: str) -> str:
    return f"{code}{text}{_RESET}" if sys.stdout.isatty() else text


@dataclass(frozen=True)
class Tool:
    name: str            # command resolved on PATH (or absolute path)
    purpose: str         # short human description
    required: bool       # True -> missing blocks startup
    install: str = ""    # how to obtain it
    env: str = ""        # env var that overrides the command name / path


# Python distributions the app imports (all required to run at all).
PYTHON_DEPS: list[tuple[str, str]] = [
    ("fastapi", "web framework"),
    ("uvicorn", "ASGI server"),
    ("python-multipart", "capture file uploads"),
    ("networkx", "graph model"),
    ("cryptography", "X.509 / RADIUS certificate parsing"),
]

# External command-line tools the app invokes. The aircrack-ng suite and tshark
# are mandatory; the rest back optional extras and only warn when absent.
TOOLS: list[Tool] = [
    Tool("aircrack-ng", "aircrack-ng suite", required=True,
         install="apt install aircrack-ng"),
    Tool("airmon-ng", "enable monitor mode", required=True,
         install="apt install aircrack-ng"),
    Tool("airodump-ng", "live radio capture", required=True,
         install="apt install aircrack-ng"),
    Tool("aireplay-ng", "deauthentication", required=True,
         install="apt install aircrack-ng"),
    Tool("tshark", "handshake detection + RADIUS cert extraction", required=True,
         install="apt install tshark"),
]


def _dist_present(dist: str) -> bool:
    try:
        metadata.version(dist)
        return True
    except metadata.PackageNotFoundError:
        return False


def _resolve(tool: Tool) -> str | None:
    """Absolute path to the tool, honouring any env override, or None.

    An env override that gives an explicit path is expanded (``~`` and
    ``$VARS``) and accepted if the file simply exists, even without the
    executable bit, so a configured-but-not-``chmod +x`` script still shows as
    present in the checklist.
    """
    name = tool.name
    if tool.env:
        override = os.environ.get(tool.env)
        if override:
            name = os.path.expanduser(os.path.expandvars(override))
    found = shutil.which(name)
    if found:
        return found
    if (os.sep in name or name.startswith("~")) and os.path.isfile(
            os.path.expanduser(name)):
        return os.path.expanduser(name)
    return None


def _line(name: str, width: int, present: bool, required: bool, note: str = "") -> None:
    mark = _c("[✓]", _GREEN) if present else _c("[✗]", _RED if required else _DIM)
    suffix = _c(f"  {note}", _DIM) if note else ""
    print(f"    {name.ljust(width)}  {mark}{suffix}")


def check() -> tuple[bool, list[str]]:
    """Return ``(ok, missing_required)`` without printing anything."""
    missing: list[str] = []
    for dist, _ in PYTHON_DEPS:
        if not _dist_present(dist):
            missing.append(dist)
    for tool in TOOLS:
        if tool.required and _resolve(tool) is None:
            missing.append(tool.name)
    return (not missing, missing)


def run() -> bool:
    """Print the dependency checklist; return True when it is safe to start."""
    print(_c("[*] preflight: verifying dependencies", _DIM))
    missing_required: list[str] = []

    print()
    print(_c("  Python packages", _DIM))
    pwidth = max(len(d) for d, _ in PYTHON_DEPS)
    for dist, purpose in PYTHON_DEPS:
        present = _dist_present(dist)
        if not present:
            missing_required.append(dist)
        _line(dist, pwidth, present, required=True,
              note="" if present else purpose)

    print()
    print(_c("  External tools", _DIM))
    twidth = max(len(t.name) for t in TOOLS)
    for tool in TOOLS:
        path = _resolve(tool)
        present = path is not None
        if tool.required and not present:
            missing_required.append(tool.name)
        if present:
            note = path
        elif tool.required:
            note = tool.purpose
        else:
            note = f"optional — {tool.purpose}"
        _line(tool.name, twidth, present, required=tool.required, note=note)

    print()
    if missing_required:
        print(_c(f"[!] cannot start — missing required: {', '.join(missing_required)}",
                 _RED))
        hints = sorted({t.install for t in TOOLS
                        if t.required and _resolve(t) is None and t.install})
        if not all(_dist_present(d) for d, _ in PYTHON_DEPS):
            hints.insert(0, "pip install -r requirements.txt")
        for hint in hints:
            print(_c(f"    → {hint}", _DIM))
        print(_c("    bypass with: --skip-checks  (offline-only use)", _DIM))
        return False

    print(_c("[*] all required dependencies present.", _DIM))
    return True
