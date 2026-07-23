"""Startup preflight: verify required Python packages and external tools (the
aircrack-ng suite, ``tshark``) are present, printing a checklist so the CLI can
refuse to start when something mandatory is missing.
"""

from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path

# ANSI colors, used only when writing to a real terminal.
_GREEN = "\033[92m"
_RED = "\033[91m"
_DIM = "\033[2m"
_RESET = "\033[0m"


def _c(text: str, code: str) -> str:
    return f"{code}{text}{_RESET}" if sys.stdout.isatty() else text


@dataclass(frozen=True)
class Tool:
    name: str            # command resolved on PATH
    purpose: str         # short human description
    required: bool       # True -> missing blocks startup
    install: str = ""    # how to obtain it


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


def _find_project_venv() -> Path | None:
    """Locate a project virtualenv interpreter, checking the app's own dir before
    cwd so an unrelated ``.venv`` isn't mistaken for the project's. ``Path.cwd()``
    is probed defensively: a deleted cwd must not turn the hint into a traceback.
    """
    bases: list[Path] = [Path(__file__).resolve().parent.parent]
    try:
        bases.append(Path.cwd())
    except OSError:
        pass
    for base in bases:
        for name in (".venv", "venv"):
            py = base / name / "bin" / "python"
            if py.exists():
                return py
    return None


def _sudo_venv_hint() -> list[str] | None:
    """Explain a missing Python package when ``sudo`` ran the system interpreter
    and hid a project ``.venv`` (the most common cause right after a successful
    install). Returns display lines pointing at the venv interpreter, or None.
    """
    if not os.environ.get("SUDO_USER"):
        return None  # not launched via sudo
    if sys.prefix != sys.base_prefix:
        return None  # already inside a venv — sudo preserved it
    venv_py = _find_project_venv()
    if venv_py is not None:
        return [
            "running under sudo with the system Python — your virtualenv's "
            "packages are not visible.",
            "re-run it with the venv's own interpreter:",
            f"  → sudo {venv_py} -m WiFiCatcher",
        ]
    return [
        "running under sudo with the system Python — a virtualenv's packages "
        "would not be visible here.",
        "if you installed the requirements in a venv, use its interpreter:",
        "  → sudo /path/to/.venv/bin/python -m WiFiCatcher",
    ]


def _resolve(tool: Tool) -> str | None:
    """Absolute path to the tool on PATH, or None."""
    return shutil.which(tool.name)


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

        py_missing = [d for d, _ in PYTHON_DEPS if not _dist_present(d)]
        # A package missing under sudo is almost always the virtualenv being
        # dropped, not a genuine install gap — lead with that when it fits.
        venv_hint = _sudo_venv_hint() if py_missing else None
        if venv_hint:
            for line in venv_hint:
                print(_c(f"    {line}", _DIM))

        hints = sorted({t.install for t in TOOLS
                        if t.required and _resolve(t) is None and t.install})
        if py_missing:
            hints.insert(0, "pip install -r requirements.txt")
        for hint in hints:
            print(_c(f"    → {hint}", _DIM))
        return False

    print(_c("[*] all required dependencies present.", _DIM))
    return True
