"""Tests for the startup preflight dependency checks."""

from __future__ import annotations

from pathlib import Path

import pytest

from WiFiCatcher import preflight


def _force_system_python(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the interpreter look like a non-venv (system) Python."""
    monkeypatch.setattr(preflight.sys, "base_prefix", preflight.sys.prefix)


def _force_venv_python(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the interpreter look like it is running inside a virtualenv."""
    monkeypatch.setattr(preflight.sys, "base_prefix", preflight.sys.prefix + "/base")


def test_sudo_venv_hint_none_without_sudo(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SUDO_USER", raising=False)
    _force_system_python(monkeypatch)
    assert preflight._sudo_venv_hint() is None


def test_sudo_venv_hint_none_inside_venv(monkeypatch: pytest.MonkeyPatch) -> None:
    # Under sudo but already in a venv: sudo preserved the environment, no hint.
    monkeypatch.setenv("SUDO_USER", "tester")
    _force_venv_python(monkeypatch)
    assert preflight._sudo_venv_hint() is None


def test_sudo_venv_hint_points_at_discovered_venv(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SUDO_USER", "tester")
    _force_system_python(monkeypatch)
    venv_py = tmp_path / ".venv" / "bin" / "python"
    monkeypatch.setattr(preflight, "_find_project_venv", lambda: venv_py)

    hint = preflight._sudo_venv_hint()
    assert hint is not None
    joined = "\n".join(hint)
    assert "sudo" in joined
    assert str(venv_py) in joined


def test_sudo_venv_hint_generic_when_no_venv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SUDO_USER", "tester")
    _force_system_python(monkeypatch)
    monkeypatch.setattr(preflight, "_find_project_venv", lambda: None)

    hint = preflight._sudo_venv_hint()
    assert hint is not None
    assert any(".venv/bin/python" in line for line in hint)


def test_find_project_venv_discovers_dot_venv(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    py = tmp_path / ".venv" / "bin" / "python"
    py.parent.mkdir(parents=True)
    py.write_text("")  # stand-in interpreter
    monkeypatch.chdir(tmp_path)
    assert preflight._find_project_venv() == py
