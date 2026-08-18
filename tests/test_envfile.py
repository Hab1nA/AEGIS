"""Tests for the project-scoped AEGIS relay environment loader."""

from __future__ import annotations

import tempfile
from pathlib import Path

from aegis.envfile import load_aegis_env


def _write_env(root: Path, text: str) -> Path:
    target = root / ".aegis.env"
    target.write_text(text, encoding="utf-8")
    return target


def test_loader_applies_relay_keys_from_project_file() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        _write_env(
            root,
            "# comment\n"
            "AEGIS_OPENAI_BASE_URL=https://opencode.ai/zen/go/v1\n"
            "AEGIS_OPENAI_API_KEY=sk-project-key\n"
            "AEGIS_OPENAI_TIMEOUT_SECONDS=120\n",
        )
        env: dict[str, str] = {}
        applied = load_aegis_env(cwd=root, env=env)
        assert applied == 3
        assert env["AEGIS_OPENAI_BASE_URL"] == "https://opencode.ai/zen/go/v1"
        assert env["AEGIS_OPENAI_API_KEY"] == "sk-project-key"
        assert env["AEGIS_OPENAI_TIMEOUT_SECONDS"] == "120"


def test_loader_never_overrides_explicit_environment() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        _write_env(
            root,
            "AEGIS_OPENAI_BASE_URL=https://opencode.ai/zen/go/v1\n"
            "AEGIS_OPENAI_API_KEY=sk-file\n",
        )
        env = {"AEGIS_OPENAI_API_KEY": "sk-explicit"}
        applied = load_aegis_env(cwd=root, env=env)
        assert applied == 1
        assert env["AEGIS_OPENAI_API_KEY"] == "sk-explicit"
        assert env["AEGIS_OPENAI_BASE_URL"] == "https://opencode.ai/zen/go/v1"


def test_loader_ignores_unknown_keys_quotes_and_blank_lines() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        _write_env(
            root,
            "\n"
            "# leading comment\n"
            'AEGIS_OPENAI_BASE_URL = "https://opencode.ai/zen/go/v1"\n'
            "SOME_OTHER_KEY=value\n"
            "MALFORMED_LINE\n",
        )
        env: dict[str, str] = {}
        applied = load_aegis_env(cwd=root, env=env)
        assert applied == 1
        assert env["AEGIS_OPENAI_BASE_URL"] == "https://opencode.ai/zen/go/v1"
        assert "SOME_OTHER_KEY" not in env


def test_loader_missing_file_is_noop() -> None:
    with tempfile.TemporaryDirectory() as directory:
        env: dict[str, str] = {}
        assert load_aegis_env(cwd=Path(directory), env=env) == 0
        assert env == {}
