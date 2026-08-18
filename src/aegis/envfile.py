"""Project-scoped environment loading for AEGIS runs.

The AEGIS model relay credentials live in a git-ignored ``.aegis.env`` file
next to the repository root, so they never leak into machine-wide or user-wide
environment variables and never affect other tools (including Codex itself).
Explicit process environment always wins over the file, and the loader is
dependency-free (no dotenv import).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Mapping, MutableMapping

_ENV_FILE = ".aegis.env"
_RELAY_KEYS = frozenset(
    {
        "AEGIS_OPENAI_BASE_URL",
        "AEGIS_OPENAI_API_KEY",
        "AEGIS_OPENAI_USER_AGENT",
        "AEGIS_OPENAI_TIMEOUT_SECONDS",
    }
)


def _parse_line(line: str) -> tuple[str, str] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    if "=" not in stripped:
        return None
    key, _, value = stripped.partition("=")
    key = key.strip()
    value = value.strip()
    if not key:
        return None
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    return key, value


def load_aegis_env(
    *,
    cwd: Path | None = None,
    env: MutableMapping[str, str] | None = None,
) -> int:
    """Apply relay keys from ``.aegis.env`` with ``setdefault`` semantics.

    Returns the number of keys applied.  Keys already present in ``env``
    (including the process environment) are never overwritten, so an operator
    can still override the project file for a single run.
    """
    target = os.environ if env is None else env
    root = (cwd or Path.cwd()).resolve()
    candidate = root / _ENV_FILE
    if not candidate.is_file():
        return 0
    applied = 0
    for line in candidate.read_text(encoding="utf-8").splitlines():
        parsed = _parse_line(line)
        if parsed is None:
            continue
        key, value = parsed
        if key not in _RELAY_KEYS:
            continue
        if key not in target or not str(target.get(key, "")).strip():
            target[key] = value
            applied += 1
    return applied


def relay_env(cwd: Path | None = None) -> Mapping[str, str]:
    """Return the effective relay environment after applying ``.aegis.env``."""
    loaded = dict(os.environ)
    load_aegis_env(cwd=cwd, env=loaded)
    return loaded


__all__ = ["load_aegis_env", "relay_env"]
