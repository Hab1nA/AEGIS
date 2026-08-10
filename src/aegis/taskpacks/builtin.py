"""Discovery of the repository-owned, integrity-checked task packs."""

from __future__ import annotations

from pathlib import Path

from .manifest import TaskPack


def builtin_python_root() -> Path:
    """Return the source-tree location of the built-in Python task packs."""
    return Path(__file__).resolve().parents[3] / "taskpacks" / "python"


def load_builtin_python_taskpacks(root: Path | None = None) -> tuple[TaskPack, ...]:
    """Load all built-in packs in deterministic order, verifying each hash."""
    base = (root or builtin_python_root()).resolve()
    if not base.is_dir():
        raise ValueError(f"built-in task-pack directory is missing: {base}")
    pack_roots = sorted(path.parent for path in base.glob("*/manifest.json"))
    if not pack_roots:
        raise ValueError(f"no built-in task packs found under: {base}")
    packs = tuple(TaskPack.load(path) for path in pack_roots)
    identities = [(pack.manifest.task_id, pack.manifest.version) for pack in packs]
    if len(identities) != len(set(identities)):
        raise ValueError("built-in task packs contain duplicate identities")
    return packs
