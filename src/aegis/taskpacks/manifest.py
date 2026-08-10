"""Task-pack layout and content integrity."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping


def _safe_relative(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"unsafe task-pack path: {value!r}")
    return path


def compute_tree_hash(root: Path, *, exclude: frozenset[str] = frozenset()) -> str:
    """Hash paths, modes and bytes in deterministic lexical order."""
    digest = hashlib.sha256()
    root = root.resolve()
    for path in sorted((p for p in root.rglob("*") if p.is_file()), key=lambda p: p.as_posix()):
        relative = path.relative_to(root).as_posix()
        if relative in exclude:
            continue
        if path.is_symlink():
            raise ValueError("task packs must not contain symbolic links")
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class TaskManifest:
    task_id: str
    version: int
    language: str
    public_dir: str
    hidden_dir: str
    reference_dir: str
    defect_dir: str
    mutant_dirs: tuple[str, ...]
    content_hash: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> TaskManifest:
        required = {
            "task_id",
            "version",
            "language",
            "public_dir",
            "hidden_dir",
            "reference_dir",
            "defect_dir",
            "mutant_dirs",
            "content_hash",
        }
        if set(data) != required:
            raise ValueError("manifest has missing or unknown fields")
        if not isinstance(data["task_id"], str) or not data["task_id"].strip():
            raise ValueError("task_id must not be empty")
        if not isinstance(data["version"], int) or data["version"] < 1:
            raise ValueError("version must be a positive integer")
        if data["language"] != "python":
            raise ValueError("v1 supports only python task packs")
        directories = [data[key] for key in ("public_dir", "hidden_dir", "reference_dir", "defect_dir")]
        if not all(isinstance(value, str) for value in directories):
            raise ValueError("task-pack directories must be strings")
        mutants = data["mutant_dirs"]
        if not isinstance(mutants, list) or not all(isinstance(value, str) for value in mutants):
            raise ValueError("mutant_dirs must be an array of strings")
        for value in [*directories, *mutants]:
            _safe_relative(value)
        if len(set([*directories, *mutants])) != len([*directories, *mutants]):
            raise ValueError("task-pack directories must be distinct")
        content_hash = data["content_hash"]
        if not isinstance(content_hash, str) or len(content_hash) != 64:
            raise ValueError("content_hash must be a SHA-256 hex digest")
        try:
            bytes.fromhex(content_hash)
        except ValueError as exc:
            raise ValueError("content_hash must be hexadecimal") from exc
        return cls(
            data["task_id"],
            data["version"],
            data["language"],
            data["public_dir"],
            data["hidden_dir"],
            data["reference_dir"],
            data["defect_dir"],
            tuple(mutants),
            content_hash.lower(),
        )


@dataclass(frozen=True, slots=True)
class TaskPack:
    root: Path
    manifest: TaskManifest

    @classmethod
    def load(cls, root: Path) -> TaskPack:
        root = root.resolve()
        manifest_path = root / "manifest.json"
        try:
            raw = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("cannot read task-pack manifest") from exc
        if not isinstance(raw, dict):
            raise ValueError("manifest must be a JSON object")
        pack = cls(root, TaskManifest.from_mapping(raw))
        pack.verify_layout()
        pack.verify_integrity()
        return pack

    def path(self, relative: str) -> Path:
        safe = _safe_relative(relative)
        candidate = self.root.joinpath(*safe.parts).resolve()
        if candidate == self.root or self.root not in candidate.parents:
            raise ValueError("task-pack path escapes root")
        return candidate

    @property
    def public_path(self) -> Path:
        return self.path(self.manifest.public_dir)

    @property
    def hidden_path(self) -> Path:
        return self.path(self.manifest.hidden_dir)

    def verify_layout(self) -> None:
        for relative in (
            self.manifest.public_dir,
            self.manifest.hidden_dir,
            self.manifest.reference_dir,
            self.manifest.defect_dir,
            *self.manifest.mutant_dirs,
        ):
            path = self.path(relative)
            if not path.is_dir() or path.is_symlink():
                raise ValueError(f"task-pack directory is missing or unsafe: {relative}")
        if self.public_path in self.hidden_path.parents or self.hidden_path in self.public_path.parents:
            raise ValueError("public and hidden directories must not be nested")

    def verify_integrity(self) -> None:
        actual = compute_tree_hash(self.root, exclude=frozenset({"manifest.json"}))
        if actual != self.manifest.content_hash:
            raise ValueError("task-pack content hash mismatch")
