"""Self-contained types used at the sandbox trust boundary."""

from __future__ import annotations

import base64
import hashlib
import io
import tarfile
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Mapping

MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_EXPANDED_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 4096


def _validate_relative_path(value: str, field_name: str) -> None:
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or "\\" in value or "\x00" in value:
        raise ValueError(f"{field_name} must be a safe POSIX relative path")


@dataclass(frozen=True, slots=True)
class WorkspaceAccessRule:
    """A workspace file or subtree that may be written by sandboxed code."""

    path: str
    recursive: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.path, str) or not self.path or self.path in {".", "./"}:
            raise ValueError("workspace access path must be a non-empty relative path")
        _validate_relative_path(self.path, "workspace access path")
        if PurePosixPath(self.path).as_posix() != self.path or any(
            part in {"", "."} for part in PurePosixPath(self.path).parts
        ):
            raise ValueError("workspace access path must be canonical")
        if not isinstance(self.recursive, bool):
            raise TypeError("recursive must be a bool")


@dataclass(frozen=True, slots=True)
class CommandSpec:
    argv: tuple[str, ...]
    cwd: str = "."
    env: Mapping[str, str] = field(default_factory=dict)
    stdin: str | None = None
    timeout_seconds: float = 60.0

    def __post_init__(self) -> None:
        if not self.argv or any(not isinstance(arg, str) or "\x00" in arg for arg in self.argv):
            raise ValueError("argv must contain non-NUL strings")
        _validate_relative_path(self.cwd, "cwd")
        if not 0 < self.timeout_seconds <= 3600:
            raise ValueError("timeout_seconds must be in (0, 3600]")
        if any(not isinstance(key, str) or not isinstance(value, str) for key, value in self.env.items()):
            raise TypeError("environment keys and values must be strings")


@dataclass(frozen=True, slots=True)
class CommandResult:
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    name: str
    passed: bool
    detail: str = ""


@dataclass(frozen=True, slots=True)
class DoctorReport:
    checks: tuple[DoctorCheck, ...]

    @property
    def passed(self) -> bool:
        return bool(self.checks) and all(check.passed for check in self.checks)

    def failed_names(self) -> tuple[str, ...]:
        return tuple(check.name for check in self.checks if not check.passed)


@dataclass(frozen=True, slots=True)
class PreparedSandbox:
    sandbox_id: str


@dataclass(frozen=True, slots=True)
class FrozenArtifact:
    sandbox_id: str
    digest: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class StagedArtifact:
    sandbox_id: str
    digest: str
    size_bytes: int
    entries: int


@dataclass(frozen=True, slots=True)
class SealedEvaluationResult:
    passed: int
    total: int
    failures: tuple[str, ...] = ()
    timed_out: bool = False
    safety_violations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.total < 1 or self.passed < 0 or self.passed > self.total:
            raise ValueError("invalid sealed evaluation counts")


def validate_staging_archive(
    archive_base64: str,
    expected_digest: str,
    *,
    max_archive_bytes: int = MAX_ARCHIVE_BYTES,
    max_expanded_bytes: int = MAX_EXPANDED_BYTES,
    max_entries: int = MAX_ARCHIVE_ENTRIES,
) -> tuple[bytes, tuple[tarfile.TarInfo, ...]]:
    """Decode and validate a tar before it crosses into a workspace.

    Extraction is deliberately left to the backend so it can use exclusive
    filesystem operations.  Only plain files and directories are accepted.
    """
    if not isinstance(archive_base64, str) or len(archive_base64) > ((max_archive_bytes + 2) // 3) * 4 + 4:
        raise ValueError("staging archive exceeds compressed size limit")
    if not isinstance(expected_digest, str) or len(expected_digest) != 64:
        raise ValueError("expected digest must be a SHA-256 digest")
    try:
        bytes.fromhex(expected_digest)
        payload = base64.b64decode(archive_base64, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("staging archive or digest is invalid") from exc
    if len(payload) > max_archive_bytes:
        raise ValueError("staging archive exceeds compressed size limit")
    if hashlib.sha256(payload).hexdigest() != expected_digest.lower():
        raise ValueError("staging archive digest mismatch")
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as archive:
            members = tuple(archive.getmembers())
    except (tarfile.TarError, OSError) as exc:
        raise ValueError("staging payload is not a valid tar archive") from exc
    if len(members) > max_entries:
        raise ValueError("staging archive has too many entries")
    expanded = 0
    seen: set[str] = set()
    for member in members:
        raw = member.name
        path = PurePosixPath(raw)
        if (
            not raw
            or raw in {".", "./"}
            or path.is_absolute()
            or ".." in path.parts
            or "\\" in raw
            or "\x00" in raw
            or any(part in {"", "."} for part in path.parts)
        ):
            raise ValueError(f"unsafe staging path: {raw!r}")
        normalized = path.as_posix()
        if normalized in seen:
            raise ValueError(f"duplicate staging path: {normalized}")
        seen.add(normalized)
        if not (member.isfile() or member.isdir()):
            raise ValueError(f"unsupported staging entry type: {normalized}")
        if member.size < 0:
            raise ValueError("staging entry has invalid size")
        expanded += member.size
        if expanded > max_expanded_bytes:
            raise ValueError("staging archive exceeds expanded size limit")
    return payload, members
