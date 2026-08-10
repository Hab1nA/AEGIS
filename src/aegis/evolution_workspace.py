"""Trusted construction and inspection of isolated self-evolution workspaces.

Candidate code crosses the host boundary only as validated tar bytes.  This
module never executes candidate code and never writes candidate files back to
the repository.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import json
import os
import stat
import tarfile
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from aegis.sandbox.backend import SandboxBackend
from aegis.sandbox.types import (
    CommandSpec,
    FrozenArtifact,
    StagedArtifact,
    WorkspaceAccessRule,
    validate_staging_archive,
)

MAX_FILES = 1_024
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
MAX_VALIDATION_COMMANDS = 16


def _relative_path(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ValueError(f"{name} must be a safe POSIX relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"{name} must be a safe POSIX relative path")
    normalized = path.as_posix()
    if normalized != value:
        raise ValueError(f"{name} must be canonical")
    return normalized


@dataclass(frozen=True, slots=True)
class EvolutionPath:
    """An exact file or a recursively evolvable directory."""

    path: str
    recursive: bool = False

    def __post_init__(self) -> None:
        normalized = _relative_path(self.path, "evolution path")
        if normalized != self.path:
            raise ValueError("evolution path must be canonical")
        if not isinstance(self.recursive, bool):
            raise TypeError("recursive must be a bool")

    def permits(self, candidate: str) -> bool:
        return candidate == self.path or (self.recursive and candidate.startswith(self.path + "/"))


EVOLUTION_WORKFLOW_ENTRY = "src/aegis/evolvable/workflow.py"


# The production canary consumes one fixed, pure-JSON workflow ABI.  Helpers
# below this capability layer may evolve with that entry point, but the
# candidate must still modify the fixed entry so inert or disconnected code
# cannot become a capability candidate.
DEFAULT_EVOLVABLE_PATHS = (
    EvolutionPath("src/aegis/evolvable", recursive=True),
)

DEFAULT_READ_ONLY_CONTEXT_PATHS = (
    EvolutionPath("pyproject.toml"),
    EvolutionPath("README.md"),
    EvolutionPath("src/aegis", recursive=True),
    EvolutionPath("taskpacks", recursive=True),
    EvolutionPath("tests", recursive=True),
)

DEFAULT_CONTEXT_EXCLUDED_PATHS = (
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tmp",
    ".venv",
    ".vscode",
    "build",
    "configs/campaign.local.json",
    "dist",
    "htmlcov",
)

PROTECTED_CONTROL_PLANE_PATHS = (
    "src/aegis/agent_runtime.py",
    "src/aegis/budget.py",
    "src/aegis/cli.py",
    "src/aegis/config.py",
    "src/aegis/evaluation",
    "src/aegis/event_store.py",
    "src/aegis/execution_lock.py",
    "src/aegis/gateway",
    "src/aegis/models.py",
    "src/aegis/orchestrator.py",
    "src/aegis/promotion_runtime.py",
    "src/aegis/sandbox",
    "src/aegis/state_machine.py",
    "src/aegis/taskpacks",
    "src/aegis/research/http.py",
    "src/aegis/research/imports.py",
    "src/aegis/research/interfaces.py",
    "src/aegis/research/runtime_imports.py",
    "src/aegis/research/searxng.py",
    "src/aegis/research/url_security.py",
    "configs",
    "deploy",
)

_SENSITIVE_TASKPACK_COMPONENTS = frozenset({"defect", "hidden", "mutants", "reference"})


def _is_at_or_below(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(prefix + "/")


def _is_sensitive_taskpack_context(path: str) -> bool:
    parts = PurePosixPath(path).parts
    if not parts or parts[0] != "taskpacks":
        return False
    return (
        any(part in _SENSITIVE_TASKPACK_COMPONENTS for part in parts[1:])
        or parts[-1].endswith(".validation.json")
    )


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _validate_digest(value: object, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or value.lower() != value:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be hexadecimal") from exc
    return value


@dataclass(frozen=True, slots=True)
class ValidationCommand:
    """An argv-only command intended exclusively for execution in a sandbox."""

    argv: tuple[str, ...]
    cwd: str = "."
    timeout_seconds: float = 300.0

    def __post_init__(self) -> None:
        if not isinstance(self.argv, tuple) or not self.argv or any(
            not isinstance(item, str) or not item or "\x00" in item for item in self.argv
        ):
            raise ValueError("argv must be a non-empty tuple of non-empty, non-NUL strings")
        if (
            len(self.argv) > 32
            or sum(len(item.encode("utf-8")) for item in self.argv) > 4_096
        ):
            raise ValueError("argv must be a bounded tuple")
        if self.cwd != ".":
            _relative_path(self.cwd, "validation cwd")
        if isinstance(self.timeout_seconds, bool) or not isinstance(self.timeout_seconds, (int, float)):
            raise TypeError("timeout_seconds must be numeric")
        # Reuse the established sandbox boundary validation and disallow env or
        # stdin so this manifest cannot smuggle host-specific state.
        CommandSpec(self.argv, cwd=self.cwd, timeout_seconds=self.timeout_seconds)

    def to_command_spec(self) -> CommandSpec:
        return CommandSpec(self.argv, cwd=self.cwd, timeout_seconds=self.timeout_seconds)


@dataclass(frozen=True, slots=True)
class EvolutionPolicy:
    evolvable_paths: tuple[EvolutionPath, ...] = DEFAULT_EVOLVABLE_PATHS
    required_effective_paths: tuple[str, ...] = (EVOLUTION_WORKFLOW_ENTRY,)
    read_only_context_paths: tuple[EvolutionPath, ...] = DEFAULT_READ_ONLY_CONTEXT_PATHS
    protected_paths: tuple[str, ...] = PROTECTED_CONTROL_PLANE_PATHS
    include_repository_context: bool = True
    context_excluded_paths: tuple[str, ...] = DEFAULT_CONTEXT_EXCLUDED_PATHS
    max_files: int = MAX_FILES
    max_file_bytes: int = MAX_FILE_BYTES
    max_total_bytes: int = MAX_TOTAL_BYTES
    validation_commands: tuple[ValidationCommand, ...] = (
        ValidationCommand(
            (
                "python",
                "-B",
                "-m",
                "pytest",
                "-q",
                "-p",
                "no:cacheprovider",
                "--ignore=tests/test_builtin_taskpacks.py",
            ),
            timeout_seconds=900.0,
        ),
    )

    def __post_init__(self) -> None:
        if not self.evolvable_paths or any(not isinstance(item, EvolutionPath) for item in self.evolvable_paths):
            raise ValueError("evolvable_paths must be a non-empty tuple of EvolutionPath values")
        if len({item.path for item in self.evolvable_paths}) != len(self.evolvable_paths):
            raise ValueError("evolvable_paths must be unique")
        effective = tuple(
            _relative_path(item, "required effective path") for item in self.required_effective_paths
        )
        if effective != self.required_effective_paths or len(set(effective)) != len(effective):
            raise ValueError("required_effective_paths must be unique and canonical")
        if any(not self.permits(item) for item in effective):
            raise ValueError("required_effective_paths must be permitted evolvable paths")
        if not isinstance(self.read_only_context_paths, tuple) or any(
            not isinstance(item, EvolutionPath) for item in self.read_only_context_paths
        ):
            raise ValueError("read_only_context_paths must be a tuple of EvolutionPath values")
        if len({item.path for item in self.read_only_context_paths}) != len(self.read_only_context_paths):
            raise ValueError("read_only_context_paths must be unique")
        protected = tuple(_relative_path(item, "protected path") for item in self.protected_paths)
        if protected != self.protected_paths or len(set(protected)) != len(protected):
            raise ValueError("protected_paths must be unique and canonical")
        if not isinstance(self.include_repository_context, bool):
            raise TypeError("include_repository_context must be a bool")
        excluded = tuple(_relative_path(item, "context excluded path") for item in self.context_excluded_paths)
        if excluded != self.context_excluded_paths or len(set(excluded)) != len(excluded):
            raise ValueError("context_excluded_paths must be unique and canonical")
        for allowed in self.evolvable_paths:
            for denied in excluded:
                if _is_at_or_below(allowed.path, denied) or (
                    allowed.recursive and _is_at_or_below(denied, allowed.path)
                ):
                    raise ValueError(f"evolvable path overlaps excluded context: {allowed.path}")
        for allowed in self.evolvable_paths:
            for denied in protected:
                if _is_at_or_below(allowed.path, denied) or (allowed.recursive and _is_at_or_below(denied, allowed.path)):
                    raise ValueError(f"evolvable path overlaps protected control plane: {allowed.path}")
        for value, name, maximum in (
            (self.max_files, "max_files", MAX_FILES),
            (self.max_file_bytes, "max_file_bytes", MAX_FILE_BYTES),
            (self.max_total_bytes, "max_total_bytes", MAX_TOTAL_BYTES),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
                raise ValueError(f"{name} must be an integer in [1, {maximum}]")
        if self.max_file_bytes > self.max_total_bytes:
            raise ValueError("max_file_bytes cannot exceed max_total_bytes")
        if (
            not isinstance(self.validation_commands, tuple)
            or len(self.validation_commands) > MAX_VALIDATION_COMMANDS
            or any(not isinstance(item, ValidationCommand) for item in self.validation_commands)
        ):
            raise ValueError("validation_commands must be a bounded tuple")

    def permits(self, path: str) -> bool:
        normalized = _relative_path(path, "candidate path")
        if any(_is_at_or_below(normalized, denied) for denied in self.protected_paths):
            return False
        return any(rule.permits(normalized) for rule in self.evolvable_paths)

    def includes_context(self, path: str) -> bool:
        normalized = _relative_path(path, "context path")
        if self.excludes_context(normalized):
            return False
        return (
            self.permits(normalized)
            or self.include_repository_context
            or any(rule.permits(normalized) for rule in self.read_only_context_paths)
        )

    def permits_container(self, path: str) -> bool:
        normalized = _relative_path(path, "container path")
        if self.excludes_context(normalized):
            return False
        if self.include_repository_context:
            return True
        rules = (*self.evolvable_paths, *self.read_only_context_paths)
        return self.includes_context(normalized) or any(
            rule.path.startswith(normalized + "/") for rule in rules
        )

    def excludes_context(self, path: str) -> bool:
        normalized = _relative_path(path, "context path")
        return _is_sensitive_taskpack_context(normalized) or any(
            _is_at_or_below(normalized, denied) for denied in self.context_excluded_paths
        )

    def workspace_access_rules(self) -> tuple[WorkspaceAccessRule, ...]:
        return tuple(
            WorkspaceAccessRule(item.path, item.recursive)
            for item in sorted(self.evolvable_paths, key=lambda rule: (rule.path, rule.recursive))
        )


@dataclass(frozen=True, slots=True)
class FileDigest:
    path: str
    sha256: str
    size_bytes: int

    def __post_init__(self) -> None:
        _relative_path(self.path, "file path")
        _validate_digest(self.sha256, "sha256")
        if isinstance(self.size_bytes, bool) or not isinstance(self.size_bytes, int) or self.size_bytes < 0:
            raise ValueError("size_bytes must be a non-negative integer")


@dataclass(frozen=True, slots=True)
class WorkspaceSnapshot:
    archive: bytes
    archive_sha256: str
    files: tuple[FileDigest, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.archive, bytes):
            raise TypeError("archive must be bytes")
        if _sha256(self.archive) != self.archive_sha256:
            raise ValueError("archive_sha256 does not match archive bytes")
        if tuple(sorted(self.files, key=lambda item: item.path)) != self.files:
            raise ValueError("files must be in canonical path order")
        if len({item.path for item in self.files}) != len(self.files):
            raise ValueError("files must have unique paths")


class ChangeKind(StrEnum):
    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"


@dataclass(frozen=True, slots=True)
class CandidateFileChange:
    path: str
    kind: ChangeKind
    baseline_sha256: str | None
    candidate_sha256: str | None
    candidate_size_bytes: int

    def __post_init__(self) -> None:
        _relative_path(self.path, "change path")
        if not isinstance(self.kind, ChangeKind):
            raise TypeError("kind must be ChangeKind")
        for digest in (self.baseline_sha256, self.candidate_sha256):
            if digest is not None:
                _validate_digest(digest, "change digest")
        if self.kind is ChangeKind.ADDED and (self.baseline_sha256 is not None or self.candidate_sha256 is None):
            raise ValueError("added change has invalid digests")
        if self.kind is ChangeKind.MODIFIED and (
            self.baseline_sha256 is None
            or self.candidate_sha256 is None
            or self.baseline_sha256 == self.candidate_sha256
        ):
            raise ValueError("modified change has invalid digests")
        if self.kind is ChangeKind.DELETED and (
            self.baseline_sha256 is None or self.candidate_sha256 is not None or self.candidate_size_bytes != 0
        ):
            raise ValueError("deleted change has invalid digests")
        if (
            isinstance(self.candidate_size_bytes, bool)
            or not isinstance(self.candidate_size_bytes, int)
            or self.candidate_size_bytes < 0
            or self.candidate_size_bytes > MAX_FILE_BYTES
        ):
            raise ValueError("candidate_size_bytes must be non-negative")


def _command_mapping(command: ValidationCommand) -> Mapping[str, Any]:
    return {
        "argv": list(command.argv),
        "cwd": command.cwd,
        "timeout_seconds": command.timeout_seconds,
    }


def _change_mapping(change: CandidateFileChange) -> Mapping[str, Any]:
    return {
        "path": change.path,
        "kind": change.kind.value,
        "baseline_sha256": change.baseline_sha256,
        "candidate_sha256": change.candidate_sha256,
        "candidate_size_bytes": change.candidate_size_bytes,
    }


def _artifact_payload(
    baseline_sha256: str,
    candidate_sha256: str,
    changes: tuple[CandidateFileChange, ...],
    commands: tuple[ValidationCommand, ...],
) -> Mapping[str, Any]:
    return {
        "schema_version": 1,
        "baseline_archive_sha256": baseline_sha256,
        "candidate_archive_sha256": candidate_sha256,
        "changes": [_change_mapping(item) for item in changes],
        "validation_commands": [_command_mapping(item) for item in commands],
    }


def _artifact_id(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return f"candidate-sha256:{_sha256(encoded)}"


@dataclass(frozen=True, slots=True)
class CandidatePatchArtifact:
    artifact_id: str
    baseline_archive_sha256: str
    candidate_archive: bytes
    candidate_archive_sha256: str
    changes: tuple[CandidateFileChange, ...]
    validation_commands: tuple[ValidationCommand, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.candidate_archive, bytes):
            raise TypeError("candidate_archive must be bytes")
        if _sha256(self.candidate_archive) != self.candidate_archive_sha256:
            raise ValueError("candidate archive digest mismatch")
        _validate_digest(self.baseline_archive_sha256, "baseline_archive_sha256")
        _validate_digest(self.candidate_archive_sha256, "candidate_archive_sha256")
        if tuple(sorted(self.changes, key=lambda item: item.path)) != self.changes:
            raise ValueError("changes must be in canonical path order")
        payload = _artifact_payload(
            self.baseline_archive_sha256,
            self.candidate_archive_sha256,
            self.changes,
            self.validation_commands,
        )
        if self.artifact_id != _artifact_id(payload):
            raise ValueError("artifact_id does not match candidate content")

    def to_mapping(self) -> Mapping[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            **_artifact_payload(
                self.baseline_archive_sha256,
                self.candidate_archive_sha256,
                self.changes,
                self.validation_commands,
            ),
        }


class EvolutionWorkspace:
    """Build and inspect candidate workspaces without applying them to the host."""

    def __init__(self, repository_root: Path, policy: EvolutionPolicy | None = None) -> None:
        root = repository_root.resolve()
        if not root.is_dir():
            raise ValueError("repository_root must be an existing directory")
        self.root = root
        self.policy = EvolutionPolicy() if policy is None else policy
        if not isinstance(self.policy, EvolutionPolicy):
            raise TypeError("policy must be EvolutionPolicy or None")

    def _read_files(self) -> Mapping[str, bytes]:
        files: dict[str, bytes] = {}
        ignored_directory_names = frozenset({"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"})

        def reject_symlink_ancestors(path: Path) -> None:
            relative = path.relative_to(self.root)
            current = self.root
            for part in relative.parts:
                current /= part
                if current.is_symlink():
                    raise ValueError(
                        f"symlink is forbidden in evolution workspace: {current.relative_to(self.root).as_posix()}"
                    )

        def visit(path: Path) -> None:
            relative = path.relative_to(self.root).as_posix()
            if relative != "." and self.policy.excludes_context(relative):
                return
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                raise ValueError(f"symlink is forbidden in evolution workspace: {relative}")
            if stat.S_ISDIR(mode):
                if path.name in ignored_directory_names:
                    return
                with os.scandir(path) as entries:
                    children = sorted((Path(entry.path) for entry in entries), key=lambda item: item.name)
                for child in children:
                    visit(child)
                return
            if not stat.S_ISREG(mode):
                raise ValueError(f"non-regular file is forbidden in evolution workspace: {relative}")
            if path.suffix in {".pyc", ".pyo"}:
                return
            if not self.policy.includes_context(relative):
                raise ValueError(f"file is outside evolution context policy: {relative}")
            size = path.stat(follow_symlinks=False).st_size
            if size > self.policy.max_file_bytes:
                raise ValueError(f"evolution context file exceeds size limit: {relative}")
            content = path.read_bytes()
            if len(content) != size:
                raise RuntimeError(f"evolution context file changed while snapshotting: {relative}")
            files[relative] = content

        if self.policy.include_repository_context:
            visit(self.root)
        else:
            rules = (*self.policy.evolvable_paths, *self.policy.read_only_context_paths)
            for rule in rules:
                target = self.root.joinpath(*PurePosixPath(rule.path).parts)
                if not target.exists() and not target.is_symlink():
                    continue
                reject_symlink_ancestors(target)
                if rule.recursive:
                    visit(target)
                else:
                    mode = target.lstat().st_mode
                    if not stat.S_ISREG(mode):
                        raise ValueError(f"exact evolution context path must be a regular file: {rule.path}")
                    visit(target)
        if len(files) > self.policy.max_files:
            raise ValueError("evolution workspace exceeds file count limit")
        if sum(len(content) for content in files.values()) > self.policy.max_total_bytes:
            raise ValueError("evolution workspace exceeds total size limit")
        return files

    @staticmethod
    def _archive(files: Mapping[str, bytes]) -> bytes:
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w", format=tarfile.GNU_FORMAT) as archive:
            for path, content in sorted(files.items()):
                info = tarfile.TarInfo(path)
                info.size = len(content)
                info.mode = 0o644
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mtime = 0
                archive.addfile(info, io.BytesIO(content))
        return output.getvalue()

    def create_snapshot(self) -> WorkspaceSnapshot:
        files = self._read_files()
        archive = self._archive(files)
        if len(archive) > MAX_TOTAL_BYTES:
            raise ValueError("evolution snapshot archive exceeds size limit")
        digests = tuple(FileDigest(path, _sha256(content), len(content)) for path, content in sorted(files.items()))
        return WorkspaceSnapshot(archive, _sha256(archive), digests)

    def snapshot_from_archive(
        self,
        archive: bytes | str,
        expected_digest: str,
    ) -> WorkspaceSnapshot:
        """Rebuild a baseline snapshot from an immutable sandbox archive.

        The archive remains opaque host data: it is validated and read in
        memory only, never extracted into the repository.
        """
        _validate_digest(expected_digest, "expected_digest")
        if isinstance(archive, str):
            try:
                archive_bytes = base64.b64decode(archive, validate=True)
            except (ValueError, binascii.Error) as exc:
                raise ValueError("archive must be valid base64") from exc
        elif isinstance(archive, bytes):
            archive_bytes = archive
        else:
            raise TypeError("archive must be bytes or base64 text")
        if _sha256(archive_bytes) != expected_digest:
            raise ValueError("archive digest does not match expected_digest")
        files = self._candidate_files(archive_bytes)
        digests = tuple(
            FileDigest(path, _sha256(content), len(content))
            for path, content in sorted(files.items())
        )
        return WorkspaceSnapshot(archive_bytes, expected_digest, digests)

    def stage_snapshot(
        self,
        backend: SandboxBackend,
        sandbox_id: str,
        snapshot: WorkspaceSnapshot,
    ) -> StagedArtifact:
        if not isinstance(snapshot, WorkspaceSnapshot):
            raise TypeError("snapshot must be WorkspaceSnapshot")
        encoded = base64.b64encode(snapshot.archive).decode("ascii")
        _, members = validate_staging_archive(
            encoded,
            snapshot.archive_sha256,
            max_archive_bytes=MAX_TOTAL_BYTES,
            max_expanded_bytes=self.policy.max_total_bytes,
            max_entries=self.policy.max_files * 2,
        )
        receipt = backend.stage_archive(
            sandbox_id,
            encoded,
            snapshot.archive_sha256,
        )
        if (
            receipt.sandbox_id != sandbox_id
            or receipt.digest != snapshot.archive_sha256
            or receipt.size_bytes != len(snapshot.archive)
            or receipt.entries != len(members)
        ):
            raise RuntimeError("sandbox returned an invalid evolution staging receipt")
        backend.configure_workspace_access(sandbox_id, self.policy.workspace_access_rules())
        return receipt

    def _candidate_files(self, archive: bytes) -> Mapping[str, bytes]:
        if not isinstance(archive, bytes) or len(archive) > MAX_TOTAL_BYTES:
            raise ValueError("candidate archive exceeds size limit")
        digest = _sha256(archive)
        _, members = validate_staging_archive(
            base64.b64encode(archive).decode("ascii"),
            digest,
            max_archive_bytes=MAX_TOTAL_BYTES,
            max_expanded_bytes=self.policy.max_total_bytes,
            max_entries=self.policy.max_files * 2,
        )
        files: dict[str, bytes] = {}
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:*") as candidate:
            for member in members:
                path = PurePosixPath(member.name).as_posix()
                if member.isdir():
                    if not self.policy.permits_container(path):
                        raise ValueError(f"candidate contains a directory outside the evolution context: {path}")
                    continue
                if not self.policy.includes_context(path):
                    raise ValueError(f"candidate contains a file outside the evolution context: {path}")
                if member.size > self.policy.max_file_bytes:
                    raise ValueError(f"candidate file exceeds size limit: {path}")
                source = candidate.extractfile(member)
                if source is None:
                    raise ValueError(f"candidate file cannot be read: {path}")
                content = source.read(self.policy.max_file_bytes + 1)
                if len(content) != member.size:
                    raise ValueError(f"candidate file size mismatch: {path}")
                files[path] = content
        if len(files) > self.policy.max_files:
            raise ValueError("candidate exceeds file count limit")
        return files

    def candidate_from_archive(
        self,
        baseline: WorkspaceSnapshot,
        candidate_archive: bytes,
        *,
        receipt: FrozenArtifact | None = None,
    ) -> CandidatePatchArtifact:
        if not isinstance(baseline, WorkspaceSnapshot):
            raise TypeError("baseline must be WorkspaceSnapshot")
        candidate_digest = _sha256(candidate_archive)
        if receipt is not None and (
            receipt.digest != candidate_digest or receipt.size_bytes != len(candidate_archive)
        ):
            raise RuntimeError("sandbox export receipt does not match candidate archive")
        candidate_files = self._candidate_files(candidate_archive)
        baseline_files = {item.path: item for item in baseline.files}
        changes: list[CandidateFileChange] = []
        for path in sorted(set(baseline_files) | set(candidate_files)):
            before = baseline_files.get(path)
            after = candidate_files.get(path)
            after_digest = None if after is None else _sha256(after)
            if not self.policy.permits(path):
                if before is None:
                    raise ValueError(f"candidate added a non-evolvable file: {path}")
                if after is None:
                    raise ValueError(f"candidate deleted read-only context: {path}")
                if before.sha256 != after_digest:
                    raise ValueError(f"candidate modified read-only context: {path}")
                continue
            if before is None and after is not None:
                changes.append(CandidateFileChange(path, ChangeKind.ADDED, None, after_digest, len(after)))
            elif before is not None and after is None:
                changes.append(CandidateFileChange(path, ChangeKind.DELETED, before.sha256, None, 0))
            elif before is not None and after is not None and before.sha256 != after_digest:
                changes.append(
                    CandidateFileChange(path, ChangeKind.MODIFIED, before.sha256, after_digest, len(after))
                )
        canonical_changes = tuple(changes)
        by_path = {item.path: item for item in canonical_changes}
        missing_effective = [
            path
            for path in self.policy.required_effective_paths
            if path not in by_path or by_path[path].kind is ChangeKind.DELETED
        ]
        if missing_effective:
            raise ValueError(
                "candidate did not modify required effective path(s): "
                + ", ".join(missing_effective)
            )
        payload = _artifact_payload(
            baseline.archive_sha256,
            candidate_digest,
            canonical_changes,
            self.policy.validation_commands,
        )
        return CandidatePatchArtifact(
            artifact_id=_artifact_id(payload),
            baseline_archive_sha256=baseline.archive_sha256,
            candidate_archive=candidate_archive,
            candidate_archive_sha256=candidate_digest,
            changes=canonical_changes,
            validation_commands=self.policy.validation_commands,
        )

    def collect_candidate(
        self,
        backend: SandboxBackend,
        sandbox_id: str,
        baseline: WorkspaceSnapshot,
        destination: Path,
    ) -> CandidatePatchArtifact:
        """Freeze/export a candidate archive; never execute or apply it on the host."""
        resolved_destination = destination.resolve(strict=False)
        if resolved_destination == self.root or self.root in resolved_destination.parents:
            raise ValueError("candidate export destination must be outside the host repository")
        backend.freeze(sandbox_id)
        receipt = backend.export(sandbox_id, destination)
        archive = destination.read_bytes()
        return self.candidate_from_archive(baseline, archive, receipt=receipt)
