"""Deterministic in-memory sandbox for controller and unit tests."""

from __future__ import annotations

import hashlib
import io
import tarfile
from collections.abc import Callable
from pathlib import Path
from typing import Any, Mapping

from .types import (
    CommandResult,
    CommandSpec,
    DoctorCheck,
    DoctorReport,
    FrozenArtifact,
    PreparedSandbox,
    SealedEvaluationResult,
    StagedArtifact,
    WorkspaceAccessRule,
    validate_staging_archive,
)


class FakeSandboxBackend:
    def __init__(
        self,
        *,
        healthy: bool = True,
        executor: Callable[[str, CommandSpec], CommandResult] | None = None,
        sealed_evaluator: Callable[[str, bytes, float], SealedEvaluationResult] | None = None,
        build_image_handler: Any = None,
        scan_image_handler: Any = None,
    ) -> None:
        self.healthy = healthy
        self.executor = executor
        self.sealed_evaluator = sealed_evaluator
        self.build_image_handler = build_image_handler
        self.scan_image_handler = scan_image_handler
        self.prepared: set[str] = set()
        self.images: dict[str, str | None] = {}
        self.frozen: set[str] = set()
        self.killed: set[str] = set()
        self.commands: list[tuple[str, CommandSpec]] = []
        self._files: dict[str, dict[str, bytes | None]] = {}
        self._frozen_archives: dict[str, bytes] = {}
        self.workspace_access: dict[str, tuple[WorkspaceAccessRule, ...]] = {}
        self.workspace_access_history: list[tuple[str, tuple[WorkspaceAccessRule, ...]]] = []

    def doctor(self) -> DoctorReport:
        return DoctorReport((DoctorCheck("fake_backend", self.healthy, "configured health"),))

    def scanner_available(self) -> bool:
        return True

    def build_image(
        self,
        recipe: Mapping[str, Any],
        *,
        dependencies: Mapping[str, bytes] | None = None,
        attempt_id: str | None = None,
        timeout_seconds: float = 1800.0,
    ) -> dict[str, Any]:
        if self.build_image_handler is not None:
            result = self.build_image_handler(recipe, dependencies, attempt_id, timeout_seconds)
            return dict(result)
        raise NotImplementedError("fake sandbox has no image builder configured")

    def scan_image(
        self, image: str, *, timeout_seconds: float = 600.0
    ) -> dict[str, Any]:
        if self.scan_image_handler is not None:
            result = self.scan_image_handler(image, timeout_seconds)
            return dict(result)
        raise NotImplementedError("fake sandbox has no image scanner configured")

    def prepare(self, sandbox_id: str, *, image: str | None = None) -> PreparedSandbox:
        self._validate_id(sandbox_id)
        if not self.doctor().passed:
            raise RuntimeError("sandbox doctor failed")
        if image is not None and (
            not isinstance(image, str)
            or "@sha256:" not in image
            or len(image.rsplit("@sha256:", 1)[1]) != 64
        ):
            raise ValueError("sandbox image must be digest-pinned")
        self.prepared.add(sandbox_id)
        self.images[sandbox_id] = image
        self._files[sandbox_id] = {}
        return PreparedSandbox(sandbox_id)

    def stage_archive(self, sandbox_id: str, archive_base64: str, expected_digest: str) -> StagedArtifact:
        self._require_runnable(sandbox_id)
        payload, members = validate_staging_archive(archive_base64, expected_digest)
        files = self._files[sandbox_id]
        incoming = {member.name for member in members}
        if incoming & files.keys():
            raise RuntimeError("staging archive would overwrite an existing path")
        # A file cannot become the parent of another staged path (or vice versa).
        all_paths = set(files) | incoming
        file_paths = {path for path, content in files.items() if content is not None}
        file_paths.update(member.name for member in members if member.isfile())
        for path in all_paths:
            parts = path.split("/")
            if any("/".join(parts[:index]) in file_paths for index in range(1, len(parts))):
                raise RuntimeError("staging archive has a file/directory collision")
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as archive:
            for member in members:
                if member.isdir():
                    files[member.name] = None
                else:
                    source = archive.extractfile(member)
                    if source is None:
                        raise RuntimeError("staging archive file cannot be read")
                    files[member.name] = source.read()
        return StagedArtifact(sandbox_id, hashlib.sha256(payload).hexdigest(), len(payload), len(members))

    def exec(self, sandbox_id: str, command: CommandSpec) -> CommandResult:
        self._require_runnable(sandbox_id)
        self.commands.append((sandbox_id, command))
        if self.executor is not None:
            return self.executor(sandbox_id, command)
        return CommandResult(0, "", "", 0.0)

    def configure_workspace_access(
        self, sandbox_id: str, writable_paths: tuple[WorkspaceAccessRule, ...]
    ) -> None:
        self._require_runnable(sandbox_id)
        if sandbox_id in self.workspace_access:
            raise RuntimeError("workspace access is already configured")
        if not isinstance(writable_paths, tuple) or any(
            not isinstance(rule, WorkspaceAccessRule) for rule in writable_paths
        ):
            raise TypeError("writable_paths must be a tuple of WorkspaceAccessRule values")
        self.workspace_access[sandbox_id] = writable_paths
        self.workspace_access_history.append((sandbox_id, writable_paths))

    def evaluate_sealed(
        self, sandbox_id: str, suite_base64: str, expected_digest: str, timeout_seconds: float
    ) -> SealedEvaluationResult:
        self._require_runnable(sandbox_id)
        payload, _ = validate_staging_archive(suite_base64, expected_digest)
        if not 0 < timeout_seconds <= 3600:
            raise ValueError("timeout_seconds must be in (0, 3600]")
        if self.sealed_evaluator is None:
            return SealedEvaluationResult(1, 1)
        return self.sealed_evaluator(sandbox_id, payload, timeout_seconds)

    def freeze(self, sandbox_id: str) -> FrozenArtifact:
        self._require_runnable(sandbox_id)
        archive = self._archive(sandbox_id)
        self._frozen_archives[sandbox_id] = archive
        self.frozen.add(sandbox_id)
        return FrozenArtifact(sandbox_id, hashlib.sha256(archive).hexdigest(), len(archive))

    def export(self, sandbox_id: str, destination: Path) -> FrozenArtifact:
        if sandbox_id not in self.frozen:
            raise RuntimeError("sandbox must be frozen before export")
        if destination.exists() and destination.is_dir():
            raise ValueError("destination must be a file path")
        if destination.exists() or not destination.parent.is_dir():
            raise ValueError("export destination must be a new file in an existing directory")
        archive = self._frozen_archives[sandbox_id]
        with destination.open("xb") as output:
            output.write(archive)
        return FrozenArtifact(sandbox_id, hashlib.sha256(archive).hexdigest(), len(archive))

    def destroy(self, sandbox_id: str) -> None:
        self.prepared.discard(sandbox_id)
        self.frozen.discard(sandbox_id)
        self._files.pop(sandbox_id, None)
        self._frozen_archives.pop(sandbox_id, None)
        self.workspace_access.pop(sandbox_id, None)

    def kill(self, sandbox_id: str) -> None:
        self.killed.add(sandbox_id)
        self.destroy(sandbox_id)

    @staticmethod
    def _validate_id(sandbox_id: str) -> None:
        if not sandbox_id or not all(char.isalnum() or char in "-_" for char in sandbox_id):
            raise ValueError("invalid sandbox id")

    def _require_runnable(self, sandbox_id: str) -> None:
        if not self.doctor().passed:
            raise RuntimeError("sandbox doctor failed; refusing execution")
        if sandbox_id not in self.prepared or sandbox_id in self.frozen:
            raise RuntimeError("sandbox is not runnable")

    def _archive(self, sandbox_id: str) -> bytes:
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as archive:
            for name, content in sorted(self._files[sandbox_id].items()):
                info = tarfile.TarInfo(name)
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mtime = 0
                if content is None:
                    info.type = tarfile.DIRTYPE
                    info.mode = 0o755
                    archive.addfile(info)
                else:
                    info.size = len(content)
                    info.mode = 0o644
                    archive.addfile(info, io.BytesIO(content))
        return output.getvalue()
