"""Backend contract; implementations are untrusted execution adapters."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Protocol, runtime_checkable

from .types import (
    CommandResult,
    CommandSpec,
    DoctorReport,
    FrozenArtifact,
    PreparedSandbox,
    SealedEvaluationResult,
    StagedArtifact,
    WorkspaceAccessRule,
)


@runtime_checkable
class SandboxBackend(Protocol):
    def doctor(self) -> DoctorReport: ...

    def scanner_available(self) -> bool: ...

    def build_image(
        self,
        recipe: Mapping[str, Any],
        *,
        dependencies: Mapping[str, bytes] | None = None,
        attempt_id: str | None = None,
        timeout_seconds: float = 1800.0,
    ) -> dict[str, Any]: ...

    def scan_image(
        self, image: str, *, timeout_seconds: float = 600.0
    ) -> dict[str, Any]: ...

    def prepare(
        self, sandbox_id: str, *, image: str | None = None
    ) -> PreparedSandbox: ...

    def stage_archive(self, sandbox_id: str, archive_base64: str, expected_digest: str) -> StagedArtifact: ...

    def configure_workspace_access(
        self, sandbox_id: str, writable_paths: tuple[WorkspaceAccessRule, ...]
    ) -> None: ...

    def exec(self, sandbox_id: str, command: CommandSpec) -> CommandResult: ...

    def evaluate_sealed(
        self, sandbox_id: str, suite_base64: str, expected_digest: str, timeout_seconds: float
    ) -> SealedEvaluationResult: ...

    def freeze(self, sandbox_id: str) -> FrozenArtifact: ...

    def export(self, sandbox_id: str, destination: Path) -> FrozenArtifact: ...

    def destroy(self, sandbox_id: str) -> None: ...

    def kill(self, sandbox_id: str) -> None: ...
