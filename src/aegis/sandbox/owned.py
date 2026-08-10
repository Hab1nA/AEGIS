"""Durable ownership wrapper for campaign-created sandboxes."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from .backend import SandboxBackend
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


class OwnedSandboxBackend:
    """Record prepare intent before crossing the backend crash boundary."""

    def __init__(self, backend: SandboxBackend, event_sink: Callable[[str, dict[str, Any]], None]) -> None:
        self._backend = backend
        self._event_sink = event_sink

    def doctor(self) -> DoctorReport:
        return self._backend.doctor()

    def prepare(self, sandbox_id: str) -> PreparedSandbox:
        self._event_sink("sandbox_prepare_intent", {"sandbox_id": sandbox_id})
        try:
            result = self._backend.prepare(sandbox_id)
        except Exception as exc:
            self._event_sink(
                "sandbox_prepare_failed",
                {
                    "sandbox_id": sandbox_id,
                    "type": type(exc).__name__,
                    "message": str(exc),
                },
            )
            raise
        self._event_sink("sandbox_prepared", {"sandbox_id": sandbox_id})
        return result

    def destroy(self, sandbox_id: str) -> None:
        self._cleanup("destroy", sandbox_id, self._backend.destroy)

    def kill(self, sandbox_id: str) -> None:
        self._cleanup("kill", sandbox_id, self._backend.kill)

    def _cleanup(self, action: str, sandbox_id: str, operation: Callable[[str], None]) -> None:
        try:
            operation(sandbox_id)
        except Exception as exc:
            self._event_sink(
                "sandbox_cleanup_failed",
                {
                    "sandbox_id": sandbox_id,
                    "action": action,
                    "type": type(exc).__name__,
                    "message": str(exc),
                },
            )
            raise
        self._event_sink(
            "sandbox_killed" if action == "kill" else "sandbox_destroyed",
            {"sandbox_id": sandbox_id},
        )

    def stage_archive(self, sandbox_id: str, archive_base64: str, expected_digest: str) -> StagedArtifact:
        return self._backend.stage_archive(sandbox_id, archive_base64, expected_digest)

    def configure_workspace_access(
        self, sandbox_id: str, writable_paths: tuple[WorkspaceAccessRule, ...]
    ) -> None:
        self._backend.configure_workspace_access(sandbox_id, writable_paths)

    def exec(self, sandbox_id: str, command: CommandSpec) -> CommandResult:
        return self._backend.exec(sandbox_id, command)

    def evaluate_sealed(
        self, sandbox_id: str, archive_base64: str, expected_digest: str, timeout_seconds: float
    ) -> SealedEvaluationResult:
        return self._backend.evaluate_sealed(sandbox_id, archive_base64, expected_digest, timeout_seconds)

    def freeze(self, sandbox_id: str) -> FrozenArtifact:
        return self._backend.freeze(sandbox_id)

    def export(self, sandbox_id: str, destination: Path) -> FrozenArtifact:
        return self._backend.export(sandbox_id, destination)
