"""Sandbox backends and their security-oriented value objects."""

from .backend import SandboxBackend
from .fake import FakeSandboxBackend
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
)
from .wsl import WslSandboxBackend

__all__ = [
    "CommandResult",
    "CommandSpec",
    "DoctorCheck",
    "DoctorReport",
    "FakeSandboxBackend",
    "FrozenArtifact",
    "PreparedSandbox",
    "SandboxBackend",
    "SealedEvaluationResult",
    "StagedArtifact",
    "WslSandboxBackend",
    "WorkspaceAccessRule",
]
