"""Fail-closed validation of self-modification candidates in disposable sandboxes."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from aegis.evolution_workspace import CandidatePatchArtifact, EvolutionPolicy, ValidationCommand
from aegis.sandbox.backend import SandboxBackend
from aegis.sandbox.types import CommandResult, FrozenArtifact, StagedArtifact, validate_staging_archive

MAX_OUTPUT_BYTES = 64 * 1024
MAX_DURATION_SECONDS = 3_600.0
MAX_TOTAL_DURATION_SECONDS = 16 * MAX_DURATION_SECONDS
_ID_PART = re.compile(r"[a-z0-9](?:[a-z0-9_-]{0,14}[a-z0-9])?\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class EvolutionValidationError(RuntimeError):
    """Raised when validation infrastructure cannot produce trustworthy evidence."""


def _digest(value: object, name: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _bounded_duration(value: object, name: str, maximum: float = MAX_DURATION_SECONDS) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be numeric")
    result = float(value)
    if not math.isfinite(result) or not 0 <= result <= maximum:
        raise ValueError(f"{name} must be finite and in [0, {maximum}]")
    return result


def _command_payload(command: ValidationCommand) -> Mapping[str, Any]:
    return {
        "argv": list(command.argv),
        "cwd": command.cwd,
        "timeout_seconds": command.timeout_seconds,
    }


def _command_digest(command: ValidationCommand) -> str:
    encoded = json.dumps(_command_payload(command), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class CommandValidationEvidence:
    index: int
    command_sha256: str
    result_sha256: str
    exit_code: int
    timed_out: bool
    reported_duration_seconds: float
    observed_duration_seconds: float
    stdout_sha256: str
    stderr_sha256: str
    stdout_bytes: int
    stderr_bytes: int
    output_within_limit: bool

    def __post_init__(self) -> None:
        if isinstance(self.index, bool) or not isinstance(self.index, int) or self.index < 0:
            raise ValueError("index must be a non-negative integer")
        for digest_value, name in (
            (self.command_sha256, "command_sha256"),
            (self.result_sha256, "result_sha256"),
            (self.stdout_sha256, "stdout_sha256"),
            (self.stderr_sha256, "stderr_sha256"),
        ):
            _digest(digest_value, name)
        if isinstance(self.exit_code, bool) or not isinstance(self.exit_code, int):
            raise TypeError("exit_code must be an integer")
        if not isinstance(self.timed_out, bool) or not isinstance(self.output_within_limit, bool):
            raise TypeError("timed_out and output_within_limit must be bools")
        _bounded_duration(self.reported_duration_seconds, "reported_duration_seconds")
        _bounded_duration(self.observed_duration_seconds, "observed_duration_seconds")
        for byte_count, name in ((self.stdout_bytes, "stdout_bytes"), (self.stderr_bytes, "stderr_bytes")):
            if isinstance(byte_count, bool) or not isinstance(byte_count, int) or byte_count < 0:
                raise ValueError(f"{name} must be a non-negative integer")


def _command_evidence_payload(item: CommandValidationEvidence) -> Mapping[str, Any]:
    return {
        "index": item.index,
        "command_sha256": item.command_sha256,
        "result_sha256": item.result_sha256,
        "exit_code": item.exit_code,
        "timed_out": item.timed_out,
        "reported_duration_seconds": item.reported_duration_seconds,
        "observed_duration_seconds": item.observed_duration_seconds,
        "stdout_sha256": item.stdout_sha256,
        "stderr_sha256": item.stderr_sha256,
        "stdout_bytes": item.stdout_bytes,
        "stderr_bytes": item.stderr_bytes,
        "output_within_limit": item.output_within_limit,
    }


def _evidence_payload(
    *,
    validation_id: str,
    candidate_artifact_id: str,
    baseline_sha256: str,
    candidate_sha256: str,
    pristine_frozen_sha256: str,
    post_validation_frozen_sha256: str,
    commands: tuple[CommandValidationEvidence, ...],
    passed: bool,
    failure_reason: str | None,
    workspace_mutated: bool,
    total_observed_seconds: float,
) -> Mapping[str, Any]:
    return {
        "schema_version": 1,
        "validation_id": validation_id,
        "candidate_artifact_id": candidate_artifact_id,
        "baseline_archive_sha256": baseline_sha256,
        "candidate_archive_sha256": candidate_sha256,
        "pristine_frozen_sha256": pristine_frozen_sha256,
        "post_validation_frozen_sha256": post_validation_frozen_sha256,
        "commands": [_command_evidence_payload(item) for item in commands],
        "passed": passed,
        "failure_reason": failure_reason,
        "workspace_mutated": workspace_mutated,
        "total_observed_seconds": total_observed_seconds,
    }


def _evidence_id(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return f"validation-sha256:{hashlib.sha256(encoded).hexdigest()}"


@dataclass(frozen=True, slots=True)
class ValidationEvidence:
    evidence_id: str
    validation_id: str
    candidate_artifact_id: str
    baseline_archive_sha256: str
    candidate_archive_sha256: str
    pristine_frozen_sha256: str
    post_validation_frozen_sha256: str
    commands: tuple[CommandValidationEvidence, ...]
    passed: bool
    failure_reason: str | None
    workspace_mutated: bool
    total_observed_seconds: float

    def __post_init__(self) -> None:
        if not _ID_PART.fullmatch(self.validation_id):
            raise ValueError("validation_id is invalid")
        if not self.candidate_artifact_id.startswith("candidate-sha256:"):
            raise ValueError("candidate_artifact_id is invalid")
        _digest(self.candidate_artifact_id.removeprefix("candidate-sha256:"), "candidate artifact digest")
        for value, name in (
            (self.baseline_archive_sha256, "baseline_archive_sha256"),
            (self.candidate_archive_sha256, "candidate_archive_sha256"),
            (self.pristine_frozen_sha256, "pristine_frozen_sha256"),
            (self.post_validation_frozen_sha256, "post_validation_frozen_sha256"),
        ):
            _digest(value, name)
        if not isinstance(self.commands, tuple) or any(
            not isinstance(item, CommandValidationEvidence) for item in self.commands
        ):
            raise TypeError("commands must be a tuple of CommandValidationEvidence")
        if tuple(item.index for item in self.commands) != tuple(range(len(self.commands))):
            raise ValueError("commands must have contiguous ordered indexes")
        if not isinstance(self.passed, bool) or not isinstance(self.workspace_mutated, bool):
            raise TypeError("passed and workspace_mutated must be bools")
        if self.passed != (self.failure_reason is None):
            raise ValueError("passed and failure_reason are inconsistent")
        if self.failure_reason not in {None, "nonzero-exit", "timeout", "output-limit"}:
            raise ValueError("failure_reason is invalid")
        _bounded_duration(
            self.total_observed_seconds,
            "total_observed_seconds",
            MAX_TOTAL_DURATION_SECONDS,
        )
        payload = _evidence_payload(
            validation_id=self.validation_id,
            candidate_artifact_id=self.candidate_artifact_id,
            baseline_sha256=self.baseline_archive_sha256,
            candidate_sha256=self.candidate_archive_sha256,
            pristine_frozen_sha256=self.pristine_frozen_sha256,
            post_validation_frozen_sha256=self.post_validation_frozen_sha256,
            commands=self.commands,
            passed=self.passed,
            failure_reason=self.failure_reason,
            workspace_mutated=self.workspace_mutated,
            total_observed_seconds=self.total_observed_seconds,
        )
        if self.evidence_id != _evidence_id(payload):
            raise ValueError("evidence_id does not match validation content")

    def to_mapping(self) -> Mapping[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            **_evidence_payload(
                validation_id=self.validation_id,
                candidate_artifact_id=self.candidate_artifact_id,
                baseline_sha256=self.baseline_archive_sha256,
                candidate_sha256=self.candidate_archive_sha256,
                pristine_frozen_sha256=self.pristine_frozen_sha256,
                post_validation_frozen_sha256=self.post_validation_frozen_sha256,
                commands=self.commands,
                passed=self.passed,
                failure_reason=self.failure_reason,
                workspace_mutated=self.workspace_mutated,
                total_observed_seconds=self.total_observed_seconds,
            ),
        }


class EvolutionValidator:
    """Validate a candidate using only SandboxBackend operations."""

    def __init__(
        self,
        backend: SandboxBackend,
        *,
        id_namespace: str = "evo-validation",
        max_output_bytes: int = MAX_OUTPUT_BYTES,
        policy: EvolutionPolicy | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if not _ID_PART.fullmatch(id_namespace):
            raise ValueError("id_namespace is invalid")
        if (
            isinstance(max_output_bytes, bool)
            or not isinstance(max_output_bytes, int)
            or not 1 <= max_output_bytes <= MAX_OUTPUT_BYTES
        ):
            raise ValueError(f"max_output_bytes must be in [1, {MAX_OUTPUT_BYTES}]")
        self.backend = backend
        self.id_namespace = id_namespace
        self.max_output_bytes = max_output_bytes
        self.policy = EvolutionPolicy() if policy is None else policy
        if not isinstance(self.policy, EvolutionPolicy):
            raise TypeError("policy must be EvolutionPolicy or None")
        self.clock = time.monotonic if clock is None else clock

    @staticmethod
    def _validate_receipt(
        receipt: StagedArtifact,
        sandbox_id: str,
        artifact: CandidatePatchArtifact,
        entries: int,
    ) -> None:
        if (
            receipt.sandbox_id != sandbox_id
            or receipt.digest != artifact.candidate_archive_sha256
            or receipt.size_bytes != len(artifact.candidate_archive)
            or receipt.entries != entries
        ):
            raise EvolutionValidationError("sandbox returned an invalid staging receipt")

    @staticmethod
    def _validate_frozen(receipt: FrozenArtifact, sandbox_id: str) -> str:
        try:
            digest = _digest(receipt.digest, "frozen digest")
        except ValueError as exc:
            raise EvolutionValidationError("sandbox returned an invalid freeze receipt") from exc
        if (
            receipt.sandbox_id != sandbox_id
            or isinstance(receipt.size_bytes, bool)
            or not isinstance(receipt.size_bytes, int)
            or receipt.size_bytes < 0
        ):
            raise EvolutionValidationError("sandbox returned an invalid freeze receipt")
        return digest

    def _stage(self, sandbox_id: str, artifact: CandidatePatchArtifact, entries: int) -> None:
        receipt = self.backend.stage_archive(
            sandbox_id,
            base64.b64encode(artifact.candidate_archive).decode("ascii"),
            artifact.candidate_archive_sha256,
        )
        self._validate_receipt(receipt, sandbox_id, artifact, entries)
        self.backend.configure_workspace_access(
            sandbox_id,
            self.policy.workspace_access_rules(),
        )

    def _command_evidence(
        self,
        index: int,
        command: ValidationCommand,
        result: CommandResult,
        observed: float,
    ) -> CommandValidationEvidence:
        if not isinstance(result, CommandResult):
            raise EvolutionValidationError("sandbox returned an invalid command result")
        if not isinstance(result.stdout, str) or not isinstance(result.stderr, str):
            raise EvolutionValidationError("sandbox returned non-text command output")
        if isinstance(result.exit_code, bool) or not isinstance(result.exit_code, int):
            raise EvolutionValidationError("sandbox returned an invalid exit code")
        if not isinstance(result.timed_out, bool):
            raise EvolutionValidationError("sandbox returned an invalid timeout flag")
        try:
            reported = _bounded_duration(result.duration_seconds, "reported duration")
            observed = _bounded_duration(observed, "observed duration")
        except (TypeError, ValueError) as exc:
            raise EvolutionValidationError("sandbox returned invalid duration evidence") from exc
        stdout = result.stdout.encode("utf-8")
        stderr = result.stderr.encode("utf-8")
        stdout_digest = hashlib.sha256(stdout).hexdigest()
        stderr_digest = hashlib.sha256(stderr).hexdigest()
        within_limit = len(stdout) + len(stderr) <= self.max_output_bytes
        result_payload = {
            "exit_code": result.exit_code,
            "timed_out": result.timed_out,
            "reported_duration_seconds": reported,
            "observed_duration_seconds": observed,
            "stdout_sha256": stdout_digest,
            "stderr_sha256": stderr_digest,
            "stdout_bytes": len(stdout),
            "stderr_bytes": len(stderr),
            "output_within_limit": within_limit,
        }
        result_digest = hashlib.sha256(
            json.dumps(result_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return CommandValidationEvidence(
            index=index,
            command_sha256=_command_digest(command),
            result_sha256=result_digest,
            exit_code=result.exit_code,
            timed_out=result.timed_out,
            reported_duration_seconds=reported,
            observed_duration_seconds=observed,
            stdout_sha256=stdout_digest,
            stderr_sha256=stderr_digest,
            stdout_bytes=len(stdout),
            stderr_bytes=len(stderr),
            output_within_limit=within_limit,
        )

    def validate(self, artifact: CandidatePatchArtifact, *, validation_id: str) -> ValidationEvidence:
        if not isinstance(artifact, CandidatePatchArtifact):
            raise TypeError("artifact must be CandidatePatchArtifact")
        if not _ID_PART.fullmatch(validation_id):
            raise ValueError("validation_id is invalid")
        if not artifact.validation_commands:
            raise EvolutionValidationError("candidate has no validation commands")
        report = self.backend.doctor()
        if not report.passed or not any(check.name == "network_none" and check.passed for check in report.checks):
            raise EvolutionValidationError("sandbox doctor did not prove network isolation")
        try:
            _, members = validate_staging_archive(
                base64.b64encode(artifact.candidate_archive).decode("ascii"),
                artifact.candidate_archive_sha256,
            )
        except ValueError as exc:
            raise EvolutionValidationError("candidate archive is invalid") from exc

        suffix = artifact.candidate_archive_sha256[:12]
        pristine_id = f"{self.id_namespace}-{suffix}-{validation_id}-p"
        execution_id = f"{self.id_namespace}-{suffix}-{validation_id}-x"
        prepared: list[str] = []
        try:
            self.backend.prepare(pristine_id)
            prepared.append(pristine_id)
            self._stage(pristine_id, artifact, len(members))
            pristine_digest = self._validate_frozen(self.backend.freeze(pristine_id), pristine_id)

            self.backend.prepare(execution_id)
            prepared.append(execution_id)
            self._stage(execution_id, artifact, len(members))
            command_evidence: list[CommandValidationEvidence] = []
            failure_reason: str | None = None
            total_observed = 0.0
            for index, command in enumerate(artifact.validation_commands):
                started = self.clock()
                result = self.backend.exec(execution_id, command.to_command_spec())
                observed = self.clock() - started
                item = self._command_evidence(index, command, result, observed)
                command_evidence.append(item)
                total_observed += item.observed_duration_seconds
                if not item.output_within_limit:
                    failure_reason = "output-limit"
                elif item.timed_out:
                    failure_reason = "timeout"
                elif item.exit_code != 0:
                    failure_reason = "nonzero-exit"
                if failure_reason is not None:
                    break
            post_digest = self._validate_frozen(self.backend.freeze(execution_id), execution_id)
            commands = tuple(command_evidence)
            passed = failure_reason is None and len(commands) == len(artifact.validation_commands)
            total_observed = _bounded_duration(
                total_observed,
                "total observed duration",
                MAX_TOTAL_DURATION_SECONDS,
            )
            payload = _evidence_payload(
                validation_id=validation_id,
                candidate_artifact_id=artifact.artifact_id,
                baseline_sha256=artifact.baseline_archive_sha256,
                candidate_sha256=artifact.candidate_archive_sha256,
                pristine_frozen_sha256=pristine_digest,
                post_validation_frozen_sha256=post_digest,
                commands=commands,
                passed=passed,
                failure_reason=failure_reason,
                workspace_mutated=post_digest != pristine_digest,
                total_observed_seconds=total_observed,
            )
            return ValidationEvidence(
                evidence_id=_evidence_id(payload),
                validation_id=validation_id,
                candidate_artifact_id=artifact.artifact_id,
                baseline_archive_sha256=artifact.baseline_archive_sha256,
                candidate_archive_sha256=artifact.candidate_archive_sha256,
                pristine_frozen_sha256=pristine_digest,
                post_validation_frozen_sha256=post_digest,
                commands=commands,
                passed=passed,
                failure_reason=failure_reason,
                workspace_mutated=post_digest != pristine_digest,
                total_observed_seconds=total_observed,
            )
        finally:
            for sandbox_id in reversed(prepared):
                try:
                    self.backend.destroy(sandbox_id)
                except Exception:
                    self.backend.kill(sandbox_id)
