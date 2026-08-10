"""Run promoted adaptive workflows only inside a networkless canary sandbox."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from aegis.evolution_registry import VersionedCandidateArchive
from aegis.evolution_workspace import EVOLUTION_WORKFLOW_ENTRY, CandidatePatchArtifact
from aegis.models import Role
from aegis.sandbox.backend import SandboxBackend
from aegis.sandbox.types import (
    CommandResult,
    CommandSpec,
    PreparedSandbox,
    StagedArtifact,
    validate_staging_archive,
)
from aegis.strategy import StrategyError, WorkflowArtifact

MAX_CONTEXT_BYTES = 32 * 1024
MAX_OUTPUT_BYTES = 64 * 1024
MAX_JSON_DEPTH = 12
MAX_JSON_NODES = 2_048
MAX_STRING_BYTES = 8 * 1024
MAX_TIMEOUT_SECONDS = 300.0
_ID_PART = re.compile(r"[a-z0-9](?:[a-z0-9_-]{0,14}[a-z0-9])?\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_ARTIFACT_ID = re.compile(r"candidate-sha256:[0-9a-f]{64}\Z")
_WORKFLOW_ENTRY = EVOLUTION_WORKFLOW_ENTRY


class EvolutionCanaryError(RuntimeError):
    """Raised when the isolation infrastructure cannot produce valid evidence."""


def _digest(value: object, name: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _duration(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be numeric")
    result = float(value)
    if not math.isfinite(result) or not 0 <= result <= 3_600:
        raise ValueError(f"{name} must be finite and in [0, 3600]")
    return result


def _strict_context(value: object) -> tuple[str, str]:
    nodes = 0

    def validate(item: object, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise ValueError("canary context exceeds structural limits")
        if item is None or isinstance(item, bool):
            return
        if isinstance(item, int):
            return
        if isinstance(item, float):
            if not math.isfinite(item):
                raise ValueError("canary context contains a non-finite number")
            return
        if isinstance(item, str):
            if len(item.encode("utf-8")) > MAX_STRING_BYTES:
                raise ValueError("canary context contains an oversized string")
            return
        if isinstance(item, list):
            for child in item:
                validate(child, depth + 1)
            return
        if isinstance(item, Mapping):
            if len(item) > 128 or any(not isinstance(key, str) for key in item):
                raise ValueError("canary context objects require bounded string keys")
            for key, child in item.items():
                if len(key.encode("utf-8")) > 128:
                    raise ValueError("canary context contains an oversized key")
                validate(child, depth + 1)
            return
        raise TypeError("canary context must contain strict JSON values")

    if not isinstance(value, Mapping):
        raise TypeError("context must be a JSON object")
    validate(value, 0)
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    if len(encoded.encode("utf-8")) > MAX_CONTEXT_BYTES:
        raise ValueError("canary context exceeds encoded size limit")
    return encoded, hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _strict_json_output(value: str) -> object:
    def object_pairs(pairs: list[tuple[str, object]]) -> Mapping[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = item
        return result

    def reject_constant(value: str) -> object:
        raise ValueError(f"non-standard JSON constant: {value}")

    return json.loads(value, object_pairs_hook=object_pairs, parse_constant=reject_constant)


def _result_payload(
    *,
    run_id: str,
    candidate: VersionedCandidateArchive,
    role: Role,
    context_sha256: str,
    exit_code: int,
    timed_out: bool,
    stdout_sha256: str,
    stderr_sha256: str,
    stdout_bytes: int,
    stderr_bytes: int,
    reported_duration_seconds: float,
    observed_duration_seconds: float,
    passed: bool,
    failure_reason: str | None,
    workflow: WorkflowArtifact | None,
) -> Mapping[str, Any]:
    return {
        "schema_version": 1,
        "run_id": run_id,
        "candidate_version": candidate.version,
        "candidate_artifact_id": candidate.artifact_id,
        "baseline_archive_sha256": candidate.baseline_archive_sha256,
        "candidate_archive_sha256": candidate.expected_digest,
        "promotion_event_hash": candidate.promotion_event_hash,
        "role": role.value,
        "context_sha256": context_sha256,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "stdout_sha256": stdout_sha256,
        "stderr_sha256": stderr_sha256,
        "stdout_bytes": stdout_bytes,
        "stderr_bytes": stderr_bytes,
        "reported_duration_seconds": reported_duration_seconds,
        "observed_duration_seconds": observed_duration_seconds,
        "passed": passed,
        "failure_reason": failure_reason,
        "workflow": None if workflow is None else workflow.to_dict(),
    }


def _result_id(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return f"canary-sha256:{hashlib.sha256(encoded).hexdigest()}"


def _workflow_from_mapping(value: object) -> WorkflowArtifact:
    if not isinstance(value, Mapping):
        raise TypeError("workflow must be a mapping or None")
    return WorkflowArtifact.from_json(value)


_RESULT_EXPECTED_KEYS = frozenset({
    "result_id",
    "schema_version",
    "run_id",
    "candidate_version",
    "candidate_artifact_id",
    "baseline_archive_sha256",
    "candidate_archive_sha256",
    "promotion_event_hash",
    "role",
    "context_sha256",
    "exit_code",
    "timed_out",
    "stdout_sha256",
    "stderr_sha256",
    "stdout_bytes",
    "stderr_bytes",
    "reported_duration_seconds",
    "observed_duration_seconds",
    "passed",
    "failure_reason",
    "workflow",
})


@dataclass(frozen=True, slots=True)
class CanaryResult:
    result_id: str
    run_id: str
    candidate_version: int
    candidate_artifact_id: str
    baseline_archive_sha256: str
    candidate_archive_sha256: str
    promotion_event_hash: str
    role: Role
    context_sha256: str
    exit_code: int
    timed_out: bool
    stdout_sha256: str
    stderr_sha256: str
    stdout_bytes: int
    stderr_bytes: int
    reported_duration_seconds: float
    observed_duration_seconds: float
    passed: bool
    failure_reason: str | None
    workflow: WorkflowArtifact | None

    def __post_init__(self) -> None:
        if not _ID_PART.fullmatch(self.run_id):
            raise ValueError("run_id is invalid")
        if isinstance(self.candidate_version, bool) or not isinstance(self.candidate_version, int) or not (
            1 <= self.candidate_version <= 1_000_000
        ):
            raise ValueError("candidate_version is invalid")
        if not isinstance(self.candidate_artifact_id, str) or not _ARTIFACT_ID.fullmatch(
            self.candidate_artifact_id
        ):
            raise ValueError("candidate_artifact_id is invalid")
        for digest_value, name in (
            (self.baseline_archive_sha256, "baseline_archive_sha256"),
            (self.candidate_archive_sha256, "candidate_archive_sha256"),
            (self.promotion_event_hash, "promotion_event_hash"),
            (self.context_sha256, "context_sha256"),
            (self.stdout_sha256, "stdout_sha256"),
            (self.stderr_sha256, "stderr_sha256"),
        ):
            _digest(digest_value, name)
        if not isinstance(self.role, Role):
            raise TypeError("role must be Role")
        if isinstance(self.exit_code, bool) or not isinstance(self.exit_code, int):
            raise TypeError("exit_code must be an integer")
        if not isinstance(self.timed_out, bool) or not isinstance(self.passed, bool):
            raise TypeError("timed_out and passed must be bools")
        for byte_count, name in ((self.stdout_bytes, "stdout_bytes"), (self.stderr_bytes, "stderr_bytes")):
            if isinstance(byte_count, bool) or not isinstance(byte_count, int) or byte_count < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        _duration(self.reported_duration_seconds, "reported_duration_seconds")
        _duration(self.observed_duration_seconds, "observed_duration_seconds")
        allowed_reasons = {None, "nonzero-exit", "timeout", "output-limit", "invalid-json", "invalid-workflow"}
        if self.failure_reason not in allowed_reasons:
            raise ValueError("failure_reason is invalid")
        if self.passed != (self.failure_reason is None and self.workflow is not None):
            raise ValueError("passed, failure_reason, and workflow are inconsistent")
        if self.workflow is not None and not isinstance(self.workflow, WorkflowArtifact):
            raise TypeError("workflow must be WorkflowArtifact or None")
        payload = {
            "schema_version": 1,
            "run_id": self.run_id,
            "candidate_version": self.candidate_version,
            "candidate_artifact_id": self.candidate_artifact_id,
            "baseline_archive_sha256": self.baseline_archive_sha256,
            "candidate_archive_sha256": self.candidate_archive_sha256,
            "promotion_event_hash": self.promotion_event_hash,
            "role": self.role.value,
            "context_sha256": self.context_sha256,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "stdout_sha256": self.stdout_sha256,
            "stderr_sha256": self.stderr_sha256,
            "stdout_bytes": self.stdout_bytes,
            "stderr_bytes": self.stderr_bytes,
            "reported_duration_seconds": self.reported_duration_seconds,
            "observed_duration_seconds": self.observed_duration_seconds,
            "passed": self.passed,
            "failure_reason": self.failure_reason,
            "workflow": None if self.workflow is None else self.workflow.to_dict(),
        }
        if self.result_id != _result_id(payload):
            raise ValueError("result_id does not match canary evidence")

    def to_mapping(self) -> Mapping[str, Any]:
        return {
            "result_id": self.result_id,
            "schema_version": 1,
            "run_id": self.run_id,
            "candidate_version": self.candidate_version,
            "candidate_artifact_id": self.candidate_artifact_id,
            "baseline_archive_sha256": self.baseline_archive_sha256,
            "candidate_archive_sha256": self.candidate_archive_sha256,
            "promotion_event_hash": self.promotion_event_hash,
            "role": self.role.value,
            "context_sha256": self.context_sha256,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "stdout_sha256": self.stdout_sha256,
            "stderr_sha256": self.stderr_sha256,
            "stdout_bytes": self.stdout_bytes,
            "stderr_bytes": self.stderr_bytes,
            "reported_duration_seconds": self.reported_duration_seconds,
            "observed_duration_seconds": self.observed_duration_seconds,
            "passed": self.passed,
            "failure_reason": self.failure_reason,
            "workflow": None if self.workflow is None else self.workflow.to_dict(),
        }

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any]) -> CanaryResult:
        """Reconstruct a *valid* ``CanaryResult`` from a mapping produced by
        :meth:`to_mapping`.

        Rejects missing, unknown, or malformed fields.  The ``result_id``
        integrity check is deferred to the dataclass ``__post_init__`` so the
        digest is independently recomputed from the other field values.
        """
        if not isinstance(mapping, Mapping):
            raise TypeError("mapping must be a Mapping")
        if any(not isinstance(key, str) for key in mapping):
            raise ValueError("mapping keys must be strings")

        unknown = frozenset(mapping.keys()) - _RESULT_EXPECTED_KEYS
        if unknown:
            raise ValueError(f"unknown keys in mapping: {sorted(unknown)}")
        missing = _RESULT_EXPECTED_KEYS - frozenset(mapping.keys())
        if missing:
            raise ValueError(f"missing keys in mapping: {sorted(missing)}")

        if type(mapping["schema_version"]) is not int or mapping["schema_version"] != 1:
            raise ValueError("schema_version must be 1")
        string_fields = (
            "result_id",
            "run_id",
            "candidate_artifact_id",
            "baseline_archive_sha256",
            "candidate_archive_sha256",
            "promotion_event_hash",
            "role",
            "context_sha256",
            "stdout_sha256",
            "stderr_sha256",
        )
        if any(not isinstance(mapping[field], str) for field in string_fields):
            raise TypeError("canary string fields must be strings")

        try:
            role = Role(mapping["role"])
        except (ValueError, KeyError) as exc:
            raise ValueError(f"invalid role value: {mapping['role']!r}") from exc

        workflow_raw = mapping["workflow"]
        workflow: WorkflowArtifact | None
        if workflow_raw is None:
            workflow = None
        else:
            workflow = _workflow_from_mapping(workflow_raw)

        return cls(
            result_id=mapping["result_id"],
            run_id=mapping["run_id"],
            candidate_version=mapping["candidate_version"],
            candidate_artifact_id=mapping["candidate_artifact_id"],
            baseline_archive_sha256=mapping["baseline_archive_sha256"],
            candidate_archive_sha256=mapping["candidate_archive_sha256"],
            promotion_event_hash=mapping["promotion_event_hash"],
            role=role,
            context_sha256=mapping["context_sha256"],
            exit_code=mapping["exit_code"],
            timed_out=mapping["timed_out"],
            stdout_sha256=mapping["stdout_sha256"],
            stderr_sha256=mapping["stderr_sha256"],
            stdout_bytes=mapping["stdout_bytes"],
            stderr_bytes=mapping["stderr_bytes"],
            reported_duration_seconds=mapping["reported_duration_seconds"],
            observed_duration_seconds=mapping["observed_duration_seconds"],
            passed=mapping["passed"],
            failure_reason=mapping["failure_reason"],
            workflow=workflow,
        )


class EvolutionCanary:
    def __init__(
        self,
        backend: SandboxBackend,
        *,
        id_namespace: str = "evo-canary",
        timeout_seconds: float = 60.0,
        max_output_bytes: int = MAX_OUTPUT_BYTES,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if not _ID_PART.fullmatch(id_namespace):
            raise ValueError("id_namespace is invalid")
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or not (
            0 < timeout_seconds <= MAX_TIMEOUT_SECONDS
        ):
            raise ValueError(f"timeout_seconds must be in (0, {MAX_TIMEOUT_SECONDS}]")
        if (
            isinstance(max_output_bytes, bool)
            or not isinstance(max_output_bytes, int)
            or not 1 <= max_output_bytes <= MAX_OUTPUT_BYTES
        ):
            raise ValueError(f"max_output_bytes must be in [1, {MAX_OUTPUT_BYTES}]")
        self.backend = backend
        self.id_namespace = id_namespace
        self.timeout_seconds = float(timeout_seconds)
        self.max_output_bytes = max_output_bytes
        self.clock = time.monotonic if clock is None else clock

    @staticmethod
    def _validate_archive(candidate: VersionedCandidateArchive) -> None:
        if not isinstance(candidate, VersionedCandidateArchive):
            raise TypeError("candidate must be VersionedCandidateArchive")
        if isinstance(candidate.version, bool) or not isinstance(candidate.version, int) or not (
            1 <= candidate.version <= 1_000_000
        ):
            raise EvolutionCanaryError("candidate version is invalid")
        if not isinstance(candidate.artifact_id, str) or not _ARTIFACT_ID.fullmatch(candidate.artifact_id):
            raise EvolutionCanaryError("candidate artifact id is invalid")
        try:
            _digest(candidate.baseline_archive_sha256, "baseline archive digest")
            _digest(candidate.expected_digest, "candidate archive digest")
            _digest(candidate.promotion_event_hash, "promotion event hash")
            payload, members = validate_staging_archive(candidate.archive_base64, candidate.expected_digest)
        except ValueError as exc:
            raise EvolutionCanaryError("candidate archive failed strict validation") from exc
        if candidate.size_bytes != len(payload) or candidate.entries != len(members):
            raise EvolutionCanaryError("candidate archive metadata is inconsistent")
        if not any(member.isfile() and member.name == _WORKFLOW_ENTRY for member in members):
            raise EvolutionCanaryError("candidate archive lacks the fixed evolvable workflow entry")

    @staticmethod
    def _validate_receipt(
        receipt: StagedArtifact, candidate: VersionedCandidateArchive, sandbox_id: str
    ) -> None:
        if (
            receipt.sandbox_id != sandbox_id
            or receipt.digest != candidate.expected_digest
            or receipt.size_bytes != candidate.size_bytes
            or receipt.entries != candidate.entries
        ):
            raise EvolutionCanaryError("sandbox returned an invalid staging receipt")

    def run(
        self,
        candidate: VersionedCandidateArchive,
        *,
        role: Role | str,
        context: Mapping[str, Any],
        run_id: str,
    ) -> CanaryResult:
        self._validate_archive(candidate)
        try:
            validated_role = role if isinstance(role, Role) else Role(role)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid role: {role!r}") from exc
        if not _ID_PART.fullmatch(run_id):
            raise ValueError("run_id is invalid")
        context_json, context_digest = _strict_context(context)
        doctor = self.backend.doctor()
        if not doctor.passed or not any(
            check.name == "network_none" and check.passed for check in doctor.checks
        ):
            raise EvolutionCanaryError("sandbox doctor did not prove network isolation")
        sandbox_id = (
            f"{self.id_namespace}-{candidate.expected_digest[:12]}-v{candidate.version}-{run_id}"
        )
        prepared = False
        try:
            prepared_receipt = self.backend.prepare(sandbox_id)
            prepared = True
            if not isinstance(prepared_receipt, PreparedSandbox) or prepared_receipt.sandbox_id != sandbox_id:
                raise EvolutionCanaryError("sandbox returned an invalid prepare receipt")
            receipt = self.backend.stage_archive(
                sandbox_id, candidate.archive_base64, candidate.expected_digest
            )
            self._validate_receipt(receipt, candidate, sandbox_id)
            self.backend.configure_workspace_access(sandbox_id, ())
            command = CommandSpec(
                (
                    "python3",
                    "-m",
                    "aegis.evolvable.workflow",
                    "--role",
                    validated_role.value,
                ),
                cwd="src",
                stdin=context_json,
                timeout_seconds=self.timeout_seconds,
            )
            started = self.clock()
            result = self.backend.exec(sandbox_id, command)
            observed = self.clock() - started
            if not isinstance(result, CommandResult):
                raise EvolutionCanaryError("sandbox returned an invalid command result")
            if (
                isinstance(result.exit_code, bool)
                or not isinstance(result.exit_code, int)
                or not isinstance(result.stdout, str)
                or not isinstance(result.stderr, str)
                or not isinstance(result.timed_out, bool)
            ):
                raise EvolutionCanaryError("sandbox returned malformed command evidence")
            try:
                reported = _duration(result.duration_seconds, "reported duration")
                observed = _duration(observed, "observed duration")
            except (TypeError, ValueError) as exc:
                raise EvolutionCanaryError("sandbox returned invalid duration evidence") from exc
            stdout = result.stdout.encode("utf-8")
            stderr = result.stderr.encode("utf-8")
            stdout_digest = hashlib.sha256(stdout).hexdigest()
            stderr_digest = hashlib.sha256(stderr).hexdigest()
            workflow: WorkflowArtifact | None = None
            failure_reason: str | None = None
            if len(stdout) + len(stderr) > self.max_output_bytes:
                failure_reason = "output-limit"
            elif result.timed_out:
                failure_reason = "timeout"
            elif result.exit_code != 0:
                failure_reason = "nonzero-exit"
            else:
                try:
                    decoded = _strict_json_output(result.stdout)
                except (TypeError, ValueError, json.JSONDecodeError, RecursionError):
                    failure_reason = "invalid-json"
                else:
                    try:
                        workflow = WorkflowArtifact.from_json(decoded)
                    except (TypeError, ValueError, StrategyError):
                        failure_reason = "invalid-workflow"
            passed = failure_reason is None and workflow is not None
            payload = _result_payload(
                run_id=run_id,
                candidate=candidate,
                role=validated_role,
                context_sha256=context_digest,
                exit_code=result.exit_code,
                timed_out=result.timed_out,
                stdout_sha256=stdout_digest,
                stderr_sha256=stderr_digest,
                stdout_bytes=len(stdout),
                stderr_bytes=len(stderr),
                reported_duration_seconds=reported,
                observed_duration_seconds=observed,
                passed=passed,
                failure_reason=failure_reason,
                workflow=workflow,
            )
            return CanaryResult(
                result_id=_result_id(payload),
                run_id=run_id,
                candidate_version=candidate.version,
                candidate_artifact_id=candidate.artifact_id,
                baseline_archive_sha256=candidate.baseline_archive_sha256,
                candidate_archive_sha256=candidate.expected_digest,
                promotion_event_hash=candidate.promotion_event_hash,
                role=validated_role,
                context_sha256=context_digest,
                exit_code=result.exit_code,
                timed_out=result.timed_out,
                stdout_sha256=stdout_digest,
                stderr_sha256=stderr_digest,
                stdout_bytes=len(stdout),
                stderr_bytes=len(stderr),
                reported_duration_seconds=reported,
                observed_duration_seconds=observed,
                passed=passed,
                failure_reason=failure_reason,
                workflow=workflow,
            )
        finally:
            if prepared:
                try:
                    self.backend.destroy(sandbox_id)
                except Exception:
                    self.backend.kill(sandbox_id)

    def run_candidate(
        self,
        candidate: CandidatePatchArtifact,
        *,
        role: Role | str,
        context: Mapping[str, Any],
        run_id: str,
    ) -> CanaryResult:
        """Evaluate an unpromoted immutable artifact with no host execution."""
        if not isinstance(candidate, CandidatePatchArtifact):
            raise TypeError("candidate must be CandidatePatchArtifact")
        encoded = base64.b64encode(candidate.candidate_archive).decode("ascii")
        _payload, members = validate_staging_archive(encoded, candidate.candidate_archive_sha256)
        evidence_hash = hashlib.sha256(
            f"candidate-evaluation:{candidate.artifact_id}".encode("utf-8")
        ).hexdigest()
        return self.run(
            VersionedCandidateArchive(
                version=1,
                artifact_id=candidate.artifact_id,
                baseline_archive_sha256=candidate.baseline_archive_sha256,
                archive_base64=encoded,
                expected_digest=candidate.candidate_archive_sha256,
                size_bytes=len(candidate.candidate_archive),
                entries=len(members),
                promotion_event_hash=evidence_hash,
            ),
            role=role,
            context=context,
            run_id=run_id,
        )
