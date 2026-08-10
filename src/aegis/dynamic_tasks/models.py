"""Strict domain models for dynamically forged task packs."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from aegis.taskpacks.validation import ExecutionResult, TaskPackValidation

_ARTIFACT_ID = re.compile(r"dynamic-task-sha256:[0-9a-f]{64}\Z")
_VALIDATION_ID = re.compile(r"task-validation-sha256:[0-9a-f]{64}\Z")
_COHORT_ID = re.compile(r"dynamic-cohort-sha256:[0-9a-f]{64}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _digest_id(prefix: str, payload: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(canonical_json(payload).encode("ascii")).hexdigest()
    return f"{prefix}{digest}"


def _bounded_text(value: object, name: str, *, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or value.strip() != value or len(value) > maximum:
        raise ValueError(f"{name} must be bounded, non-empty, trimmed text")
    return value


def _positive_generation(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


class DynamicTaskOrigin(StrEnum):
    DYNAMIC = "dynamic"
    FIXED_ANCHOR = "fixed-anchor"


class DynamicTaskStatus(StrEnum):
    QUARANTINED = "quarantined"
    HOLDOUT_PASSED = "holdout-passed"
    HALL_OF_FAME = "hall-of-fame"
    FIXED_ANCHOR = "fixed-anchor"
    REJECTED = "rejected"
    RETIRED = "retired"


class CohortTier(StrEnum):
    FRESH_HOLDOUT = "fresh-holdout"
    HALL_OF_FAME = "hall-of-fame"


@dataclass(frozen=True, slots=True)
class ExecutionEvidence:
    passed: bool
    tests_run: int
    exit_code: int
    timed_out: bool
    output_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.passed, bool) or not isinstance(self.timed_out, bool):
            raise TypeError("execution flags must be bool values")
        if isinstance(self.tests_run, bool) or not isinstance(self.tests_run, int) or self.tests_run < 0:
            raise ValueError("tests_run must be a non-negative integer")
        if isinstance(self.exit_code, bool) or not isinstance(self.exit_code, int):
            raise TypeError("exit_code must be an integer")
        if not isinstance(self.output_digest, str) or len(self.output_digest) > 1024:
            raise ValueError("output_digest must be bounded text")

    @classmethod
    def from_result(cls, result: ExecutionResult) -> ExecutionEvidence:
        return cls(
            result.passed,
            result.tests_run,
            result.exit_code,
            result.timed_out,
            result.output_digest,
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> ExecutionEvidence:
        if set(value) != {"passed", "tests_run", "exit_code", "timed_out", "output_digest"}:
            raise ValueError("execution evidence has missing or unknown fields")
        return cls(
            value["passed"],
            value["tests_run"],
            value["exit_code"],
            value["timed_out"],
            value["output_digest"],
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "tests_run": self.tests_run,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "output_digest": self.output_digest,
        }


@dataclass(frozen=True, slots=True)
class DynamicTaskArtifact:
    artifact_id: str
    task_id: str
    task_version: int
    language: str
    content_hash: str
    archive_sha256: str
    size_bytes: int

    def __post_init__(self) -> None:
        if _ARTIFACT_ID.fullmatch(self.artifact_id) is None:
            raise ValueError("artifact_id must be a dynamic task content id")
        _bounded_text(self.task_id, "task_id", maximum=128)
        _positive_generation(self.task_version, "task_version")
        _bounded_text(self.language, "language", maximum=32)
        if _SHA256.fullmatch(self.content_hash) is None:
            raise ValueError("content_hash must be a lowercase SHA-256 digest")
        if _SHA256.fullmatch(self.archive_sha256) is None:
            raise ValueError("archive_sha256 must be a lowercase SHA-256 digest")
        if self.artifact_id != f"dynamic-task-sha256:{self.archive_sha256}":
            raise ValueError("artifact_id does not match archive_sha256")
        if isinstance(self.size_bytes, bool) or not isinstance(self.size_bytes, int) or self.size_bytes <= 0:
            raise ValueError("size_bytes must be a positive integer")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> DynamicTaskArtifact:
        required = {
            "artifact_id",
            "task_id",
            "task_version",
            "language",
            "content_hash",
            "archive_sha256",
            "size_bytes",
        }
        if set(value) != required:
            raise ValueError("dynamic task artifact has missing or unknown fields")
        return cls(
            value["artifact_id"],
            value["task_id"],
            value["task_version"],
            value["language"],
            value["content_hash"],
            value["archive_sha256"],
            value["size_bytes"],
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "task_id": self.task_id,
            "task_version": self.task_version,
            "language": self.language,
            "content_hash": self.content_hash,
            "archive_sha256": self.archive_sha256,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True, slots=True)
class TaskValidationEvidence:
    validation_id: str
    artifact_id: str
    valid: bool
    reasons: tuple[str, ...]
    reference_public: ExecutionEvidence
    reference_hidden: ExecutionEvidence
    defect_public: ExecutionEvidence
    defect_hidden: ExecutionEvidence
    mutant_hidden: tuple[ExecutionEvidence, ...]

    def __post_init__(self) -> None:
        if _VALIDATION_ID.fullmatch(self.validation_id) is None:
            raise ValueError("validation_id must be a task validation content id")
        if _ARTIFACT_ID.fullmatch(self.artifact_id) is None:
            raise ValueError("validation artifact_id is invalid")
        if not isinstance(self.valid, bool):
            raise TypeError("valid must be a bool")
        if any(not isinstance(reason, str) or not reason or len(reason) > 1024 for reason in self.reasons):
            raise ValueError("validation reasons must be bounded non-empty strings")
        expected = _digest_id("task-validation-sha256:", self.to_mapping(include_id=False))
        if self.validation_id != expected:
            raise ValueError("validation_id does not match validation evidence")

    @classmethod
    def from_report(
        cls, artifact_id: str, report: TaskPackValidation
    ) -> TaskValidationEvidence:
        values: dict[str, Any] = {
            "artifact_id": artifact_id,
            "valid": report.valid,
            "reasons": list(report.reasons),
            "reference_public": ExecutionEvidence.from_result(report.reference_public).to_mapping(),
            "reference_hidden": ExecutionEvidence.from_result(report.reference_hidden).to_mapping(),
            "defect_public": ExecutionEvidence.from_result(report.defect_public).to_mapping(),
            "defect_hidden": ExecutionEvidence.from_result(report.defect_hidden).to_mapping(),
            "mutant_hidden": [ExecutionEvidence.from_result(item).to_mapping() for item in report.mutant_hidden],
        }
        return cls.from_mapping(
            {"validation_id": _digest_id("task-validation-sha256:", values), **values}
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> TaskValidationEvidence:
        required = {
            "validation_id",
            "artifact_id",
            "valid",
            "reasons",
            "reference_public",
            "reference_hidden",
            "defect_public",
            "defect_hidden",
            "mutant_hidden",
        }
        if set(value) != required:
            raise ValueError("task validation evidence has missing or unknown fields")
        reasons = value["reasons"]
        mutants = value["mutant_hidden"]
        if not isinstance(reasons, list) or not isinstance(mutants, list):
            raise TypeError("validation reasons and mutant evidence must be arrays")
        executions = {
            name: value[name]
            for name in ("reference_public", "reference_hidden", "defect_public", "defect_hidden")
        }
        if any(not isinstance(item, Mapping) for item in executions.values()) or any(
            not isinstance(item, Mapping) for item in mutants
        ):
            raise TypeError("execution evidence values must be objects")
        return cls(
            value["validation_id"],
            value["artifact_id"],
            value["valid"],
            tuple(reasons),
            ExecutionEvidence.from_mapping(executions["reference_public"]),
            ExecutionEvidence.from_mapping(executions["reference_hidden"]),
            ExecutionEvidence.from_mapping(executions["defect_public"]),
            ExecutionEvidence.from_mapping(executions["defect_hidden"]),
            tuple(ExecutionEvidence.from_mapping(item) for item in mutants),
        )

    def to_mapping(self, *, include_id: bool = True) -> dict[str, Any]:
        value: dict[str, Any] = {
            "artifact_id": self.artifact_id,
            "valid": self.valid,
            "reasons": list(self.reasons),
            "reference_public": self.reference_public.to_mapping(),
            "reference_hidden": self.reference_hidden.to_mapping(),
            "defect_public": self.defect_public.to_mapping(),
            "defect_hidden": self.defect_hidden.to_mapping(),
            "mutant_hidden": [item.to_mapping() for item in self.mutant_hidden],
        }
        if include_id:
            return {"validation_id": self.validation_id, **value}
        return value


@dataclass(frozen=True, slots=True)
class DynamicTaskRecord:
    artifact: DynamicTaskArtifact
    origin: DynamicTaskOrigin
    creator_generation: int
    source_spec_id: str
    source_evidence_ids: tuple[str, ...]
    eligible_generation: int
    status: DynamicTaskStatus
    validation: TaskValidationEvidence
    revision: str

    def __post_init__(self) -> None:
        _positive_generation(self.creator_generation, "creator_generation")
        _positive_generation(self.eligible_generation, "eligible_generation")
        if self.eligible_generation <= self.creator_generation:
            raise ValueError("eligible_generation must be later than creator_generation")
        _bounded_text(self.source_spec_id, "source_spec_id")
        if not isinstance(self.source_evidence_ids, tuple):
            raise TypeError("source_evidence_ids must be a tuple")
        if tuple(sorted(set(self.source_evidence_ids))) != self.source_evidence_ids:
            raise ValueError("source_evidence_ids must be unique and canonically sorted")
        for evidence_id in self.source_evidence_ids:
            _bounded_text(evidence_id, "source_evidence_id")
        if _SHA256.fullmatch(self.revision) is None:
            raise ValueError("revision must be a lowercase SHA-256 digest")
        if self.validation.artifact_id != self.artifact.artifact_id:
            raise ValueError("validation evidence is bound to another artifact")
        if not self.validation.valid and self.status is not DynamicTaskStatus.REJECTED:
            raise ValueError("a task that failed validation must remain rejected")
        if self.origin is DynamicTaskOrigin.FIXED_ANCHOR:
            if self.status not in {DynamicTaskStatus.FIXED_ANCHOR, DynamicTaskStatus.REJECTED}:
                raise ValueError("fixed anchors cannot enter a dynamic task state")
        elif self.status is DynamicTaskStatus.FIXED_ANCHOR:
            raise ValueError("dynamic tasks cannot use the fixed-anchor status")
        elif not self.source_evidence_ids:
            raise ValueError("dynamic tasks require research source evidence")


@dataclass(frozen=True, slots=True)
class CohortMember:
    artifact_id: str
    tier: CohortTier
    creator_generation: int
    revision: str

    def __post_init__(self) -> None:
        if _ARTIFACT_ID.fullmatch(self.artifact_id) is None:
            raise ValueError("cohort artifact_id must be a dynamic task content id")
        if not isinstance(self.tier, CohortTier):
            raise TypeError("cohort tier must be a CohortTier")
        _positive_generation(self.creator_generation, "creator_generation")
        if _SHA256.fullmatch(self.revision) is None:
            raise ValueError("cohort revision must be a lowercase SHA-256 digest")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "tier": self.tier.value,
            "creator_generation": self.creator_generation,
            "revision": self.revision,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> CohortMember:
        if set(value) != {"artifact_id", "tier", "creator_generation", "revision"}:
            raise ValueError("cohort member has missing or unknown fields")
        return cls(
            value["artifact_id"],
            CohortTier(value["tier"]),
            value["creator_generation"],
            value["revision"],
        )


@dataclass(frozen=True, slots=True)
class DynamicTaskCohort:
    cohort_id: str
    target_generation: int
    members: tuple[CohortMember, ...]

    def __post_init__(self) -> None:
        if _COHORT_ID.fullmatch(self.cohort_id) is None:
            raise ValueError("cohort_id must be a dynamic cohort content id")
        _positive_generation(self.target_generation, "target_generation")
        if not isinstance(self.members, tuple) or any(
            not isinstance(member, CohortMember) for member in self.members
        ):
            raise TypeError("members must be a tuple of CohortMember values")
        if len({member.artifact_id for member in self.members}) != len(self.members):
            raise ValueError("a dynamic cohort cannot contain duplicate tasks")
        if any(member.creator_generation >= self.target_generation for member in self.members):
            raise ValueError("a dynamic cohort cannot contain same-generation tasks")
        payload = {
            "target_generation": self.target_generation,
            "members": [
                {
                    **member.to_mapping(),
                }
                for member in self.members
            ],
        }
        expected = _digest_id("dynamic-cohort-sha256:", payload)
        if self.cohort_id != expected:
            raise ValueError("cohort_id does not match cohort members")

    @classmethod
    def create(
        cls, target_generation: int, members: tuple[CohortMember, ...]
    ) -> DynamicTaskCohort:
        payload = {
            "target_generation": target_generation,
            "members": [
                {
                    **member.to_mapping(),
                }
                for member in members
            ],
        }
        return cls(
            _digest_id("dynamic-cohort-sha256:", payload),
            target_generation,
            members,
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "cohort_id": self.cohort_id,
            "target_generation": self.target_generation,
            "members": [member.to_mapping() for member in self.members],
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> DynamicTaskCohort:
        if set(value) != {"cohort_id", "target_generation", "members"}:
            raise ValueError("dynamic cohort has missing or unknown fields")
        members = value["members"]
        if not isinstance(members, list) or any(not isinstance(item, Mapping) for item in members):
            raise TypeError("dynamic cohort members must be an array of objects")
        return cls(
            value["cohort_id"],
            value["target_generation"],
            tuple(CohortMember.from_mapping(item) for item in members),
        )
