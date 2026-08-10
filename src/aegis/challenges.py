"""Deterministic, bounded challenge specifications derived from sealed metadata.

This module emits declarative data only.  It never reads hidden tests and a
challenge cannot carry source code, shell commands, paths, or free-form model
instructions.  A trusted builder may later translate a variant enum into a
pre-reviewed task template.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Iterable, Mapping

from aegis.taskpacks.manifest import TaskManifest

MAX_DIFFICULTY = 5
MAX_COST_UNITS = 10_000
MAX_CHALLENGES = 16
MAX_CAPABILITY_TAGS = 24
MAX_SEED = (1 << 63) - 1

_SLUG = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class FailureCategory(StrEnum):
    BOUNDARY = "boundary"
    CONCURRENCY = "concurrency"
    INPUT_VALIDATION = "input-validation"
    NUMERIC = "numeric"
    RESOURCE = "resource"
    SECURITY = "security"
    SERIALIZATION = "serialization"
    STATE_MANAGEMENT = "state-management"


class ChallengeVariant(StrEnum):
    BASELINE_REPLAY = "baseline-replay"
    BOUNDARY_MATRIX = "boundary-matrix"
    CONCURRENCY_SCHEDULE = "concurrency-schedule"
    INVALID_INPUT_MATRIX = "invalid-input-matrix"
    NUMERIC_EXTREMES = "numeric-extremes"
    RESOURCE_PRESSURE = "resource-pressure"
    SECURITY_INVARIANTS = "security-invariants"
    SERIALIZATION_ROUNDTRIP = "serialization-roundtrip"
    STATE_SEQUENCE = "state-sequence"


_FAILURE_VARIANT: Mapping[FailureCategory, ChallengeVariant] = {
    FailureCategory.BOUNDARY: ChallengeVariant.BOUNDARY_MATRIX,
    FailureCategory.CONCURRENCY: ChallengeVariant.CONCURRENCY_SCHEDULE,
    FailureCategory.INPUT_VALIDATION: ChallengeVariant.INVALID_INPUT_MATRIX,
    FailureCategory.NUMERIC: ChallengeVariant.NUMERIC_EXTREMES,
    FailureCategory.RESOURCE: ChallengeVariant.RESOURCE_PRESSURE,
    FailureCategory.SECURITY: ChallengeVariant.SECURITY_INVARIANTS,
    FailureCategory.SERIALIZATION: ChallengeVariant.SERIALIZATION_ROUNDTRIP,
    FailureCategory.STATE_MANAGEMENT: ChallengeVariant.STATE_SEQUENCE,
}

_VARIANT_COST: Mapping[ChallengeVariant, tuple[int, int]] = {
    ChallengeVariant.BASELINE_REPLAY: (0, 0),
    ChallengeVariant.BOUNDARY_MATRIX: (1, 20),
    ChallengeVariant.CONCURRENCY_SCHEDULE: (2, 80),
    ChallengeVariant.INVALID_INPUT_MATRIX: (1, 30),
    ChallengeVariant.NUMERIC_EXTREMES: (1, 35),
    ChallengeVariant.RESOURCE_PRESSURE: (2, 100),
    ChallengeVariant.SECURITY_INVARIANTS: (2, 75),
    ChallengeVariant.SERIALIZATION_ROUNDTRIP: (1, 40),
    ChallengeVariant.STATE_SEQUENCE: (2, 60),
}


def _positive_int(value: object, name: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if not 1 <= value <= maximum:
        raise ValueError(f"{name} must be in [1, {maximum}]")
    return value


def _seed(value: object, name: str = "seed") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if not 0 <= value <= MAX_SEED:
        raise ValueError(f"{name} must be in [0, {MAX_SEED}]")
    return value


def _slug(value: object, name: str) -> str:
    if not isinstance(value, str) or not _SLUG.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase ASCII slug")
    return value


def _digest(value: object, name: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _capability_tags(values: Iterable[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise TypeError("capability_tags must be an iterable of strings")
    items = tuple(values)
    if not items or len(items) > MAX_CAPABILITY_TAGS:
        raise ValueError(f"capability_tags must contain 1..{MAX_CAPABILITY_TAGS} entries")
    validated = tuple(_slug(item, "capability tag") for item in items)
    if len(set(validated)) != len(validated):
        raise ValueError("capability_tags must be unique")
    return tuple(sorted(validated))


@dataclass(frozen=True, slots=True)
class ChallengeLimits:
    """Trusted upper bounds applied before emitting a challenge."""

    max_difficulty: int = MAX_DIFFICULTY
    max_cost_units: int = MAX_COST_UNITS

    def __post_init__(self) -> None:
        _positive_int(self.max_difficulty, "max_difficulty", MAX_DIFFICULTY)
        _positive_int(self.max_cost_units, "max_cost_units", MAX_COST_UNITS)


@dataclass(frozen=True, slots=True)
class SealedTaskMetadata:
    """Allowlisted metadata copied from a sealed task pack.

    Hidden directory names, cases, mutant identities, and reference material
    are intentionally absent from this type.
    """

    task_id: str
    version: int
    language: str
    content_hash: str
    base_difficulty: int
    base_cost_units: int
    capability_tags: tuple[str, ...]

    def __post_init__(self) -> None:
        _slug(self.task_id, "task_id")
        _positive_int(self.version, "version", 1_000_000)
        _slug(self.language, "language")
        _digest(self.content_hash, "content_hash")
        _positive_int(self.base_difficulty, "base_difficulty", MAX_DIFFICULTY)
        _positive_int(self.base_cost_units, "base_cost_units", MAX_COST_UNITS)
        if self.capability_tags != _capability_tags(self.capability_tags):
            raise ValueError("capability_tags must be in canonical order")

    @classmethod
    def from_manifest(
        cls,
        manifest: TaskManifest,
        *,
        base_difficulty: int,
        base_cost_units: int,
        capability_tags: Iterable[str],
    ) -> SealedTaskMetadata:
        if not isinstance(manifest, TaskManifest):
            raise TypeError("manifest must be a TaskManifest")
        return cls(
            task_id=manifest.task_id,
            version=manifest.version,
            language=manifest.language,
            content_hash=manifest.content_hash,
            base_difficulty=base_difficulty,
            base_cost_units=base_cost_units,
            capability_tags=_capability_tags(capability_tags),
        )

    def to_mapping(self) -> Mapping[str, Any]:
        return {
            "task_id": self.task_id,
            "version": self.version,
            "language": self.language,
            "content_hash": self.content_hash,
            "base_difficulty": self.base_difficulty,
            "base_cost_units": self.base_cost_units,
            "capability_tags": list(self.capability_tags),
        }


def _challenge_payload(
    *,
    metadata: SealedTaskMetadata,
    variant: ChallengeVariant,
    historical_failures: tuple[FailureCategory, ...],
    seed: int,
    variant_seed: int,
    difficulty: int,
    cost_units: int,
    capability_tags: tuple[str, ...],
) -> Mapping[str, Any]:
    return {
        "schema_version": 1,
        "base_task_id": metadata.task_id,
        "base_task_version": metadata.version,
        "base_content_hash": metadata.content_hash,
        "language": metadata.language,
        "variant": variant.value,
        "historical_failures": [item.value for item in historical_failures],
        "seed": seed,
        "variant_seed": variant_seed,
        "difficulty": difficulty,
        "cost_units": cost_units,
        "capability_tags": list(capability_tags),
    }


def _content_id(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return f"challenge-sha256:{hashlib.sha256(encoded).hexdigest()}"


@dataclass(frozen=True, slots=True)
class ChallengeSpec:
    """A content-addressed instruction to a trusted challenge builder."""

    challenge_id: str
    base_task_id: str
    base_task_version: int
    base_content_hash: str
    language: str
    variant: ChallengeVariant
    historical_failures: tuple[FailureCategory, ...]
    seed: int
    variant_seed: int
    difficulty: int
    cost_units: int
    capability_tags: tuple[str, ...]

    def __post_init__(self) -> None:
        _slug(self.base_task_id, "base_task_id")
        _positive_int(self.base_task_version, "base_task_version", 1_000_000)
        _digest(self.base_content_hash, "base_content_hash")
        _slug(self.language, "language")
        if not isinstance(self.variant, ChallengeVariant):
            raise TypeError("variant must be a ChallengeVariant")
        if not isinstance(self.historical_failures, tuple) or any(
            not isinstance(item, FailureCategory) for item in self.historical_failures
        ):
            raise TypeError("historical_failures must be a tuple of FailureCategory values")
        if tuple(sorted(set(self.historical_failures), key=lambda item: item.value)) != self.historical_failures:
            raise ValueError("historical_failures must be unique and canonical")
        _seed(self.seed)
        _seed(self.variant_seed, "variant_seed")
        _positive_int(self.difficulty, "difficulty", MAX_DIFFICULTY)
        _positive_int(self.cost_units, "cost_units", MAX_COST_UNITS)
        if self.capability_tags != _capability_tags(self.capability_tags):
            raise ValueError("capability_tags must be in canonical order")
        expected = _content_id(self.to_mapping(include_id=False))
        if self.challenge_id != expected:
            raise ValueError("challenge_id does not match the canonical challenge content")

    def to_mapping(self, *, include_id: bool = True) -> Mapping[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": 1,
            "base_task_id": self.base_task_id,
            "base_task_version": self.base_task_version,
            "base_content_hash": self.base_content_hash,
            "language": self.language,
            "variant": self.variant.value,
            "historical_failures": [item.value for item in self.historical_failures],
            "seed": self.seed,
            "variant_seed": self.variant_seed,
            "difficulty": self.difficulty,
            "cost_units": self.cost_units,
            "capability_tags": list(self.capability_tags),
        }
        if include_id:
            return {"challenge_id": self.challenge_id, **payload}
        return payload


def _failure_categories(values: Iterable[FailureCategory | str]) -> tuple[FailureCategory, ...]:
    if isinstance(values, (str, bytes)):
        raise TypeError("historical_failures must be an iterable")
    converted: list[FailureCategory] = []
    for value in values:
        try:
            converted.append(value if isinstance(value, FailureCategory) else FailureCategory(value))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"unknown failure category: {value!r}") from exc
    if len(set(converted)) != len(converted):
        raise ValueError("historical_failures must be unique")
    return tuple(sorted(converted, key=lambda item: item.value))


def _variant_seed(metadata: SealedTaskMetadata, seed: int, ordinal: int, variant: ChallengeVariant) -> int:
    material = (
        f"AEGIS challenge v1\0{metadata.content_hash}\0{seed}\0{ordinal}\0{variant.value}"
    ).encode("ascii")
    return int.from_bytes(hashlib.sha256(material).digest()[:8], "big") & MAX_SEED


def derive_challenges(
    metadata: SealedTaskMetadata,
    historical_failures: Iterable[FailureCategory | str],
    *,
    seed: int,
    count: int = 1,
    limits: ChallengeLimits | None = None,
) -> tuple[ChallengeSpec, ...]:
    """Derive deterministic variants without reading any sealed test material."""
    if not isinstance(metadata, SealedTaskMetadata):
        raise TypeError("metadata must be SealedTaskMetadata")
    validated_seed = _seed(seed)
    validated_count = _positive_int(count, "count", MAX_CHALLENGES)
    validated_limits = ChallengeLimits() if limits is None else limits
    if not isinstance(validated_limits, ChallengeLimits):
        raise TypeError("limits must be ChallengeLimits or None")
    if metadata.base_difficulty > validated_limits.max_difficulty:
        raise ValueError("base task difficulty exceeds the challenge limit")
    if metadata.base_cost_units > validated_limits.max_cost_units:
        raise ValueError("base task cost exceeds the challenge limit")
    failures = _failure_categories(historical_failures)
    variants = (
        {_FAILURE_VARIANT[item] for item in failures}
        if failures
        else {ChallengeVariant.BASELINE_REPLAY}
    )
    eligible = []
    for variant in variants:
        difficulty_delta, cost_delta = _VARIANT_COST[variant]
        difficulty = metadata.base_difficulty + difficulty_delta
        cost = metadata.base_cost_units + cost_delta
        if difficulty <= validated_limits.max_difficulty and cost <= validated_limits.max_cost_units:
            eligible.append((variant, difficulty, cost))
    eligible.sort(
        key=lambda item: hashlib.sha256(
            f"{metadata.content_hash}\0{validated_seed}\0{item[0].value}".encode("ascii")
        ).digest()
    )
    if not eligible:
        # The base task was already checked against the limits.  Falling back
        # to a replay is safer than silently exceeding the trusted envelope.
        eligible.append(
            (ChallengeVariant.BASELINE_REPLAY, metadata.base_difficulty, metadata.base_cost_units)
        )

    specs: list[ChallengeSpec] = []
    for ordinal in range(validated_count):
        variant, difficulty, cost = eligible[ordinal % len(eligible)]
        derived_seed = _variant_seed(metadata, validated_seed, ordinal, variant)
        tags = metadata.capability_tags
        payload = _challenge_payload(
            metadata=metadata,
            variant=variant,
            historical_failures=failures,
            seed=validated_seed,
            variant_seed=derived_seed,
            difficulty=difficulty,
            cost_units=cost,
            capability_tags=tags,
        )
        specs.append(
            ChallengeSpec(
                challenge_id=_content_id(payload),
                base_task_id=metadata.task_id,
                base_task_version=metadata.version,
                base_content_hash=metadata.content_hash,
                language=metadata.language,
                variant=variant,
                historical_failures=failures,
                seed=validated_seed,
                variant_seed=derived_seed,
                difficulty=difficulty,
                cost_units=cost,
                capability_tags=tags,
            )
        )
    return tuple(specs)
