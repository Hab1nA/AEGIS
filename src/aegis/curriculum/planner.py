"""Content-addressed curriculum hypotheses and deterministic cohort planning."""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from typing import Any, ClassVar, Mapping, Sequence

from aegis.models import canonical_json

SCHEMA_VERSION = 2


class CurriculumPlanningError(ValueError):
    """Raised when frozen evidence cannot produce a policy-compliant cohort."""


def _text(value: object, name: str, *, maximum: int = 1024) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError(f"{name} must be bounded, trimmed, non-empty text")
    return value


def _positive_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _non_negative_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


def _unit_float(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be numeric")
    normalized = float(value)
    if not math.isfinite(normalized) or not 0.0 <= normalized <= 1.0:
        raise ValueError(f"{name} must be finite and in [0,1]")
    return normalized


def _text_tuple(
    value: object, name: str, *, allow_empty: bool = False, canonical: bool = True
) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        raise TypeError(f"{name} must be a tuple")
    if not value and not allow_empty:
        raise ValueError(f"{name} must not be empty")
    for item in value:
        _text(item, f"{name}[]")
    if len(set(value)) != len(value):
        raise ValueError(f"{name} must not contain duplicates")
    if canonical and tuple(sorted(value)) != value:
        raise ValueError(f"{name} must be in canonical order")
    return value


def _content_id(prefix: str, payload: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    return f"{prefix}{digest}"


def _strict(value: object, fields: set[str], name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise TypeError(f"{name} must be a string-keyed mapping")
    if set(value) != fields:
        raise ValueError(f"{name} has missing or unknown fields")
    if type(value["schema_version"]) is not int or value["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"{name}.schema_version must be {SCHEMA_VERSION}")
    return value


def _array(value: object, name: str) -> tuple[Any, ...]:
    if not isinstance(value, (list, tuple)):
        raise TypeError(f"{name} must be an array")
    return tuple(value)


@dataclass(frozen=True, slots=True)
class CapabilityGap:
    """Frozen evidence that one capability deserves curriculum attention."""

    ID_PREFIX: ClassVar[str] = "capability-gap-sha256:"

    capability: str
    evidence_cycle: int
    evidence_ids: tuple[str, ...]
    counter_evidence_ids: tuple[str, ...]
    severity: float
    expected_gain: float
    estimated_cost_units: int
    stop_conditions: tuple[str, ...]
    priority: float
    uncertainty: float
    consecutive_failures: int = 0
    last_targeted_cycle: int | None = None
    gap_id: str = field(init=False)

    def __post_init__(self) -> None:
        _text(self.capability, "capability", maximum=128)
        _positive_int(self.evidence_cycle, "evidence_cycle")
        _text_tuple(self.evidence_ids, "evidence_ids")
        _text_tuple(
            self.counter_evidence_ids, "counter_evidence_ids", allow_empty=True
        )
        object.__setattr__(self, "severity", _unit_float(self.severity, "severity"))
        object.__setattr__(
            self, "expected_gain", _unit_float(self.expected_gain, "expected_gain")
        )
        _non_negative_int(self.estimated_cost_units, "estimated_cost_units")
        _text_tuple(self.stop_conditions, "stop_conditions", canonical=False)
        object.__setattr__(self, "priority", _unit_float(self.priority, "priority"))
        object.__setattr__(
            self, "uncertainty", _unit_float(self.uncertainty, "uncertainty")
        )
        _non_negative_int(self.consecutive_failures, "consecutive_failures")
        if self.last_targeted_cycle is not None:
            _positive_int(self.last_targeted_cycle, "last_targeted_cycle")
            if self.last_targeted_cycle > self.evidence_cycle:
                raise ValueError("last_targeted_cycle cannot exceed evidence_cycle")
        object.__setattr__(self, "gap_id", _content_id(self.ID_PREFIX, self._payload()))

    def _payload(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "capability": self.capability,
            "evidence_cycle": self.evidence_cycle,
            "evidence_ids": list(self.evidence_ids),
            "counter_evidence_ids": list(self.counter_evidence_ids),
            "severity": self.severity,
            "expected_gain": self.expected_gain,
            "estimated_cost_units": self.estimated_cost_units,
            "stop_conditions": list(self.stop_conditions),
            "priority": self.priority,
            "uncertainty": self.uncertainty,
            "consecutive_failures": self.consecutive_failures,
            "last_targeted_cycle": self.last_targeted_cycle,
        }

    def to_mapping(self) -> dict[str, Any]:
        return {"gap_id": self.gap_id, **self._payload()}

    @classmethod
    def from_mapping(cls, value: object) -> CapabilityGap:
        data = _strict(
            value,
            {
                "schema_version",
                "gap_id",
                "capability",
                "evidence_cycle",
                "evidence_ids",
                "counter_evidence_ids",
                "severity",
                "expected_gain",
                "estimated_cost_units",
                "stop_conditions",
                "priority",
                "uncertainty",
                "consecutive_failures",
                "last_targeted_cycle",
            },
            "capability gap",
        )
        item = cls(
            capability=data["capability"],
            evidence_cycle=data["evidence_cycle"],
            evidence_ids=tuple(_array(data["evidence_ids"], "evidence_ids")),
            counter_evidence_ids=tuple(
                _array(data["counter_evidence_ids"], "counter_evidence_ids")
            ),
            severity=data["severity"],
            expected_gain=data["expected_gain"],
            estimated_cost_units=data["estimated_cost_units"],
            stop_conditions=tuple(_array(data["stop_conditions"], "stop_conditions")),
            priority=data["priority"],
            uncertainty=data["uncertainty"],
            consecutive_failures=data["consecutive_failures"],
            last_targeted_cycle=data["last_targeted_cycle"],
        )
        if data["gap_id"] != item.gap_id:
            raise ValueError("gap_id does not match canonical content")
        return item


@dataclass(frozen=True, slots=True)
class CurriculumHypothesis:
    """A falsifiable curriculum intervention derived from a capability gap."""

    ID_PREFIX: ClassVar[str] = "curriculum-hypothesis-sha256:"

    gap_id: str
    evidence_ids: tuple[str, ...]
    counter_evidence_ids: tuple[str, ...]
    target_capabilities: tuple[str, ...]
    task_attributes: tuple[str, ...]
    expected_gain: float
    estimated_cost_units: int
    stop_conditions: tuple[str, ...]
    priority: float
    uncertainty: float
    hypothesis_id: str = field(init=False)

    def __post_init__(self) -> None:
        _text(self.gap_id, "gap_id")
        if not self.gap_id.startswith(CapabilityGap.ID_PREFIX):
            raise ValueError("gap_id must be a capability-gap content address")
        _text_tuple(self.evidence_ids, "evidence_ids")
        _text_tuple(
            self.counter_evidence_ids, "counter_evidence_ids", allow_empty=True
        )
        _text_tuple(self.target_capabilities, "target_capabilities")
        _text_tuple(self.task_attributes, "task_attributes")
        object.__setattr__(
            self, "expected_gain", _unit_float(self.expected_gain, "expected_gain")
        )
        _non_negative_int(self.estimated_cost_units, "estimated_cost_units")
        _text_tuple(self.stop_conditions, "stop_conditions", canonical=False)
        object.__setattr__(self, "priority", _unit_float(self.priority, "priority"))
        object.__setattr__(
            self, "uncertainty", _unit_float(self.uncertainty, "uncertainty")
        )
        object.__setattr__(
            self, "hypothesis_id", _content_id(self.ID_PREFIX, self._payload())
        )

    def _payload(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "gap_id": self.gap_id,
            "evidence_ids": list(self.evidence_ids),
            "counter_evidence_ids": list(self.counter_evidence_ids),
            "target_capabilities": list(self.target_capabilities),
            "task_attributes": list(self.task_attributes),
            "expected_gain": self.expected_gain,
            "estimated_cost_units": self.estimated_cost_units,
            "stop_conditions": list(self.stop_conditions),
            "priority": self.priority,
            "uncertainty": self.uncertainty,
        }

    def to_mapping(self) -> dict[str, Any]:
        return {"hypothesis_id": self.hypothesis_id, **self._payload()}

    @classmethod
    def from_mapping(cls, value: object) -> CurriculumHypothesis:
        data = _strict(
            value,
            {
                "schema_version",
                "hypothesis_id",
                "gap_id",
                "evidence_ids",
                "counter_evidence_ids",
                "target_capabilities",
                "task_attributes",
                "expected_gain",
                "estimated_cost_units",
                "stop_conditions",
                "priority",
                "uncertainty",
            },
            "curriculum hypothesis",
        )
        item = cls(
            gap_id=data["gap_id"],
            evidence_ids=tuple(_array(data["evidence_ids"], "evidence_ids")),
            counter_evidence_ids=tuple(
                _array(data["counter_evidence_ids"], "counter_evidence_ids")
            ),
            target_capabilities=tuple(
                _array(data["target_capabilities"], "target_capabilities")
            ),
            task_attributes=tuple(_array(data["task_attributes"], "task_attributes")),
            expected_gain=data["expected_gain"],
            estimated_cost_units=data["estimated_cost_units"],
            stop_conditions=tuple(_array(data["stop_conditions"], "stop_conditions")),
            priority=data["priority"],
            uncertainty=data["uncertainty"],
        )
        if data["hypothesis_id"] != item.hypothesis_id:
            raise ValueError("hypothesis_id does not match canonical content")
        return item


@dataclass(frozen=True, slots=True)
class TaskCapabilityProfile:
    """Frozen dynamic-task metadata used for cohort planning, never task content."""

    ID_PREFIX: ClassVar[str] = "task-capability-profile-sha256:"

    task_id: str
    evidence_cycle: int
    available_since_cycle: int
    capabilities: tuple[str, ...]
    difficulty: int
    hall_of_fame_age: int | None
    lagged_holdout: bool
    exploration: bool
    estimated_cost_units: int
    last_selected_cycle: int | None = None
    profile_id: str = field(init=False)

    def __post_init__(self) -> None:
        _text(self.task_id, "task_id", maximum=256)
        _positive_int(self.evidence_cycle, "evidence_cycle")
        _positive_int(self.available_since_cycle, "available_since_cycle")
        if self.available_since_cycle > self.evidence_cycle:
            raise ValueError("available_since_cycle cannot exceed evidence_cycle")
        _text_tuple(self.capabilities, "capabilities")
        if isinstance(self.difficulty, bool) or not isinstance(self.difficulty, int):
            raise TypeError("difficulty must be an integer")
        if not 1 <= self.difficulty <= 10:
            raise ValueError("difficulty must be in [1,10]")
        if self.hall_of_fame_age is not None:
            _non_negative_int(self.hall_of_fame_age, "hall_of_fame_age")
        if not isinstance(self.lagged_holdout, bool) or not isinstance(self.exploration, bool):
            raise TypeError("lagged_holdout and exploration must be bool values")
        _positive_int(self.estimated_cost_units, "estimated_cost_units")
        if self.last_selected_cycle is not None:
            _positive_int(self.last_selected_cycle, "last_selected_cycle")
            if self.last_selected_cycle > self.evidence_cycle:
                raise ValueError("last_selected_cycle cannot exceed evidence_cycle")
            if self.last_selected_cycle < self.available_since_cycle:
                raise ValueError("last_selected_cycle cannot precede availability")
        object.__setattr__(self, "profile_id", _content_id(self.ID_PREFIX, self._payload()))

    def _payload(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "task_id": self.task_id,
            "evidence_cycle": self.evidence_cycle,
            "available_since_cycle": self.available_since_cycle,
            "capabilities": list(self.capabilities),
            "difficulty": self.difficulty,
            "hall_of_fame_age": self.hall_of_fame_age,
            "lagged_holdout": self.lagged_holdout,
            "exploration": self.exploration,
            "estimated_cost_units": self.estimated_cost_units,
            "last_selected_cycle": self.last_selected_cycle,
        }

    def to_mapping(self) -> dict[str, Any]:
        return {"profile_id": self.profile_id, **self._payload()}

    @classmethod
    def from_mapping(cls, value: object) -> TaskCapabilityProfile:
        data = _strict(
            value,
            {
                "schema_version",
                "profile_id",
                "task_id",
                "evidence_cycle",
                "available_since_cycle",
                "capabilities",
                "difficulty",
                "hall_of_fame_age",
                "lagged_holdout",
                "exploration",
                "estimated_cost_units",
                "last_selected_cycle",
            },
            "task capability profile",
        )
        item = cls(
            task_id=data["task_id"],
            evidence_cycle=data["evidence_cycle"],
            available_since_cycle=data["available_since_cycle"],
            capabilities=tuple(_array(data["capabilities"], "capabilities")),
            difficulty=data["difficulty"],
            hall_of_fame_age=data["hall_of_fame_age"],
            lagged_holdout=data["lagged_holdout"],
            exploration=data["exploration"],
            estimated_cost_units=data["estimated_cost_units"],
            last_selected_cycle=data["last_selected_cycle"],
        )
        if data["profile_id"] != item.profile_id:
            raise ValueError("profile_id does not match canonical content")
        return item


@dataclass(frozen=True, slots=True)
class CurriculumPlan:
    """Immutable plan binding its evidence cutoff, hypotheses, and selected cohort."""

    ID_PREFIX: ClassVar[str] = "curriculum-plan-sha256:"

    target_cycle: int
    evidence_cutoff_cycle: int
    source_gap_ids: tuple[str, ...]
    source_profile_ids: tuple[str, ...]
    hypotheses: tuple[CurriculumHypothesis, ...]
    cohort: tuple[TaskCapabilityProfile, ...]
    cohort_strata: tuple[str, ...]
    exploration_quota: int
    total_cost_units: int
    max_total_cost_units: int
    stop_conditions: tuple[str, ...]
    plan_id: str = field(init=False)

    def __post_init__(self) -> None:
        _positive_int(self.target_cycle, "target_cycle")
        _positive_int(self.evidence_cutoff_cycle, "evidence_cutoff_cycle")
        if self.evidence_cutoff_cycle != self.target_cycle - 1:
            raise ValueError("evidence cutoff must be the cycle immediately before target_cycle")
        _text_tuple(self.source_gap_ids, "source_gap_ids")
        _text_tuple(self.source_profile_ids, "source_profile_ids")
        if not self.hypotheses or any(
            not isinstance(item, CurriculumHypothesis) for item in self.hypotheses
        ):
            raise TypeError("hypotheses must be a non-empty tuple of CurriculumHypothesis values")
        if not self.cohort or any(
            not isinstance(item, TaskCapabilityProfile) for item in self.cohort
        ):
            raise TypeError("cohort must be a non-empty tuple of TaskCapabilityProfile values")
        if len({item.profile_id for item in self.cohort}) != len(self.cohort):
            raise ValueError("cohort must not contain duplicate task profiles")
        if len(self.cohort_strata) != len(self.cohort):
            raise ValueError("cohort_strata must align exactly with cohort")
        for value in self.cohort_strata:
            _text(value, "cohort_strata[]")
        _non_negative_int(self.exploration_quota, "exploration_quota")
        if sum(item.exploration for item in self.cohort) < self.exploration_quota:
            raise ValueError("cohort does not satisfy exploration_quota")
        _non_negative_int(self.total_cost_units, "total_cost_units")
        _positive_int(self.max_total_cost_units, "max_total_cost_units")
        if self.total_cost_units != sum(item.estimated_cost_units for item in self.cohort):
            raise ValueError("total_cost_units does not match the cohort")
        if self.total_cost_units > self.max_total_cost_units:
            raise ValueError("cohort exceeds max_total_cost_units")
        _text_tuple(self.stop_conditions, "stop_conditions", canonical=False)
        object.__setattr__(self, "plan_id", _content_id(self.ID_PREFIX, self._payload()))

    def _payload(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "target_cycle": self.target_cycle,
            "evidence_cutoff_cycle": self.evidence_cutoff_cycle,
            "source_gap_ids": list(self.source_gap_ids),
            "source_profile_ids": list(self.source_profile_ids),
            "hypotheses": [item.to_mapping() for item in self.hypotheses],
            "cohort": [item.to_mapping() for item in self.cohort],
            "cohort_strata": list(self.cohort_strata),
            "exploration_quota": self.exploration_quota,
            "total_cost_units": self.total_cost_units,
            "max_total_cost_units": self.max_total_cost_units,
            "stop_conditions": list(self.stop_conditions),
        }

    def to_mapping(self) -> dict[str, Any]:
        return {"plan_id": self.plan_id, **self._payload()}

    @classmethod
    def from_mapping(cls, value: object) -> CurriculumPlan:
        data = _strict(
            value,
            {
                "schema_version",
                "plan_id",
                "target_cycle",
                "evidence_cutoff_cycle",
                "source_gap_ids",
                "source_profile_ids",
                "hypotheses",
                "cohort",
                "cohort_strata",
                "exploration_quota",
                "total_cost_units",
                "max_total_cost_units",
                "stop_conditions",
            },
            "curriculum plan",
        )
        hypotheses = _array(data["hypotheses"], "hypotheses")
        cohort = _array(data["cohort"], "cohort")
        if any(not isinstance(item, Mapping) for item in hypotheses + cohort):
            raise TypeError("plan hypotheses and cohort must contain objects")
        item = cls(
            target_cycle=data["target_cycle"],
            evidence_cutoff_cycle=data["evidence_cutoff_cycle"],
            source_gap_ids=tuple(_array(data["source_gap_ids"], "source_gap_ids")),
            source_profile_ids=tuple(
                _array(data["source_profile_ids"], "source_profile_ids")
            ),
            hypotheses=tuple(CurriculumHypothesis.from_mapping(value) for value in hypotheses),
            cohort=tuple(TaskCapabilityProfile.from_mapping(value) for value in cohort),
            cohort_strata=tuple(_array(data["cohort_strata"], "cohort_strata")),
            exploration_quota=data["exploration_quota"],
            total_cost_units=data["total_cost_units"],
            max_total_cost_units=data["max_total_cost_units"],
            stop_conditions=tuple(_array(data["stop_conditions"], "stop_conditions")),
        )
        if data["plan_id"] != item.plan_id:
            raise ValueError("plan_id does not match canonical content")
        return item


@dataclass(frozen=True, slots=True)
class CurriculumPlanner:
    """Deterministic planner over a caller-provided, immutable evidence snapshot."""

    cohort_size: int
    max_total_cost_units: int
    exploration_quota: int
    starvation_window: int
    repeated_failure_weight_cap: int = 3

    def __post_init__(self) -> None:
        _positive_int(self.cohort_size, "cohort_size")
        _positive_int(self.max_total_cost_units, "max_total_cost_units")
        _non_negative_int(self.exploration_quota, "exploration_quota")
        if self.exploration_quota > self.cohort_size:
            raise ValueError("exploration_quota cannot exceed cohort_size")
        _positive_int(self.starvation_window, "starvation_window")
        _non_negative_int(
            self.repeated_failure_weight_cap, "repeated_failure_weight_cap"
        )

    def plan(
        self,
        target_cycle: int,
        gaps: Sequence[CapabilityGap],
        profiles: Sequence[TaskCapabilityProfile],
    ) -> CurriculumPlan:
        _positive_int(target_cycle, "target_cycle")
        if target_cycle < 2:
            raise CurriculumPlanningError("planning requires at least one completed evidence cycle")
        gap_tuple = tuple(gaps)
        profile_tuple = tuple(profiles)
        if not gap_tuple or any(not isinstance(item, CapabilityGap) for item in gap_tuple):
            raise TypeError("gaps must contain CapabilityGap values")
        if not profile_tuple or any(
            not isinstance(item, TaskCapabilityProfile) for item in profile_tuple
        ):
            raise TypeError("profiles must contain TaskCapabilityProfile values")
        if len({item.gap_id for item in gap_tuple}) != len(gap_tuple):
            raise CurriculumPlanningError("gaps must not contain duplicates")
        if len({item.profile_id for item in profile_tuple}) != len(profile_tuple):
            raise CurriculumPlanningError("profiles must not contain duplicates")
        cutoff = target_cycle - 1
        if any(item.evidence_cycle > cutoff for item in gap_tuple):
            raise CurriculumPlanningError("current or future capability-gap evidence is forbidden")
        if any(item.evidence_cycle > cutoff for item in profile_tuple):
            raise CurriculumPlanningError("current or future task-profile evidence is forbidden")
        hypotheses = self._hypotheses(gap_tuple)
        selected = self._select(target_cycle, gap_tuple, profile_tuple)
        strata = tuple(self._stratum(item, gap_tuple) for item in selected)
        stop_conditions = tuple(
            dict.fromkeys(
                condition for hypothesis in hypotheses for condition in hypothesis.stop_conditions
            )
        )
        return CurriculumPlan(
            target_cycle=target_cycle,
            evidence_cutoff_cycle=cutoff,
            source_gap_ids=tuple(sorted(item.gap_id for item in gap_tuple)),
            source_profile_ids=tuple(sorted(item.profile_id for item in profile_tuple)),
            hypotheses=hypotheses,
            cohort=selected,
            cohort_strata=strata,
            exploration_quota=self.exploration_quota,
            total_cost_units=sum(item.estimated_cost_units for item in selected),
            max_total_cost_units=self.max_total_cost_units,
            stop_conditions=stop_conditions,
        )

    def _hypotheses(
        self, gaps: tuple[CapabilityGap, ...]
    ) -> tuple[CurriculumHypothesis, ...]:
        hypotheses = []
        for gap in sorted(gaps, key=lambda item: item.gap_id):
            effective_priority = min(
                1.0,
                gap.priority
                * (1.0 + min(gap.consecutive_failures, self.repeated_failure_weight_cap)),
            )
            hypotheses.append(
                CurriculumHypothesis(
                    gap_id=gap.gap_id,
                    evidence_ids=gap.evidence_ids,
                    counter_evidence_ids=gap.counter_evidence_ids,
                    target_capabilities=(gap.capability,),
                    task_attributes=tuple(
                        sorted(
                            (
                                f"capability:{gap.capability}",
                                "difficulty:adaptive",
                                "source:dynamic",
                            )
                        )
                    ),
                    expected_gain=gap.expected_gain,
                    estimated_cost_units=gap.estimated_cost_units,
                    stop_conditions=gap.stop_conditions,
                    priority=effective_priority,
                    uncertainty=gap.uncertainty,
                )
            )
        return tuple(hypotheses)

    def _select(
        self,
        target_cycle: int,
        gaps: tuple[CapabilityGap, ...],
        profiles: tuple[TaskCapabilityProfile, ...],
    ) -> tuple[TaskCapabilityProfile, ...]:
        selected: list[TaskCapabilityProfile] = []
        selected_ids: set[str] = set()
        cost = 0

        def add(profile: TaskCapabilityProfile, *, mandatory: bool) -> bool:
            nonlocal cost
            if profile.profile_id in selected_ids:
                return True
            if len(selected) >= self.cohort_size:
                if mandatory:
                    raise CurriculumPlanningError("anti-starvation tasks exceed cohort_size")
                return False
            if cost + profile.estimated_cost_units > self.max_total_cost_units:
                if mandatory:
                    raise CurriculumPlanningError("anti-starvation tasks exceed total cost")
                return False
            selected.append(profile)
            selected_ids.add(profile.profile_id)
            cost += profile.estimated_cost_units
            return True

        ranked = sorted(
            profiles,
            key=lambda item: (-self._score(item, gaps), self._stratum(item, gaps), item.profile_id),
        )
        starved = [item for item in ranked if self._is_starved(item, target_cycle)]
        for profile in starved:
            add(profile, mandatory=True)
        exploration_needed = self.exploration_quota - sum(item.exploration for item in selected)
        for profile in (
            item
            for item in ranked
            if item.exploration and item.profile_id not in selected_ids
        ):
            if exploration_needed <= 0:
                break
            if add(profile, mandatory=False):
                exploration_needed -= 1
        if exploration_needed > 0:
            raise CurriculumPlanningError("available tasks cannot satisfy exploration_quota")
        while len(selected) < self.cohort_size:
            candidates = [item for item in ranked if item.profile_id not in selected_ids]
            if not candidates:
                break
            stratum_counts: dict[str, int] = {}
            for item in selected:
                key = self._stratum(item, gaps)
                stratum_counts[key] = stratum_counts.get(key, 0) + 1
            candidates.sort(
                key=lambda item: (
                    stratum_counts.get(self._stratum(item, gaps), 0),
                    -self._score(item, gaps),
                    self._stratum(item, gaps),
                    item.profile_id,
                )
            )
            if not any(add(item, mandatory=False) for item in candidates):
                break
        if len(selected) != self.cohort_size:
            raise CurriculumPlanningError("total cost or available tasks cannot fill cohort_size")
        return tuple(selected)

    def _score(
        self, profile: TaskCapabilityProfile, gaps: tuple[CapabilityGap, ...]
    ) -> float:
        score = 0.0
        for gap in gaps:
            if gap.capability in profile.capabilities:
                capped_failures = min(
                    gap.consecutive_failures, self.repeated_failure_weight_cap
                )
                score += gap.priority * (1.0 + capped_failures) * (
                    gap.severity + gap.uncertainty
                )
        if profile.exploration:
            score += 0.01
        return score / profile.estimated_cost_units

    def _stratum(
        self, profile: TaskCapabilityProfile, gaps: tuple[CapabilityGap, ...]
    ) -> str:
        relevant = sorted(
            (
                (-self._gap_weight(gap), gap.capability)
                for gap in gaps
                if gap.capability in profile.capabilities
            )
        )
        capability = relevant[0][1] if relevant else profile.capabilities[0]
        hof_age = "fresh" if profile.hall_of_fame_age is None else str(profile.hall_of_fame_age)
        lagged = "lagged" if profile.lagged_holdout else "training"
        return f"{capability}|difficulty:{profile.difficulty}|hof-age:{hof_age}|{lagged}"

    def _gap_weight(self, gap: CapabilityGap) -> float:
        return gap.priority * (
            1.0 + min(gap.consecutive_failures, self.repeated_failure_weight_cap)
        )

    def _is_starved(self, profile: TaskCapabilityProfile, target_cycle: int) -> bool:
        reference = (
            profile.last_selected_cycle
            if profile.last_selected_cycle is not None
            else profile.available_since_cycle - 1
        )
        return target_cycle - reference >= self.starvation_window
