"""Trusted Judge evidence models: frozen submissions, forecasts and calibration.

The Judge is an independent predictor, not a quality authority.  This module
defines the value objects that separate what the Judge may observe (frozen
submission workspace, public contract, diagnostic feedback) from what only the
control plane may lock (quality, integrity, safety, cost).  Calibration is
computed after the sealed evaluator has produced a locked quality, over
retired or diagnostic cohorts only, so live Fresh holdout results never feed
the Judge's own next forecast.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Mapping, Sequence

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ARTIFACT_ID = re.compile(r"^[a-z0-9-]+-sha256:[0-9a-f]{64}\Z")


def _bounded_text(value: object, name: str, *, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or value.strip() != value or len(value) > maximum:
        raise ValueError(f"{name} must be bounded, non-empty, trimmed text")
    return value


def _digest(value: object, name: str) -> str:
    text = _bounded_text(value, name, maximum=128)
    if not text.startswith("sha256:") or len(text) != 71:
        raise ValueError(f"{name} must be a sha256 content address")
    if _SHA256.fullmatch(text[7:]) is None:
        raise ValueError(f"{name} must be a sha256 content address")
    return text.lower()


def _artifact_id(value: object, name: str) -> str:
    text = _bounded_text(value, name, maximum=192)
    if _ARTIFACT_ID.fullmatch(text) is None:
        raise ValueError(f"{name} must be a typed content address")
    return text.lower()


def _typed_or_bare_digest(value: object, name: str) -> str:
    """Accept either a typed content address or a bare sha256: digest."""
    text = _bounded_text(value, name, maximum=192)
    if text.startswith("sha256:") and len(text) == 71 and _SHA256.fullmatch(text[7:]):
        return text.lower()
    if _ARTIFACT_ID.fullmatch(text) is not None:
        return text.lower()
    raise ValueError(f"{name} must be a sha256 content address or typed content address")


def estimate_message_tokens(text: str) -> int:
    """Content-length token estimate for council transcripts.

    This deliberately measures message content, not provider billing.  Billing
    usage is tracked separately in role evidence; the council transcript limit
    is a protocol bound over the messages themselves.
    """
    if not isinstance(text, str):
        raise TypeError("message text must be a string")
    return max(1, (len(text) + 3) // 4)


class EvidenceKind(StrEnum):
    OBSERVED = "observed"
    INFERRED = "inferred"
    HYPOTHESIS = "hypothesis"
    SELF_REPORTED = "self_reported"


@dataclass(frozen=True, slots=True)
class FrozenSubmissionEvidence:
    """Control-plane object binding a sealed submission to its frozen workspace."""

    submission_artifact_id: str
    workspace_artifact_id: str
    workspace_digest: str
    workspace_size_bytes: int
    producer_role_version_id: str
    snapshot_id: str
    cohort_id: str
    freeze_receipt_id: str

    def __post_init__(self) -> None:
        _artifact_id(self.submission_artifact_id, "submission_artifact_id")
        _artifact_id(self.workspace_artifact_id, "workspace_artifact_id")
        if _SHA256.fullmatch(self.workspace_digest) is None:
            raise ValueError("workspace_digest must be a lowercase SHA-256 digest")
        if (
            isinstance(self.workspace_size_bytes, bool)
            or not isinstance(self.workspace_size_bytes, int)
            or self.workspace_size_bytes <= 0
        ):
            raise ValueError("workspace_size_bytes must be a positive integer")
        _typed_or_bare_digest(self.producer_role_version_id, "producer_role_version_id")
        _typed_or_bare_digest(self.snapshot_id, "snapshot_id")
        if not isinstance(self.cohort_id, str) or not self.cohort_id.startswith(
            "dynamic-cohort-sha256:"
        ):
            raise ValueError("cohort_id must be a dynamic cohort content address")
        if _SHA256.fullmatch(self.cohort_id.removeprefix("dynamic-cohort-sha256:")) is None:
            raise ValueError("cohort_id must be a dynamic cohort content address")
        _digest(self.freeze_receipt_id, "freeze_receipt_id")

    @classmethod
    def create(
        cls,
        *,
        submission_artifact_id: str,
        workspace_artifact_id: str,
        workspace_digest: str,
        workspace_size_bytes: int,
        producer_role_version_id: str,
        snapshot_id: str,
        cohort_id: str,
    ) -> "FrozenSubmissionEvidence":
        receipt_payload = {
            "submission_artifact_id": submission_artifact_id,
            "workspace_artifact_id": workspace_artifact_id,
            "workspace_digest": workspace_digest,
            "workspace_size_bytes": workspace_size_bytes,
            "producer_role_version_id": producer_role_version_id,
            "snapshot_id": snapshot_id,
            "cohort_id": cohort_id,
        }
        receipt_id = hashlib.sha256(
            json.dumps(
                receipt_payload,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
        ).hexdigest()
        return cls(
            submission_artifact_id,
            workspace_artifact_id,
            workspace_digest,
            workspace_size_bytes,
            producer_role_version_id,
            snapshot_id,
            cohort_id,
            "sha256:" + receipt_id,
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "submission_artifact_id": self.submission_artifact_id,
            "workspace_artifact_id": self.workspace_artifact_id,
            "workspace_digest": self.workspace_digest,
            "workspace_size_bytes": self.workspace_size_bytes,
            "producer_role_version_id": self.producer_role_version_id,
            "snapshot_id": self.snapshot_id,
            "cohort_id": self.cohort_id,
            "freeze_receipt_id": self.freeze_receipt_id,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "FrozenSubmissionEvidence":
        expected = {
            "submission_artifact_id",
            "workspace_artifact_id",
            "workspace_digest",
            "workspace_size_bytes",
            "producer_role_version_id",
            "snapshot_id",
            "cohort_id",
            "freeze_receipt_id",
        }
        if set(value) != expected:
            raise ValueError("frozen submission evidence has missing or unknown fields")
        return cls(
            value["submission_artifact_id"],
            value["workspace_artifact_id"],
            value["workspace_digest"],
            value["workspace_size_bytes"],
            value["producer_role_version_id"],
            value["snapshot_id"],
            value["cohort_id"],
            value["freeze_receipt_id"],
        )


@dataclass(frozen=True, slots=True)
class TaskFailureForecast:
    task_artifact_id: str
    failure_probability: float
    confidence: float
    evidence_coverage: float

    def __post_init__(self) -> None:
        _artifact_id(self.task_artifact_id, "task_artifact_id")
        for name, value in (
            ("failure_probability", self.failure_probability),
            ("confidence", self.confidence),
            ("evidence_coverage", self.evidence_coverage),
        ):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{name} must be numeric")
            numeric = float(value)
            if not math.isfinite(numeric) or not 0.0 <= numeric <= 1.0:
                raise ValueError(f"{name} must be finite and in [0,1]")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "task_artifact_id": self.task_artifact_id,
            "failure_probability": float(self.failure_probability),
            "confidence": float(self.confidence),
            "evidence_coverage": float(self.evidence_coverage),
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "TaskFailureForecast":
        if set(value) != {
            "task_artifact_id",
            "failure_probability",
            "confidence",
            "evidence_coverage",
        }:
            raise ValueError("task failure forecast has missing or unknown fields")
        return cls(
            value["task_artifact_id"],
            value["failure_probability"],
            value["confidence"],
            value["evidence_coverage"],
        )


@dataclass(frozen=True, slots=True)
class JudgeForecast:
    """Pre-seal forecast: what the Judge predicts before hidden results exist."""

    forecasts: tuple[TaskFailureForecast, ...]
    probes_run: tuple[str, ...]
    hidden_data_disclosed: bool = False

    def to_mapping(self) -> dict[str, Any]:
        return {
            "forecasts": [item.to_mapping() for item in self.forecasts],
            "probes_run": list(self.probes_run),
            "hidden_data_disclosed": self.hidden_data_disclosed,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "JudgeForecast":
        expected = {"forecasts", "probes_run", "hidden_data_disclosed"}
        if set(value) != expected:
            raise ValueError("judge forecast has missing or unknown fields")
        raw_forecasts = value["forecasts"]
        probes = value["probes_run"]
        if not isinstance(raw_forecasts, list) or not isinstance(probes, list):
            raise TypeError("judge forecast arrays are invalid")
        if not isinstance(value["hidden_data_disclosed"], bool):
            raise TypeError("hidden_data_disclosed must be a boolean")
        return cls(
            tuple(TaskFailureForecast.from_mapping(item) for item in raw_forecasts),
            tuple(str(item) for item in probes),
            value["hidden_data_disclosed"],
        )


@dataclass(frozen=True, slots=True)
class CalibrationBin:
    lower: float
    upper: float
    count: int
    mean_prediction: float
    observed_frequency: float

    def __post_init__(self) -> None:
        for name, value in (
            ("lower", self.lower),
            ("upper", self.upper),
            ("mean_prediction", self.mean_prediction),
            ("observed_frequency", self.observed_frequency),
        ):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{name} must be numeric")
            numeric = float(value)
            if not math.isfinite(numeric) or not 0.0 <= numeric <= 1.0:
                raise ValueError(f"{name} must be finite and in [0,1]")
        if isinstance(self.count, bool) or not isinstance(self.count, int) or self.count < 0:
            raise ValueError("count must be a non-negative integer")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "lower": float(self.lower),
            "upper": float(self.upper),
            "count": self.count,
            "mean_prediction": float(self.mean_prediction),
            "observed_frequency": float(self.observed_frequency),
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CalibrationBin":
        if set(value) != {
            "lower",
            "upper",
            "count",
            "mean_prediction",
            "observed_frequency",
        }:
            raise ValueError("calibration bin has missing or unknown fields")
        return cls(
            value["lower"],
            value["upper"],
            value["count"],
            value["mean_prediction"],
            value["observed_frequency"],
        )


@dataclass(frozen=True, slots=True)
class JudgeCalibration:
    """Post-seal calibration over diagnostic or retired cohorts only."""

    forecast_count: int
    brier_score: float
    ece: float
    false_positives: int
    false_negatives: int
    bins: tuple[CalibrationBin, ...] = field(default=())
    cohort_note: str = "diagnostic-only; live Fresh holdout results are excluded"

    def __post_init__(self) -> None:
        if isinstance(self.forecast_count, bool) or not isinstance(
            self.forecast_count, int
        ) or self.forecast_count < 0:
            raise ValueError("forecast_count must be a non-negative integer")
        for name in ("brier_score", "ece"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{name} must be numeric")
            numeric = float(value)
            if not math.isfinite(numeric) or not 0.0 <= numeric <= 1.0:
                raise ValueError(f"{name} must be finite and in [0,1]")
        for name in ("false_positives", "false_negatives"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "forecast_count": self.forecast_count,
            "brier_score": float(self.brier_score),
            "ece": float(self.ece),
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "bins": [item.to_mapping() for item in self.bins],
            "cohort_note": self.cohort_note,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "JudgeCalibration":
        expected = {
            "forecast_count",
            "brier_score",
            "ece",
            "false_positives",
            "false_negatives",
            "bins",
            "cohort_note",
        }
        if set(value) != expected:
            raise ValueError("judge calibration has missing or unknown fields")
        return cls(
            value["forecast_count"],
            value["brier_score"],
            value["ece"],
            value["false_positives"],
            value["false_negatives"],
            tuple(CalibrationBin.from_mapping(item) for item in value["bins"]),
            value["cohort_note"],
        )


def _brier(forecasts: Sequence[TaskFailureForecast], outcomes: Sequence[bool]) -> float:
    if len(forecasts) != len(outcomes) or not forecasts:
        raise ValueError("calibration requires paired forecasts and outcomes")
    total = 0.0
    for forecast, outcome in zip(forecasts, outcomes):
        probability = float(forecast.failure_probability)
        actual = 1.0 if outcome else 0.0
        total += (probability - actual) ** 2
    return round(total / len(forecasts), 12)


def _ece(forecasts: Sequence[TaskFailureForecast], outcomes: Sequence[bool]) -> float:
    """Expected calibration error over 10 equal-width probability bins."""
    if len(forecasts) != len(outcomes) or not forecasts:
        raise ValueError("calibration requires paired forecasts and outcomes")
    buckets: list[list[float]] = [[] for _ in range(10)]
    for forecast, outcome in zip(forecasts, outcomes):
        probability = float(forecast.failure_probability)
        index = min(9, int(probability * 10))
        buckets[index].append(1.0 if outcome else 0.0)
    error = 0.0
    for index, bucket in enumerate(buckets):
        if not bucket:
            continue
        bin_error = abs(sum(bucket) / len(bucket) - (index + 0.5) / 10.0)
        error += (len(bucket) / len(forecasts)) * bin_error
    return round(error, 12)


def compute_calibration(
    forecasts: Sequence[TaskFailureForecast],
    outcomes: Sequence[bool],
    *,
    cohort_note: str = "diagnostic-only; live Fresh holdout results are excluded",
) -> JudgeCalibration:
    """Compute post-seal calibration without touching live holdout data."""
    if len(forecasts) != len(outcomes):
        raise ValueError("forecast and outcome counts must match")
    bins: list[CalibrationBin] = []
    for lower in range(0, 10):
        bucket_forecasts = [
            forecast
            for forecast in forecasts
            if int(float(forecast.failure_probability) * 10) == lower
        ]
        if not bucket_forecasts:
            continue
        bucket_outcomes = [
            outcomes[index]
            for index, forecast in enumerate(forecasts)
            if int(float(forecast.failure_probability) * 10) == lower
        ]
        bins.append(
            CalibrationBin(
                lower / 10.0,
                (lower + 1) / 10.0,
                len(bucket_forecasts),
                round(
                    sum(float(item.failure_probability) for item in bucket_forecasts)
                    / len(bucket_forecasts),
                    12,
                ),
                round(sum(1 for item in bucket_outcomes if item) / len(bucket_outcomes), 12),
            )
        )
    false_positives = sum(
        1
        for forecast, outcome in zip(forecasts, outcomes)
        if not outcome and float(forecast.failure_probability) > 0.5
    )
    false_negatives = sum(
        1
        for forecast, outcome in zip(forecasts, outcomes)
        if outcome and float(forecast.failure_probability) <= 0.5
    )
    return JudgeCalibration(
        len(forecasts),
        _brier(forecasts, outcomes),
        _ece(forecasts, outcomes),
        false_positives,
        false_negatives,
        tuple(bins),
        cohort_note,
    )


def sanitize_diagnostic_quality(quality_lock: Mapping[str, Any]) -> Mapping[str, Any]:
    """Strip per-task hidden pass counts before any reflection feedback.

    The Judge, Warrior and Prosecutor may see aggregate locked quality and
    clause-level diagnostic categories, but never live per-task hidden
    pass/total counts, hidden case names, or per-task hidden scores.
    """
    tasks = quality_lock.get("tasks")
    sanitized_tasks: list[Mapping[str, Any]] = []
    if isinstance(tasks, list):
        for task in tasks:
            if not isinstance(task, Mapping):
                continue
            sanitized = {
                key: value
                for key, value in task.items()
                if key
                not in {
                    "hidden",
                    "passed",
                    "total",
                    "hidden_passed",
                    "hidden_total",
                    "score",
                    "artifact_id",
                }
            }
            sanitized["diagnostic_failure_categories"] = task.get(
                "diagnostic_failure_categories", []
            )
            sanitized_tasks.append(sanitized)
    evaluation = quality_lock.get("evaluation")
    sanitized_evaluation: Mapping[str, Any] = {}
    if isinstance(evaluation, Mapping):
        sanitized_evaluation = {
            key: value
            for key, value in evaluation.items()
            if key not in {"tasks", "artifact_ids", "fresh", "regression"}
        }
        fresh = evaluation.get("fresh")
        regression = evaluation.get("regression")
        if isinstance(fresh, Mapping):
            sanitized_evaluation["fresh_task_count"] = fresh.get("task_count", 0)
        if isinstance(regression, Mapping):
            sanitized_evaluation["regression_task_count"] = regression.get("task_count", 0)
    return {
        "score": quality_lock.get("score"),
        "locked": quality_lock.get("locked"),
        "evaluation": sanitized_evaluation,
        "tasks": sanitized_tasks,
        "diagnostic_only": True,
        "hidden_results_disclosed": False,
    }