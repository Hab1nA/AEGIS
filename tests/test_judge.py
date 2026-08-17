"""Unit tests for trusted Judge evidence models, calibration and diagnostic sanitization."""

from __future__ import annotations

import pytest

from aegis.judge import (
    CalibrationBin,
    EvidenceKind,
    FrozenSubmissionEvidence,
    JudgeCalibration,
    JudgeForecast,
    TaskFailureForecast,
    compute_calibration,
    sanitize_diagnostic_quality,
)

SHA = "a" * 64
TYPED_SHA = "sha256:" + "a" * 64


def frozen(**overrides: object) -> FrozenSubmissionEvidence:
    values = dict(
        submission_artifact_id="submission-sha256:" + "1" * 64,
        workspace_artifact_id="arm-workspace-sha256:" + "2" * 64,
        workspace_digest="3" * 64,
        workspace_size_bytes=1024,
        producer_role_version_id="role-version-sha256:" + "4" * 64,
        snapshot_id="snapshot-sha256:" + "5" * 64,
        cohort_id="dynamic-cohort-sha256:" + "6" * 64,
    )
    values.update(overrides)
    return FrozenSubmissionEvidence.create(**values)


def test_frozen_submission_evidence_round_trip() -> None:
    evidence = frozen()
    restored = FrozenSubmissionEvidence.from_mapping(evidence.to_mapping())
    assert restored == evidence
    assert evidence.freeze_receipt_id.startswith("sha256:")
    assert len(evidence.freeze_receipt_id) == 71


def test_frozen_submission_evidence_rejects_invalid_digests() -> None:
    with pytest.raises(ValueError):
        frozen(workspace_digest="not-a-digest")
    with pytest.raises(ValueError):
        frozen(workspace_size_bytes=0)
    with pytest.raises(ValueError):
        frozen(cohort_id="cohort-not-dynamic")


def test_forecast_round_trip_and_advisory_quality() -> None:
    forecast = JudgeForecast(
        forecasts=(
            TaskFailureForecast("task-sha256:" + "1" * 64, 0.2, 0.8, 1.0),
            TaskFailureForecast("task-sha256:" + "2" * 64, 0.8, 0.9, 0.5),
        ),
        probes_run=("sandbox.exec",),
        hidden_data_disclosed=False,
    )
    restored = JudgeForecast.from_mapping(forecast.to_mapping())
    assert restored == forecast
    assert restored.hidden_data_disclosed is False


def test_calibration_scores_known_pairs() -> None:
    forecasts = (
        TaskFailureForecast("task-sha256:" + "1" * 64, 0.9, 0.9, 1.0),
        TaskFailureForecast("task-sha256:" + "2" * 64, 0.9, 0.9, 1.0),
    )
    calibration = compute_calibration(forecasts, (True, True))
    assert calibration.forecast_count == 2
    assert calibration.brier_score == pytest.approx(0.01)
    assert calibration.false_negatives == 0
    assert calibration.false_positives == 0
    assert calibration.bins


def test_calibration_counts_false_positive_and_false_negative() -> None:
    forecasts = (
        TaskFailureForecast("task-sha256:" + "1" * 64, 0.9, 0.9, 1.0),  # predicted fail, passed
        TaskFailureForecast("task-sha256:" + "2" * 64, 0.1, 0.9, 1.0),  # predicted pass, failed
    )
    calibration = compute_calibration(forecasts, (False, True))
    assert calibration.false_positives == 1
    assert calibration.false_negatives == 1


def test_calibration_requires_paired_forecasts() -> None:
    forecasts = (TaskFailureForecast("task-sha256:" + "1" * 64, 0.5, 0.5, 1.0),)
    with pytest.raises(ValueError):
        compute_calibration(forecasts, ())


def test_sanitize_diagnostic_quality_strips_hidden_details() -> None:
    lock = {
        "locked": True,
        "score": 0.75,
        "tasks": [
            {
                "task_id": "task-a",
                "tier": "fresh",
                "hidden": {"passed": 3, "total": 3},
                "score": 1.0,
                "diagnostic_failure_categories": [],
                "artifact_id": "task-sha256:" + "1" * 64,
            },
            {
                "task_id": "task-b",
                "tier": "regression",
                "hidden": {"passed": 1, "total": 4},
                "score": 0.5,
                "diagnostic_failure_categories": ["edge-condition"],
                "artifact_id": "task-sha256:" + "2" * 64,
            },
        ],
        "evaluation": {
            "quality": 0.75,
            "integrity_passed": True,
            "tasks": [],
            "fresh": {"quality": 0.8, "task_count": 1, "artifact_ids": ["x"]},
            "regression": {"quality": 0.6, "task_count": 1, "artifact_ids": ["y"]},
        },
    }
    sanitized = sanitize_diagnostic_quality(lock)
    assert sanitized["diagnostic_only"] is True
    assert sanitized["hidden_results_disclosed"] is False
    for task in sanitized["tasks"]:
        assert "hidden" not in task
        assert "score" not in task
        assert "artifact_id" not in task
    assert sanitized["evaluation"].get("fresh_task_count") == 1
    assert sanitized["evaluation"].get("fresh") is None


def test_evidence_kind_values() -> None:
    assert {item.value for item in EvidenceKind} == {
        "observed",
        "inferred",
        "hypothesis",
        "self_reported",
    }


def test_calibration_bin_validation() -> None:
    with pytest.raises(ValueError):
        CalibrationBin(0.0, 0.1, -1, 0.05, 0.0)
    with pytest.raises(ValueError):
        JudgeCalibration(1, 2.0, 2.0, 0, 0, ())
