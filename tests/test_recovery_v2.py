from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from aegis.models import Role
from aegis.recovery import (
    BrickKind,
    GenerationHealthSnapshot,
    IncidentReport,
    RecoveryContractError,
    RepairDisposition,
    RepairPlan,
    detect_brick,
)

NOW = datetime(2026, 8, 9, 12, tzinfo=timezone.utc)


def digest(char: str) -> str:
    return "sha256:" + char * 64


def healthy() -> GenerationHealthSnapshot:
    return GenerationHealthSnapshot(
        digest("1"),
        NOW - timedelta(minutes=10),
        True,
        True,
        NOW - timedelta(seconds=5),
        NOW - timedelta(seconds=10),
    )


def test_healthy_generation_is_not_fenced() -> None:
    decision = detect_brick(healthy(), observed_at=NOW)
    assert not decision.bricked
    assert not decision.fence_generation
    assert not decision.automatic_rollback


def test_hard_failures_are_combined_and_force_rollback() -> None:
    snapshot = GenerationHealthSnapshot(
        digest("2"),
        NOW - timedelta(minutes=10),
        True,
        True,
        NOW - timedelta(minutes=2),
        NOW - timedelta(minutes=10),
        consecutive_phase_crashes=3,
        consecutive_protocol_errors=3,
        orphan_sandboxes=1,
        event_replay_ok=False,
        safety_violation=True,
    )
    decision = detect_brick(snapshot, observed_at=NOW)
    assert decision.bricked and decision.automatic_rollback
    assert set(decision.reasons) == {
        BrickKind.HEARTBEAT_TIMEOUT,
        BrickKind.EVENT_STALL,
        BrickKind.CRASH_LOOP,
        BrickKind.PROTOCOL_FAILURE,
        BrickKind.EVENT_REPLAY_FAILURE,
        BrickKind.RESOURCE_LEAK,
        BrickKind.SAFETY_VIOLATION,
    }


def test_startup_failure_waits_for_deadline() -> None:
    recent = GenerationHealthSnapshot(digest("3"), NOW, False, False, None, None)
    assert not detect_brick(recent, observed_at=NOW + timedelta(seconds=59)).bricked
    decision = detect_brick(recent, observed_at=NOW + timedelta(seconds=61))
    assert decision.reasons == (BrickKind.STARTUP_FAILURE,)


def test_incident_and_repair_plan_are_content_addressed() -> None:
    incident = IncidentReport(
        "campaign",
        "cycle-2",
        digest("4"),
        digest("5"),
        Role.WARRIOR,
        (BrickKind.CRASH_LOOP,),
        (digest("6"),),
        "candidate introduced a deterministic startup loop",
        "the previous generation reproduces the same loop",
        0.9,
    )
    assert incident.incident_id.startswith("incident-sha256:")
    plan = RepairPlan(
        incident.incident_id,
        Role.WARRIOR,
        RepairDisposition.RETRY_AFTER_FIX,
        digest("5"),
        digest("7"),
        ("replay the incident", "run sealed canary"),
        "apply the minimal bounded repair",
    )
    assert plan.repair_plan_id.startswith("repair-plan-sha256:")


def test_prosecutor_plan_cannot_smuggle_patch_into_plain_rollback() -> None:
    with pytest.raises(RecoveryContractError, match="must not carry"):
        RepairPlan(
            "incident-sha256:" + "a" * 64,
            Role.WARRIOR,
            RepairDisposition.ROLLBACK,
            digest("b"),
            digest("c"),
            ("verify rollback",),
            "rollback first",
        )
