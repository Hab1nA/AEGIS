from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from typing import Any

from aegis.event_store import EventStore
from aegis.promotion_runtime import PromotionArmResult, PromotionBudgetUnavailable
from aegis.research.imports import ResearchImportArtifact, validate_skill_import
from aegis.skill_promotion_runtime import NO_SKILL_BASELINE_ID, SkillPromotionScheduler
from aegis.skill_registry import SkillCandidate, SkillCandidateState, SkillPromotionEvidence, SkillRegistry
from aegis.skill_validation import SkillStaticValidator


def artifact_for(name: str, version: str, content: bytes) -> ResearchImportArtifact:
    return validate_skill_import(
        {
            "schema_version": 1,
            "kind": "skill",
            "source_url": f"https://skills.example.org/{name}/{version}/manifest.json",
            "content_sha256": hashlib.sha256(content).hexdigest(),
            "size_bytes": len(content),
            "metadata": {
                "name": name,
                "version": version,
                "permissions": [],
                "dependencies": [],
            },
        }
    )


class RecordingRunner:
    def __init__(self, *, reject_smoke: bool = False, fail_after: int | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self.reject_smoke = reject_smoke
        self.fail_after = fail_after

    def __call__(self, **kwargs: Any) -> PromotionArmResult:
        if self.fail_after is not None and len(self.calls) >= self.fail_after:
            raise PromotionBudgetUnavailable
        self.calls.append(kwargs)
        candidate = kwargs["arm"] == "candidate"
        quality = 0.2 if self.reject_smoke and candidate else (0.9 if candidate else 0.5)
        return PromotionArmResult(quality, 100, True)


class FutureRegistry(SkillRegistry):
    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self.evaluated_calls: list[dict[str, object]] = []

    def promote_evaluated(self, **kwargs: object) -> None:
        self.evaluated_calls.append(kwargs)


class SkillPromotionSchedulerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        root = Path(self.tempdir.name)
        self.registry = SkillRegistry(root / "skills.sqlite3")
        self.events = EventStore(root / "events.sqlite3")
        self.tasks = tuple(f"task-{index:02d}" for index in range(12))

    def tearDown(self) -> None:
        self.events.close()
        self.registry.close()
        self.tempdir.cleanup()

    def register(self, version: str = "1.0.0") -> SkillCandidate:
        content = f"skill {version}".encode()
        artifact = artifact_for("helper", version, content)
        self.registry.register_candidate(artifact, content)
        evidence = SkillStaticValidator().validate(artifact, content)
        return self.registry.record_static_evidence(evidence)

    def scheduler(self, runner: RecordingRunner) -> SkillPromotionScheduler:
        return SkillPromotionScheduler(
            self.registry,
            self.events,
            "campaign",
            self.tasks,
            runner,
        )

    def test_no_skill_baseline_smoke_is_reused_in_exact_12x2_and_promotes(self) -> None:
        candidate = self.register()
        runner = RecordingRunner()

        summary = self.scheduler(runner).run_pending()

        self.assertEqual(summary.arms_added, 48)
        self.assertEqual(summary.outcomes[0].state, "promoted")
        self.assertEqual(self.registry.champion("helper").artifact.artifact_id, candidate.artifact.artifact_id)  # type: ignore[union-attr]
        self.assertEqual({call["baseline_artifact_id"] for call in runner.calls}, {NO_SKILL_BASELINE_ID})
        keys = {(call["task_id"], call["seed"], call["arm"]) for call in runner.calls}
        self.assertEqual(len(keys), 48)
        self.assertEqual(len(runner.calls), 48)

    def test_smoke_rejection_stops_after_two_pairs(self) -> None:
        self.register()
        runner = RecordingRunner(reject_smoke=True)

        summary = self.scheduler(runner).run_pending()

        self.assertEqual(summary.arms_added, 4)
        self.assertEqual(summary.outcomes[0].state, "rejected")
        self.assertIn("quality regression", summary.outcomes[0].reason)
        self.assertIsNone(self.registry.champion("helper"))
        rerun = self.scheduler(RecordingRunner()).run_pending()
        self.assertEqual(rerun.arms_added, 0)
        self.assertEqual(rerun.outcomes[0].state, "rejected")

    def test_arm_level_recovery_does_not_rerun_completed_arm(self) -> None:
        self.register()
        interrupted = RecordingRunner(fail_after=1)

        first = self.scheduler(interrupted).run_pending()

        self.assertTrue(first.pending_for_budget)
        self.assertEqual(first.arms_added, 1)
        resumed = RecordingRunner()
        second = self.scheduler(resumed).run_pending()
        self.assertFalse(second.pending_for_budget)
        self.assertEqual(second.arms_added, 47)
        self.assertEqual(len(resumed.calls), 47)

    def test_locks_same_name_champion_and_stales_if_it_changes(self) -> None:
        champion = self.register("1.0.0")
        self.registry.promote(
            champion.name,
            champion.version,
            SkillPromotionEvidence(champion.artifact.artifact_id, True, True, "a" * 64, "b" * 64),
        )
        pending = self.register("2.0.0")
        interrupted = RecordingRunner(fail_after=1)
        self.scheduler(interrupted).run_pending()
        self.registry.revoke(champion.name, champion.version, "replace locked baseline")

        summary = self.scheduler(RecordingRunner()).run_pending()

        outcome = next(item for item in summary.outcomes if item.candidate_artifact_id == pending.artifact.artifact_id)
        self.assertEqual(outcome.state, "stale")
        self.assertEqual(summary.arms_added, 0)

    def test_unverified_usage_fails_closed_at_smoke(self) -> None:
        self.register()

        def runner(**kwargs: Any) -> PromotionArmResult:
            return PromotionArmResult(0.9, 100, kwargs["arm"] != "candidate")

        summary = SkillPromotionScheduler(
            self.registry, self.events, "campaign", self.tasks, runner
        ).run_pending()

        self.assertEqual(summary.arms_added, 4)
        self.assertIn("unverified token", summary.outcomes[0].reason)

    def test_prefers_future_promote_evaluated_cas_api(self) -> None:
        root = Path(self.tempdir.name)
        self.registry.close()
        self.registry = FutureRegistry(root / "future-skills.sqlite3")
        candidate = self.register()

        summary = self.scheduler(RecordingRunner()).run_pending()

        self.assertEqual(summary.outcomes[0].state, "promoted")
        registry = self.registry
        self.assertIsInstance(registry, FutureRegistry)
        calls = registry.evaluated_calls
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["artifact_id"], candidate.artifact.artifact_id)
        self.assertIsNone(calls[0]["expected_champion_id"])
        self.assertEqual(len(str(calls[0]["funnel_report_id"])), 64)
        self.assertEqual(calls[0]["expected_champion_revision"], "0" * 64)
        self.assertEqual(candidate.state, SkillCandidateState.VALIDATED_PENDING)


if __name__ == "__main__":
    unittest.main()
