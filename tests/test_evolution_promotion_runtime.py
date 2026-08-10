import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from aegis.event_store import EventStore
from aegis.evolution_promotion_runtime import EvolutionPromotionScheduler
from aegis.evolution_registry import EvolutionCandidateState, EvolutionRegistry
from aegis.evolution_validation import EvolutionValidator
from aegis.evolution_workspace import EvolutionPath, EvolutionPolicy, EvolutionWorkspace, ValidationCommand
from aegis.promotion_runtime import PromotionArmResult, PromotionBudgetUnavailable
from aegis.sandbox.fake import FakeSandboxBackend
from aegis.sandbox.types import DoctorCheck, DoctorReport


class NetworklessBackend(FakeSandboxBackend):
    def doctor(self) -> DoctorReport:
        return DoctorReport((DoctorCheck("network_none", True, "test"),))


def archive(value: bytes) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as tar:
        info = tarfile.TarInfo("adaptive/logic.py")
        info.size = len(value)
        info.mtime = 0
        tar.addfile(info, io.BytesIO(value))
    return stream.getvalue()


class EvolutionPromotionSchedulerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        repo = root / "repo"
        (repo / "adaptive").mkdir(parents=True)
        (repo / "adaptive" / "logic.py").write_bytes(b"old")
        self.workspace = EvolutionWorkspace(
            repo,
            EvolutionPolicy(
                evolvable_paths=(EvolutionPath("adaptive", recursive=True),),
                required_effective_paths=(),
                validation_commands=(ValidationCommand(("python", "-m", "pytest", "-q")),),
            ),
        )
        baseline = self.workspace.create_snapshot()
        self.artifact = self.workspace.candidate_from_archive(baseline, archive(b"new"))
        self.registry = EvolutionRegistry(root / "evolution.db")
        self.registry.register_collected(self.artifact, baseline)
        evidence = EvolutionValidator(NetworklessBackend()).validate(
            self.artifact, validation_id="promotion"
        )
        self.registry.record_validation(self.artifact.artifact_id, evidence)
        self.store = EventStore(root / "events.db")
        self.tasks = tuple(f"task-{index}" for index in range(12))

    def tearDown(self) -> None:
        self.store.close()
        self.registry.close()
        self.temp.cleanup()

    def scheduler(self, runner, *, can_start_pair=None, smoke_only=False) -> EvolutionPromotionScheduler:
        return EvolutionPromotionScheduler(
            self.registry,
            self.store,
            "campaign",
            self.tasks,
            runner,
            can_start_pair=can_start_pair,
            smoke_only=smoke_only,
        )

    def test_smoke_reused_by_full_design_and_promotes(self) -> None:
        calls = []

        def runner(**kwargs):
            calls.append(kwargs)
            candidate = kwargs["arm"] == "candidate"
            return PromotionArmResult(0.9 if candidate else 0.8, 90 if candidate else 100, True)

        summary = self.scheduler(runner).run_pending()
        self.assertEqual(summary.pairs_added, 24)
        self.assertEqual(len(calls), 48)
        self.assertEqual(summary.promoted, (self.artifact.artifact_id,))
        self.assertEqual(
            self.registry.candidate(self.artifact.artifact_id).state,
            EvolutionCandidateState.CHAMPION,
        )
        events = self.store.read("campaign")
        self.assertEqual(
            len([event for event in events if event.event_type == "evolution_promotion_observation_recorded"]),
            24,
        )

    def test_budget_resume_reuses_completed_arms_and_pairs(self) -> None:
        calls = 0

        def interrupted(**kwargs):
            nonlocal calls
            calls += 1
            if calls == 4:
                raise PromotionBudgetUnavailable("budget")
            return PromotionArmResult(0.9 if kwargs["arm"] == "candidate" else 0.8, 100, True)

        first = self.scheduler(interrupted).run_pending()
        self.assertTrue(first.pending_for_budget)
        resumed = []

        def runner(**kwargs):
            resumed.append(kwargs)
            return PromotionArmResult(0.9 if kwargs["arm"] == "candidate" else 0.8, 100, True)

        second = self.scheduler(runner).run_pending()
        self.assertEqual(second.promoted, (self.artifact.artifact_id,))
        self.assertEqual(len(resumed), 45)

    def test_smoke_safety_failure_is_terminal_without_full_run(self) -> None:
        calls = []

        def runner(**kwargs):
            calls.append(kwargs)
            violations = ("unsafe",) if kwargs["arm"] == "candidate" else ()
            return PromotionArmResult(0.9, 100, True, violations)

        summary = self.scheduler(runner).run_pending()
        self.assertEqual(summary.rejected, (self.artifact.artifact_id,))
        self.assertEqual(len(calls), 4)
        self.assertEqual(
            self.registry.candidate(self.artifact.artifact_id).state,
            EvolutionCandidateState.SUPERSEDED,
        )

    def test_smoke_only_promotes_after_smoke_pairs_without_full_run(self) -> None:
        calls = []

        def runner(**kwargs):
            calls.append(kwargs)
            candidate = kwargs["arm"] == "candidate"
            return PromotionArmResult(0.9 if candidate else 0.8, 90 if candidate else 100, True)

        summary = self.scheduler(runner, smoke_only=True).run_pending()
        self.assertEqual(summary.pairs_added, 2)
        self.assertEqual(len(calls), 4)
        self.assertEqual(summary.promoted, (self.artifact.artifact_id,))
        self.assertEqual(
            self.registry.candidate(self.artifact.artifact_id).state,
            EvolutionCandidateState.CHAMPION,
        )
        events = self.store.read("campaign")
        self.assertEqual(
            len(
                [
                    event
                    for event in events
                    if event.event_type == "evolution_promotion_observation_recorded"
                ]
            ),
            2,
        )
        self.assertTrue(
            any(event.event_type == "evolution_candidate_promoted" for event in events)
        )


if __name__ == "__main__":
    unittest.main()
