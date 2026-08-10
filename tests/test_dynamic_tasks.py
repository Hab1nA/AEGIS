from __future__ import annotations

import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from aegis.dynamic_tasks import (
    CohortTier,
    DynamicTaskCohort,
    DynamicTaskConflictError,
    DynamicTaskEligibilityError,
    DynamicTaskOrigin,
    DynamicTaskRegistry,
    DynamicTaskStatus,
    TaskForge,
)
from aegis.dynamic_tasks.forge import canonical_taskpack_archive
from aegis.taskpacks.manifest import TaskPack, compute_tree_hash
from aegis.taskpacks.validation import ExecutionResult


class RecordingRunner:
    def __init__(self, *, valid: bool = True) -> None:
        self.valid = valid
        self.calls: list[tuple[str, str]] = []

    def run(self, _pack: TaskPack, implementation_dir: str, suite: str) -> ExecutionResult:
        self.calls.append((implementation_dir, suite))
        if implementation_dir == "reference":
            return ExecutionResult(True, 3, 0, output_digest="reference passed")
        if implementation_dir == "defect":
            passed = suite == "public"
            return ExecutionResult(passed, 3, 0 if passed else 1, output_digest="defect checked")
        return ExecutionResult(
            not self.valid,
            3,
            0 if not self.valid else 1,
            output_digest="mutant checked",
        )


def make_pack(root: Path, task_id: str, marker: str) -> TaskPack:
    for relative in ("public", "hidden", "reference", "defect", "mutants/one"):
        directory = root / relative
        directory.mkdir(parents=True)
        (directory / "marker.txt").write_text(f"{marker}:{relative}\n", encoding="utf-8")
    (root / "prompt.md").write_text(f"Repair {marker}.\n", encoding="utf-8")
    content_hash = compute_tree_hash(root, exclude=frozenset({"manifest.json"}))
    manifest = {
        "task_id": task_id,
        "version": 1,
        "language": "python",
        "public_dir": "public",
        "hidden_dir": "hidden",
        "reference_dir": "reference",
        "defect_dir": "defect",
        "mutant_dirs": ["mutants/one"],
        "content_hash": content_hash,
    }
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return TaskPack.load(root)


class DynamicTaskTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = self.root / "dynamic-tasks.sqlite3"
        self.registry = DynamicTaskRegistry(self.db)
        self.forge = TaskForge(self.registry)

    def tearDown(self) -> None:
        self.registry.close()
        self.temp.cleanup()

    def forge_task(
        self,
        name: str,
        *,
        generation: int = 1,
        delay: int = 1,
        origin: DynamicTaskOrigin = DynamicTaskOrigin.DYNAMIC,
        valid: bool = True,
    ):
        pack = make_pack(self.root / f"pack-{name}", f"python-{name}", name)
        runner = RecordingRunner(valid=valid)
        record = self.forge.forge(
            pack,
            runner,
            creator_generation=generation,
            source_spec_id=f"challenge:{name}",
            source_evidence_ids=(f"research:{name}",),
            holdout_delay=delay,
            origin=origin,
        )
        return record, runner

    def test_forge_reuses_taskpack_validation_and_deduplicates_content(self) -> None:
        pack = make_pack(self.root / "dedupe", "python-dedupe", "same")
        first_runner = RecordingRunner()
        first = self.forge.forge(
            pack,
            first_runner,
            creator_generation=1,
            source_spec_id="challenge:first",
            source_evidence_ids=("research:first",),
        )
        second = self.forge.forge(
            pack,
            RecordingRunner(),
            creator_generation=9,
            source_spec_id="challenge:attempted-delay-bypass",
            source_evidence_ids=("research:second",),
        )

        self.assertEqual(
            first_runner.calls,
            [
                ("reference", "public"),
                ("reference", "hidden"),
                ("defect", "public"),
                ("defect", "hidden"),
                ("mutants/one", "hidden"),
            ],
        )
        self.assertEqual(first, second)
        self.assertEqual(second.creator_generation, 1)
        self.assertEqual(second.source_spec_id, "challenge:first")
        self.assertEqual(len(self.registry.records()), 1)
        self.assertEqual(self.registry.archive(first.artifact.artifact_id), self.registry.archive(second.artifact.artifact_id))
        self.assertTrue(first.validation.valid)
        self.assertEqual(first.status, DynamicTaskStatus.QUARANTINED)
        with self.assertRaises(DynamicTaskConflictError):
            self.forge.forge(
                pack,
                RecordingRunner(),
                creator_generation=1,
                source_spec_id="anchor:cannot-reclassify",
                source_evidence_ids=(),
                origin=DynamicTaskOrigin.FIXED_ANCHOR,
            )

    def test_invalid_task_is_rejected_by_existing_validation_gate(self) -> None:
        rejected, _ = self.forge_task("surviving-mutant", valid=False)
        self.assertEqual(rejected.status, DynamicTaskStatus.REJECTED)
        self.assertFalse(rejected.validation.valid)
        self.assertIn("does not kill mutants", rejected.validation.reasons[0])
        self.assertEqual(self.registry.select_dynamic_cohort(2).members, ())
        with self.assertRaises(DynamicTaskEligibilityError):
            self.registry.record_holdout(
                rejected.artifact.artifact_id,
                evaluated_generation=2,
                accepted=True,
                evidence_id="holdout:invalid",
                expected_revision=rejected.revision,
            )

    def test_same_generation_cannot_self_prove_and_holdout_is_delayed(self) -> None:
        record, _ = self.forge_task("delayed", generation=2, delay=2)

        self.assertEqual(self.registry.select_dynamic_cohort(2).members, ())
        self.assertEqual(self.registry.select_dynamic_cohort(3).members, ())
        cohort = self.registry.select_dynamic_cohort(4)
        self.assertEqual([member.artifact_id for member in cohort.members], [record.artifact.artifact_id])
        self.assertEqual(cohort.members[0].tier, CohortTier.FRESH_HOLDOUT)
        with self.assertRaisesRegex(DynamicTaskEligibilityError, "same-generation or premature"):
            self.registry.record_holdout(
                record.artifact.artifact_id,
                evaluated_generation=3,
                accepted=True,
                evidence_id="holdout:too-early",
                expected_revision=record.revision,
            )

    def test_fresh_holdout_promotes_to_hall_of_fame_and_replays(self) -> None:
        record, _ = self.forge_task("hof")
        held = self.registry.record_holdout(
            record.artifact.artifact_id,
            evaluated_generation=2,
            accepted=True,
            evidence_id="cross-play:accepted",
            expected_revision=record.revision,
        )
        self.assertEqual(held.status, DynamicTaskStatus.HOLDOUT_PASSED)
        self.assertEqual(self.registry.select_dynamic_cohort(2).members, ())
        champion = self.registry.promote_hall_of_fame(
            held.artifact.artifact_id,
            expected_revision=held.revision,
        )
        self.assertEqual(champion.status, DynamicTaskStatus.HALL_OF_FAME)
        cohort = self.registry.select_dynamic_cohort(3)
        self.assertEqual(cohort.members[0].tier, CohortTier.HALL_OF_FAME)

        self.registry.close()
        self.registry = DynamicTaskRegistry(self.db)
        replayed = self.registry.record(champion.artifact.artifact_id)
        self.assertEqual(replayed, champion)
        self.assertEqual(self.registry.select_dynamic_cohort(3), cohort)

    def test_holdout_failure_is_terminal_and_never_enters_cohort(self) -> None:
        record, _ = self.forge_task("failed-holdout")
        failed = self.registry.record_holdout(
            record.artifact.artifact_id,
            evaluated_generation=2,
            accepted=False,
            evidence_id="cross-play:failed",
            expected_revision=record.revision,
        )
        self.assertEqual(failed.status, DynamicTaskStatus.REJECTED)
        self.assertEqual(self.registry.select_dynamic_cohort(3).members, ())
        with self.assertRaises(DynamicTaskEligibilityError):
            self.registry.promote_hall_of_fame(
                failed.artifact.artifact_id,
                expected_revision=failed.revision,
            )

    def test_cas_allows_one_transition_and_rejects_stale_controller(self) -> None:
        record, _ = self.forge_task("cas")
        other = DynamicTaskRegistry(self.db)
        try:
            first = self.registry.record_holdout(
                record.artifact.artifact_id,
                evaluated_generation=2,
                accepted=True,
                evidence_id="cross-play:first",
                expected_revision=record.revision,
            )
            with self.assertRaises(DynamicTaskConflictError):
                other.record_holdout(
                    record.artifact.artifact_id,
                    evaluated_generation=2,
                    accepted=True,
                    evidence_id="cross-play:stale",
                    expected_revision=record.revision,
                )
            self.assertEqual(other.record(record.artifact.artifact_id), first)
        finally:
            other.close()

    def test_v2_promotion_cohort_is_pure_dynamic_and_excludes_fixed_twelve(self) -> None:
        anchors = [
            self.forge_task(
                f"anchor-{index}",
                origin=DynamicTaskOrigin.FIXED_ANCHOR,
            )[0]
            for index in range(12)
        ]
        dynamics = [self.forge_task(f"dynamic-{index}")[0] for index in range(3)]

        cohort = self.registry.select_dynamic_cohort(2)
        selected = {member.artifact_id for member in cohort.members}
        self.assertEqual(selected, {record.artifact.artifact_id for record in dynamics})
        self.assertTrue(
            selected.isdisjoint({record.artifact.artifact_id for record in anchors})
        )
        self.assertTrue(all(member.tier is CohortTier.FRESH_HOLDOUT for member in cohort.members))
        self.assertTrue(
            all(
                self.registry.record(member.artifact_id).origin is DynamicTaskOrigin.DYNAMIC
                and self.registry.record(member.artifact_id).creator_generation < 2
                for member in cohort.members
            )
        )

    def test_cohort_selection_is_deterministic_content_addressed_and_limited(self) -> None:
        for index in range(5):
            self.forge_task(f"cohort-{index}")
        first = self.registry.select_dynamic_cohort(2, limit=3)
        second = self.registry.select_dynamic_cohort(2, limit=3)
        all_members = self.registry.select_dynamic_cohort(2)

        self.assertEqual(first, second)
        self.assertEqual(len(first.members), 3)
        self.assertEqual(first.members, all_members.members[:3])
        self.assertEqual(DynamicTaskCohort.from_mapping(first.to_mapping()), first)
        self.assertTrue(first.cohort_id.startswith("dynamic-cohort-sha256:"))

    def test_hall_of_fame_retirement_is_durable_and_removes_eligibility(self) -> None:
        record, _ = self.forge_task("retired")
        held = self.registry.record_holdout(
            record.artifact.artifact_id,
            evaluated_generation=2,
            accepted=True,
            evidence_id="cross-play:passed",
            expected_revision=record.revision,
        )
        champion = self.registry.promote_hall_of_fame(
            held.artifact.artifact_id,
            expected_revision=held.revision,
        )
        retired = self.registry.retire(
            champion.artifact.artifact_id,
            "obsolete coverage",
            expected_revision=champion.revision,
        )
        self.assertEqual(retired.status, DynamicTaskStatus.RETIRED)
        self.assertEqual(self.registry.select_dynamic_cohort(4).members, ())

    def test_judge_can_submit_a_complete_archive_to_the_isolated_forge(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pack = make_pack(Path(directory), "archive-task", "judge")
            archive = canonical_taskpack_archive(pack)
        record = self.forge.forge_archive(
            archive,
            RecordingRunner(),
            creator_generation=1,
            source_spec_id="judge-proposal:archive-task",
            source_evidence_ids=("research:archive-task",),
        )
        self.assertEqual(record.artifact.task_id, "archive-task")
        self.assertEqual(record.status, DynamicTaskStatus.QUARANTINED)

    def test_untrusted_task_archive_rejects_traversal_and_symlinks(self) -> None:
        for kind in ("traversal", "symlink"):
            with self.subTest(kind=kind):
                output = io.BytesIO()
                with tarfile.open(fileobj=output, mode="w") as archive:
                    info = tarfile.TarInfo("../escape" if kind == "traversal" else "unsafe-link")
                    if kind == "symlink":
                        info.type = tarfile.SYMTYPE
                        info.linkname = "manifest.json"
                        archive.addfile(info)
                    else:
                        payload = b"escape"
                        info.size = len(payload)
                        archive.addfile(info, io.BytesIO(payload))
                with self.assertRaisesRegex(ValueError, "unsafe path|only files"):
                    self.forge.forge_archive(
                        output.getvalue(),
                        RecordingRunner(),
                        creator_generation=1,
                        source_spec_id=f"judge-proposal:{kind}",
                        source_evidence_ids=(f"research:{kind}",),
                    )


if __name__ == "__main__":
    unittest.main()
