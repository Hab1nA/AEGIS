from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from aegis.dynamic_tasks import (
    CohortTier,
    DynamicTaskOrigin,
    DynamicTaskRegistry,
    DynamicTaskStatus,
    GenesisSeeder,
    TaskForge,
)
from aegis.taskpacks.builtin import load_builtin_python_taskpacks
from aegis.taskpacks.manifest import TaskPack
from aegis.taskpacks.validation import ExecutionResult


class AnchorRunner:
    """Deterministic runner: reference passes; defect and mutants always fail."""

    def run(self, pack, implementation_dir: str, suite: str) -> ExecutionResult:
        passed = implementation_dir == pack.manifest.reference_dir
        return ExecutionResult(
            passed=passed,
            tests_run=1,
            exit_code=0 if passed else 1,
            timed_out=False,
            output_digest="anchor",
        )


class GenesisSeederTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.registry = DynamicTaskRegistry(self.root / "tasks.sqlite3")
        self.runner = AnchorRunner()
        self.seeder = GenesisSeeder(self.registry, TaskForge(self.registry))

    def tearDown(self) -> None:
        self.registry.close()
        self.temporary.cleanup()

    def test_seed_registers_all_builtin_anchors_and_is_idempotent(self) -> None:
        records = self.seeder.seed(self.runner)
        builtin = load_builtin_python_taskpacks()
        self.assertEqual(len(records), len(builtin))
        self.assertEqual(
            {record.artifact.task_id for record in records},
            {pack.manifest.task_id for pack in builtin},
        )
        self.assertTrue(all(record.status is DynamicTaskStatus.FIXED_ANCHOR for record in records))
        self.assertTrue(all(record.origin is DynamicTaskOrigin.FIXED_ANCHOR for record in records))

        self.assertEqual(self.seeder.seed(self.runner), ())
        self.assertEqual(len(self.registry.records()), len(builtin))

    def test_empty_bank_cold_starts_from_anchors(self) -> None:
        self.seeder.seed(self.runner)
        cohort = self.registry.select_dynamic_cohort(2)
        self.assertTrue(cohort.members)
        self.assertTrue(all(member.tier is CohortTier.HALL_OF_FAME for member in cohort.members))
        self.assertEqual(
            {member.artifact_id for member in cohort.members},
            {record.artifact.artifact_id for record in self.registry.records()},
        )

    def test_anchors_disappear_once_a_dynamic_task_is_eligible(self) -> None:
        self.seeder.seed(self.runner)
        source = sorted(
            load_builtin_python_taskpacks(), key=lambda item: item.manifest.task_id
        )[0]
        copied_root = self.root / "copied-pack"
        shutil.copytree(source.root, copied_root)
        manifest_path = copied_root / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["task_id"] = "dynamic-genesis-copy"
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        pack = TaskPack.load(copied_root)
        self.assertNotEqual(pack.manifest.task_id, source.manifest.task_id)
        TaskForge(self.registry).forge(
            pack,
            self.runner,
            creator_generation=1,
            source_spec_id="dynamic:genesis",
            source_evidence_ids=("research:genesis-evidence",),
            holdout_delay=1,
            origin=DynamicTaskOrigin.DYNAMIC,
        )
        cohort = self.registry.select_dynamic_cohort(2)
        self.assertEqual(len(cohort.members), 1)
        self.assertIs(cohort.members[0].tier, CohortTier.FRESH_HOLDOUT)
        registered = self.registry.record(cohort.members[0].artifact_id)
        self.assertEqual(registered.artifact.task_id, "dynamic-genesis-copy")

    def test_anchors_backfill_and_fresh_wins_priority_under_limit(self) -> None:
        self.seeder.seed(self.runner)
        source = sorted(
            load_builtin_python_taskpacks(), key=lambda item: item.manifest.task_id
        )[0]
        copied_root = self.root / "copied-pack-2"
        shutil.copytree(source.root, copied_root)
        manifest_path = copied_root / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["task_id"] = "dynamic-genesis-copy-2"
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        TaskForge(self.registry).forge(
            TaskPack.load(copied_root),
            self.runner,
            creator_generation=1,
            source_spec_id="dynamic:genesis-2",
            source_evidence_ids=("research:genesis-evidence-2",),
            holdout_delay=1,
            origin=DynamicTaskOrigin.DYNAMIC,
        )
        cohort = self.registry.select_dynamic_cohort(2, limit=3)
        # The fresh dynamic task leads the cohort and anchors only backfill.
        self.assertIs(cohort.members[0].tier, CohortTier.FRESH_HOLDOUT)
        self.assertEqual(len(cohort.members), 3)
        self.assertTrue(
            all(member.tier is CohortTier.HALL_OF_FAME for member in cohort.members[1:])
        )
