from __future__ import annotations

import hashlib
import unittest
from dataclasses import FrozenInstanceError, replace

from aegis.attribution import (
    AttributionDisposition,
    AttributionReport,
    EvaluationArm,
    PairedObservation,
    QualificationPath,
    QualificationPolicy,
    RoleGeneration,
    qualify_attribution,
)


def role_generation(role: str, generation: int) -> RoleGeneration:
    digest = hashlib.sha256(f"{role}:{generation}".encode()).hexdigest()
    return RoleGeneration(role, generation, f"role-version-sha256:{digest}")


def arm(
    *,
    target_generation: int,
    task_id: str = "dynamic-task-1",
    seed: int = 7,
    quality: float = 0.70,
    cost_units: int = 100,
    **changes: object,
) -> EvaluationArm:
    values: dict[str, object] = {
        "cycle_id": "cycle-8",
        "objective_id": "objective-sha256:" + "a" * 64,
        "task_id": task_id,
        "seed": seed,
        "model_id": "model-snapshot-2026-08",
        "environment_id": "sandbox-image-sha256:" + "b" * 64,
        "plugin_ids": ("filesystem-v2", "python-v1"),
        "role_generations": (
            role_generation("judge", 3),
            role_generation("prosecutor", 5),
            role_generation("warrior", target_generation),
        ),
        "quality": quality,
        "cost_units": cost_units,
        "usage_verified": True,
        "safety_passed": True,
        "integrity_passed": True,
    }
    values.update(changes)
    return EvaluationArm(**values)  # type: ignore[arg-type]


def pair(
    *,
    task_id: str = "dynamic-task-1",
    seed: int = 7,
    baseline_quality: float = 0.70,
    candidate_quality: float = 0.74,
    baseline_cost: int = 100,
    candidate_cost: int = 105,
    baseline_changes: dict[str, object] | None = None,
    candidate_changes: dict[str, object] | None = None,
) -> PairedObservation:
    baseline = arm(
        target_generation=4,
        task_id=task_id,
        seed=seed,
        quality=baseline_quality,
        cost_units=baseline_cost,
        **(baseline_changes or {}),
    )
    candidate = arm(
        target_generation=5,
        task_id=task_id,
        seed=seed,
        quality=candidate_quality,
        cost_units=candidate_cost,
        **(candidate_changes or {}),
    )
    return PairedObservation.create("warrior", baseline, candidate)


class AttributionV2Tests(unittest.TestCase):
    def test_observation_and_report_are_content_addressed_immutable_and_replayable(self) -> None:
        observation = pair()
        replayed_observation = PairedObservation.from_mapping(observation.to_mapping())
        report = qualify_attribution((observation,))
        replayed_report = AttributionReport.from_mapping(report.to_mapping())

        self.assertEqual(replayed_observation, observation)
        self.assertEqual(replayed_report, report)
        self.assertTrue(observation.observation_id.startswith("attribution-observation-sha256:"))
        self.assertTrue(report.report_id.startswith("attribution-report-sha256:"))
        with self.assertRaises(FrozenInstanceError):
            report.quality_delta = 1.0  # type: ignore[misc]

        tampered = report.to_mapping()
        tampered["quality_delta"] = 0.5
        with self.assertRaisesRegex(ValueError, "does not match"):
            AttributionReport.from_mapping(tampered)

    def test_only_target_role_generation_may_differ_between_arms(self) -> None:
        clean = pair()
        self.assertEqual(clean.confounded_fields(), ())
        self.assertTrue(qualify_attribution((clean,)).qualified)

        scalar_changes: dict[str, object] = {
            "cycle_id": "cycle-9",
            "objective_id": "objective-sha256:" + "c" * 64,
            "task_id": "another-task",
            "seed": 8,
            "model_id": "another-model",
            "environment_id": "another-environment",
        }
        for field, changed in scalar_changes.items():
            with self.subTest(field=field):
                observation = PairedObservation.create(
                    "warrior",
                    clean.baseline,
                    replace(clean.candidate, **{field: changed}),
                )
                report = qualify_attribution((observation,))
                self.assertEqual(report.disposition, AttributionDisposition.CONFOUNDED)
                self.assertIn(field, report.reason)

        changed_teammate = replace(
            clean.candidate,
            role_generations=(
                role_generation("judge", 4),
                role_generation("prosecutor", 5),
                role_generation("warrior", 5),
            ),
        )
        teammate_report = qualify_attribution(
            (PairedObservation.create("warrior", clean.baseline, changed_teammate),)
        )
        self.assertEqual(teammate_report.disposition, AttributionDisposition.CONFOUNDED)
        self.assertIn("teammate_generation:judge", teammate_report.reason)

        unchanged_target = replace(clean.candidate, role_generations=clean.baseline.role_generations)
        target_report = qualify_attribution(
            (PairedObservation.create("warrior", clean.baseline, unchanged_target),)
        )
        self.assertEqual(target_report.disposition, AttributionDisposition.CONFOUNDED)
        self.assertIn("target_role_generation", target_report.reason)

    def test_single_plugin_intervention_is_attributable(self) -> None:
        plugin_report = qualify_attribution(
            (
                pair(
                    baseline_changes={"plugin_ids": ("filesystem-v2",)},
                    candidate_changes={"plugin_ids": ("filesystem-v2", "python-v1")},
                ),
            )
        )
        self.assertEqual(plugin_report.disposition, AttributionDisposition.QUALIFIED)
        self.assertIn("plugin_ids", plugin_report.reason)

        unchanged_quality = qualify_attribution(
            (
                pair(
                    baseline_quality=0.70,
                    candidate_quality=0.70,
                    baseline_changes={"plugin_ids": ("filesystem-v2",)},
                    candidate_changes={"plugin_ids": ("filesystem-v2", "python-v1")},
                ),
            )
        )
        self.assertEqual(unchanged_quality.disposition, AttributionDisposition.NOT_QUALIFIED)

    def test_single_runtime_variant_intervention_is_attributable(self) -> None:
        variant_report = qualify_attribution(
            (
                pair(
                    baseline_changes={"runtime_variant": "image=default;plugins=no-plugins"},
                    candidate_changes={"runtime_variant": "image=sha256:image;plugins=no-plugins"},
                ),
            )
        )
        self.assertEqual(variant_report.disposition, AttributionDisposition.QUALIFIED)
        self.assertIn("runtime_variant", variant_report.reason)

        multi_coordinate = qualify_attribution(
            (
                pair(
                    baseline_changes={
                        "plugin_ids": ("filesystem-v2",),
                        "runtime_variant": "image=default;plugins=no-plugins",
                    },
                    candidate_changes={
                        "plugin_ids": ("filesystem-v2", "python-v1"),
                        "runtime_variant": "image=sha256:image;plugins=python-v1",
                    },
                ),
            )
        )
        self.assertEqual(multi_coordinate.disposition, AttributionDisposition.CONFOUNDED)

    def test_cross_observation_intervention_tuple_is_locked(self) -> None:
        first = pair(task_id="task-a", seed=1)
        second = pair(
            task_id="task-b",
            seed=2,
            baseline_changes={"model_id": "model-b"},
            candidate_changes={"model_id": "model-b"},
        )
        report = qualify_attribution((first, second))

        self.assertEqual(report.disposition, AttributionDisposition.CONFOUNDED)
        self.assertIn("cohort changes", report.reason)

    def test_safety_and_integrity_are_non_compensable(self) -> None:
        failures = (
            ("safety_passed", False, AttributionDisposition.SAFETY_REJECTED),
            ("integrity_passed", False, AttributionDisposition.INTEGRITY_REJECTED),
        )
        for field, value, expected in failures:
            for target_arm in ("baseline", "candidate"):
                with self.subTest(field=field, arm=target_arm):
                    kwargs = {f"{target_arm}_changes": {field: value}}
                    observation = pair(
                        baseline_quality=0.0,
                        candidate_quality=1.0,
                        candidate_cost=1,
                        **kwargs,  # type: ignore[arg-type]
                    )
                    report = qualify_attribution((observation,))
                    self.assertFalse(report.qualified)
                    self.assertEqual(report.disposition, expected)
                    self.assertEqual(report.qualification_path, QualificationPath.NONE)

    def test_unverified_usage_blocks_efficiency_but_not_quality(self) -> None:
        quality = qualify_attribution(
            (pair(baseline_changes={"usage_verified": False}),)
        )
        efficiency = qualify_attribution(
            (
                pair(
                    baseline_quality=0.70,
                    candidate_quality=0.695,
                    candidate_cost=80,
                    candidate_changes={"usage_verified": False},
                ),
            )
        )
        self.assertEqual(quality.qualification_path, QualificationPath.QUALITY_IMPROVEMENT)
        self.assertEqual(efficiency.disposition, AttributionDisposition.UNVERIFIED_USAGE)

    def test_quality_improvement_with_cost_cap_qualifies(self) -> None:
        report = qualify_attribution(
            (
                pair(task_id="a", seed=1, baseline_quality=0.60, candidate_quality=0.64),
                pair(task_id="b", seed=2, baseline_quality=0.70, candidate_quality=0.74),
            )
        )

        self.assertTrue(report.qualified)
        self.assertEqual(report.qualification_path, QualificationPath.QUALITY_IMPROVEMENT)
        self.assertAlmostEqual(report.quality_delta, 0.04)
        self.assertAlmostEqual(report.cost_change, 0.05)

    def test_quality_noninferiority_with_cost_saving_qualifies(self) -> None:
        report = qualify_attribution(
            (
                pair(
                    task_id="a",
                    seed=1,
                    baseline_quality=0.70,
                    candidate_quality=0.695,
                    candidate_cost=80,
                ),
                pair(
                    task_id="b",
                    seed=2,
                    baseline_quality=0.80,
                    candidate_quality=0.795,
                    candidate_cost=80,
                ),
            )
        )

        self.assertTrue(report.qualified)
        self.assertEqual(report.qualification_path, QualificationPath.COST_EFFICIENCY)
        self.assertAlmostEqual(report.quality_delta, -0.005)
        self.assertAlmostEqual(report.cost_change, -0.2)

    def test_neither_path_and_zero_baseline_cost_fail_closed(self) -> None:
        ordinary = qualify_attribution(
            (pair(baseline_quality=0.70, candidate_quality=0.69, candidate_cost=95),)
        )
        zero_baseline = qualify_attribution(
            (pair(baseline_cost=0, candidate_cost=0),)
        )

        self.assertEqual(ordinary.disposition, AttributionDisposition.NOT_QUALIFIED)
        self.assertEqual(zero_baseline.disposition, AttributionDisposition.QUALIFIED)
        self.assertEqual(zero_baseline.qualification_path, QualificationPath.QUALITY_IMPROVEMENT)

    def test_reordering_replays_same_report_and_duplicates_are_rejected(self) -> None:
        first = pair(task_id="a", seed=1)
        second = pair(task_id="b", seed=2)
        forward = qualify_attribution((first, second))
        reverse = qualify_attribution((second, first))
        duplicate = qualify_attribution((first, first))

        self.assertEqual(forward, reverse)
        self.assertEqual(forward.report_id, reverse.report_id)
        self.assertEqual(duplicate.disposition, AttributionDisposition.INVALID_DESIGN)

    def test_policy_is_integrity_bound_and_minimum_pair_count_is_enforced(self) -> None:
        policy = QualificationPolicy(minimum_pairs=2, quality_improvement=0.03)
        report = qualify_attribution((pair(),), policy)

        self.assertEqual(report.disposition, AttributionDisposition.INVALID_DESIGN)
        self.assertEqual(report.policy, policy)
        tampered = report.to_mapping()
        assert isinstance(tampered["policy"], dict)
        tampered["policy"]["quality_improvement"] = 0.0
        with self.assertRaisesRegex(ValueError, "does not match"):
            AttributionReport.from_mapping(tampered)


if __name__ == "__main__":
    unittest.main()
