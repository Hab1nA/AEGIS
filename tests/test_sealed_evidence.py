from __future__ import annotations

import unittest
from dataclasses import replace

from aegis.evolution.sealed_evaluation import (
    CandidateEvaluationDesign,
    EvaluationTaskBinding,
    EvaluationTier,
    SealedArmEvidence,
)


class SealedEvidenceTests(unittest.TestCase):
    def _design(self) -> CandidateEvaluationDesign:
        return CandidateEvaluationDesign.create(
            campaign_id="campaign-1",
            cycle_id="cycle-4",
            snapshot_id="snapshot-sha256:" + "1" * 64,
            objective_id="objective-sha256:" + "2" * 64,
            candidate_id="evolution-candidate-sha256:" + "3" * 64,
            surface="harness-code",
            target_role="warrior",
            cohort_id="cohort-sha256:" + "4" * 64,
            tasks=(
                EvaluationTaskBinding("fresh", "artifact:a", 1, EvaluationTier.FRESH, "a" * 64),
                EvaluationTaskBinding("hof", "artifact:b", 2, EvaluationTier.REGRESSION, "b" * 64),
            ),
            seeds=(0, 1),
            baseline_runtime_id="commit:" + "5" * 40,
            candidate_runtime_id="commit:" + "6" * 40,
            runtime_policy_id="runtime-policy-sha256:" + "7" * 64,
            evaluator_fingerprint="image-sha256:" + "8" * 64,
            public_weight=0.25,
            hidden_weight=0.75,
            gate_policy_sha256="9" * 64,
        )

    def test_design_and_arm_evidence_are_content_addressed(self) -> None:
        design = self._design()
        evidence = SealedArmEvidence.create(
            design_id=design.design_id,
            seed=0,
            arm="candidate",
            workspace_artifact_id="artifact-sha256:" + "a" * 64,
            workspace_sha256="b" * 64,
            runtime_id=design.candidate_runtime_id,
            role_generation_id="role-generation-sha256:" + "c" * 64,
            plugin_ids=(),
            mcp_ids=(),
            environment_id="environment-sha256:" + "d" * 64,
            task_result_ids=("task-result-sha256:" + "e" * 64,),
            evaluator_fingerprint=design.evaluator_fingerprint,
            verified_usage_units=None,
            integrity_passed=True,
        )

        self.assertTrue(design.design_id.startswith("candidate-evaluation-design-sha256:"))
        self.assertTrue(evidence.evidence_id.startswith("sealed-arm-evidence-sha256:"))
        with self.assertRaisesRegex(ValueError, "content id mismatch"):
            replace(design, design_id="bad")

    def test_design_requires_fresh_and_regression_tiers(self) -> None:
        design = self._design()
        values = design.to_mapping(include_id=False)
        values["tasks"] = (design.tasks[0],)
        values["seeds"] = design.seeds
        with self.assertRaisesRegex(ValueError, "regression"):
            CandidateEvaluationDesign.create(**values)


if __name__ == "__main__":
    unittest.main()
