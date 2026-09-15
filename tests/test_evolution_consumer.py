from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from aegis.artifacts import ContentAddressedArtifactStore
from aegis.event_store import EventStore
from aegis.evolution.consumer import consume_cycle_proposals
from aegis.evolution.registry import CandidateState, EvolutionRegistry
from aegis.evolution.surfaces import EvolutionSurface
from aegis.models import Role


def workflow() -> dict[str, object]:
    return {
        "stage_plan": ["inspect", "implement"],
        "research_query_templates": ["python behavior"],
        "tool_selection_rules": ["use sandbox.exec for tests"],
        "stop_conditions": ["stop when tests pass"],
        "verification_checklist": ["run public tests"],
        "skill_references": ["python"],
        "max_steps": None,
    }


class EvolutionConsumerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._root = tempfile.TemporaryDirectory(prefix="aegis-consumer-")
        self.root = Path(self._root.name)
        self.artifacts = ContentAddressedArtifactStore(self.root / "artifacts")
        self.store = EventStore(self.root / "events.sqlite3")
        self.registry = EvolutionRegistry(self.store, "campaign")
        self.objective = "objective-sha256:" + "a" * 64

    def tearDown(self) -> None:
        self.store.close()
        self._root.cleanup()

    def test_consumes_strategy_proposals_from_evidence_payload(self) -> None:
        submission = {
            "role": "warrior",
            "submission": {
                "results": [],
                "strategy_proposals": [
                    {
                        "proposal_id": "p1",
                        "target_role": "warrior",
                        "content": workflow(),
                        "rationale": "improve workflow",
                    }
                ],
            },
        }
        consumed = consume_cycle_proposals(
            registry=self.registry,
            artifacts=self.artifacts,
            submission=submission,
            prosecutor_audit={},
            objective_id=self.objective,
            collection_evidence_id="cycle:1:eval",
        )
        self.assertEqual(len(consumed), 1)
        self.assertTrue(consumed[0].collected)
        self.assertTrue(consumed[0].validated)
        self.assertIs(consumed[0].surface, EvolutionSurface.WORKFLOW)
        self.assertIs(consumed[0].target_role, Role.WARRIOR)
        records = self.registry.candidates()
        self.assertEqual(len(records), 1)
        self.assertIs(records[0].state, CandidateState.VALIDATED)

    def test_reflection_proposals_targeting_non_warrior_are_rejected_at_collection(self) -> None:
        consumed = consume_cycle_proposals(
            registry=self.registry,
            artifacts=self.artifacts,
            submission={},
            prosecutor_audit={},
            objective_id=self.objective,
            collection_evidence_id="cycle:1:eval",
            reflections=[
                {
                    "proposals": [
                        {
                            "proposal_id": "w1",
                            "target_role": "warrior",
                            "content": workflow(),
                            "rationale": "warrior workflow",
                        },
                        {
                            "proposal_id": "j1",
                            "target_role": "judge",
                            "content": workflow(),
                            "rationale": "judge workflow",
                        },
                    ]
                }
            ],
        )
        self.assertEqual(len(consumed), 2)
        by_id = {item.proposal_id: item for item in consumed}
        self.assertTrue(by_id["w1"].collected and by_id["w1"].validated)
        # The judge-target reflection proposal is rejected at collection:
        # non-Warrior targets have no shadow attribution, so registering it
        # would only guarantee a later rejection.
        self.assertFalse(by_id["j1"].collected)
        self.assertFalse(by_id["j1"].validated)
        self.assertIn("may only target the Warrior", by_id["j1"].error)
        records = self.registry.candidates()
        self.assertEqual(len(records), 1)
        self.assertIs(records[0].state, CandidateState.VALIDATED)

    def test_consumes_evolution_request_proposal_and_subject_role_candidates(self) -> None:
        submission = {
            "role": "warrior",
            "submission": {
                "evolution_requests": [
                    {
                        "objective": "add a stop condition",
                        "rationale": "evidence",
                        "source_refs": [],
                        "proposal": {
                            "surface": "workflow",
                            "target_role": "warrior",
                            "content": workflow(),
                        },
                    }
                ]
            },
        }
        audit = {
            "role_candidates": {
                "judge": {
                    "artifact_id": "subject-sha256:" + "b" * 64,
                    "artifact_sha256": "b" * 64,
                    "content": {
                        "content_markdown": "Be rigorous and bounded.",
                        "rationale": "sharpening",
                    },
                }
            }
        }
        consumed = consume_cycle_proposals(
            registry=self.registry,
            artifacts=self.artifacts,
            submission=submission,
            prosecutor_audit=audit,
            objective_id=self.objective,
            collection_evidence_id="cycle:1:eval",
        )
        by_surface = {item.surface: item for item in consumed}
        self.assertIn(EvolutionSurface.WORKFLOW, by_surface)
        self.assertIn(EvolutionSurface.SUBJECT, by_surface)
        self.assertIs(by_surface[EvolutionSurface.SUBJECT].target_role, Role.JUDGE)
        # The Warrior workflow proposal is collected and validated; the
        # Prosecutor's JUDGE-target subject nomination is rejected at
        # collection (only Warrior-target candidates are shadow-evaluated).
        workflow_item = by_surface[EvolutionSurface.WORKFLOW]
        self.assertTrue(workflow_item.collected and workflow_item.validated)
        subject_item = by_surface[EvolutionSurface.SUBJECT]
        self.assertFalse(subject_item.collected)
        self.assertIn("only Warrior-target", subject_item.error)

    def test_opt_in_surfaces_are_consumed_when_enabled_and_rejected_when_not(self) -> None:
        from aegis.evolution.control_core import DEFAULT_CONTROL_CORE_POLICY

        submission = {
            "role": "warrior",
            "submission": {
                "evolution_requests": [
                    {
                        "objective": "tune inner promotion gate",
                        "rationale": "evidence",
                        "source_refs": [],
                        "proposal": {
                            "surface": "control-core",
                            "target_role": "warrior",
                            "content": DEFAULT_CONTROL_CORE_POLICY.to_mapping(),
                        },
                    }
                ]
            },
        }
        enabled = consume_cycle_proposals(
            registry=self.registry,
            artifacts=self.artifacts,
            submission=submission,
            prosecutor_audit={},
            objective_id=self.objective,
            collection_evidence_id="cycle:1:eval",
            enabled_surfaces=["workflow", "subject", "plugin", "environment", "control-core"],
        )
        self.assertEqual(len(enabled), 1)
        self.assertTrue(enabled[0].collected)
        self.assertTrue(enabled[0].validated)
        self.assertIs(enabled[0].surface, EvolutionSurface.CONTROL_CORE)

        disabled = consume_cycle_proposals(
            registry=EvolutionRegistry(self.store, "campaign-b"),
            artifacts=ContentAddressedArtifactStore(self.root / "artifacts-b"),
            submission=submission,
            prosecutor_audit={},
            objective_id=self.objective,
            collection_evidence_id="cycle:1:eval",
            enabled_surfaces=["workflow", "subject", "plugin", "environment"],
        )
        self.assertEqual(len(disabled), 1)
        self.assertFalse(disabled[0].collected)
        self.assertIn("not enabled", disabled[0].error or "")

    def test_rejects_invalid_and_non_materializable_proposals(self) -> None:
        submission = {
            "role": "warrior",
            "submission": {
                "evolution_requests": [
                    {
                        "objective": "bad",
                        "rationale": "x",
                        "source_refs": [],
                        "proposal": {
                            "surface": "environment",
                            "target_role": "judge",
                            "content": {},
                        },
                    }
                ]
            },
        }
        audit = {
            "role_candidates": {
                "warrior": {
                    "artifact_id": "subject-sha256:" + "c" * 64,
                    "artifact_sha256": "c" * 64,
                }
            }
        }
        consumed = consume_cycle_proposals(
            registry=self.registry,
            artifacts=self.artifacts,
            submission=submission,
            prosecutor_audit=audit,
            objective_id=self.objective,
            collection_evidence_id="cycle:1:eval",
        )
        self.assertTrue(all(not item.collected for item in consumed))
        self.assertTrue(all(item.error for item in consumed))
        self.assertEqual(self.registry.candidates(), ())

    def test_duplicate_proposal_is_idempotent(self) -> None:
        submission = {
            "role": "warrior",
            "submission": {
                "strategy_proposals": [
                    {
                        "proposal_id": "p1",
                        "target_role": "warrior",
                        "content": workflow(),
                        "rationale": "again",
                    }
                ]
            },
        }
        first = consume_cycle_proposals(
            registry=self.registry,
            artifacts=self.artifacts,
            submission=submission,
            prosecutor_audit={},
            objective_id=self.objective,
            collection_evidence_id="cycle:1:eval",
        )
        second = consume_cycle_proposals(
            registry=self.registry,
            artifacts=self.artifacts,
            submission=submission,
            prosecutor_audit={},
            objective_id=self.objective,
            collection_evidence_id="cycle:2:eval",
        )
        self.assertEqual(len(first), 1)
        self.assertEqual(len(second), 1)
        self.assertTrue(second[0].collected)
        self.assertTrue(second[0].validated)
        self.assertEqual(len(self.registry.candidates()), 1)


if __name__ == "__main__":
    unittest.main()
