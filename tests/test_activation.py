from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from aegis.activation import (
    ACTIVATION_COMPLETED,
    ACTIVATION_EVOLUTION_ACTIVATED,
    ACTIVATION_HARNESS_COMMITTED,
    ACTIVATION_INTENT_RECORDED,
    ACTIVATION_ROLE_COMMITTED,
    ActivationError,
    ActivationIntent,
    ActivationJournal,
    ActivationReconciler,
    activation_stream_id,
)
from aegis.event_store import EventStore


class ActivationJournalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.store = EventStore(Path(self.temporary.name) / "events.db")
        self.journal = ActivationJournal(self.store, "campaign")
        self.intent = ActivationIntent.create(
            evolution_candidate_id="evolution-candidate-sha256:" + "a" * 64,
            role_candidate_id="role-version-sha256:" + "b" * 64,
            objective_id="objective-sha256:" + "c" * 64,
            qualification_evidence_id="candidate-gate-report-sha256:" + "d" * 64,
            expected_current_active_set_id="active-role-set-sha256:" + "e" * 64,
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def test_intent_and_receipts_survive_registry_reconstruction(self) -> None:
        self.journal.begin(self.intent)
        self.journal.record_role_commit(self.intent.intent_id, "active-set-next")

        replayed = ActivationJournal(self.store, "campaign")
        record = replayed.projection.records[self.intent.intent_id]
        self.assertEqual(record.role_active_set_id, "active-set-next")
        self.assertFalse(record.evolution_activated)
        replayed.record_evolution_activation(self.intent.intent_id)
        completed = replayed.complete(self.intent.intent_id)
        self.assertTrue(completed.completed)
        self.assertEqual(replayed.projection.pending, ())

    def test_commands_are_idempotent_after_their_receipt(self) -> None:
        first = self.journal.begin(self.intent)
        self.assertEqual(self.journal.begin(self.intent), first)
        role = self.journal.record_role_commit(self.intent.intent_id, "active-set-next")
        self.assertEqual(self.journal.record_role_commit(self.intent.intent_id, "active-set-next"), role)
        evolution = self.journal.record_evolution_activation(self.intent.intent_id)
        self.assertEqual(self.journal.record_evolution_activation(self.intent.intent_id), evolution)
        completed = self.journal.complete(self.intent.intent_id)
        self.assertEqual(self.journal.complete(self.intent.intent_id), completed)

    def test_reconciler_uses_probes_to_recover_after_unreceipted_side_effects(self) -> None:
        self.journal.begin(self.intent)
        external = {"active_set_id": "active-set-next", "evolution": False}
        calls = {"role": 0, "evolution": 0}

        def probe_role(_intent: ActivationIntent) -> str | None:
            return external["active_set_id"]  # type: ignore[return-value]

        def commit_role(_intent: ActivationIntent) -> str:
            calls["role"] += 1
            return "unexpected"

        def probe_evolution(_intent: ActivationIntent) -> bool:
            return bool(external["evolution"])

        def activate_evolution(_intent: ActivationIntent) -> None:
            calls["evolution"] += 1
            external["evolution"] = True

        reconciler = ActivationReconciler(
            self.journal,
            probe_role_commit=probe_role,
            commit_role=commit_role,
            probe_evolution_activation=probe_evolution,
            activate_evolution=activate_evolution,
        )
        completed = reconciler.reconcile()

        self.assertEqual(calls, {"role": 0, "evolution": 1})
        self.assertEqual(len(completed), 1)
        self.assertTrue(completed[0].completed)
        self.assertEqual(reconciler.reconcile(), ())

    def test_role_evolution_and_mcp_activation_are_strictly_ordered(self) -> None:
        intent = ActivationIntent.create(
            evolution_candidate_id="evolution-candidate-sha256:" + "1" * 64,
            role_candidate_id="role-version-sha256:" + "2" * 64,
            mcp_candidate_id="mcp-candidate-sha256:" + "3" * 64,
            objective_id="objective-sha256:" + "4" * 64,
            qualification_evidence_id="candidate-gate-report-sha256:" + "5" * 64,
            expected_current_active_set_id=None,
        )
        self.journal.begin(intent)
        calls: list[str] = []

        def probe_role(_intent: ActivationIntent) -> str | None:
            calls.append("probe-role")
            return None

        def commit_role(_intent: ActivationIntent) -> str:
            calls.append("commit-role")
            return "active-set-next"

        def probe_evolution(_intent: ActivationIntent) -> bool:
            calls.append("probe-evolution")
            return False

        def activate_evolution(_intent: ActivationIntent) -> None:
            calls.append("activate-evolution")

        def probe_mcp(_intent: ActivationIntent) -> str | None:
            calls.append("probe-mcp")
            return None

        def activate_mcp(_intent: ActivationIntent) -> str:
            calls.append("activate-mcp")
            return "mcp-binding-sha256:" + "6" * 64

        completed = ActivationReconciler(
            self.journal,
            probe_role_commit=probe_role,
            commit_role=commit_role,
            probe_evolution_activation=probe_evolution,
            activate_evolution=activate_evolution,
            probe_mcp_activation=probe_mcp,
            activate_mcp=activate_mcp,
        ).reconcile()

        self.assertEqual(
            calls,
            [
                "probe-role",
                "commit-role",
                "probe-evolution",
                "activate-evolution",
                "probe-mcp",
                "activate-mcp",
            ],
        )
        self.assertEqual(completed[0].mcp_binding_id, "mcp-binding-sha256:" + "6" * 64)
        self.assertTrue(completed[0].receipts_complete)

    def test_harness_side_effect_precedes_role_and_recovers_after_crash(self) -> None:
        intent = ActivationIntent.create(
            evolution_candidate_id="evolution-candidate-sha256:" + "1" * 64,
            role_candidate_id="role-version-sha256:" + "2" * 64,
            objective_id="objective-sha256:" + "3" * 64,
            qualification_evidence_id="candidate-evaluation-sha256:" + "4" * 64,
            expected_current_active_set_id=None,
            harness_candidate_commit="5" * 40,
            harness_expected_champion="6" * 40,
        )
        self.journal.begin(intent)
        external: dict[str, object] = {"harness": None, "role": None, "evolution": False}
        calls: list[str] = []

        def activate_harness(_intent: ActivationIntent) -> str:
            calls.append("activate-harness")
            external["harness"] = "harness-activation-sha256:" + "7" * 64
            raise RuntimeError("crash after harness CAS")

        reconciler = ActivationReconciler(
            self.journal,
            probe_harness_activation=lambda _intent: None,
            activate_harness=activate_harness,
            probe_role_commit=lambda _intent: None,
            commit_role=lambda _intent: "active-next",
            probe_evolution_activation=lambda _intent: False,
            activate_evolution=lambda _intent: None,
        )
        with self.assertRaisesRegex(RuntimeError, "crash after harness CAS"):
            reconciler.reconcile()
        self.assertIsNone(self.journal.projection.records[intent.intent_id].role_active_set_id)

        replayed = ActivationJournal(self.store, "campaign")

        def probe_harness(_intent: ActivationIntent) -> str | None:
            calls.append("probe-harness")
            value = external["harness"]
            return value if isinstance(value, str) else None

        def commit_role(_intent: ActivationIntent) -> str:
            calls.append("commit-role")
            external["role"] = "active-next"
            return "active-next"

        def activate_evolution(_intent: ActivationIntent) -> None:
            calls.append("activate-evolution")
            external["evolution"] = True

        completed = ActivationReconciler(
            replayed,
            probe_harness_activation=probe_harness,
            activate_harness=activate_harness,
            probe_role_commit=lambda _intent: (
                external["role"] if isinstance(external["role"], str) else None
            ),
            commit_role=commit_role,
            probe_evolution_activation=lambda _intent: bool(external["evolution"]),
            activate_evolution=activate_evolution,
        ).reconcile()
        self.assertEqual(
            calls,
            ["activate-harness", "probe-harness", "commit-role", "activate-evolution"],
        )
        self.assertTrue(completed[0].completed)
        event_types = [event.event_type for event in self.store.read(activation_stream_id("campaign"))]
        self.assertLess(
            event_types.index(ACTIVATION_HARNESS_COMMITTED),
            event_types.index(ACTIVATION_ROLE_COMMITTED),
        )

    def test_mcp_only_reconciliation_recovers_side_effect_before_receipt(self) -> None:
        intent = ActivationIntent.create(
            evolution_candidate_id="evolution-candidate-sha256:" + "7" * 64,
            mcp_candidate_id="mcp-candidate-sha256:" + "8" * 64,
            objective_id="objective-sha256:" + "9" * 64,
            qualification_evidence_id="candidate-gate-report-sha256:" + "a" * 64,
            expected_current_active_set_id=None,
        )
        self.journal.begin(intent)
        external: dict[str, object] = {"evolution": False, "binding_id": None}
        calls = {"evolution": 0, "mcp": 0}

        def activate_evolution(_intent: ActivationIntent) -> None:
            calls["evolution"] += 1
            external["evolution"] = True

        def probe_mcp(_intent: ActivationIntent) -> str | None:
            value = external["binding_id"]
            return value if isinstance(value, str) else None

        def activate_mcp(_intent: ActivationIntent) -> str:
            calls["mcp"] += 1
            binding_id = "mcp-binding-sha256:" + "b" * 64
            external["binding_id"] = binding_id
            raise RuntimeError("simulated crash after MCP activation")

        reconciler = ActivationReconciler(
            self.journal,
            probe_evolution_activation=lambda _intent: bool(external["evolution"]),
            activate_evolution=activate_evolution,
            probe_mcp_activation=probe_mcp,
            activate_mcp=activate_mcp,
        )
        with self.assertRaisesRegex(RuntimeError, "simulated crash"):
            reconciler.reconcile()

        after_crash = ActivationJournal(self.store, "campaign")
        pending = after_crash.projection.records[intent.intent_id]
        self.assertIsNone(pending.role_active_set_id)
        self.assertTrue(pending.evolution_activated)
        self.assertIsNone(pending.mcp_binding_id)

        recovered = ActivationReconciler(
            after_crash,
            probe_evolution_activation=lambda _intent: bool(external["evolution"]),
            activate_evolution=activate_evolution,
            probe_mcp_activation=probe_mcp,
            activate_mcp=activate_mcp,
        ).reconcile()
        self.assertEqual(calls, {"evolution": 1, "mcp": 1})
        self.assertEqual(recovered[0].mcp_binding_id, external["binding_id"])
        self.assertTrue(recovered[0].completed)

    def test_mcp_receipt_is_required_and_survives_replay(self) -> None:
        intent = ActivationIntent.create(
            evolution_candidate_id="evolution-candidate-sha256:" + "c" * 64,
            mcp_candidate_id="mcp-candidate-sha256:" + "d" * 64,
            objective_id="objective-sha256:" + "e" * 64,
            qualification_evidence_id="candidate-gate-report-sha256:" + "f" * 64,
            expected_current_active_set_id=None,
        )
        self.journal.begin(intent)
        with self.assertRaisesRegex(ActivationError, "evolution activation"):
            self.journal.record_mcp_activation(intent.intent_id, "binding")
        self.journal.record_evolution_activation(intent.intent_id)
        with self.assertRaisesRegex(ActivationError, "all declared"):
            self.journal.complete(intent.intent_id)
        receipt = self.journal.record_mcp_activation(intent.intent_id, "binding")
        self.assertEqual(self.journal.record_mcp_activation(intent.intent_id, "binding"), receipt)

        replayed = ActivationJournal(self.store, "campaign")
        self.assertEqual(replayed.projection.records[intent.intent_id].mcp_binding_id, "binding")
        self.assertTrue(replayed.complete(intent.intent_id).completed)

    def test_legacy_schema_replays_but_v2_intent_shape_is_strict(self) -> None:
        stream_id = activation_stream_id("legacy")
        mapping = self.intent.to_mapping()
        mapping.pop("mcp_candidate_id")
        self.store.append(
            stream_id,
            ACTIVATION_INTENT_RECORDED,
            {"schema_version": 1, **mapping},
        )
        self.store.append(
            stream_id,
            ACTIVATION_ROLE_COMMITTED,
            {
                "schema_version": 1,
                "intent_id": self.intent.intent_id,
                "active_set_id": "active-set-next",
            },
        )
        self.store.append(
            stream_id,
            ACTIVATION_EVOLUTION_ACTIVATED,
            {"schema_version": 1, "intent_id": self.intent.intent_id},
        )
        self.store.append(
            stream_id,
            ACTIVATION_COMPLETED,
            {"schema_version": 1, "intent_id": self.intent.intent_id},
        )
        replayed = ActivationJournal(self.store, "legacy")
        self.assertTrue(replayed.projection.records[self.intent.intent_id].completed)

        invalid_stream = activation_stream_id("invalid")
        self.store.append(
            invalid_stream,
            ACTIVATION_INTENT_RECORDED,
            {"schema_version": 2, **mapping},
        )
        with self.assertRaisesRegex(ActivationError, "invalid activation intent payload"):
            ActivationJournal(self.store, "invalid")


if __name__ == "__main__":
    unittest.main()
