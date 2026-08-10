from __future__ import annotations

import base64
import hashlib
import io
import json
import sqlite3
import tarfile
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from aegis.evolution_registry import (
    EvolutionCandidateState,
    EvolutionPromotionEvidence,
    EvolutionRegistry,
    EvolutionRegistryError,
    EvolutionRegistryIntegrityError,
)
from aegis.evolution_validation import EvolutionValidator
from aegis.evolution_workspace import (
    CandidatePatchArtifact,
    EvolutionPath,
    EvolutionPolicy,
    EvolutionWorkspace,
    ValidationCommand,
)
from aegis.sandbox.fake import FakeSandboxBackend
from aegis.sandbox.types import DoctorCheck, DoctorReport, validate_staging_archive

REPORT = "f" * 64


class NetworklessFakeBackend(FakeSandboxBackend):
    def doctor(self) -> DoctorReport:
        return DoctorReport((DoctorCheck("network_none", self.healthy, "test isolation"),))


def tar_bytes(value: bytes) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        info = tarfile.TarInfo("adaptive/logic.py")
        info.size = len(value)
        info.mtime = 0
        archive.addfile(info, io.BytesIO(value))
    return stream.getvalue()


def candidate(root: Path, value: bytes) -> CandidatePatchArtifact:
    workspace = evolution_workspace(root)
    baseline = workspace.create_snapshot()
    return workspace.candidate_from_archive(baseline, tar_bytes(value))


def evolution_workspace(root: Path) -> EvolutionWorkspace:
    return EvolutionWorkspace(
        root,
        EvolutionPolicy(
            evolvable_paths=(EvolutionPath("adaptive", recursive=True),),
            required_effective_paths=(),
            protected_paths=("control",),
            validation_commands=(ValidationCommand(("python", "-m", "pytest", "-q")),),
        ),
    )


def proof(artifact: CandidatePatchArtifact, **changes: object) -> EvolutionPromotionEvidence:
    values: dict[str, object] = {
        "candidate_artifact_id": artifact.artifact_id,
        "baseline_archive_sha256": artifact.baseline_archive_sha256,
        "static_checks_passed": True,
        "safety_regression_passed": True,
        "quality_comparison_passed": True,
        "usage_verified": True,
        "candidate_tokens": 100,
        "baseline_tokens": 120,
        "static_report_sha256": REPORT,
        "safety_report_sha256": "e" * 64,
        "quality_report_sha256": "d" * 64,
        "usage_report_sha256": "c" * 64,
    }
    values.update(changes)
    return EvolutionPromotionEvidence(**values)  # type: ignore[arg-type]


class EvolutionRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "repo"
        (self.root / "adaptive").mkdir(parents=True)
        (self.root / "adaptive" / "logic.py").write_bytes(b"old")
        self.db = Path(self.temp.name) / "evolution.sqlite3"
        self.registry = EvolutionRegistry(self.db)

    def tearDown(self) -> None:
        self.registry.close()
        self.temp.cleanup()

    def test_register_is_idempotent_wal_and_immutable(self) -> None:
        artifact = candidate(self.root, b"new")
        first = self.registry.register_candidate(artifact)
        self.assertEqual(first, self.registry.register_candidate(artifact))
        self.assertEqual(first.state, EvolutionCandidateState.CANDIDATE)
        self.assertEqual(self.registry._connection.execute("PRAGMA journal_mode").fetchone()[0], "wal")
        with self.assertRaises(sqlite3.DatabaseError):
            self.registry._connection.execute("UPDATE evolution_artifacts SET archive=x'00'")
        with self.assertRaises(sqlite3.DatabaseError):
            self.registry._connection.execute("DELETE FROM evolution_events")

    def test_rejects_forged_artifact_and_unsafe_archive_metadata(self) -> None:
        artifact = candidate(self.root, b"new")
        object.__setattr__(artifact, "artifact_id", "candidate-sha256:" + "0" * 64)
        with self.assertRaises(EvolutionRegistryError):
            self.registry.register_candidate(artifact)
        artifact = candidate(self.root, b"new")
        malicious = io.BytesIO()
        with tarfile.open(fileobj=malicious, mode="w") as archive:
            info = tarfile.TarInfo("../escape.py")
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))
        malicious_bytes = malicious.getvalue()
        malicious_digest = hashlib.sha256(malicious_bytes).hexdigest()
        payload = dict(artifact.to_mapping())
        payload.pop("artifact_id")
        payload["candidate_archive_sha256"] = malicious_digest
        malicious_id = "candidate-sha256:" + hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()
        forged = CandidatePatchArtifact(
            malicious_id,
            artifact.baseline_archive_sha256,
            malicious_bytes,
            malicious_digest,
            artifact.changes,
            artifact.validation_commands,
        )
        with self.assertRaises(EvolutionRegistryError):
            self.registry.register_candidate(forged)

    def test_promotion_requires_bound_complete_passing_evidence(self) -> None:
        artifact = candidate(self.root, b"new")
        self.registry.register_candidate(artifact)
        failures = (
            proof(artifact, static_checks_passed=False),
            proof(artifact, safety_regression_passed=False),
            proof(artifact, quality_comparison_passed=False),
            proof(artifact, usage_verified=False),
            proof(artifact, candidate_artifact_id="candidate-sha256:" + "0" * 64),
            proof(artifact, baseline_archive_sha256="0" * 64),
        )
        for evidence in failures:
            with self.subTest(evidence=evidence), self.assertRaises(EvolutionRegistryError):
                self.registry.promote(artifact.artifact_id, evidence)
        package = self.registry.promote(artifact.artifact_id, proof(artifact))
        self.assertEqual(package.version, 1)
        self.assertEqual(self.registry.champion().artifact_id, artifact.artifact_id)  # type: ignore[union-attr]

    def test_promotion_returns_only_versioned_sandbox_archive(self) -> None:
        artifact = candidate(self.root, b"new")
        self.registry.register_candidate(artifact)
        package = self.registry.promote(artifact.artifact_id, proof(artifact))
        archive = base64.b64decode(package.archive_base64, validate=True)
        self.assertEqual(hashlib.sha256(archive).hexdigest(), package.expected_digest)
        self.assertEqual(package.expected_digest, artifact.candidate_archive_sha256)
        self.assertNotIn(str(self.root).encode(), archive)
        _, members = validate_staging_archive(package.archive_base64, package.expected_digest)
        self.assertEqual(package.entries, len(members))
        self.assertEqual(package, self.registry.champion_archive())
        self.assertEqual((self.root / "adaptive" / "logic.py").read_bytes(), b"old")

    def test_collected_candidate_validation_and_lineage_survive_restart(self) -> None:
        workspace = evolution_workspace(self.root)
        baseline = workspace.create_snapshot()
        artifact = workspace.candidate_from_archive(baseline, tar_bytes(b"new"))
        collected = self.registry.register_collected(artifact, baseline)
        self.assertEqual(collected.state, EvolutionCandidateState.COLLECTED)
        self.assertEqual(self.registry.pending_candidates(), ())

        evidence = EvolutionValidator(NetworklessFakeBackend()).validate(
            artifact, validation_id="registry-1"
        )
        validated = self.registry.record_validation(artifact.artifact_id, evidence)
        self.assertEqual(validated.state, EvolutionCandidateState.CANDIDATE)
        self.assertEqual(validated.parent_champion_id, None)
        self.assertEqual(validated.baseline_archive_digest, baseline.archive_sha256)
        self.assertEqual(self.registry.candidate_artifact(artifact.artifact_id), artifact)
        self.assertEqual(self.registry.validation(artifact.artifact_id), evidence)
        self.assertEqual(self.registry.baseline_snapshot(artifact.artifact_id), baseline)
        self.assertEqual(
            tuple(item.artifact_id for item in self.registry.pending_candidates()),
            (artifact.artifact_id,),
        )

        self.registry.close()
        self.registry = EvolutionRegistry(self.db)
        self.assertEqual(self.registry.validation(artifact.artifact_id), evidence)
        self.assertEqual(self.registry.baseline_snapshot(artifact.artifact_id), baseline)
        self.assertEqual(
            self.registry.register_collected(artifact, baseline).state,
            EvolutionCandidateState.CANDIDATE,
        )
        self.assertEqual(
            self.registry.record_validation(artifact.artifact_id, evidence).state,
            EvolutionCandidateState.CANDIDATE,
        )

    def test_request_origin_is_idempotent_immutable_and_survives_restart(self) -> None:
        workspace = evolution_workspace(self.root)
        baseline = workspace.create_snapshot()
        artifact = workspace.candidate_from_archive(baseline, tar_bytes(b"new"))
        request_id = "evolution-request-sha256:" + "1" * 64

        first = self.registry.register_collected(artifact, baseline, request_id=request_id)
        second = self.registry.register_collected(artifact, baseline, request_id=request_id)
        self.assertEqual(first, second)
        self.assertEqual(self.registry.candidate_for_request(request_id), artifact)
        with self.assertRaises(sqlite3.DatabaseError):
            self.registry._connection.execute(
                "UPDATE evolution_request_origins SET request_id=?",
                ("evolution-request-sha256:" + "2" * 64,),
            )
        with self.assertRaises(sqlite3.DatabaseError):
            self.registry._connection.execute("DELETE FROM evolution_request_origins")

        self.registry.close()
        self.registry = EvolutionRegistry(self.db)
        self.assertEqual(self.registry.candidate_for_request(request_id), artifact)

    def test_request_origin_rejects_both_binding_conflicts(self) -> None:
        workspace = evolution_workspace(self.root)
        baseline = workspace.create_snapshot()
        first = workspace.candidate_from_archive(baseline, tar_bytes(b"first"))
        second = workspace.candidate_from_archive(baseline, tar_bytes(b"second"))
        request_id = "evolution-request-sha256:" + "3" * 64
        other_request_id = "evolution-request-sha256:" + "4" * 64
        self.registry.register_collected(first, baseline, request_id=request_id)

        with self.assertRaisesRegex(EvolutionRegistryError, "another artifact"):
            self.registry.register_collected(second, baseline, request_id=request_id)
        with self.assertRaisesRegex(EvolutionRegistryError, "another request"):
            self.registry.register_collected(first, baseline, request_id=other_request_id)
        self.assertIsNone(self.registry.candidate_for_request(other_request_id))
        with self.assertRaises(EvolutionRegistryError):
            self.registry.candidate(second.artifact_id)

    def test_request_origin_rejects_invalid_ids_and_unknown_lookup_is_empty(self) -> None:
        workspace = evolution_workspace(self.root)
        baseline = workspace.create_snapshot()
        artifact = workspace.candidate_from_archive(baseline, tar_bytes(b"new"))
        with self.assertRaisesRegex(EvolutionRegistryError, "request_id"):
            self.registry.register_collected(artifact, baseline, request_id="invalid")
        with self.assertRaisesRegex(EvolutionRegistryError, "request_id"):
            self.registry.candidate_for_request("invalid")
        self.assertIsNone(
            self.registry.candidate_for_request("evolution-request-sha256:" + "5" * 64)
        )

    def test_request_origin_insert_failure_rolls_back_entire_collection(self) -> None:
        workspace = evolution_workspace(self.root)
        baseline = workspace.create_snapshot()
        artifact = workspace.candidate_from_archive(baseline, tar_bytes(b"new"))
        request_id = "evolution-request-sha256:" + "6" * 64
        self.registry._connection.execute(
            "CREATE TRIGGER reject_request_origin BEFORE INSERT ON evolution_request_origins "
            "BEGIN SELECT RAISE(ABORT, 'injected origin failure'); END"
        )
        with self.assertRaises(sqlite3.DatabaseError):
            self.registry.register_collected(artifact, baseline, request_id=request_id)
        self.assertEqual(
            self.registry._connection.execute("SELECT COUNT(*) FROM evolution_artifacts").fetchone()[0],
            0,
        )
        self.assertEqual(
            self.registry._connection.execute("SELECT COUNT(*) FROM baseline_archives").fetchone()[0],
            0,
        )
        self.assertEqual(
            self.registry._connection.execute("SELECT COUNT(*) FROM evolution_events").fetchone()[0],
            0,
        )

    def test_request_origin_tampering_is_detected_on_reopen(self) -> None:
        workspace = evolution_workspace(self.root)
        baseline = workspace.create_snapshot()
        artifact = workspace.candidate_from_archive(baseline, tar_bytes(b"new"))
        request_id = "evolution-request-sha256:" + "7" * 64
        self.registry.register_collected(artifact, baseline, request_id=request_id)
        self.registry.close()
        connection = sqlite3.connect(self.db)
        connection.execute("DROP TRIGGER evolution_request_origins_no_update")
        connection.execute(
            "UPDATE evolution_request_origins SET request_id=?",
            ("evolution-request-sha256:" + "8" * 64,),
        )
        connection.commit()
        connection.close()
        with self.assertRaises(EvolutionRegistryIntegrityError):
            EvolutionRegistry(self.db)

    def test_promote_if_current_rejects_stale_sibling(self) -> None:
        parent = candidate(self.root, b"parent")
        self.registry.register_candidate(parent)
        parent_archive = self.registry.promote(parent.artifact_id, proof(parent))
        workspace = evolution_workspace(self.root)
        baseline = workspace.snapshot_from_archive(
            parent_archive.archive_base64, parent_archive.expected_digest
        )
        first = workspace.candidate_from_archive(baseline, tar_bytes(b"first"))
        second = workspace.candidate_from_archive(baseline, tar_bytes(b"second"))
        for index, artifact in enumerate((first, second), 1):
            self.registry.register_collected(
                artifact, baseline, parent_champion_id=parent.artifact_id
            )
            evidence = EvolutionValidator(NetworklessFakeBackend()).validate(
                artifact, validation_id=f"child-{index}"
            )
            self.registry.record_validation(artifact.artifact_id, evidence)

        promoted = self.registry.promote_if_current(
            first.artifact_id,
            proof(first),
            expected_champion_id=parent.artifact_id,
            expected_promotion_version=1,
        )
        self.assertEqual(promoted.version, 2)
        with self.assertRaisesRegex(EvolutionRegistryError, "champion changed"):
            self.registry.promote_if_current(
                second.artifact_id,
                proof(second),
                expected_champion_id=parent.artifact_id,
                expected_promotion_version=1,
            )

    def test_supersede_revoke_and_rollback_replay_after_restart(self) -> None:
        first = candidate(self.root, b"one")
        second = candidate(self.root, b"two")
        third = candidate(self.root, b"three")
        for artifact in (first, second, third):
            self.registry.register_candidate(artifact)
        self.registry.promote(first.artifact_id, proof(first))
        self.registry.promote(second.artifact_id, proof(second))
        self.registry.supersede(third.artifact_id, "inferior candidate")
        restored = self.registry.rollback(first.artifact_id, "v2 regression")
        self.assertEqual(restored.version, 3)
        self.registry.revoke(first.artifact_id, "security issue")
        self.assertIsNone(self.registry.champion())
        with self.assertRaises(EvolutionRegistryError):
            self.registry.rollback(first.artifact_id, "unsafe")
        self.registry.close()
        self.registry = EvolutionRegistry(self.db)
        self.assertEqual(self.registry.candidate(first.artifact_id).state, EvolutionCandidateState.REVOKED)
        self.assertEqual(
            self.registry.candidate(second.artifact_id).state, EvolutionCandidateState.SUPERSEDED
        )
        self.assertEqual(
            self.registry.candidate(third.artifact_id).state, EvolutionCandidateState.SUPERSEDED
        )

    def test_two_registries_cannot_promote_same_candidate_concurrently(self) -> None:
        artifact = candidate(self.root, b"new")
        self.registry.register_candidate(artifact)
        other = EvolutionRegistry(self.db)

        def attempt(registry: EvolutionRegistry) -> str:
            try:
                registry.promote(artifact.artifact_id, proof(artifact))
                return "promoted"
            except EvolutionRegistryError:
                return "rejected"

        try:
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = tuple(
                    future.result()
                    for future in (pool.submit(attempt, self.registry), pool.submit(attempt, other))
                )
            self.assertCountEqual(results, ("promoted", "rejected"))
        finally:
            other.close()

    def test_hash_chain_tampering_is_detected_without_handle_leak(self) -> None:
        artifact = candidate(self.root, b"new")
        self.registry.register_candidate(artifact)
        self.registry.close()
        connection = sqlite3.connect(self.db)
        connection.execute("DROP TRIGGER evolution_events_no_update")
        connection.execute("UPDATE evolution_events SET event_hash=?", ("0" * 64,))
        connection.commit()
        connection.close()
        with self.assertRaises(EvolutionRegistryIntegrityError):
            EvolutionRegistry(self.db)

    def test_archive_tampering_is_detected_on_reopen(self) -> None:
        artifact = candidate(self.root, b"new")
        self.registry.register_candidate(artifact)
        self.registry.close()
        connection = sqlite3.connect(self.db)
        connection.execute("DROP TRIGGER evolution_artifacts_no_update")
        connection.execute("UPDATE evolution_artifacts SET archive=x'00'")
        connection.commit()
        connection.close()
        with self.assertRaises(EvolutionRegistryIntegrityError):
            EvolutionRegistry(self.db)


if __name__ == "__main__":
    unittest.main()
