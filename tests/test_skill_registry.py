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
from dataclasses import replace
from pathlib import Path

from aegis.research.imports import (
    ResearchImportArtifact,
    ResearchImportKind,
    SkillImportMetadata,
    validate_skill_import,
)
from aegis.sandbox.types import validate_staging_archive
from aegis.skill_registry import (
    SandboxSkillPackage,
    SkillCandidateState,
    SkillEvaluationReport,
    SkillFunnelReport,
    SkillPromotionEvidence,
    SkillRegistry,
    SkillRegistryError,
    SkillRegistryIntegrityError,
    SkillVersionConflictError,
)
from aegis.skill_validation import SkillStaticValidator

REPORT = "f" * 64


def artifact_for(
    content: bytes,
    *,
    name: str = "testing-helper",
    version: str = "1.0.0",
    permissions: list[str] | None = None,
    dependency_hash: str = "1" * 64,
) -> ResearchImportArtifact:
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
                "permissions": permissions or [],
                "dependencies": [
                    {"name": "parser", "version": "2.0.0", "sha256": dependency_hash}
                ],
            },
        }
    )


def evidence(artifact_id: str, *, safety: bool = True, quality: bool = True) -> SkillPromotionEvidence:
    return SkillPromotionEvidence(artifact_id, safety, quality, REPORT, "e" * 64)


class SkillRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db = Path(self.tempdir.name) / "skills.sqlite3"
        self.registry = SkillRegistry(self.db)

    def tearDown(self) -> None:
        self.registry.close()
        self.tempdir.cleanup()

    def test_registers_immutable_candidate_and_uses_wal(self) -> None:
        content = b"declarative skill"
        artifact = artifact_for(content)
        candidate = self.registry.register_candidate(artifact, content)
        self.assertEqual(candidate.state, SkillCandidateState.CANDIDATE)
        self.assertEqual(candidate.artifact, artifact)
        self.assertEqual(self.registry.register_candidate(artifact, content), candidate)
        mode = self.registry._connection.execute("PRAGMA journal_mode").fetchone()[0]
        self.assertEqual(mode, "wal")
        with self.assertRaises(sqlite3.DatabaseError):
            self.registry._connection.execute("UPDATE skill_artifacts SET content=x'00'")
        with self.assertRaises(sqlite3.DatabaseError):
            self.registry._connection.execute("DELETE FROM skill_events")

    def test_rejects_wrong_kind_forgery_and_content_mismatch(self) -> None:
        content = b"skill"
        artifact = artifact_for(content)
        forged_kind = replace(artifact, kind=ResearchImportKind.PAPER)
        forged_id = replace(artifact, artifact_id="0" * 64)
        for candidate, payload in (
            (forged_kind, content),
            (forged_id, content),
            (artifact, b"tampered"),
            (artifact, bytearray(content)),
        ):
            with self.subTest(candidate=candidate), self.assertRaises(SkillRegistryError):
                self.registry.register_candidate(candidate, payload)  # type: ignore[arg-type]

    def test_forbids_same_version_redefinition(self) -> None:
        first = b"first"
        second = b"second"
        self.registry.register_candidate(artifact_for(first), first)
        with self.assertRaises(SkillVersionConflictError):
            self.registry.register_candidate(artifact_for(second), second)

    def test_concurrent_registries_cannot_redefine_one_version(self) -> None:
        other = SkillRegistry(self.db)
        first, second = b"concurrent-one", b"concurrent-two"

        def attempt(registry: SkillRegistry, content: bytes) -> str:
            try:
                registry.register_candidate(artifact_for(content), content)
                return "registered"
            except SkillVersionConflictError:
                return "conflict"

        try:
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = tuple(
                    future.result()
                    for future in (
                        pool.submit(attempt, self.registry, first),
                        pool.submit(attempt, other, second),
                    )
                )
            self.assertCountEqual(results, ("registered", "conflict"))
            self.assertEqual(len(self.registry.candidates("testing-helper")), 1)
        finally:
            other.close()

    def test_permission_ceiling_can_only_narrow_import_allowlist(self) -> None:
        self.registry.close()
        self.registry = SkillRegistry(self.db, permission_ceiling=frozenset({"workspace.read"}))
        accepted = b"accepted"
        self.registry.register_candidate(
            artifact_for(accepted, permissions=["workspace.read"]), accepted
        )
        rejected = b"rejected"
        with self.assertRaisesRegex(SkillRegistryError, "ceiling"):
            self.registry.register_candidate(
                artifact_for(rejected, version="2.0.0", permissions=["sandbox.exec"]), rejected
            )
        with self.assertRaises(ValueError):
            SkillRegistry(Path(self.tempdir.name) / "bad.sqlite3", permission_ceiling=frozenset({"secret.read"}))

    def test_promotion_requires_external_safety_and_quality_evidence(self) -> None:
        content = b"candidate"
        artifact = artifact_for(content)
        self.registry.register_candidate(artifact, content)
        for proof in (
            None,
            evidence(artifact.artifact_id, safety=False),
            evidence(artifact.artifact_id, quality=False),
            evidence("0" * 64),
        ):
            with self.subTest(proof=proof), self.assertRaises(SkillRegistryError):
                self.registry.promote("testing-helper", "1.0.0", proof)  # type: ignore[arg-type]
        champion = self.registry.promote("testing-helper", "1.0.0", evidence(artifact.artifact_id))
        self.assertEqual(champion.state, SkillCandidateState.CHAMPION)
        self.assertEqual(self.registry.champion("testing-helper"), champion)

    def test_champion_supersession_rollback_and_revocation_are_replayed(self) -> None:
        one, two = b"one", b"two"
        first = artifact_for(one, version="1.0.0")
        second = artifact_for(two, version="2.0.0")
        self.registry.register_candidate(first, one)
        self.registry.register_candidate(second, two)
        self.registry.promote("testing-helper", "1.0.0", evidence(first.artifact_id))
        self.registry.promote("testing-helper", "2.0.0", evidence(second.artifact_id))
        self.assertEqual(
            self.registry.candidate("testing-helper", "1.0.0").state,
            SkillCandidateState.SUPERSEDED,
        )
        restored = self.registry.rollback("testing-helper", "1.0.0", "regression in v2")
        self.assertEqual(restored.state, SkillCandidateState.CHAMPION)
        revoked = self.registry.revoke("testing-helper", "1.0.0", "security advisory")
        self.assertEqual(revoked.state, SkillCandidateState.REVOKED)
        self.assertIsNone(self.registry.champion("testing-helper"))
        with self.assertRaises(SkillRegistryError):
            self.registry.rollback("testing-helper", "1.0.0", "unsafe")
        with self.assertRaises(SkillRegistryError):
            self.registry.promote("testing-helper", "1.0.0", evidence(first.artifact_id))

        self.registry.close()
        self.registry = SkillRegistry(self.db)
        self.assertEqual(
            self.registry.candidate("testing-helper", "1.0.0").state,
            SkillCandidateState.REVOKED,
        )
        self.assertEqual(
            self.registry.candidate("testing-helper", "2.0.0").state,
            SkillCandidateState.SUPERSEDED,
        )

    def test_outputs_deterministic_content_addressed_sandbox_package(self) -> None:
        content = b"opaque; never execute this on host"
        artifact = artifact_for(content)
        self.registry.register_candidate(artifact, content)
        package = self.registry.sandbox_package("testing-helper", "1.0.0")
        second = self.registry.sandbox_package("testing-helper", "1.0.0")
        self.assertIsInstance(package, SandboxSkillPackage)
        self.assertEqual(package, second)
        archive = base64.b64decode(package.archive_base64, validate=True)
        self.assertEqual(hashlib.sha256(archive).hexdigest(), package.expected_digest)
        _, members = validate_staging_archive(package.archive_base64, package.expected_digest)
        self.assertEqual(len(members), 2)
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
            names = tar.getnames()
            self.assertEqual(
                names,
                [
                    "skills/testing-helper/1.0.0/manifest.json",
                    "skills/testing-helper/1.0.0/payload.bin",
                ],
            )
            payload_file = tar.extractfile(names[1])
            manifest_file = tar.extractfile(names[0])
            assert payload_file is not None and manifest_file is not None
            self.assertEqual(payload_file.read(), content)
            manifest = json.loads(manifest_file.read())
            self.assertTrue(manifest["quarantined"])
            self.assertFalse(manifest["host_execution_allowed"])
            self.assertEqual(manifest["artifact"]["artifact_id"], artifact.artifact_id)

    def test_revoked_candidate_cannot_be_staged(self) -> None:
        content = b"bad"
        artifact = artifact_for(content)
        self.registry.register_candidate(artifact, content)
        self.registry.revoke("testing-helper", "1.0.0", "malicious behavior")
        with self.assertRaises(SkillRegistryError):
            self.registry.sandbox_package("testing-helper", "1.0.0")

    def test_exact_dependency_hash_is_preserved(self) -> None:
        content = b"dependency"
        artifact = artifact_for(content, dependency_hash="a" * 64)
        candidate = self.registry.register_candidate(artifact, content)
        metadata = candidate.artifact.metadata
        assert isinstance(metadata, SkillImportMetadata)
        self.assertEqual(metadata.dependencies[0].sha256, "a" * 64)

    def test_hash_chain_corruption_is_detected_on_reopen(self) -> None:
        content = b"candidate"
        self.registry.register_candidate(artifact_for(content), content)
        self.registry.close()
        connection = sqlite3.connect(self.db)
        connection.execute("DROP TRIGGER skill_events_no_update")
        connection.execute("UPDATE skill_events SET event_hash=? WHERE sequence=1", ("0" * 64,))
        connection.commit()
        connection.close()
        with self.assertRaises(SkillRegistryIntegrityError):
            SkillRegistry(self.db)

    def test_static_evidence_and_evaluated_promotion_use_revision_cas(self) -> None:
        content = b"# Declarative review guidance\n"
        artifact = validate_skill_import({
            **artifact_for(content).to_dict(include_artifact_id=False),
            "metadata": {
                "name": "testing-helper", "version": "1.0.0",
                "permissions": ["workspace.read"], "dependencies": [],
            },
        })
        self.registry.register_candidate(artifact, content)
        static = SkillStaticValidator().validate(artifact, content)
        candidate = self.registry.record_static_evidence(static)
        self.assertEqual(candidate.state, SkillCandidateState.VALIDATED_PENDING)
        self.assertEqual(self.registry.pending_validated(), (candidate,))
        revision = self.registry.champion_revision("testing-helper")
        smoke = SkillEvaluationReport.create(
            artifact_id=artifact.artifact_id, baseline_artifact_id=None, phase="smoke",
            observations_sha256="1" * 64, safety_verified=True, quality_verified=True,
            usage_verified=True, candidate_tokens=10, baseline_tokens=12,
        )
        full = SkillEvaluationReport.create(
            artifact_id=artifact.artifact_id, baseline_artifact_id=None, phase="full",
            observations_sha256="2" * 64, safety_verified=True, quality_verified=True,
            usage_verified=True, candidate_tokens=100, baseline_tokens=120,
        )
        self.registry.record_evaluation_report(smoke)
        self.registry.record_evaluation_report(full)
        funnel = SkillFunnelReport.create(
            artifact_id=artifact.artifact_id, baseline_artifact_id=None,
            baseline_revision=revision, static_evidence_id=static.evidence_id,
            smoke_report_id=smoke.report_id, full_report_id=full.report_id, promotable=True,
        )
        self.registry.record_funnel_report(funnel)
        with self.assertRaisesRegex(SkillRegistryError, "changed"):
            self.registry.promote_evaluated(
                artifact_id=artifact.artifact_id, funnel_report_id=funnel.report_id,
                expected_champion_id=None, expected_champion_revision="f" * 64,
            )
        champion = self.registry.promote_evaluated(
            artifact_id=artifact.artifact_id, funnel_report_id=funnel.report_id,
            expected_champion_id=None, expected_champion_revision=revision,
        )
        self.assertEqual(champion.state, SkillCandidateState.CHAMPION)
        package = self.registry.sandbox_package_by_artifact_id(artifact.artifact_id, active_path=True)
        archive = base64.b64decode(package.archive_base64)
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
            self.assertEqual(tar.getnames(), [
                ".aegis/skills/testing-helper/active/SKILL.md",
                ".aegis/skills/testing-helper/active/attestation.json",
            ])
        with self.assertRaises(sqlite3.DatabaseError):
            self.registry._connection.execute("DELETE FROM skill_funnel_reports")


if __name__ == "__main__":
    unittest.main()
