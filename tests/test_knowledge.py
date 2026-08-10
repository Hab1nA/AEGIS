from __future__ import annotations

import sqlite3
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from aegis.knowledge import (
    KnowledgeArtifact,
    KnowledgeConflictError,
    KnowledgeStore,
    KnowledgeStoreClosedError,
    ResearchBlob,
    ResearchSnapshotConflictError,
    sha256_bytes,
)
from aegis.models import Role


class KnowledgeStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.path = Path(self.temp.name) / "nested" / "knowledge.sqlite3"
        self.store = KnowledgeStore(self.path)

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def add(self, content: bytes = b"paper", **overrides: object):
        values: dict[str, object] = {
            "source_url": "https://arxiv.org/abs/2501.00001",
            "sha256": sha256_bytes(content),
            "media_type": "application/pdf",
            "summary": "A verified workflow for property-based testing.",
            "tags": ("paper", "testing"),
            "applicable_roles": (Role.WARRIOR, Role.JUDGE),
            "experiment_result": "Reduced escaped defects by 12 percent.",
            "created_at": datetime(2026, 8, 6, tzinfo=timezone.utc),
        }
        values.update(overrides)
        return self.store.add(**values)  # type: ignore[arg-type]

    def test_round_trip_is_typed_immutable_and_persistent(self) -> None:
        artifact = self.add()
        self.assertEqual(artifact.artifact_id, f"sha256:{sha256_bytes(b'paper')}")
        self.assertEqual(artifact.tags, ("paper", "testing"))
        self.assertEqual(artifact.applicable_roles, (Role.JUDGE, Role.WARRIOR))
        with self.assertRaises((AttributeError, TypeError)):
            artifact.summary = "mutated"  # type: ignore[misc]
        self.store.close()
        self.store = KnowledgeStore(self.path)
        self.assertEqual(self.store.get(artifact.artifact_id), artifact)

        connection = sqlite3.connect(self.path)
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE knowledge_artifacts SET summary = 'changed' WHERE artifact_id = ?",
                    (artifact.artifact_id,),
                )
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "DELETE FROM knowledge_artifacts WHERE artifact_id = ?", (artifact.artifact_id,)
                )
        finally:
            connection.close()

    def test_exact_duplicate_is_idempotent_and_conflict_is_rejected(self) -> None:
        first = self.add()
        self.assertEqual(self.add(), first)
        self.assertEqual(
            self.add(created_at=datetime(2026, 8, 7, tzinfo=timezone.utc)),
            first,
        )
        self.assertEqual(len(self.store.query()), 1)
        with self.assertRaises(KnowledgeConflictError):
            self.add(summary="A different interpretation of identical bytes.")

    def test_query_combines_text_terms_and_role_filter(self) -> None:
        paper = self.add()
        failed = self.add(
            b"skill",
            source_url="https://github.com/example/testing-skill",
            media_type="text/markdown",
            summary="A mutation testing skill.",
            tags=("github", "skill"),
            applicable_roles=(Role.PROSECUTOR,),
            experiment_result=None,
            failure_reason="Introduced nondeterministic test ordering.",
            created_at=datetime(2026, 8, 6, 1, tzinfo=timezone.utc),
        )
        self.assertEqual(self.store.query("property testing", role="judge"), (paper,))
        self.assertEqual(self.store.query("nondeterministic", role=Role.PROSECUTOR), (failed,))
        self.assertEqual(self.store.query("mutation", role=Role.WARRIOR), ())
        self.assertEqual(self.store.query("%"), ())

    def test_strict_schema_and_size_limits(self) -> None:
        invalid: tuple[dict[str, object], ...] = (
            {"source_url": "http://example.com/file"},
            {"source_url": "https://user:pass@example.com/file"},
            {"source_url": "https://example.com/file#fragment"},
            {"sha256": "A" * 64},
            {"media_type": "Application/PDF"},
            {"summary": "x" * 16_385},
            {"tags": ("UPPER",)},
            {"tags": ("same", "same")},
            {"tags": tuple(f"t{i}" for i in range(33))},
            {"applicable_roles": ()},
            {"applicable_roles": ("warrior", "warrior")},
            {"applicable_roles": ("administrator",)},
            {"experiment_result": "passed", "failure_reason": "failed"},
            {"created_at": datetime(2026, 8, 6)},
        )
        for override in invalid:
            with self.subTest(override=override), self.assertRaises((TypeError, ValueError)):
                self.add(**override)
        with self.assertRaises(ValueError):
            self.store.query("x" * 513)
        with self.assertRaises(ValueError):
            self.store.query(limit=101)

    def test_concurrent_duplicates_store_one_artifact(self) -> None:
        stores = [KnowledgeStore(self.path, busy_retries=12, retry_delay=0.001) for _ in range(4)]

        def add(index: int):
            return stores[index % len(stores)].add(
                source_url="https://example.com/research",
                sha256=sha256_bytes(b"same"),
                media_type="text/plain",
                summary="Same immutable artifact.",
                tags=("research",),
                applicable_roles=(Role.WARRIOR,),
                created_at=datetime(2026, 8, 6, tzinfo=timezone.utc),
            )

        try:
            with ThreadPoolExecutor(max_workers=12) as pool:
                artifacts = list(pool.map(add, range(40)))
            self.assertEqual(len(set(artifacts)), 1)
            self.assertEqual(len(self.store.query()), 1)
        finally:
            for store in stores:
                store.close()

    def test_closed_store_rejects_operations(self) -> None:
        self.store.close()
        with self.assertRaises(KnowledgeStoreClosedError):
            self.store.query()

    def test_research_snapshot_is_immutable_hash_recallable_and_persistent(self) -> None:
        content = b"declarative research text"
        digest = sha256_bytes(content)
        artifact_id = f"sha256:{sha256_bytes(b'manifest')}"
        snapshot = self.store.archive_research(
            artifact_id=artifact_id,
            kind="skill",
            content_sha256=digest,
            source_url="https://github.com/example/skill/tree/" + "a" * 40,
            descriptor={"version": 1, "name": "testing-helper"},
            blobs=(ResearchBlob("skill:SKILL.md", digest, "text/markdown", content),),
            created_at=datetime(2026, 8, 6, tzinfo=timezone.utc),
        )
        self.assertEqual(self.store.research_by_hash(digest), (snapshot,))
        self.assertEqual(self.store.archive_research(
            artifact_id=artifact_id,
            kind="skill",
            content_sha256=digest,
            source_url="https://github.com/example/skill/tree/" + "a" * 40,
            descriptor={"name": "testing-helper", "version": 1},
            blobs=(ResearchBlob("skill:SKILL.md", digest, "text/markdown", content),),
        ), snapshot)
        with self.assertRaises(ResearchSnapshotConflictError):
            self.store.archive_research(
                artifact_id=artifact_id,
                kind="skill",
                content_sha256=digest,
                source_url="https://github.com/example/skill/tree/" + "a" * 40,
                descriptor={"name": "different"},
                blobs=(ResearchBlob("skill:SKILL.md", digest, "text/markdown", content),),
            )

        self.store.close()
        self.store = KnowledgeStore(self.path)
        self.assertEqual(self.store.research_get(artifact_id), snapshot)
        connection = sqlite3.connect(self.path)
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE research_snapshots SET kind='paper' WHERE artifact_id=?",
                    (artifact_id,),
                )
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "DELETE FROM research_snapshot_blobs WHERE artifact_id=?",
                    (artifact_id,),
                )
        finally:
            connection.close()


class Sha256Tests(unittest.TestCase):
    def test_hashes_bytes_only(self) -> None:
        self.assertEqual(
            sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )
        with self.assertRaises(TypeError):
            sha256_bytes("abc")  # type: ignore[arg-type]

    def test_artifact_value_object_rejects_noncanonical_identity(self) -> None:
        with self.assertRaises(ValueError):
            KnowledgeArtifact(
                artifact_id="not-derived",
                source_url="https://example.com/item",
                sha256="0" * 64,
                media_type="text/plain",
                summary="Summary.",
                tags=("tag",),
                applicable_roles=(Role.WARRIOR,),
                experiment_result=None,
                failure_reason=None,
                created_at=datetime.now(timezone.utc),
            )


if __name__ == "__main__":
    unittest.main()
