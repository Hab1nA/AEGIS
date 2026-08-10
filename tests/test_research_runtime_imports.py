from __future__ import annotations

import copy
import hashlib
import unittest
from dataclasses import replace
from datetime import datetime, timezone

from aegis.research.imports import (
    GitHubImportMetadata,
    PaperImportMetadata,
    ResearchImportError,
    SkillImportMetadata,
)
from aegis.research.runtime_imports import (
    ResearchImportBindingError,
    RuntimeResearchImporter,
    bind_research_import,
)
from aegis.research.types import Provenance, ResearchArtifact

COMMIT = "a" * 40
FILE_HASH = "1" * 64


def fetched(content: bytes, final_url: str, *, requested_url: str | None = None) -> ResearchArtifact:
    digest = hashlib.sha256(content).hexdigest()
    requested = requested_url or final_url
    redirects = () if requested == final_url else (final_url,)
    return ResearchArtifact(
        content,
        Provenance(
            requested_url=requested,
            final_url=final_url,
            retrieved_at=datetime.now(timezone.utc).isoformat(),
            sha256=digest,
            size_bytes=len(content),
            media_type="application/octet-stream",
            redirect_chain=redirects,
        ),
    )


def envelope(kind: str, source_url: str, content: bytes, metadata: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": kind,
        "source_url": source_url,
        "content_sha256": hashlib.sha256(content).hexdigest(),
        "size_bytes": len(content),
        "metadata": metadata,
    }


class RuntimeImportSuccessTests(unittest.TestCase):
    def test_binds_github_content_to_exact_commit_and_license(self) -> None:
        content = b"1234567"
        source = f"https://github.com/example/project/tree/{COMMIT}"
        manifest = envelope(
            "github",
            source,
            content,
            {
                "repository_url": "https://github.com/example/project",
                "commit_sha": COMMIT,
                "license": "MIT",
                "files": [
                    {
                        "path": "src/main.py",
                        "size_bytes": len(content),
                        "sha256": FILE_HASH,
                        "media_type": "text/x-python",
                    }
                ],
            },
        )
        artifact = bind_research_import(fetched(content, source), manifest)
        self.assertIsInstance(artifact.metadata, GitHubImportMetadata)
        assert isinstance(artifact.metadata, GitHubImportMetadata)
        self.assertEqual(artifact.metadata.commit_sha, COMMIT)

    def test_binds_paper_with_page_provenance_after_redirect(self) -> None:
        content = b"paper"
        source = "https://arxiv.org/pdf/2501.00001"
        manifest = envelope(
            "paper",
            source,
            content,
            {
                "title": "Result",
                "authors": ["Ada Example"],
                "identifier": "arxiv:2501.00001v1",
                "provenance": [
                    {
                        "source_url": source,
                        "locator_type": "page",
                        "locator": "2",
                        "content_sha256": FILE_HASH,
                    }
                ],
            },
        )
        broker_result = fetched(content, source, requested_url="https://arxiv.org/abs/2501.00001")
        artifact = RuntimeResearchImporter().bind(broker_result, manifest)
        self.assertIsInstance(artifact.metadata, PaperImportMetadata)
        assert isinstance(artifact.metadata, PaperImportMetadata)
        self.assertEqual(artifact.metadata.provenance[0].locator, "2")

    def test_binds_skill_but_does_not_grant_more_than_declared(self) -> None:
        content = b"skill-manifest"
        source = "https://skills.example.org/testing/1.0.0/manifest.json"
        manifest = envelope(
            "skill",
            source,
            content,
            {
                "name": "testing-helper",
                "version": "1.0.0",
                "permissions": ["research.search", "workspace.read"],
                "dependencies": [{"name": "parser", "version": "2.1.0", "sha256": FILE_HASH}],
            },
        )
        artifact = bind_research_import(fetched(content, source), manifest)
        self.assertIsInstance(artifact.metadata, SkillImportMetadata)
        assert isinstance(artifact.metadata, SkillImportMetadata)
        self.assertEqual(artifact.metadata.permissions, ("research.search", "workspace.read"))

    def test_manifest_is_snapshotted_without_mutation(self) -> None:
        content = b"skill"
        source = "https://skills.example.org/demo/1.0.0/manifest.json"
        manifest = envelope(
            "skill",
            source,
            content,
            {"name": "demo", "version": "1.0.0", "permissions": [], "dependencies": []},
        )
        original = copy.deepcopy(manifest)
        bind_research_import(fetched(content, source), manifest)
        self.assertEqual(manifest, original)


class RuntimeImportTamperingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.content = b"skill"
        self.source = "https://skills.example.org/demo/1.0.0/manifest.json"
        self.manifest = envelope(
            "skill",
            self.source,
            self.content,
            {"name": "demo", "version": "1.0.0", "permissions": [], "dependencies": []},
        )
        self.fetched = fetched(self.content, self.source)

    def test_rejects_content_provenance_and_manifest_hash_or_size_mismatch(self) -> None:
        bad_digest = replace(self.fetched.provenance, sha256="0" * 64)
        bad_size = replace(self.fetched.provenance, size_bytes=len(self.content) + 1)
        cases: list[tuple[ResearchArtifact, dict[str, object]]] = [
            (ResearchArtifact(b"other", self.fetched.provenance), self.manifest),
            (ResearchArtifact(self.content, bad_digest), self.manifest),
            (ResearchArtifact(self.content, bad_size), self.manifest),
        ]
        manifest_hash = copy.deepcopy(self.manifest)
        manifest_hash["content_sha256"] = "0" * 64
        cases.append((self.fetched, manifest_hash))
        manifest_size = copy.deepcopy(self.manifest)
        manifest_size["size_bytes"] = len(self.content) + 1
        cases.append((self.fetched, manifest_size))
        for broker_result, manifest in cases:
            with self.subTest(manifest=manifest), self.assertRaises(ResearchImportError):
                bind_research_import(broker_result, manifest)

    def test_rejects_source_and_redirect_chain_mismatch(self) -> None:
        wrong_source = copy.deepcopy(self.manifest)
        wrong_source["source_url"] = "https://skills.example.org/other/1.0.0/manifest.json"
        with self.assertRaisesRegex(ResearchImportBindingError, "final_url"):
            bind_research_import(self.fetched, wrong_source)

        bad_chain = replace(self.fetched.provenance, redirect_chain=("https://example.org/not-final",))
        with self.assertRaisesRegex(ResearchImportBindingError, "redirect chain"):
            bind_research_import(ResearchArtifact(self.content, bad_chain), self.manifest)

    def test_reuses_license_permission_and_locator_validation(self) -> None:
        github_content = b"12345"
        github_source = f"https://github.com/example/project/tree/{COMMIT}"
        github = envelope(
            "github",
            github_source,
            github_content,
            {
                "repository_url": "https://github.com/example/project",
                "commit_sha": COMMIT,
                "license": "MIT OR Proprietary",
                "files": [
                    {
                        "path": "main.py",
                        "size_bytes": 5,
                        "sha256": FILE_HASH,
                        "media_type": "text/x-python",
                    }
                ],
            },
        )
        skill = copy.deepcopy(self.manifest)
        skill_metadata = skill["metadata"]
        assert isinstance(skill_metadata, dict)
        skill_metadata["permissions"] = ["campaign.write"]
        paper_content = b"paper"
        paper_source = "https://arxiv.org/pdf/2501.00001"
        paper = envelope(
            "paper",
            paper_source,
            paper_content,
            {
                "title": "Result",
                "authors": ["Ada Example"],
                "identifier": "arxiv:2501.00001",
                "provenance": [
                    {
                        "source_url": paper_source,
                        "locator_type": "section",
                        "locator": "methods",
                        "content_sha256": FILE_HASH,
                    }
                ],
            },
        )
        for broker_result, manifest in (
            (fetched(github_content, github_source), github),
            (self.fetched, skill),
            (fetched(paper_content, paper_source), paper),
        ):
            with self.subTest(kind=manifest["kind"]), self.assertRaises(ResearchImportError):
                bind_research_import(broker_result, manifest)

    def test_rejects_forged_or_noncanonical_provenance(self) -> None:
        cases = (
            replace(self.fetched.provenance, retrieved_at="2026-01-01T00:00:00"),
            replace(self.fetched.provenance, media_type="Application/JSON"),
            replace(self.fetched.provenance, final_url=""),
        )
        for provenance in cases:
            with self.subTest(provenance=provenance), self.assertRaises(ResearchImportBindingError):
                bind_research_import(ResearchArtifact(self.content, provenance), self.manifest)

    def test_rejects_empty_mutable_or_non_artifact_content(self) -> None:
        empty = fetched(b"x", self.source)
        empty = ResearchArtifact(b"", replace(empty.provenance, sha256=hashlib.sha256(b"").hexdigest(), size_bytes=0))
        for value in (empty, ResearchArtifact(bytearray(b"x"), self.fetched.provenance), object()):  # type: ignore[arg-type]
            with self.subTest(value=type(value).__name__), self.assertRaises(ResearchImportBindingError):
                bind_research_import(value, self.manifest)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
