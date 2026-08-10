from __future__ import annotations

import copy
import dataclasses
import unittest

from aegis.research import (
    GitHubImportMetadata,
    PaperImportMetadata,
    ResearchImportError,
    ResearchImportKind,
    SkillImportMetadata,
    validate_github_import,
    validate_paper_import,
    validate_research_import,
    validate_skill_import,
)

ZERO = "0" * 64
ONE = "1" * 64
COMMIT = "a" * 40


def github_manifest() -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": "github",
        "source_url": f"https://github.com/example/project/tree/{COMMIT}",
        "content_sha256": ZERO,
        "size_bytes": 7,
        "metadata": {
            "repository_url": "https://github.com/example/project",
            "commit_sha": COMMIT,
            "license": "Apache-2.0",
            "files": [
                {"path": "src/main.py", "size_bytes": 7, "sha256": ONE, "media_type": "text/x-python"}
            ],
        },
    }


def paper_manifest() -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": "paper",
        "source_url": "https://arxiv.org/pdf/2501.00001",
        "content_sha256": ZERO,
        "size_bytes": 1234,
        "metadata": {
            "title": "A Reproducible Result",
            "authors": ["Ada Example", "Lin Example"],
            "identifier": "arxiv:2501.00001v2",
            "provenance": [
                {
                    "source_url": "https://arxiv.org/pdf/2501.00001",
                    "locator_type": "page",
                    "locator": "3-4",
                    "content_sha256": ONE,
                },
                {
                    "source_url": "https://arxiv.org/html/2501.00001",
                    "locator_type": "paragraph",
                    "locator": "sec-2.p-3",
                    "content_sha256": "2" * 64,
                },
            ],
        },
    }


def skill_manifest() -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": "skill",
        "source_url": "https://skills.example.org/testing/1.2.3/manifest.json",
        "content_sha256": ZERO,
        "size_bytes": 321,
        "metadata": {
            "name": "testing-helper",
            "version": "1.2.3",
            "permissions": ["research.search", "workspace.read", "sandbox.exec"],
            "dependencies": [{"name": "parser-lib", "version": "2.0.1", "sha256": ONE}],
        },
    }


class GitHubImportTests(unittest.TestCase):
    def test_normalizes_to_immutable_content_addressed_artifact(self) -> None:
        artifact = validate_github_import(github_manifest())
        self.assertEqual(artifact.kind, ResearchImportKind.GITHUB)
        self.assertIsInstance(artifact.metadata, GitHubImportMetadata)
        self.assertEqual(len(artifact.artifact_id), 64)
        self.assertEqual(artifact, validate_research_import(github_manifest()))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            artifact.size_bytes = 8  # type: ignore[misc]

    def test_requires_exact_commit_in_url_and_matching_file_total(self) -> None:
        for source, size in (
            ("https://github.com/example/project/tree/main", 7),
            (f"https://github.com/example/project/commit/{COMMIT}", 7),
            (f"https://github.com/example/other/tree/{COMMIT}", 7),
            (f"https://github.com/example/project/tree/{COMMIT}", 8),
        ):
            value = github_manifest()
            value["source_url"] = source
            value["size_bytes"] = size
            with self.subTest(source=source, size=size), self.assertRaises(ResearchImportError):
                validate_github_import(value)

    def test_rejects_paths_binaries_duplicates_bad_hash_and_license(self) -> None:
        mutations: list[tuple[str, object]] = [
            ("path", "../escape.py"),
            ("path", "C:\\escape.py"),
            ("path", "payload.exe"),
            ("media_type", "application/octet-stream"),
            ("sha256", "A" * 64),
        ]
        for key, replacement in mutations:
            value = github_manifest()
            metadata = value["metadata"]
            assert isinstance(metadata, dict)
            files = metadata["files"]
            assert isinstance(files, list) and isinstance(files[0], dict)
            files[0][key] = replacement
            with self.subTest(key=key), self.assertRaises(ResearchImportError):
                validate_github_import(value)
        value = github_manifest()
        metadata = value["metadata"]
        assert isinstance(metadata, dict)
        metadata["license"] = "NOASSERTION OR proprietary"
        with self.assertRaises(ResearchImportError):
            validate_github_import(value)

        duplicate = github_manifest()
        duplicate_metadata = duplicate["metadata"]
        assert isinstance(duplicate_metadata, dict)
        files = duplicate_metadata["files"]
        assert isinstance(files, list)
        files.append({"path": "SRC/MAIN.PY", "size_bytes": 0, "sha256": ZERO, "media_type": "text/x-python"})
        with self.assertRaisesRegex(ResearchImportError, "duplicate"):
            validate_github_import(duplicate)


class PaperImportTests(unittest.TestCase):
    def test_requires_identity_authors_and_fine_grained_provenance(self) -> None:
        artifact = validate_paper_import(paper_manifest())
        self.assertIsInstance(artifact.metadata, PaperImportMetadata)
        self.assertEqual(len(artifact.metadata.provenance), 2)

        for field, replacement in (
            ("identifier", "some paper"),
            ("authors", []),
            ("provenance", []),
        ):
            value = paper_manifest()
            metadata = value["metadata"]
            assert isinstance(metadata, dict)
            metadata[field] = replacement
            with self.subTest(field=field), self.assertRaises(ResearchImportError):
                validate_paper_import(value)

    def test_rejects_weak_locators_and_nonpublic_sources(self) -> None:
        for locator_type, locator in (("section", "methods"), ("page", "0"), ("paragraph", "../p")):
            value = paper_manifest()
            metadata = value["metadata"]
            assert isinstance(metadata, dict)
            provenance = metadata["provenance"]
            assert isinstance(provenance, list) and isinstance(provenance[0], dict)
            provenance[0]["locator_type"] = locator_type
            provenance[0]["locator"] = locator
            with self.subTest(locator_type=locator_type), self.assertRaises(ResearchImportError):
                validate_paper_import(value)
        for url in (
            "http://arxiv.org/pdf/2501.00001",
            "https://127.0.0.1/paper.pdf",
            "https://user:pass@arxiv.org/paper.pdf",
            "https://papers.internal/paper.pdf",
        ):
            value = paper_manifest()
            value["source_url"] = url
            with self.subTest(url=url), self.assertRaises(ResearchImportError):
                validate_paper_import(value)


class SkillImportTests(unittest.TestCase):
    def test_accepts_pinned_dependencies_and_bounded_data_plane_permissions(self) -> None:
        artifact = validate_skill_import(skill_manifest())
        self.assertIsInstance(artifact.metadata, SkillImportMetadata)
        self.assertEqual(artifact.metadata.dependencies[0].version, "2.0.1")

    def test_rejects_control_plane_and_unknown_permissions(self) -> None:
        for permission in (
            "campaign.write",
            "secret.read",
            "promotion.approve",
            "sandbox.admin",
            "network.unrestricted",
            "workspace.delete",
        ):
            value = skill_manifest()
            metadata = value["metadata"]
            assert isinstance(metadata, dict)
            metadata["permissions"] = [permission]
            with self.subTest(permission=permission), self.assertRaises(ResearchImportError):
                validate_skill_import(value)

    def test_requires_exact_hashed_unique_dependencies(self) -> None:
        for version, digest in ((">=2", ONE), ("latest", ONE), ("2.0.1", "bad")):
            value = skill_manifest()
            metadata = value["metadata"]
            assert isinstance(metadata, dict)
            dependencies = metadata["dependencies"]
            assert isinstance(dependencies, list) and isinstance(dependencies[0], dict)
            dependencies[0]["version"] = version
            dependencies[0]["sha256"] = digest
            with self.subTest(version=version), self.assertRaises(ResearchImportError):
                validate_skill_import(value)

        value = skill_manifest()
        metadata = value["metadata"]
        assert isinstance(metadata, dict)
        dependencies = metadata["dependencies"]
        assert isinstance(dependencies, list)
        dependencies.append(copy.deepcopy(dependencies[0]))
        with self.assertRaisesRegex(ResearchImportError, "duplicate"):
            validate_skill_import(value)


class SchemaTests(unittest.TestCase):
    def test_rejects_unknown_fields_wrong_kind_and_non_json(self) -> None:
        value = github_manifest()
        value["extra"] = True
        with self.assertRaises(ResearchImportError):
            validate_research_import(value)
        value = github_manifest()
        value["kind"] = "plugin"
        with self.assertRaises(ResearchImportError):
            validate_research_import(value)
        value = github_manifest()
        metadata = value["metadata"]
        assert isinstance(metadata, dict)
        metadata["files"] = {"not": "an array"}
        with self.assertRaises(ResearchImportError):
            validate_research_import(value)


if __name__ == "__main__":
    unittest.main()
