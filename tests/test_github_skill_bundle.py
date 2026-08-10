from __future__ import annotations

import hashlib
import unittest

from aegis.research.github_skill_bundle import (
    GitHubSkillBundleError,
    GitHubSkillSourceFile,
    build_github_skill_bundle,
)

REPOSITORY = "https://github.com/example/skills"
COMMIT = "a" * 40


def source(path: str, content: bytes) -> GitHubSkillSourceFile:
    raw_url = REPOSITORY.replace("https://github.com/", "https://raw.githubusercontent.com/")
    raw_url += f"/{COMMIT}/{path}"
    sha256 = hashlib.sha256(content).hexdigest()
    git_blob = hashlib.sha1(
        f"blob {len(content)}\0".encode("ascii") + content,
        usedforsecurity=False,
    ).hexdigest()
    return GitHubSkillSourceFile(
        path,
        content,
        sha256,
        git_blob,
        "text/markdown",
        {
            "requested_url": raw_url,
            "final_url": raw_url,
            "retrieved_at": "2026-01-01T00:00:00+00:00",
            "sha256": sha256,
            "size_bytes": len(content),
            "media_type": "text/markdown",
            "redirect_chain": [],
        },
    )


class GitHubSkillBundleTests(unittest.TestCase):
    def test_bundle_identity_is_stable_and_ignores_executable_files(self) -> None:
        files = (
            source("skill/notes.md", b"# Notes\n"),
            source("skill/SKILL.md", b"# Helper\n"),
            source("skill/install.sh", b"#!/bin/sh\nexit 0\n"),
        )
        first = build_github_skill_bundle(
            repository_url=REPOSITORY,
            commit_sha=COMMIT,
            root="skill",
            name="helper",
            version="1.0.0",
            files=files,
        )
        second = build_github_skill_bundle(
            repository_url=REPOSITORY,
            commit_sha=COMMIT,
            root="skill",
            name="helper",
            version="1.0.0",
            files=tuple(reversed(files)),
        )
        self.assertEqual(first, second)
        self.assertEqual([item.path for item in first.files], ["SKILL.md", "notes.md"])
        self.assertEqual(first.artifact.metadata.permissions, ())
        self.assertEqual(first.artifact.metadata.dependencies, ())
        self.assertNotIn(b"#!/bin/sh", first.content)

    def test_bundle_requires_exact_root_skill_file(self) -> None:
        with self.assertRaisesRegex(GitHubSkillBundleError, "exact file SKILL.md"):
            build_github_skill_bundle(
                repository_url=REPOSITORY,
                commit_sha=COMMIT,
                root="skill",
                name="helper",
                version="1.0.0",
                files=(source("skill/readme.md", b"# Not a skill\n"),),
            )

    def test_bundle_rejects_forged_git_blob_or_provenance(self) -> None:
        valid = source("skill/SKILL.md", b"# Helper\n")
        forged = GitHubSkillSourceFile(
            valid.path,
            valid.content,
            valid.sha256,
            "b" * 40,
            valid.media_type,
            valid.provenance,
        )
        with self.assertRaisesRegex(GitHubSkillBundleError, "Git blob"):
            build_github_skill_bundle(
                repository_url=REPOSITORY,
                commit_sha=COMMIT,
                root="skill",
                name="helper",
                version="1.0.0",
                files=(forged,),
            )


if __name__ == "__main__":
    unittest.main()
