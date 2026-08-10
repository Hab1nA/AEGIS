from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
from typing import Any, Callable

from aegis.research.github_collector import (
    GitHubCollectionError,
    GitHubCollector,
    GitHubCollectorLimits,
)
from aegis.research.types import Provenance, ResearchArtifact, SearchHit

COMMIT = "a" * 40
TREE = "b" * 40
REPOSITORY = "https://github.com/example/project"
API = "https://api.github.com/repos/example/project"


def blob_sha(content: bytes) -> str:
    return hashlib.sha1(
        f"blob {len(content)}\0".encode("ascii") + content, usedforsecurity=False
    ).hexdigest()


def fetched(url: str, content: bytes, media_type: str) -> ResearchArtifact:
    return ResearchArtifact(
        content,
        Provenance(
            url,
            url,
            datetime.now(timezone.utc).isoformat(),
            hashlib.sha256(content).hexdigest(),
            len(content),
            media_type,
            (),
        ),
    )


class FakeResearch:
    def __init__(self, responses: dict[str, ResearchArtifact]) -> None:
        self.responses = responses
        self.fetches: list[str] = []

    def search(self, query: str, *, limit: int = 10) -> list[SearchHit]:
        del query, limit
        return []

    def fetch(self, url: str, *, validate_as_archive: bool = False) -> ResearchArtifact:
        self.fetches.append(url)
        if validate_as_archive:
            raise AssertionError("collector must not request archive handling")
        return self.responses[url]


def fixtures(*, source: bytes = b"print('ok')\n") -> tuple[dict[str, ResearchArtifact], str]:
    commit_url = f"{API}/commits/{COMMIT}"
    tree_url = f"{API}/git/trees/{TREE}?recursive=1"
    license_url = f"{API}/license?ref={COMMIT}"
    raw_url = f"https://raw.githubusercontent.com/example/project/{COMMIT}/src/main.py"
    values = {
        commit_url: fetched(
            commit_url,
            json.dumps({"sha": COMMIT, "commit": {"tree": {"sha": TREE}}}).encode(),
            "application/json",
        ),
        tree_url: fetched(
            tree_url,
            json.dumps(
                {
                    "sha": TREE,
                    "truncated": False,
                    "tree": [
                        {
                            "path": "src/main.py",
                            "mode": "100644",
                            "type": "blob",
                            "sha": blob_sha(source),
                            "size": len(source),
                        },
                        {
                            "path": "image.png",
                            "mode": "100644",
                            "type": "blob",
                            "sha": "c" * 40,
                            "size": 100,
                        },
                    ],
                }
            ).encode(),
            "application/vnd.github+json",
        ),
        license_url: fetched(
            license_url,
            json.dumps({"license": {"spdx_id": "MIT"}}).encode(),
            "application/json",
        ),
        raw_url: fetched(raw_url, source, "text/x-python"),
    }
    return values, raw_url


def replace_json(
    responses: dict[str, ResearchArtifact],
    url: str,
    transform: Callable[[dict[str, Any]], None],
) -> dict[str, ResearchArtifact]:
    copied = dict(responses)
    original = copied[url]
    value = json.loads(original.content)
    transform(value)
    copied[url] = fetched(url, json.dumps(value).encode(), original.provenance.media_type)
    return copied


class GitHubCollectorTests(unittest.TestCase):
    def test_resolves_mutable_ref_to_exact_commit_with_provenance(self) -> None:
        resolve_url = f"{API}/commits/HEAD"
        research = FakeResearch(
            {
                resolve_url: fetched(
                    resolve_url,
                    json.dumps({"sha": COMMIT}).encode(),
                    "application/vnd.github+json",
                )
            }
        )
        resolved = GitHubCollector(research).resolve(REPOSITORY)
        self.assertEqual(resolved.repository_url, REPOSITORY)
        self.assertEqual(resolved.requested_ref, "HEAD")
        self.assertEqual(resolved.commit_sha, COMMIT)
        self.assertEqual(resolved.provenance.final_url, resolve_url)

    def test_resolve_rejects_unsafe_ref_and_invalid_commit_response(self) -> None:
        with self.assertRaisesRegex(GitHubCollectionError, "bounded safe"):
            GitHubCollector(FakeResearch({})).resolve(REPOSITORY, "main?redirect=evil")
        resolve_url = f"{API}/commits/main"
        research = FakeResearch(
            {
                resolve_url: fetched(
                    resolve_url,
                    json.dumps({"sha": "not-a-commit"}).encode(),
                    "application/json",
                )
            }
        )
        with self.assertRaisesRegex(GitHubCollectionError, "exact lowercase commit"):
            GitHubCollector(research).resolve(REPOSITORY, "main")

    def test_collects_immutable_content_addressed_snapshot_without_execution(self) -> None:
        responses, raw_url = fixtures()
        research = FakeResearch(responses)
        snapshot = GitHubCollector(research).collect(REPOSITORY, COMMIT)
        self.assertEqual(snapshot.commit_sha, COMMIT)
        self.assertEqual(snapshot.tree_sha, TREE)
        self.assertEqual(snapshot.license_spdx, "MIT")
        self.assertEqual(snapshot.files[0].path, "src/main.py")
        self.assertEqual(snapshot.files[0].content, b"print('ok')\n")
        self.assertEqual(snapshot.artifact.content_sha256, snapshot.snapshot_sha256)
        self.assertFalse(snapshot.execution_granted)
        self.assertEqual(len(snapshot.response_provenance), 3)
        self.assertEqual(research.fetches[-1], raw_url)
        with self.assertRaises(FrozenInstanceError):
            snapshot.commit_sha = "c" * 40  # type: ignore[misc]

    def test_rejects_commit_drift_and_truncated_tree(self) -> None:
        responses, _ = fixtures()
        commit_url = f"{API}/commits/{COMMIT}"
        drifted = replace_json(responses, commit_url, lambda value: value.update(sha="d" * 40))
        with self.assertRaisesRegex(GitHubCollectionError, "commit response drifted"):
            GitHubCollector(FakeResearch(drifted)).collect(REPOSITORY, COMMIT)

        tree_url = f"{API}/git/trees/{TREE}?recursive=1"
        truncated = replace_json(responses, tree_url, lambda value: value.update(truncated=True))
        with self.assertRaisesRegex(GitHubCollectionError, "tree is truncated"):
            GitHubCollector(FakeResearch(truncated)).collect(REPOSITORY, COMMIT)

    def test_rejects_file_count_and_size_limits_before_raw_fetch(self) -> None:
        responses, raw_url = fixtures()
        tree_url = f"{API}/git/trees/{TREE}?recursive=1"
        too_many = replace_json(
            responses,
            tree_url,
            lambda value: value["tree"].append(
                {
                    "path": "README.md",
                    "mode": "100644",
                    "type": "blob",
                    "sha": "e" * 40,
                    "size": 1,
                }
            ),
        )
        with self.assertRaisesRegex(GitHubCollectionError, "file count"):
            GitHubCollector(
                FakeResearch(too_many), limits=GitHubCollectorLimits(max_files=1)
            ).collect(REPOSITORY, COMMIT)

        oversized = replace_json(
            responses,
            tree_url,
            lambda value: value["tree"][0].update(size=20),
        )
        research = FakeResearch(oversized)
        with self.assertRaisesRegex(GitHubCollectionError, "file size"):
            GitHubCollector(
                research, limits=GitHubCollectorLimits(max_file_bytes=10)
            ).collect(REPOSITORY, COMMIT)
        self.assertNotIn(raw_url, research.fetches)

    def test_rejects_binary_source_even_with_source_suffix(self) -> None:
        source = b"\x00\xffnot-text"
        responses, _ = fixtures(source=source)
        with self.assertRaisesRegex(GitHubCollectionError, "UTF-8 text|binary control"):
            GitHubCollector(FakeResearch(responses)).collect(REPOSITORY, COMMIT)

    def test_rejects_raw_hash_size_and_url_anomalies(self) -> None:
        responses, raw_url = fixtures()
        tree_url = f"{API}/git/trees/{TREE}?recursive=1"
        bad_hash = replace_json(
            responses,
            tree_url,
            lambda value: value["tree"][0].update(sha="d" * 40),
        )
        with self.assertRaisesRegex(GitHubCollectionError, "Git blob"):
            GitHubCollector(FakeResearch(bad_hash)).collect(REPOSITORY, COMMIT)

        bad_size = dict(responses)
        bad_size[raw_url] = fetched(raw_url, b"different", "text/plain")
        with self.assertRaisesRegex(GitHubCollectionError, "size"):
            GitHubCollector(FakeResearch(bad_size)).collect(REPOSITORY, COMMIT)

        bad_url = dict(responses)
        original = bad_url[raw_url]
        bad_url[raw_url] = ResearchArtifact(
            original.content,
            Provenance(
                raw_url,
                "https://raw.githubusercontent.com/evil/project/x/file.py",
                original.provenance.retrieved_at,
                original.provenance.sha256,
                original.provenance.size_bytes,
                original.provenance.media_type,
                (),
            ),
        )
        with self.assertRaisesRegex(GitHubCollectionError, "provenance URL"):
            GitHubCollector(FakeResearch(bad_url)).collect(REPOSITORY, COMMIT)

    def test_rejects_provenance_digest_and_spdx_anomalies(self) -> None:
        responses, raw_url = fixtures()
        original = responses[raw_url]
        bad_provenance = dict(responses)
        bad_provenance[raw_url] = ResearchArtifact(
            original.content,
            Provenance(
                raw_url,
                raw_url,
                original.provenance.retrieved_at,
                "0" * 64,
                original.provenance.size_bytes,
                original.provenance.media_type,
                (),
            ),
        )
        with self.assertRaisesRegex(GitHubCollectionError, "hash or size"):
            GitHubCollector(FakeResearch(bad_provenance)).collect(REPOSITORY, COMMIT)

        license_url = f"{API}/license?ref={COMMIT}"
        no_license = replace_json(
            responses,
            license_url,
            lambda value: value["license"].update(spdx_id="NOASSERTION"),
        )
        with self.assertRaisesRegex(GitHubCollectionError, "SPDX"):
            GitHubCollector(FakeResearch(no_license)).collect(REPOSITORY, COMMIT)


if __name__ == "__main__":
    unittest.main()
