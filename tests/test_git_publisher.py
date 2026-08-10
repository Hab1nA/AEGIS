from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from dataclasses import fields, replace
from pathlib import Path
from typing import Callable

from aegis.publishing import (
    GitCheckpointRequest,
    GitFileChange,
    GitPublisher,
    GitPublisherError,
    PromotionEvidence,
    PublishOperation,
    StablePromotionRequest,
)


def git(
    cwd: Path,
    *args: str,
    stdin: bytes | None = None,
    allowed_codes: tuple[int, ...] = (0,),
) -> str:
    result = subprocess.run(
        ("git", *args),
        cwd=cwd,
        input=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    if result.returncode not in allowed_codes:
        raise AssertionError(result.stderr.decode("utf-8", errors="replace"))
    return result.stdout.decode("utf-8", errors="strict").strip()


class RacingPublisher(GitPublisher):
    def __init__(self, *args: object, before_stable_push: Callable[[], None], **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self._before_stable_push = before_stable_push

    def _push(self, repo: Path, commit: str, ref: str, *, expected_old: str | None) -> None:
        if expected_old is not None:
            self._before_stable_push()
        super()._push(repo, commit, ref, expected_old=expected_old)


class GitPublisherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.worktree = self.root / "user-worktree"
        self.remote = self.root / "public.git"
        self.worktree.mkdir()
        git(self.worktree, "init", "-b", "stable")
        git(self.worktree, "config", "user.name", "Test Operator")
        git(self.worktree, "config", "user.email", "operator@example.invalid")
        (self.worktree / "roles" / "warrior").mkdir(parents=True)
        (self.worktree / "roles" / "warrior" / "base.py").write_text(
            "VALUE = 1\n", encoding="utf-8"
        )
        (self.worktree / "README.md").write_text("public root\n", encoding="utf-8")
        git(self.worktree, "add", ".")
        git(self.worktree, "commit", "-m", "initial stable")
        self.base = git(self.worktree, "rev-parse", "HEAD")
        git(self.root, "init", "--bare", str(self.remote))
        git(self.worktree, "remote", "add", "origin", str(self.remote))
        git(self.worktree, "push", "-u", "origin", "stable")
        self.publisher = GitPublisher(
            str(self.remote),
            remote_id="public-test-origin",
            allowed_role_paths={
                "warrior": ("roles/warrior",),
                "judge": ("roles/judge",),
            },
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def checkpoint(
        self,
        *,
        generation_id: str = "gen-2",
        base_commit: str | None = None,
        changes: tuple[GitFileChange, ...] | None = None,
    ) -> GitCheckpointRequest:
        return GitCheckpointRequest.create(
            role="warrior",
            generation_id=generation_id,
            base_commit=base_commit or self.base,
            changes=changes
            or (GitFileChange("roles/warrior/strategy.py", b"QUALITY = 2\n"),),
            message="candidate: warrior generation 2",
        )

    @staticmethod
    def evidence(
        candidate_commit: str,
        *,
        qualified: bool = True,
        probation_passed: bool = True,
    ) -> PromotionEvidence:
        return PromotionEvidence.create(
            candidate_commit=candidate_commit,
            qualification_report_id="attribution-report-sha256:" + "a" * 64,
            qualified=qualified,
            probation_report_id="probation-report-sha256:" + "b" * 64,
            probation_passed=probation_passed,
        )

    def stable_request(
        self,
        candidate_commit: str,
        *,
        evidence: PromotionEvidence | None = None,
        expected_stable: str | None = None,
    ) -> StablePromotionRequest:
        return StablePromotionRequest.create(
            role="warrior",
            generation_id="gen-2",
            expected_stable_commit=expected_stable or self.base,
            evidence=evidence or self.evidence(candidate_commit),
        )

    def remote_head(self, ref: str) -> str | None:
        output = git(self.root, "ls-remote", "--heads", str(self.remote), ref)
        return output.partition("\t")[0] if output else None

    def test_candidate_and_stable_publish_are_isolated_content_addressed_fast_forwards(self) -> None:
        before_head = git(self.worktree, "rev-parse", "HEAD")
        before_status = git(self.worktree, "status", "--porcelain=v1", "--untracked-files=all")
        candidate = self.publisher.publish_candidate(self.checkpoint())

        candidate_ref = "refs/heads/candidate/warrior/gen-2"
        self.assertEqual(candidate.intent.operation, PublishOperation.CANDIDATE)
        self.assertEqual(candidate.intent.expected_old_commit, None)
        self.assertEqual(candidate.receipt.intent_id, candidate.intent.intent_id)
        self.assertEqual(self.remote_head(candidate_ref), candidate.receipt.new_commit)
        self.assertEqual(
            git(self.root, "--git-dir", str(self.remote), "rev-parse", candidate.receipt.new_commit + "^"),
            self.base,
        )
        self.assertEqual(self.remote_head("refs/heads/stable"), self.base)

        stable = self.publisher.promote_stable(self.stable_request(candidate.receipt.new_commit))
        self.assertEqual(stable.intent.operation, PublishOperation.STABLE)
        self.assertEqual(stable.receipt.old_commit, self.base)
        self.assertEqual(stable.receipt.new_commit, candidate.receipt.new_commit)
        self.assertEqual(self.remote_head("refs/heads/stable"), candidate.receipt.new_commit)
        self.assertTrue(candidate.intent.intent_id.startswith("git-publish-intent-sha256:"))
        self.assertTrue(candidate.receipt.receipt_id.startswith("git-publish-receipt-sha256:"))
        self.assertTrue(stable.intent.intent_id.startswith("git-publish-intent-sha256:"))
        self.assertTrue(stable.receipt.receipt_id.startswith("git-publish-receipt-sha256:"))
        with self.assertRaisesRegex(ValueError, "does not match"):
            replace(candidate.intent, remote_id="tampered-origin")
        with self.assertRaisesRegex(ValueError, "does not match"):
            replace(candidate.receipt, new_commit=self.base)

        self.assertEqual(git(self.worktree, "rev-parse", "HEAD"), before_head)
        self.assertEqual(
            git(self.worktree, "status", "--porcelain=v1", "--untracked-files=all"),
            before_status,
        )
        self.assertFalse((self.worktree / "roles" / "warrior" / "strategy.py").exists())

    def test_role_request_has_no_remote_or_credential_fields_and_is_integrity_bound(self) -> None:
        request = self.checkpoint()
        names = {item.name for item in fields(GitCheckpointRequest)}
        wire = json.dumps(request.to_mapping(), sort_keys=True)

        self.assertFalse(names & {"remote_url", "username", "password", "token", "credential"})
        self.assertNotIn(str(self.remote), wire)
        with self.assertRaisesRegex(ValueError, "does not match"):
            replace(request, message="tampered")

    def test_exact_base_and_role_path_grants_fail_closed(self) -> None:
        with self.assertRaisesRegex(GitPublisherError, "exact remote stable"):
            self.publisher.publish_candidate(self.checkpoint(base_commit="0" * 40))
        with self.assertRaisesRegex(GitPublisherError, "outside the role grant"):
            self.publisher.publish_candidate(
                self.checkpoint(changes=(GitFileChange("src/control_plane.py", b"changed\n"),))
            )
        self.assertEqual(self.remote_head("refs/heads/stable"), self.base)
        self.assertIsNone(self.remote_head("refs/heads/candidate/warrior/gen-2"))

    def test_git_hooks_submodules_and_secret_patterns_are_rejected(self) -> None:
        cases = (
            (GitFileChange("roles/warrior/.git/hooks/pre-commit", b"exit 0\n"), ".git"),
            (GitFileChange("roles/warrior/.gitmodules", b"[submodule \"x\"]\n"), "submodule"),
            (GitFileChange("roles/warrior/.env", b"SAFE=true\n"), "secret-like paths"),
            (
                GitFileChange("roles/warrior/config.py", b'API_KEY="abcdefgh12345678"\n'),
                "secret-like file content",
            ),
        )
        for change, reason in cases:
            with self.subTest(path=change.path):
                with self.assertRaisesRegex(GitPublisherError, reason):
                    self.publisher.publish_candidate(self.checkpoint(changes=(change,)))

    def test_symlink_and_submodule_tree_entries_are_rejected(self) -> None:
        for mode, name, object_id in (
            (
                "120000",
                "link",
                git(self.worktree, "hash-object", "-w", "--stdin", stdin=b"../../outside\n"),
            ),
            ("160000", "vendor", self.base),
        ):
            with self.subTest(mode=mode):
                git(
                    self.worktree,
                    "update-index",
                    "--add",
                    "--cacheinfo",
                    f"{mode},{object_id},roles/warrior/{name}",
                )
                git(self.worktree, "commit", "-m", f"malicious {mode}")
                malicious = git(self.worktree, "rev-parse", "HEAD")
                git(self.worktree, "push", "origin", "stable")
                with self.assertRaisesRegex(GitPublisherError, "symlink and submodule"):
                    self.publisher.publish_candidate(
                        self.checkpoint(
                            generation_id=f"bad-{mode}",
                            base_commit=malicious,
                            changes=(GitFileChange("roles/warrior/new.py", b"safe = True\n"),),
                        )
                    )
                git(self.worktree, "reset", "--hard", self.base)
                git(self.worktree, "push", "--force", "origin", "stable")

    def test_candidate_ref_is_create_only_and_cannot_be_rewritten(self) -> None:
        first = self.publisher.publish_candidate(self.checkpoint())
        with self.assertRaisesRegex(GitPublisherError, "cannot be rewritten"):
            self.publisher.publish_candidate(
                self.checkpoint(
                    changes=(GitFileChange("roles/warrior/strategy.py", b"QUALITY = 999\n"),)
                )
            )
        self.assertEqual(
            self.remote_head("refs/heads/candidate/warrior/gen-2"),
            first.receipt.new_commit,
        )

    def test_stable_requires_both_qualification_and_probation(self) -> None:
        candidate = self.publisher.publish_candidate(self.checkpoint()).receipt.new_commit
        for evidence, reason in (
            (self.evidence(candidate, qualified=False), "qualified evidence"),
            (self.evidence(candidate, probation_passed=False), "probation evidence"),
        ):
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(GitPublisherError, reason):
                    self.publisher.promote_stable(
                        self.stable_request(candidate, evidence=evidence)
                    )
        self.assertEqual(self.remote_head("refs/heads/stable"), self.base)

    def test_remote_drift_and_candidate_evidence_mismatch_fail_closed(self) -> None:
        candidate = self.publisher.publish_candidate(self.checkpoint()).receipt.new_commit
        mismatched = self.evidence("f" * 40)
        with self.assertRaisesRegex(GitPublisherError, "candidate ref does not match"):
            self.publisher.promote_stable(self.stable_request(candidate, evidence=mismatched))

        (self.worktree / "README.md").write_text("operator drift\n", encoding="utf-8")
        git(self.worktree, "add", "README.md")
        git(self.worktree, "commit", "-m", "operator advances stable")
        drift = git(self.worktree, "rev-parse", "HEAD")
        git(self.worktree, "push", "origin", "stable")
        with self.assertRaisesRegex(GitPublisherError, "drifted from the expected CAS"):
            self.publisher.promote_stable(self.stable_request(candidate))
        self.assertEqual(self.remote_head("refs/heads/stable"), drift)

    def test_atomic_lease_rejects_drift_between_last_read_and_stable_push(self) -> None:
        candidate = self.publisher.publish_candidate(self.checkpoint()).receipt.new_commit

        def concurrent_fast_forward() -> None:
            git(
                self.root,
                "--git-dir",
                str(self.remote),
                "update-ref",
                "refs/heads/stable",
                candidate,
                self.base,
            )

        racing = RacingPublisher(
            str(self.remote),
            remote_id="public-test-origin",
            allowed_role_paths={"warrior": ("roles/warrior",)},
            before_stable_push=concurrent_fast_forward,
        )
        with self.assertRaisesRegex(GitPublisherError, "before CAS"):
            racing.promote_stable(self.stable_request(candidate))
        self.assertEqual(self.remote_head("refs/heads/stable"), candidate)

    def test_stable_rejects_non_fast_forward_candidate(self) -> None:
        rogue = self.root / "rogue"
        rogue.mkdir()
        git(rogue, "init", "-b", "rogue")
        git(rogue, "config", "user.name", "Rogue")
        git(rogue, "config", "user.email", "rogue@example.invalid")
        (rogue / "roles" / "warrior").mkdir(parents=True)
        (rogue / "roles" / "warrior" / "rogue.py").write_text("ROGUE = True\n", encoding="utf-8")
        git(rogue, "add", ".")
        git(rogue, "commit", "-m", "unrelated candidate")
        rogue_commit = git(rogue, "rev-parse", "HEAD")
        git(rogue, "remote", "add", "origin", str(self.remote))
        git(rogue, "push", "origin", "HEAD:refs/heads/candidate/warrior/gen-2")

        with self.assertRaisesRegex(GitPublisherError, "fast-forward"):
            self.publisher.promote_stable(
                self.stable_request(rogue_commit, evidence=self.evidence(rogue_commit))
            )
        self.assertEqual(self.remote_head("refs/heads/stable"), self.base)


if __name__ == "__main__":
    unittest.main()
