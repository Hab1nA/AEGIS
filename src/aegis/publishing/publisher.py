"""Fail-closed Git publisher that never mutates the caller's working tree."""

from __future__ import annotations

import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
from typing import Mapping, Sequence

from .models import (
    GitCheckpointRequest,
    GitFileChange,
    PublicationResult,
    PublishIntent,
    PublishOperation,
    PublishReceipt,
    StablePromotionRequest,
)

_SECRET_PATH_PARTS = {
    ".env",
    ".npmrc",
    ".pypirc",
    "credentials",
    "credentials.json",
    "id_rsa",
    "id_ed25519",
    "secrets",
    "secrets.json",
}
_SECRET_SUFFIXES = (".key", ".pem", ".p12", ".pfx")
_SECRET_CONTENT = re.compile(
    rb"(?i)(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    rb"(?:api[_-]?key|access[_-]?token|client[_-]?secret|password|authorization)"
    rb"\s*[:=]\s*['\"]?[A-Za-z0-9_+/=-]{8,})"
)


class GitPublisherError(RuntimeError):
    """A policy, integrity, or remote-CAS failure."""


class GitPublisher:
    """Publish role-owned changes through isolated clones and fast-forward refs."""

    def __init__(
        self,
        remote_url: str,
        *,
        remote_id: str,
        allowed_role_paths: Mapping[str, Sequence[str]],
        stable_branch: str = "stable",
    ) -> None:
        if not isinstance(remote_url, str) or not remote_url:
            raise ValueError("remote_url must be non-empty")
        if not isinstance(remote_id, str) or not remote_id or remote_id.strip() != remote_id:
            raise ValueError("remote_id must be non-empty trimmed text")
        if not isinstance(stable_branch, str) or not stable_branch or "/" in stable_branch:
            raise ValueError("stable_branch must be one safe branch component")
        normalized: dict[str, tuple[PurePosixPath, ...]] = {}
        for role, roots in allowed_role_paths.items():
            if not roots:
                raise ValueError(f"role {role!r} must have at least one allowed path")
            normalized[role] = tuple(self._safe_path(item) for item in roots)
        if not normalized:
            raise ValueError("allowed_role_paths must not be empty")
        self._remote_url = remote_url
        self._remote_id = remote_id
        self._allowed_role_paths = normalized
        self._stable_ref = f"refs/heads/{stable_branch}"

    def publish_candidate(self, request: GitCheckpointRequest) -> PublicationResult:
        roots = self._allowed_role_paths.get(request.role)
        if roots is None:
            raise GitPublisherError("checkpoint role has no publishing path grant")
        self._validate_changes(request.changes, roots)
        candidate_ref = f"refs/heads/candidate/{request.role}/{request.generation_id}"

        with tempfile.TemporaryDirectory(prefix="aegis-publisher-") as temporary:
            repo = Path(temporary) / "repo"
            self._clone(repo)
            stable = self._remote_head(repo, self._stable_ref)
            if stable != request.base_commit:
                raise GitPublisherError("checkpoint base is not the exact remote stable commit")
            if self._remote_head(repo, candidate_ref) is not None:
                raise GitPublisherError("candidate ref already exists and cannot be rewritten")
            self._validate_tree(repo, request.base_commit)
            self._git(repo, ("checkout", "--detach", request.base_commit), "checkout base")
            self._apply_changes(repo, request.changes)
            self._git(repo, ("add", "--all", "--"), "stage checkpoint")
            staged = self._nul_paths(
                self._git_bytes(repo, ("diff", "--cached", "--name-only", "-z"), "inspect staged paths")
            )
            requested = {item.path for item in request.changes}
            if staged != requested:
                raise GitPublisherError("staged checkpoint paths do not exactly match the request")
            if not staged:
                raise GitPublisherError("checkpoint produced no Git change")
            self._git(
                repo,
                (
                    "-c",
                    "user.name=AEGIS Publisher",
                    "-c",
                    "user.email=publisher@aegis.invalid",
                    "commit",
                    "--no-verify",
                    "-m",
                    request.message,
                ),
                "commit checkpoint",
            )
            candidate_commit = self._git(repo, ("rev-parse", "HEAD"), "resolve candidate")
            parent = self._git(repo, ("rev-parse", "HEAD^"), "resolve candidate parent")
            if parent != request.base_commit:
                raise GitPublisherError("candidate commit does not have the exact requested base")
            self._validate_tree(repo, candidate_commit)
            # Recheck both refs immediately before the push. Git's ordinary update
            # still includes the advertised old oid, so a concurrent drift is
            # rejected by receive-pack without requiring force.
            if self._remote_head(repo, self._stable_ref) != request.base_commit:
                raise GitPublisherError("remote stable drifted during candidate publication")
            if self._remote_head(repo, candidate_ref) is not None:
                raise GitPublisherError("candidate ref appeared concurrently")
            intent = PublishIntent.create(
                operation=PublishOperation.CANDIDATE,
                request_id=request.request_id,
                remote_id=self._remote_id,
                ref=candidate_ref,
                expected_old_commit=None,
                new_commit=candidate_commit,
            )
            self._push(repo, candidate_commit, candidate_ref, expected_old=None)
            if self._remote_head(repo, candidate_ref) != candidate_commit:
                raise GitPublisherError("candidate remote receipt verification failed")
            return PublicationResult(intent, PublishReceipt.create(intent))

    def promote_stable(self, request: StablePromotionRequest) -> PublicationResult:
        if request.role not in self._allowed_role_paths:
            raise GitPublisherError("promotion role has no publishing path grant")
        if not request.evidence.qualified:
            raise GitPublisherError("stable promotion requires qualified evidence")
        if not request.evidence.probation_passed:
            raise GitPublisherError("stable promotion requires passed probation evidence")
        candidate_ref = f"refs/heads/candidate/{request.role}/{request.generation_id}"

        with tempfile.TemporaryDirectory(prefix="aegis-publisher-") as temporary:
            repo = Path(temporary) / "repo"
            self._clone(repo)
            stable = self._remote_head(repo, self._stable_ref)
            if stable != request.expected_stable_commit:
                raise GitPublisherError("remote stable drifted from the expected CAS commit")
            candidate = self._remote_head(repo, candidate_ref)
            if candidate != request.evidence.candidate_commit:
                raise GitPublisherError("candidate ref does not match promotion evidence")
            self._validate_tree(repo, candidate)
            ancestor = self._run(
                repo,
                ("git", "merge-base", "--is-ancestor", stable, candidate),
                allowed_codes=(0, 1),
                label="check stable fast-forward",
            )
            if ancestor.returncode != 0:
                raise GitPublisherError("stable promotion must be a fast-forward")
            # One final read narrows the race; receive-pack provides the atomic
            # compare-and-swap for the subsequently advertised normal push.
            if self._remote_head(repo, self._stable_ref) != stable:
                raise GitPublisherError("remote stable drifted during promotion")
            intent = PublishIntent.create(
                operation=PublishOperation.STABLE,
                request_id=request.request_id,
                remote_id=self._remote_id,
                ref=self._stable_ref,
                expected_old_commit=stable,
                new_commit=candidate,
            )
            self._push(repo, candidate, self._stable_ref, expected_old=stable)
            if self._remote_head(repo, self._stable_ref) != candidate:
                raise GitPublisherError("stable remote receipt verification failed")
            return PublicationResult(intent, PublishReceipt.create(intent))

    @staticmethod
    def _safe_path(value: str) -> PurePosixPath:
        if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
            raise ValueError("Git paths must be non-empty canonical POSIX paths")
        path = PurePosixPath(value)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise ValueError("Git paths must be relative and traversal-free")
        if any(part.lower() == ".git" for part in path.parts):
            raise ValueError(".git paths are forbidden")
        return path

    def _validate_changes(
        self, changes: Sequence[GitFileChange], roots: tuple[PurePosixPath, ...]
    ) -> None:
        for change in changes:
            try:
                path = self._safe_path(change.path)
            except ValueError as exc:
                raise GitPublisherError(str(exc)) from exc
            if not any(path == root or root in path.parents for root in roots):
                raise GitPublisherError(f"path is outside the role grant: {change.path}")
            lowered = tuple(part.lower() for part in path.parts)
            if path.name.lower() == ".gitmodules":
                raise GitPublisherError("submodule declarations are forbidden")
            if any(part in _SECRET_PATH_PARTS for part in lowered) or path.name.lower().endswith(
                _SECRET_SUFFIXES
            ):
                raise GitPublisherError("secret-like paths are forbidden")
            if change.content is not None and _SECRET_CONTENT.search(change.content):
                raise GitPublisherError("secret-like file content is forbidden")

    def _clone(self, repo: Path) -> None:
        repo.parent.mkdir(parents=True, exist_ok=True)
        self._run(
            repo.parent,
            ("git", "clone", "--no-checkout", "--quiet", "--", self._remote_url, str(repo)),
            label="clone remote",
        )

    def _apply_changes(self, repo: Path, changes: Sequence[GitFileChange]) -> None:
        resolved_root = repo.resolve()
        for change in changes:
            path = self._safe_path(change.path)
            destination = repo.joinpath(*path.parts)
            current = repo
            for part in path.parts[:-1]:
                current /= part
                if current.is_symlink():
                    raise GitPublisherError("checkpoint path has a symlink ancestor")
            resolved_parent = destination.parent.resolve()
            if resolved_parent != resolved_root and resolved_root not in resolved_parent.parents:
                raise GitPublisherError("checkpoint path escapes the isolated clone")
            if destination.is_symlink():
                raise GitPublisherError("checkpoint cannot replace a symlink")
            if change.content is None:
                if not destination.is_file():
                    raise GitPublisherError("checkpoint deletion target is not a regular file")
                destination.unlink()
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(change.content)
            destination.chmod(
                stat.S_IRUSR
                | stat.S_IWUSR
                | stat.S_IRGRP
                | stat.S_IROTH
                | (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH if change.executable else 0)
            )

    def _validate_tree(self, repo: Path, commit: str) -> None:
        raw = self._git_bytes(
            repo,
            ("ls-tree", "-rz", "--full-tree", commit),
            "inspect Git tree",
        )
        for record in raw.split(b"\0"):
            if not record:
                continue
            metadata, separator, encoded_path = record.partition(b"\t")
            if not separator:
                raise GitPublisherError("Git tree entry is malformed")
            fields = metadata.split()
            if len(fields) != 3:
                raise GitPublisherError("Git tree metadata is malformed")
            mode, kind, _object_id = fields
            path = encoded_path.decode("utf-8", errors="strict")
            try:
                safe = self._safe_path(path)
            except (ValueError, UnicodeError) as exc:
                raise GitPublisherError("Git tree contains an unsafe path") from exc
            if mode == b"120000" or kind == b"commit" or mode == b"160000":
                raise GitPublisherError("symlink and submodule tree entries are forbidden")
            if safe.name.lower() == ".gitmodules":
                raise GitPublisherError("submodule declarations are forbidden")
            lowered = tuple(part.lower() for part in safe.parts)
            if any(part in _SECRET_PATH_PARTS for part in lowered) or safe.name.lower().endswith(
                _SECRET_SUFFIXES
            ):
                raise GitPublisherError("Git tree contains a secret-like path")
            if kind == b"blob":
                blob = self._git_bytes(repo, ("cat-file", "blob", _object_id.decode("ascii")), "inspect blob")
                if _SECRET_CONTENT.search(blob):
                    raise GitPublisherError("Git tree contains secret-like content")

    def _remote_head(self, repo: Path, ref: str) -> str | None:
        result = self._run(
            repo,
            ("git", "ls-remote", "--heads", "origin", ref),
            label="read remote ref",
        )
        output = result.stdout.decode("utf-8", errors="strict").strip()
        if not output:
            return None
        lines = output.splitlines()
        if len(lines) != 1:
            raise GitPublisherError("remote returned an ambiguous ref")
        object_id, separator, actual_ref = lines[0].partition("\t")
        if not separator or actual_ref != ref:
            raise GitPublisherError("remote returned a malformed ref")
        return object_id

    def _push(self, repo: Path, commit: str, ref: str, *, expected_old: str | None) -> None:
        # A lease is the remote compare-and-swap primitive. The caller has
        # already proved fast-forward ancestry (or create-only candidate state),
        # so this cannot authorize a rewrite even though Git names the option
        # ``force-with-lease``.
        expected = "" if expected_old is None else expected_old
        result = self._run(
            repo,
            (
                "git",
                "push",
                "--porcelain",
                f"--force-with-lease={ref}:{expected}",
                "origin",
                f"{commit}:{ref}",
            ),
            label="push ref",
        )
        if b"[up to date]" in result.stdout.lower():
            raise GitPublisherError("remote ref drifted to the requested value before CAS")

    def _git(self, repo: Path, args: tuple[str, ...], label: str) -> str:
        result = self._run(repo, ("git", *args), label=label)
        return result.stdout.decode("utf-8", errors="strict").strip()

    def _git_bytes(self, repo: Path, args: tuple[str, ...], label: str) -> bytes:
        return self._run(repo, ("git", *args), label=label).stdout

    @staticmethod
    def _nul_paths(raw: bytes) -> set[str]:
        try:
            return {item.decode("utf-8", errors="strict") for item in raw.split(b"\0") if item}
        except UnicodeError as exc:
            raise GitPublisherError("Git returned a non-UTF-8 path") from exc

    @staticmethod
    def _run(
        cwd: Path,
        argv: tuple[str, ...],
        *,
        label: str,
        allowed_codes: tuple[int, ...] = (0,),
    ) -> subprocess.CompletedProcess[bytes]:
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "LC_ALL": "C",
        }
        result = subprocess.run(
            argv,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
        if result.returncode not in allowed_codes:
            # Do not echo argv, remote URL, environment, or stderr: any of those
            # may contain publisher-owned credentials unavailable to the role.
            raise GitPublisherError(f"{label} failed")
        return result
