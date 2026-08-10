"""Real code-level evolution of the AEGIS harness itself.

The Warrior proposes a strict JSON patch against the harness grant (see
``aegis.evolution.surfaces``).  The control plane then:

1. verifies the proposal's checkpoint ref really exists and carries exactly the
   proposed tree (integrity),
2. applies the patch to an isolated real Git clone of the harness repo,
3. smoke-compiles and imports the modified harness,
4. runs a canary suite on both the pristine baseline and the candidate and
   requires zero regression,
5. on pass, activates the patch into the live harness repo and commits it,
6. on failure, the Prosecutor can order a rollback that resets the live
   harness repo to the pre-change commit.

Nothing here is a mock: every operation runs through real ``git`` and real
Python subprocesses against a configurable repository root.  Tests point the
repo at a disposable temporary Git repository.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from aegis.models import canonical_json
from aegis.publishing.models import GitFileChange

from .surfaces import (
    EvolutionSurfaceError,
    HARNESS_ALLOWED_ROOTS,
    HARNESS_FORBIDDEN_FILES,
    HARNESS_FORBIDDEN_ROOTS,
    HARNESS_SECRET_PATH_PARTS,
    HARNESS_SECRET_SUFFIXES,
    META_ALLOWED_ROOTS,
    META_FORBIDDEN_FILES,
    MAX_HARNESS_CHANGES,
    MAX_HARNESS_FILE_BYTES,
)

_COMMIT = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
_CONTENT_ID = re.compile(r"[a-z][a-z0-9-]*-sha256:[0-9a-f]{64}\Z")


class HarnessEvolutionError(RuntimeError):
    """A policy, integrity, or subprocess failure in harness code evolution."""


def _safe_path(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise HarnessEvolutionError("harness paths must be canonical POSIX paths")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise HarnessEvolutionError("harness paths must be relative and traversal-free")
    if any(part.lower() == ".git" for part in path.parts):
        raise HarnessEvolutionError(".git paths are forbidden")
    return path


def validate_harness_patch_paths(
    paths: Sequence[str], *, meta_evolution_enabled: bool = False
) -> None:
    """Apply the same grant used by the surface validator to raw patch paths."""
    for raw in paths:
        path = _safe_path(raw).as_posix()
        if path in HARNESS_FORBIDDEN_FILES and not meta_evolution_enabled:
            raise HarnessEvolutionError(f"harness path is a protected control file: {path}")
        if any(
            path == root or path.startswith(root) for root in HARNESS_FORBIDDEN_ROOTS
        ):
            raise HarnessEvolutionError(
                f"harness path is outside the evolvable harness grant: {path}"
            )
        if meta_evolution_enabled and path in META_ALLOWED_ROOTS:
            continue
        if not any(
            path == root or path.startswith(root) for root in HARNESS_ALLOWED_ROOTS
        ):
            raise HarnessEvolutionError(
                f"harness path is not under an allowed harness root: {path}"
            )
        lowered = tuple(part.lower() for part in path.split("/"))
        if any(part in HARNESS_SECRET_PATH_PARTS for part in lowered) or path.lower().endswith(
            HARNESS_SECRET_SUFFIXES
        ):
            raise HarnessEvolutionError("harness path looks like a secret file")


@dataclass(frozen=True, slots=True)
class ChangeManifest:
    """AHE-style decision manifest: what changed, why, and what may regress."""

    surface: str
    files: tuple[str, ...]
    failure_mode_targeted: str | None
    expected_fix: tuple[str, ...]
    regression_risk: tuple[str, ...]
    evidence_ref: str | None
    base_commit: str
    checkpoint_ref: str
    objective: str
    rationale: str
    manifest_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.surface, str) or not self.surface:
            raise HarnessEvolutionError("manifest surface must be non-empty")
        if not self.files or len(self.files) > MAX_HARNESS_CHANGES:
            raise HarnessEvolutionError("manifest files must be a bounded non-empty list")
        if _COMMIT.fullmatch(self.base_commit) is None:
            raise HarnessEvolutionError("manifest base_commit must be a full Git commit id")
        if not isinstance(self.checkpoint_ref, str) or not self.checkpoint_ref.startswith(
            "refs/heads/candidate/warrior/"
        ):
            raise HarnessEvolutionError("manifest checkpoint_ref must be a Warrior candidate ref")
        if not isinstance(self.objective, str) or not self.objective.strip():
            raise HarnessEvolutionError("manifest objective must be non-empty")
        expected = _digest(self.to_mapping(include_id=False))
        if self.manifest_id != expected:
            raise HarnessEvolutionError("manifest_id does not match manifest content")

    @classmethod
    def create(
        cls,
        *,
        surface: str,
        files: Sequence[str],
        failure_mode_targeted: str | None,
        expected_fix: Sequence[str],
        regression_risk: Sequence[str],
        evidence_ref: str | None,
        base_commit: str,
        checkpoint_ref: str,
        objective: str,
        rationale: str,
    ) -> ChangeManifest:
        ordered = tuple(sorted(set(files)))
        payload = {
            "surface": surface,
            "files": ordered,
            "failure_mode_targeted": failure_mode_targeted,
            "expected_fix": tuple(expected_fix),
            "regression_risk": tuple(regression_risk),
            "evidence_ref": evidence_ref,
            "base_commit": base_commit,
            "checkpoint_ref": checkpoint_ref,
            "objective": objective,
            "rationale": rationale,
        }
        return cls(
            surface,
            ordered,
            failure_mode_targeted,
            tuple(expected_fix),
            tuple(regression_risk),
            evidence_ref,
            base_commit,
            checkpoint_ref,
            objective,
            rationale,
            _digest(payload),
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> ChangeManifest:
        expected = {
            "manifest_id",
            "surface",
            "files",
            "failure_mode_targeted",
            "expected_fix",
            "regression_risk",
            "evidence_ref",
            "base_commit",
            "checkpoint_ref",
            "objective",
            "rationale",
        }
        if set(value) != expected:
            raise HarnessEvolutionError("change manifest has missing or unknown fields")
        return cls(
            value["surface"],
            tuple(value["files"]),
            value["failure_mode_targeted"],
            tuple(value["expected_fix"]),
            tuple(value["regression_risk"]),
            value["evidence_ref"],
            value["base_commit"],
            value["checkpoint_ref"],
            value["objective"],
            value["rationale"],
            value["manifest_id"],
        )

    def to_mapping(self, *, include_id: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "surface": self.surface,
            "files": list(self.files),
            "failure_mode_targeted": self.failure_mode_targeted,
            "expected_fix": list(self.expected_fix),
            "regression_risk": list(self.regression_risk),
            "evidence_ref": self.evidence_ref,
            "base_commit": self.base_commit,
            "checkpoint_ref": self.checkpoint_ref,
            "objective": self.objective,
            "rationale": self.rationale,
        }
        return {"manifest_id": self.manifest_id, **payload} if include_id else payload


def manifest_from_harness_content(content: Mapping[str, Any]) -> ChangeManifest:
    """Derive the decision manifest from a validated harness_code proposal."""
    return ChangeManifest.create(
        surface="harness-code",
        files=tuple(item["path"] for item in content["changes"]),
        failure_mode_targeted=content.get("failure_mode_targeted"),
        expected_fix=content.get("expected_fix", ()),
        regression_risk=content.get("regression_risk", ()),
        evidence_ref=content.get("evidence_ref"),
        base_commit=content["base_commit"],
        checkpoint_ref=content["checkpoint_ref"],
        objective=content["objective"],
        rationale=content["rationale"],
    )


def _digest(payload: Mapping[str, Any]) -> str:
    return "change-manifest-sha256:" + hashlib.sha256(
        canonical_json(payload).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class RollbackOrder:
    """A Prosecutor-issued rollback order for one failed harness evolution."""

    candidate_id: str
    reason: str
    analysis: str
    order_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.candidate_id, str) or not self.candidate_id.startswith(
            "evolution-candidate-sha256:"
        ) or _CONTENT_ID.fullmatch(self.candidate_id) is None:
            raise HarnessEvolutionError("rollback order candidate_id is invalid")
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise HarnessEvolutionError("rollback order reason must be non-empty")
        if not isinstance(self.analysis, str):
            raise HarnessEvolutionError("rollback order analysis must be text")
        expected = "rollback-order-sha256:" + hashlib.sha256(
            canonical_json(self.to_mapping(include_id=False)).encode("utf-8")
        ).hexdigest()
        if self.order_id != expected:
            raise HarnessEvolutionError("rollback order content id mismatch")

    @classmethod
    def create(cls, *, candidate_id: str, reason: str, analysis: str) -> RollbackOrder:
        payload = {
            "candidate_id": candidate_id,
            "reason": reason,
            "analysis": analysis,
        }
        return cls(
            candidate_id,
            reason,
            analysis,
            "rollback-order-sha256:"
            + hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest(),
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> RollbackOrder:
        expected = {"order_id", "candidate_id", "reason", "analysis"}
        if set(value) != expected:
            raise HarnessEvolutionError("rollback order has missing or unknown fields")
        return cls(
            value["candidate_id"],
            value["reason"],
            value["analysis"],
            value["order_id"],
        )

    def to_mapping(self, *, include_id: bool = True) -> dict[str, Any]:
        payload = {
            "candidate_id": self.candidate_id,
            "reason": self.reason,
            "analysis": self.analysis,
        }
        return {"order_id": self.order_id, **payload} if include_id else payload


def changes_to_git_file_changes(
    changes: Sequence[Mapping[str, Any]],
) -> tuple[GitFileChange, ...]:
    """Convert validated harness change mappings into Git file changes."""
    converted: list[GitFileChange] = []
    paths: set[str] = set()
    for item in changes:
        path = item["path"]
        if path in paths:
            raise HarnessEvolutionError("harness change paths must be unique")
        paths.add(path)
        encoded = item["content_base64"]
        if item["delete"]:
            content: bytes | None = None
        else:
            try:
                content = base64.b64decode(encoded, validate=True)
            except ValueError as exc:
                raise HarnessEvolutionError("harness content_base64 is invalid") from exc
            if not content or len(content) > MAX_HARNESS_FILE_BYTES:
                raise HarnessEvolutionError("harness file content is empty or oversized")
        converted.append(GitFileChange(path, content, item["executable"]))
    return tuple(sorted(converted, key=lambda item: item.path))


def _apply_file_changes(repo_root: Path, changes: Sequence[GitFileChange]) -> None:
    resolved_root = repo_root.resolve()
    for change in changes:
        path = _safe_path(change.path)
        destination = repo_root.joinpath(*path.parts)
        current = repo_root
        for part in path.parts[:-1]:
            current /= part
            if current.is_symlink():
                raise HarnessEvolutionError("harness path has a symlink ancestor")
        resolved_parent = destination.parent.resolve()
        if resolved_parent != resolved_root and resolved_root not in resolved_parent.parents:
            raise HarnessEvolutionError("harness path escapes the repository root")
        if destination.is_symlink():
            raise HarnessEvolutionError("harness cannot replace a symlink")
        if change.content is None:
            if not destination.is_file():
                raise HarnessEvolutionError("harness deletion target is not a regular file")
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


@dataclass(frozen=True, slots=True)
class CanaryVerdict:
    passed: bool
    reason: str
    smoke_output: str
    canary_output: str
    evidence_id: str

    def to_mapping(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "reason": self.reason[:4096],
            "smoke_output": self.smoke_output[:4096],
            "canary_output": self.canary_output[:4096],
            "evidence_id": self.evidence_id,
        }


class HarnessRepo:
    """Real Git operations against the harness repository."""

    def __init__(
        self,
        repo_root: Path,
        *,
        git_timeout_seconds: float = 120.0,
        python: str | None = None,
        meta_evolution_enabled: bool = False,
    ) -> None:
        root = Path(repo_root).resolve()
        if not root.is_dir():
            raise HarnessEvolutionError(f"harness repo root is not a directory: {root}")
        if not (root / ".git").exists():
            raise HarnessEvolutionError(f"harness repo root is not a Git repository: {root}")
        if (
            isinstance(git_timeout_seconds, bool)
            or not isinstance(git_timeout_seconds, (int, float))
            or not 1 <= float(git_timeout_seconds) <= 3600
        ):
            raise HarnessEvolutionError("git_timeout_seconds must be in (0, 3600]")
        self._root = root
        self._timeout = float(git_timeout_seconds)
        self._python = python or sys.executable
        self._meta_evolution_enabled = bool(meta_evolution_enabled)

    @property
    def root(self) -> Path:
        return self._root

    def _git(self, *argv: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                ("git", *argv),
                cwd=cwd or self._root,
                capture_output=True,
                text=True,
                timeout=self._timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise HarnessEvolutionError(f"git failed: {exc}") from exc

    def resolve_commit(self, ref: str) -> str:
        result = self._git("rev-parse", "--verify", f"{ref}^{{commit}}")
        if result.returncode != 0:
            raise HarnessEvolutionError(f"cannot resolve Git ref {ref!r}")
        commit = result.stdout.strip()
        if _COMMIT.fullmatch(commit) is None:
            raise HarnessEvolutionError("resolved Git commit is malformed")
        return commit

    def ref_exists(self, ref: str) -> bool:
        result = self._git("show-ref", "--verify", "--quiet", ref)
        return result.returncode == 0

    def ensure_checkpoint_ref(self, ref: str) -> None:
        """Make a candidate ref locally visible: already present, or fetched
        from the origin remote when the control plane publishes checkpoints
        to a shared harness repository."""
        if self.ref_exists(ref):
            return
        remote = self._git("remote", "get-url", "origin")
        if remote.returncode != 0:
            raise HarnessEvolutionError(
                f"checkpoint ref {ref!r} is not present and no origin remote exists"
            )
        fetch = self._git("fetch", "--quiet", "origin", f"{ref}:{ref}")
        if fetch.returncode != 0:
            raise HarnessEvolutionError(
                f"cannot fetch checkpoint ref {ref!r} from origin"
            )
        if not self.ref_exists(ref):
            raise HarnessEvolutionError(
                f"checkpoint ref {ref!r} was not created by the fetch"
            )

    def is_ancestor(self, ancestor: str, descendant: str) -> bool:
        result = self._git(
            "merge-base",
            "--is-ancestor",
            self.resolve_commit(ancestor),
            self.resolve_commit(descendant),
        )
        return result.returncode == 0

    def verify_checkpoint(
        self, *, base_commit: str, checkpoint_ref: str, changes: Sequence[GitFileChange]
    ) -> str:
        """Verify the checkpoint ref exists, is based on base_commit, and its
        tree exactly equals base_commit plus the proposed changes."""
        validate_harness_patch_paths(
            [item.path for item in changes],
            meta_evolution_enabled=self._meta_evolution_enabled,
        )
        self.ensure_checkpoint_ref(checkpoint_ref)
        if not self.ref_exists(checkpoint_ref):
            raise HarnessEvolutionError(f"checkpoint ref does not exist: {checkpoint_ref}")
        checkpoint_commit = self.resolve_commit(checkpoint_ref)
        if not self.is_ancestor(base_commit, checkpoint_commit):
            raise HarnessEvolutionError("checkpoint is not based on the proposed base commit")
        with tempfile.TemporaryDirectory(prefix="aegis-harness-checkpoint-") as directory:
            clone = self.clone_at(Path(directory) / "repo", base_commit)
            _apply_file_changes(clone, changes)
            staged = {item.path for item in changes}
            result = self._git("add", "--", *sorted(staged), cwd=clone)
            if result.returncode != 0:
                raise HarnessEvolutionError("cannot stage harness changes for tree compare")
            tree = self._git("write-tree", cwd=clone)
            if tree.returncode != 0:
                raise HarnessEvolutionError("cannot compute candidate tree")
            expected_tree = tree.stdout.strip()
            checkpoint_tree = self._git("rev-parse", f"{checkpoint_commit}^{{tree}}")
            if (
                checkpoint_tree.returncode != 0
                or checkpoint_tree.stdout.strip() != expected_tree
            ):
                raise HarnessEvolutionError(
                    "checkpoint tree does not match the proposed harness changes"
                )
        return checkpoint_commit

    def clone_at(self, destination: Path, base_commit: str) -> Path:
        destination.mkdir(parents=True)
        result = self._git(
            "clone", "--no-checkout", "--quiet", "--", str(self._root), str(destination)
        )
        if result.returncode != 0:
            raise HarnessEvolutionError("cannot clone the harness repository")
        checkout = self._git(
            "checkout", "--quiet", "--detach", self.resolve_commit(base_commit), cwd=destination
        )
        if checkout.returncode != 0:
            raise HarnessEvolutionError("cannot detach the harness clone at base_commit")
        return destination

    def apply_changes(
        self, repo_root: Path, changes: Sequence[GitFileChange]
    ) -> None:
        validate_harness_patch_paths(
            [item.path for item in changes],
            meta_evolution_enabled=self._meta_evolution_enabled,
        )
        _apply_file_changes(repo_root, changes)

    def smoke(self, repo_root: Path) -> str:
        """Compile the harness package and import it from the modified clone."""
        compile_result = self._run(
            repo_root,
            (
                self._python,
                "-m",
                "compileall",
                "-q",
                "-f",
                "src/aegis",
            ),
            timeout=120.0,
        )
        if compile_result.returncode != 0:
            raise HarnessEvolutionError(
                f"harness package failed to compile:\n{compile_result.stdout}\n{compile_result.stderr}"
            )
        import_result = self._run(
            repo_root,
            (
                self._python,
                "-c",
                "import sys; sys.path.insert(0, 'src'); import aegis",
            ),
            timeout=120.0,
        )
        if import_result.returncode != 0:
            raise HarnessEvolutionError(
                f"modified harness failed to import:\n{import_result.stdout}\n{import_result.stderr}"
            )
        return import_result.stdout + import_result.stderr

    def run_canary(
        self, repo_root: Path, canary_argv: Sequence[str], *, timeout: float = 300.0
    ) -> subprocess.CompletedProcess[str]:
        argv = tuple(
            self._python if item == "{python}" else item for item in canary_argv
        )
        return self._run(repo_root, argv, timeout=timeout)

    def _run(
        self, cwd: Path, argv: Sequence[str], *, timeout: float
    ) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(cwd / "src")
        environment.pop("PYTHONDONTWRITEBYTECODE", None)
        try:
            return subprocess.run(
                tuple(argv),
                cwd=cwd,
                env=environment,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise HarnessEvolutionError(f"harness command failed: {exc}") from exc

    def activate(
        self, changes: Sequence[GitFileChange], *, message: str
    ) -> str:
        """Apply and commit the approved patch on the live harness repo."""
        validate_harness_patch_paths(
            [item.path for item in changes],
            meta_evolution_enabled=self._meta_evolution_enabled,
        )
        _apply_file_changes(self._root, changes)
        requested = {item.path for item in changes}
        add_result = self._git("add", "--", *sorted(requested))
        if add_result.returncode != 0:
            raise HarnessEvolutionError(f"cannot stage harness activation: {add_result.stderr}")
        staged_result = self._git("diff", "--cached", "--name-only", "-z")
        staged = {item for item in staged_result.stdout.split("\0") if item}
        if staged != requested:
            raise HarnessEvolutionError("staged activation paths do not match the request")
        commit_result = self._git(
            "-c",
            "user.name=AEGIS Harness Evolution",
            "-c",
            "user.email=evolution@aegis.invalid",
            "commit",
            "--no-verify",
            "-m",
            message[:512],
        )
        if commit_result.returncode != 0:
            raise HarnessEvolutionError(f"harness activation commit failed: {commit_result.stderr}")
        return self.resolve_commit("HEAD")

    def rollback(self, commit: str) -> str:
        """Reset the live harness repo to a verified ancestor commit."""
        target = self.resolve_commit(commit)
        if not self.is_ancestor(target, "HEAD"):
            raise HarnessEvolutionError("rollback target is not an ancestor of HEAD")
        result = self._git("reset", "--hard", target)
        if result.returncode != 0:
            raise HarnessEvolutionError(f"harness rollback failed: {result.stderr}")
        head = self.resolve_commit("HEAD")
        if head != target:
            raise HarnessEvolutionError("harness rollback did not reach the target commit")
        return target


class HarnessCanaryRunner:
    """Baseline-vs-candidate canary for one harness_code proposal."""

    def __init__(
        self,
        repo: HarnessRepo,
        *,
        canary_argv: Sequence[str] = (
            "{python}",
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            "tests/test_evolution_surfaces.py",
        ),
        canary_timeout: float = 300.0,
    ) -> None:
        self._repo = repo
        self._canary_argv = tuple(canary_argv)
        self._timeout = canary_timeout

    def run(
        self,
        content: Mapping[str, Any],
        changes: Sequence[GitFileChange],
        *,
        base_commit: str | None = None,
    ) -> CanaryVerdict:
        base = base_commit or content["base_commit"]
        checkpoint_commit = self._repo.verify_checkpoint(
            base_commit=base,
            checkpoint_ref=content["checkpoint_ref"],
            changes=changes,
        )
        baseline_verdict = self._canary_once(base, None)
        if not baseline_verdict.passed:
            return baseline_verdict
        candidate_verdict = self._canary_once(base, changes)
        if not candidate_verdict.passed:
            return candidate_verdict
        payload = {
            "passed": True,
            "base_commit": base,
            "checkpoint_commit": checkpoint_commit,
            "baseline": baseline_verdict.to_mapping(),
            "candidate": candidate_verdict.to_mapping(),
        }
        evidence_id = "harness-canary-sha256:" + hashlib.sha256(
            canonical_json(payload).encode("utf-8")
        ).hexdigest()
        return CanaryVerdict(
            True,
            "baseline and candidate both passed; zero-regression gate satisfied",
            candidate_verdict.smoke_output,
            candidate_verdict.canary_output,
            evidence_id,
        )

    def _canary_once(
        self, base_commit: str, changes: Sequence[GitFileChange] | None
    ) -> CanaryVerdict:
        with tempfile.TemporaryDirectory(prefix="aegis-harness-canary-") as directory:
            clone = self._repo.clone_at(Path(directory) / "repo", base_commit)
            if changes is not None:
                self._repo.apply_changes(clone, changes)
            try:
                smoke_output = self._repo.smoke(clone)
            except HarnessEvolutionError as exc:
                return CanaryVerdict(
                    False,
                    str(exc)[:2000],
                    str(exc)[:2000],
                    "",
                    "",
                )
            canary = self._repo.run_canary(
                clone, self._canary_argv, timeout=self._timeout
            )
            if canary.returncode != 0:
                return CanaryVerdict(
                    False,
                    "canary suite failed on the harness worktree",
                    smoke_output,
                    (canary.stdout + canary.stderr)[:4000],
                    "",
                )
            payload = {
                "passed": True,
                "base_commit": base_commit,
                "applied_changes": changes is not None,
                "smoke_output": smoke_output[:4096],
                "canary_output": (canary.stdout + canary.stderr)[:4096],
            }
            evidence_id = "harness-canary-arm-sha256:" + hashlib.sha256(
                canonical_json(payload).encode("utf-8")
            ).hexdigest()
            return CanaryVerdict(
                True,
                "harness worktree compiled, imported, and passed the canary suite",
                smoke_output,
                canary.stdout + canary.stderr,
                evidence_id,
            )


class HarnessRollbackExecutor:
    """Executes a Prosecutor rollback order against the live harness repo."""

    def __init__(self, repo: HarnessRepo) -> None:
        self._repo = repo

    def execute(
        self, order: RollbackOrder, *, base_commit: str
    ) -> Mapping[str, Any]:
        restored = self._repo.rollback(base_commit)
        payload = {
            "order_id": order.order_id,
            "candidate_id": order.candidate_id,
            "reason": order.reason,
            "analysis": order.analysis,
            "restored_commit": restored,
        }
        return {
            "restored_commit": restored,
            "evidence_id": "harness-rollback-sha256:"
            + hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest(),
            "payload": payload,
        }


__all__ = [
    "CanaryVerdict",
    "ChangeManifest",
    "HarnessCanaryRunner",
    "HarnessEvolutionError",
    "HarnessRepo",
    "HarnessRollbackExecutor",
    "RollbackOrder",
    "changes_to_git_file_changes",
    "manifest_from_harness_content",
    "validate_harness_patch_paths",
]
