"""Trusted Linux-side Git agent for :mod:`aegis.evolution.harness_backend`.

Install this module's ``main`` as ``/usr/local/bin/aegis-harness-agent`` in the
dedicated distribution.  Requests contain data, never commands or filesystem
locations.  Every campaign directory is derived from SHA-256(campaign_id).
"""

from __future__ import annotations

import base64
import hashlib
import importlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any, Iterator
from urllib.parse import urlsplit

from aegis.models import canonical_json

from .harness import validate_harness_patch_paths

CAMPAIGNS_ROOT = Path("/var/lib/aegis/campaigns")
_fcntl: Any | None
try:
    _fcntl = importlib.import_module("fcntl")
except ImportError:  # pragma: no cover - the production agent is Linux-only
    _fcntl = None
_COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_OPERATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_SECRET_NAME = re.compile(
    r"(?i)(?:^|/)(?:\.env(?:\..*)?|id_(?:rsa|dsa|ecdsa|ed25519)|credentials?|secrets?)(?:$|\.)"
)
_SECRET_CONTENT = re.compile(
    rb"(?:-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
    rb"AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{20,}|gh[opsu]_[A-Za-z0-9]{24,})"
)
_MAX_FILE_BYTES = 4 * 1024 * 1024
_MAX_TOTAL_BYTES = 128 * 1024 * 1024


class AgentError(RuntimeError):
    pass


class HarnessAgent:
    def __init__(self, root: Path = CAMPAIGNS_ROOT) -> None:
        if not root.is_absolute():
            raise ValueError("campaign root must be absolute")
        if _fcntl is None:
            raise RuntimeError("the harness agent requires Linux flock support")
        self.root = root

    def handle(self, request: Mapping[str, Any]) -> dict[str, Any]:
        if request.get("version") != 1:
            raise AgentError("unsupported request version")
        operation = _required(request, "operation", 64)
        operation_id = _required(request, "operation_id", 128)
        campaign_id = _required(request, "campaign_id", 512)
        if _OPERATION_ID.fullmatch(operation_id) is None:
            raise AgentError("unsafe operation_id")
        if operation not in {
            "ensure_campaign",
            "status",
            "checkpoint",
            "validate",
            "activate",
            "rollback",
            "cleanup_candidate",
        }:
            raise AgentError("unsupported harness operation")
        campaign_key = hashlib.sha256(campaign_id.encode()).hexdigest()
        campaign = self.root / campaign_key
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        with self._campaign_lock(campaign_key):
            receipt_path = campaign / "operations" / f"{operation_id}.json"
            if receipt_path.is_file():
                receipt = _read_object(receipt_path)
                request_sha256 = hashlib.sha256(canonical_json(request).encode()).hexdigest()
                if (
                    receipt.get("operation") != operation
                    or receipt.get("campaign_id") != campaign_id
                    or receipt.get("request_sha256") != request_sha256
                ):
                    raise AgentError("operation_id was reused for another request")
                return {"ok": True, "receipt": receipt}
            handler = getattr(self, f"_{operation}")
            values = handler(campaign, campaign_id, request)
            receipt = self._receipt(
                operation,
                operation_id,
                campaign_id,
                campaign_key,
                hashlib.sha256(canonical_json(request).encode()).hexdigest(),
                **values,
            )
            receipt_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            _atomic_json(receipt_path, receipt)
            return {"ok": True, "receipt": receipt}

    @contextmanager
    def _campaign_lock(self, campaign_key: str) -> Iterator[None]:
        locks = self.root / ".locks"
        locks.mkdir(mode=0o700, parents=True, exist_ok=True)
        with (locks / f"{campaign_key}.lock").open("a+b") as stream:
            assert _fcntl is not None
            _fcntl.flock(stream.fileno(), _fcntl.LOCK_EX)
            try:
                yield
            finally:
                _fcntl.flock(stream.fileno(), _fcntl.LOCK_UN)

    def _ensure_campaign(
        self, campaign: Path, campaign_id: str, request: Mapping[str, Any]
    ) -> dict[str, Any]:
        source_url = _source_url(request.get("source_url"))
        source_ref = _commit(request.get("source_ref"), "source_ref")
        repo = campaign / "repo.git"
        state_path = campaign / "state.json"
        if state_path.is_file():
            state = _read_object(state_path)
            if (
                state.get("campaign_id") != campaign_id
                or state.get("source_url") != source_url
                or state.get("source_ref") != source_ref
            ):
                raise AgentError("campaign source binding mismatch")
            champion = self._resolve(repo, "refs/aegis/champion")
            return self._values("ready", champion, detail="campaign already exists")
        campaign.mkdir(mode=0o700, parents=True, exist_ok=True)
        (campaign / "worktrees").mkdir(mode=0o700)
        (campaign / "events").mkdir(mode=0o700)
        (campaign / "artifacts").mkdir(mode=0o700)
        (campaign / "operations").mkdir(mode=0o700)
        _git(None, "clone", "--bare", "--filter=blob:none", "--", source_url, str(repo), timeout=3600)
        try:
            _git(repo, "fetch", "--no-tags", "origin", source_ref, timeout=3600)
            resolved = self._resolve(repo, "FETCH_HEAD")
            if resolved != source_ref:
                raise AgentError("fetched source_ref did not resolve exactly")
            _git(repo, "update-ref", "refs/aegis/champion", resolved, "0" * len(resolved))
            self._add_worktree(campaign, "champion", resolved)
            _atomic_json(
                state_path,
                {
                    "campaign_id": campaign_id,
                    "source_url": source_url,
                    "source_ref": source_ref,
                    "champion_commit": resolved,
                    "last_known_good": resolved,
                },
            )
        except Exception:
            shutil.rmtree(campaign, ignore_errors=True)
            raise
        return self._values("created", resolved, detail="campaign initialized")

    def _status(
        self, campaign: Path, campaign_id: str, request: Mapping[str, Any]
    ) -> dict[str, Any]:
        del campaign_id, request
        repo = self._repo(campaign)
        return self._values("ready", self._resolve(repo, "refs/aegis/champion"))

    def _checkpoint(
        self, campaign: Path, campaign_id: str, request: Mapping[str, Any]
    ) -> dict[str, Any]:
        del campaign_id
        repo = self._repo(campaign)
        candidate_id = _required(request, "candidate_id", 256)
        base = _commit(request.get("base_commit"), "base_commit")
        if self._resolve(repo, "refs/aegis/champion") != base:
            raise AgentError("checkpoint base is not current champion")
        raw_changes = request.get("changes")
        if not isinstance(raw_changes, list) or not raw_changes or len(raw_changes) > 128:
            raise AgentError("changes must be a bounded non-empty array")
        try:
            validate_harness_patch_paths(
                [str(item.get("path", "")) for item in raw_changes if isinstance(item, Mapping)]
            )
        except (TypeError, RuntimeError) as exc:
            raise AgentError(str(exc)) from exc
        token = _candidate_key(candidate_id)
        candidate_ref = f"refs/aegis/candidates/{token}"
        worktree = campaign / "worktrees" / f"candidate-{token}"
        existing = _git(
            repo, "show-ref", "--verify", "--hash", candidate_ref, check=False
        ).stdout.strip()
        if isinstance(existing, str) and existing:
            self._validate_tree(repo, existing)
            return self._values("checkpointed", base, candidate=existing)
        if worktree.exists():
            _git(repo, "worktree", "remove", "--force", "--", str(worktree), check=False)
            shutil.rmtree(worktree, ignore_errors=True)
        _git(repo, "worktree", "add", "--detach", "--", str(worktree), base)
        try:
            self._apply_changes(worktree, raw_changes)
            _git(worktree, "add", "--all", "--", ".")
            _git(
                worktree,
                "-c",
                "user.name=AEGIS Warrior",
                "-c",
                "user.email=aegis@invalid",
                "commit",
                "--no-gpg-sign",
                "-m",
                f"AEGIS candidate {token}",
            )
            commit = self._resolve(worktree, "HEAD")
            self._validate_tree(repo, commit)
            _git(repo, "update-ref", candidate_ref, commit, "0" * len(commit))
        except Exception:
            _git(repo, "worktree", "remove", "--force", "--", str(worktree), check=False)
            shutil.rmtree(worktree, ignore_errors=True)
            raise
        return self._values("checkpointed", base, candidate=commit)

    def _validate(
        self, campaign: Path, campaign_id: str, request: Mapping[str, Any]
    ) -> dict[str, Any]:
        del campaign_id
        repo = self._repo(campaign)
        candidate_id = _required(request, "candidate_id", 256)
        expected = _commit(request.get("candidate_commit"), "candidate_commit")
        actual = self._resolve(repo, f"refs/aegis/candidates/{_candidate_key(candidate_id)}")
        if actual != expected:
            raise AgentError("candidate ref does not match candidate_commit")
        self._validate_tree(repo, actual)
        if not self._is_ancestor(repo, self._resolve(repo, "refs/aegis/champion"), actual):
            raise AgentError("candidate is not based on current champion")
        return self._values(
            "validated", self._resolve(repo, "refs/aegis/champion"), candidate=actual
        )

    def _activate(
        self, campaign: Path, campaign_id: str, request: Mapping[str, Any]
    ) -> dict[str, Any]:
        del campaign_id
        repo = self._repo(campaign)
        candidate_id = _required(request, "candidate_id", 256)
        candidate = _commit(request.get("candidate_commit"), "candidate_commit")
        expected = _commit(request.get("expected_champion"), "expected_champion")
        if self._resolve(repo, f"refs/aegis/candidates/{_candidate_key(candidate_id)}") != candidate:
            raise AgentError("candidate ref does not match candidate_commit")
        self._validate_tree(repo, candidate)
        current = self._resolve(repo, "refs/aegis/champion")
        if current != candidate:
            if current != expected:
                raise AgentError("champion changed before candidate activation")
            _git(repo, "update-ref", "refs/aegis/champion", candidate, expected)
        self._add_worktree(campaign, "champion", candidate)
        state = _read_object(campaign / "state.json")
        if current != candidate:
            state["last_known_good"] = expected
        state["champion_commit"] = candidate
        _atomic_json(campaign / "state.json", state)
        return self._values("activated", candidate, candidate=candidate, previous=expected)

    def _rollback(
        self, campaign: Path, campaign_id: str, request: Mapping[str, Any]
    ) -> dict[str, Any]:
        del campaign_id
        repo = self._repo(campaign)
        failed = _commit(request.get("failed_commit"), "failed_commit")
        target = _commit(request.get("target_commit"), "target_commit")
        state = _read_object(campaign / "state.json")
        if state.get("last_known_good") != target:
            raise AgentError("rollback target is not the recorded last-known-good commit")
        self._validate_tree(repo, target)
        current = self._resolve(repo, "refs/aegis/champion")
        if current != target:
            if current != failed:
                raise AgentError("champion changed before rollback")
            _git(repo, "update-ref", "refs/aegis/champion", target, failed)
        self._add_worktree(campaign, "champion", target)
        state["champion_commit"] = target
        _atomic_json(campaign / "state.json", state)
        return self._values("rolled_back", target, previous=failed)

    def _cleanup_candidate(
        self, campaign: Path, campaign_id: str, request: Mapping[str, Any]
    ) -> dict[str, Any]:
        del campaign_id
        repo = self._repo(campaign)
        token = _candidate_key(_required(request, "candidate_id", 256))
        worktree = campaign / "worktrees" / f"candidate-{token}"
        _git(repo, "worktree", "remove", "--force", "--", str(worktree), check=False)
        shutil.rmtree(worktree, ignore_errors=True)
        _git(repo, "update-ref", "-d", f"refs/aegis/candidates/{token}", check=False)
        return self._values("cleaned", self._resolve(repo, "refs/aegis/champion"))

    def _repo(self, campaign: Path) -> Path:
        repo = campaign / "repo.git"
        if not (repo / "HEAD").is_file() or not (campaign / "state.json").is_file():
            raise AgentError("campaign is not initialized")
        return repo

    def _add_worktree(self, campaign: Path, kind: str, commit: str) -> Path:
        repo = campaign / "repo.git"
        destination = campaign / "worktrees" / f"{kind}-{commit[:12]}"
        if not destination.exists():
            _git(repo, "worktree", "add", "--detach", "--", str(destination), commit)
        return destination

    def _apply_changes(self, worktree: Path, changes: Sequence[object]) -> None:
        seen: set[str] = set()
        for raw in changes:
            if not isinstance(raw, Mapping) or set(raw) != {
                "path",
                "content_base64",
                "delete",
                "executable",
            }:
                raise AgentError("change has missing or unknown fields")
            path = _safe_relative(raw["path"])
            normalized = path.as_posix()
            if normalized in seen:
                raise AgentError("duplicate change path")
            seen.add(normalized)
            destination = worktree.joinpath(*path.parts)
            _ensure_no_symlink_ancestors(worktree, destination)
            if not isinstance(raw["delete"], bool) or not isinstance(raw["executable"], bool):
                raise AgentError("change flags must be booleans")
            if raw["delete"]:
                if not destination.is_file() or destination.is_symlink():
                    raise AgentError("deletion target must be a regular file")
                destination.unlink()
                continue
            encoded = raw["content_base64"]
            if not isinstance(encoded, str):
                raise AgentError("change content must be base64 text")
            try:
                content = base64.b64decode(encoded, validate=True)
            except ValueError as exc:
                raise AgentError("change content is invalid base64") from exc
            if not content or len(content) > _MAX_FILE_BYTES:
                raise AgentError("change content is empty or oversized")
            destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            destination.write_bytes(content)
            destination.chmod(0o755 if raw["executable"] else 0o644)

    def _validate_tree(self, repo: Path, commit: str) -> None:
        listing = _git(repo, "ls-tree", "-r", "-z", "--full-tree", commit).stdout
        total = 0
        for entry in listing.split("\0"):
            if not entry:
                continue
            metadata, raw_path = entry.split("\t", 1)
            mode, kind, object_id = metadata.split(" ", 2)
            path = _safe_relative(raw_path).as_posix()
            if mode in {"120000", "160000"} or kind != "blob":
                raise AgentError(f"forbidden symlink or submodule: {path}")
            if _SECRET_NAME.search(path):
                raise AgentError(f"secret-like path is forbidden: {path}")
            size_text = _git(repo, "cat-file", "-s", object_id).stdout.strip()
            size = int(size_text)
            total += size
            if size > _MAX_FILE_BYTES or total > _MAX_TOTAL_BYTES:
                raise AgentError("candidate tree exceeds size limits")
            if size <= _MAX_FILE_BYTES:
                content = _git(repo, "cat-file", "blob", object_id, text=False).stdout
                assert isinstance(content, bytes)
                if _SECRET_CONTENT.search(content):
                    raise AgentError(f"secret-like content is forbidden: {path}")

    @staticmethod
    def _is_ancestor(repo: Path, ancestor: str, descendant: str) -> bool:
        return _git(
            repo, "merge-base", "--is-ancestor", ancestor, descendant, check=False
        ).returncode == 0

    @staticmethod
    def _resolve(repo: Path, ref: str) -> str:
        commit = _git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}").stdout.strip()
        if not isinstance(commit, str) or _COMMIT.fullmatch(commit) is None:
            raise AgentError("Git resolved a malformed commit")
        return commit

    @staticmethod
    def _values(
        status: str,
        champion: str,
        *,
        candidate: str | None = None,
        previous: str | None = None,
        detail: str = "",
    ) -> dict[str, Any]:
        return {
            "status": status,
            "champion_commit": champion,
            "candidate_commit": candidate,
            "previous_champion": previous,
            "detail": detail,
        }

    @staticmethod
    def _receipt(
        operation: str,
        operation_id: str,
        campaign_id: str,
        campaign_key: str,
        request_sha256: str,
        **values: Any,
    ) -> dict[str, Any]:
        payload = {
            "operation": operation,
            "operation_id": operation_id,
            "campaign_id": campaign_id,
            "campaign_key": campaign_key,
            "request_sha256": request_sha256,
            **values,
        }
        return {
            **payload,
            "receipt_sha256": hashlib.sha256(
                canonical_json(payload).encode("utf-8")
            ).hexdigest(),
        }


def _git(
    cwd: Path | None,
    *args: str,
    check: bool = True,
    timeout: float = 120,
    text: bool = True,
) -> subprocess.CompletedProcess[Any]:
    env = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_ALLOW_PROTOCOL": "https",
    }
    try:
        result = subprocess.run(
            ("git", *args),
            cwd=cwd,
            env=env,
            capture_output=True,
            text=text,
            shell=False,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise AgentError(f"Git transport failed: {exc}") from exc
    if check and result.returncode != 0:
        stderr = result.stderr if isinstance(result.stderr, str) else result.stderr.decode(errors="replace")
        raise AgentError(f"Git operation failed: {stderr[:512].strip()}")
    return result


def _source_url(value: object) -> str:
    source = _required_value(value, "source_url", 2048)
    parsed = urlsplit(source)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in {None, 443}
        or parsed.query
        or parsed.fragment
        or "\\" in source
    ):
        raise AgentError("source_url must be credential-free HTTPS")
    assert parsed.hostname is not None
    _reject_private_hostname(parsed.hostname)
    return source


def _reject_private_hostname(hostname: str) -> None:
    lowered = hostname.rstrip(".").lower()
    if lowered == "localhost" or lowered.endswith((".localhost", ".local", ".internal")):
        raise AgentError("source_url must name a public HTTPS host")
    try:
        address = ipaddress.ip_address(lowered.strip("[]"))
    except ValueError:
        return
    if not address.is_global:
        raise AgentError("source_url must not use a private or reserved IP address")


def _required(request: Mapping[str, Any], name: str, maximum: int) -> str:
    return _required_value(request.get(name), name, maximum)


def _required_value(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise AgentError(f"invalid {name}")
    if len(value.encode()) > maximum:
        raise AgentError(f"{name} exceeds size limit")
    return value


def _commit(value: object, name: str) -> str:
    if not isinstance(value, str) or _COMMIT.fullmatch(value) is None:
        raise AgentError(f"{name} must be a full commit id")
    return value


def _candidate_key(candidate_id: str) -> str:
    return hashlib.sha256(candidate_id.encode()).hexdigest()


def _safe_relative(value: object) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise AgentError("path must be canonical relative POSIX text")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or any(part in {"", ".", ".."} for part in path.parts):
        raise AgentError("path traversal is forbidden")
    if any(part.lower() == ".git" for part in path.parts):
        raise AgentError(".git paths are forbidden")
    return path


def _ensure_no_symlink_ancestors(root: Path, destination: Path) -> None:
    current = root
    for part in destination.relative_to(root).parts:
        current /= part
        if current.is_symlink():
            raise AgentError("symlink path is forbidden")


def _read_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AgentError("cannot read harness state") from exc
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise AgentError("harness state is malformed")
    return value


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(canonical_json(value) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def main() -> int:
    try:
        line = sys.stdin.readline()
        if not line or sys.stdin.read(1):
            raise AgentError("agent requires exactly one JSON object")
        request = json.loads(line)
        if not isinstance(request, dict):
            raise AgentError("request must be an object")
        response = HarnessAgent().handle(request)
        sys.stdout.write(canonical_json(response) + "\n")
        return 0
    except Exception as exc:
        sys.stdout.write(
            canonical_json(
                {"ok": False, "error": type(exc).__name__, "message": str(exc)[:1024]}
            )
            + "\n"
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
