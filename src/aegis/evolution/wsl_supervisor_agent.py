"""Trusted Linux supervisor that boots exactly ``refs/aegis/champion``.

Install this module's ``main`` as ``/usr/local/bin/aegis-supervisor-agent``.
The public JSON protocol accepts data only.  Repository locations, the Python
module, interpreter arguments, and sandbox construction are fixed here.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, TextIO

from aegis.models import canonical_json

CAMPAIGNS_ROOT = Path("/var/lib/aegis/campaigns")
_OPERATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_MAX_REQUEST_BYTES = 65_536
_MAX_OUTPUT_BYTES = 65_536
_MAX_SUMMARY_BYTES = 8192
_BOOTSTRAP = r"""
import hashlib, importlib, json, os, sys
payload = json.loads(sys.stdin.read())
module = importlib.import_module("aegis.evolution.cycle_entrypoint")
print(json.dumps({"event": "import", "ok": True}, sort_keys=True), flush=True)
print(json.dumps({"event": "heartbeat", "commit": os.environ["AEGIS_EXECUTED_COMMIT"]}, sort_keys=True), flush=True)
result = module.run_cycle(payload)
encoded = json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
if len(encoded.encode("utf-8")) > 16384:
    raise RuntimeError("cycle result exceeded its size limit")
print(json.dumps({"event": "complete", "result": result}, ensure_ascii=False, sort_keys=True), flush=True)
""".strip()

_fcntl: Any | None
try:
    _fcntl = importlib.import_module("fcntl")
except ImportError:  # pragma: no cover - production is Linux-only
    _fcntl = None
_resource: Any | None
try:
    _resource = importlib.import_module("resource")
except ImportError:  # pragma: no cover - production is Linux-only
    _resource = None


class SupervisorAgentError(RuntimeError):
    pass


class SupervisorAgent:
    """Resolve, isolate, launch, and receipt one campaign champion."""

    def __init__(
        self,
        root: Path = CAMPAIGNS_ROOT,
        *,
        use_mount_namespace: bool = True,
        timeout_seconds: float = 3600.0,
    ) -> None:
        if not root.is_absolute():
            raise ValueError("campaign root must be absolute")
        if _fcntl is None:
            raise RuntimeError("the supervisor requires Linux flock support")
        if _resource is None:
            raise RuntimeError("the supervisor requires Linux resource limits")
        if isinstance(timeout_seconds, bool) or not 1 <= timeout_seconds <= 3600:
            raise ValueError("timeout_seconds must be in [1, 3600]")
        self.root = root
        self.use_mount_namespace = use_mount_namespace
        self.timeout_seconds = float(timeout_seconds)

    def handle(self, request: Mapping[str, Any]) -> dict[str, Any]:
        if set(request) != {
            "version",
            "operation",
            "operation_id",
            "campaign_id",
            "expected_commit",
            "request_payload",
        }:
            raise SupervisorAgentError("request has missing or unknown fields")
        if request.get("version") != 1 or request.get("operation") != "launch_cycle":
            raise SupervisorAgentError("unsupported supervisor operation")
        operation_id = _required(request.get("operation_id"), "operation_id", 128)
        campaign_id = _required(request.get("campaign_id"), "campaign_id", 512)
        expected = _commit(request.get("expected_commit"), "expected_commit")
        payload = request.get("request_payload")
        if _OPERATION_ID.fullmatch(operation_id) is None:
            raise SupervisorAgentError("unsafe operation_id")
        if not isinstance(payload, Mapping):
            raise SupervisorAgentError("request_payload must be an object")
        _validate_payload_shape(payload)
        encoded_request = canonical_json(request).encode("utf-8")
        if len(encoded_request) > _MAX_REQUEST_BYTES:
            raise SupervisorAgentError("request exceeds its size limit")
        request_sha256 = hashlib.sha256(encoded_request).hexdigest()
        campaign_key = hashlib.sha256(campaign_id.encode()).hexdigest()
        campaign = self.root / campaign_key
        with self._campaign_lock(campaign_key):
            receipt_path = campaign / "operations" / f"supervisor-{operation_id}.json"
            if receipt_path.is_file():
                receipt = _read_object(receipt_path)
                if receipt.get("request_sha256") != request_sha256:
                    raise SupervisorAgentError("operation_id was reused for another request")
                return {"ok": True, "receipt": receipt}
            repo = self._repo(campaign)
            champion = _git(repo, "rev-parse", "--verify", "refs/aegis/champion^{commit}").strip()
            if champion != expected:
                raise SupervisorAgentError("expected_commit does not match refs/aegis/champion")
            tree_hash = _git(repo, "rev-parse", f"{champion}^{{tree}}").strip()
            if _COMMIT.fullmatch(tree_hash) is None:
                raise SupervisorAgentError("Git returned a malformed tree id")
            state = _read_object(campaign / "state.json")
            if state.get("campaign_id") != campaign_id:
                raise SupervisorAgentError("campaign identity mismatch")
            previous = _optional_commit(state.get("last_known_good"), "last_known_good")
            worktree = campaign / "worktrees" / f"champion-{champion[:12]}"
            self._verify_worktree(repo, worktree, champion)
            result = self._launch(worktree, champion, payload)
            receipt = self._receipt(
                operation_id=operation_id,
                campaign_id=campaign_id,
                campaign_key=campaign_key,
                executed_commit=champion,
                tree_hash=tree_hash,
                previous_champion=previous if previous != champion else None,
                last_known_good=previous,
                request_sha256=request_sha256,
                **result,
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

    @staticmethod
    def _repo(campaign: Path) -> Path:
        repo = campaign / "repo.git"
        if not (repo / "HEAD").is_file() or not (campaign / "state.json").is_file():
            raise SupervisorAgentError("campaign is not initialized")
        return repo

    @staticmethod
    def _verify_worktree(repo: Path, worktree: Path, commit: str) -> None:
        if not worktree.is_dir() or worktree.is_symlink():
            raise SupervisorAgentError("detached champion worktree is missing")
        actual = _git(worktree, "rev-parse", "--verify", "HEAD^{commit}").strip()
        if actual != commit:
            raise SupervisorAgentError("champion worktree does not match the active ref")
        common = _git(worktree, "rev-parse", "--git-common-dir").strip()
        resolved_common = (worktree / common).resolve() if not Path(common).is_absolute() else Path(common).resolve()
        if resolved_common != repo.resolve():
            raise SupervisorAgentError("champion worktree belongs to another repository")
        dirty = _git(worktree, "status", "--porcelain", "--untracked-files=no").strip()
        if dirty:
            raise SupervisorAgentError("champion worktree contains tracked modifications")

    def _launch(
        self, worktree: Path, commit: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        wire = canonical_json(payload).encode("utf-8")
        if len(wire) > 32_768:
            raise SupervisorAgentError("request_payload exceeds its size limit")
        if self.use_mount_namespace:
            argv: tuple[str, ...] = (
                "unshare",
                "--user",
                "--map-root-user",
                "--mount",
                "--pid",
                "--fork",
                "--kill-child",
                "--mount-proc",
                sys.executable,
                str(Path(__file__).resolve()),
                "--sandbox-child",
                str(worktree),
                str(self.root),
                commit,
            )
            cwd: Path | None = None
            env = _trusted_env(commit)
        else:
            # Explicitly test-only: production construction keeps namespace isolation on.
            argv = (sys.executable, "-S", "-c", _BOOTSTRAP)
            cwd = worktree
            env = _candidate_env(worktree, commit)
        try:
            with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
                process = subprocess.Popen(
                    argv,
                    cwd=cwd,
                    env=env,
                    stdin=subprocess.PIPE,
                    stdout=stdout,
                    stderr=stderr,
                    shell=False,
                    start_new_session=True,
                    preexec_fn=_limit_child,
                )
                try:
                    process.communicate(wire, timeout=self.timeout_seconds)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
                stdout.seek(0)
                out = stdout.read(_MAX_OUTPUT_BYTES + 1)
                stderr.seek(0)
                err = stderr.read(_MAX_OUTPUT_BYTES + 1)
                returncode = process.returncode
        except (OSError, subprocess.SubprocessError) as exc:
            return self._launch_failure("launch_failed", str(exc))
        oversized = len(out) > _MAX_OUTPUT_BYTES or len(err) > _MAX_OUTPUT_BYTES
        out = out[:_MAX_OUTPUT_BYTES]
        err = err[:_MAX_OUTPUT_BYTES]
        import_ok, heartbeat_ok = _handshake(out, commit)
        if not import_ok:
            status, failure = "boot_failed", "import_failed"
        elif not heartbeat_ok:
            status, failure = "boot_failed", "heartbeat_failed"
        elif returncode != 0 or oversized:
            status, failure = "failed", "runtime_failed" if not oversized else "output_limit"
        else:
            status, failure = "completed", None
        summary = _summary(out, err)
        return {
            "status": status,
            "failure_kind": failure,
            "import_ok": import_ok,
            "heartbeat_ok": heartbeat_ok,
            "exit_code": returncode,
            "output_sha256": hashlib.sha256(out + b"\0" + err).hexdigest(),
            "output_summary": summary,
        }

    @staticmethod
    def _launch_failure(failure: str, message: str) -> dict[str, Any]:
        encoded = message.encode("utf-8", errors="replace")[:_MAX_SUMMARY_BYTES]
        return {
            "status": "boot_failed",
            "failure_kind": failure,
            "import_ok": False,
            "heartbeat_ok": False,
            "exit_code": None,
            "output_sha256": hashlib.sha256(encoded).hexdigest(),
            "output_summary": encoded.decode("utf-8", errors="replace"),
        }

    @staticmethod
    def _receipt(**values: Any) -> dict[str, Any]:
        payload = dict(values)
        return {
            **payload,
            "receipt_sha256": hashlib.sha256(
                canonical_json(payload).encode("utf-8")
            ).hexdigest(),
        }


def _sandbox_child(worktree_text: str, root_text: str, commit: str) -> int:
    """Enter a private mount view hiding all campaigns and every DrvFS mount."""

    worktree = Path(worktree_text).resolve(strict=True)
    root = Path(root_text).resolve(strict=True)
    if root not in worktree.parents or worktree.name != f"champion-{commit[:12]}":
        raise SupervisorAgentError("sandbox worktree is outside the selected campaign")
    runtime = Path(tempfile.mkdtemp(prefix="aegis-cycle-", dir="/tmp"))
    try:
        _mount("--bind", str(worktree), str(runtime))
        _mount("-o", "remount,bind,ro,nosuid,nodev", str(runtime))
        _mount("-t", "tmpfs", "-o", "mode=000,nosuid,nodev,noexec", "none", str(root))
        Path("/mnt").mkdir(parents=True, exist_ok=True)
        _mount("-t", "tmpfs", "-o", "mode=0555,nosuid,nodev,noexec", "none", "/mnt")
        process = subprocess.run(
            (
                "setpriv",
                "--no-new-privs",
                "--bounding-set=-all",
                "--inh-caps=-all",
                "--ambient-caps=-all",
                sys.executable,
                "-S",
                "-c",
                _BOOTSTRAP,
            ),
            cwd=runtime,
            env=_candidate_env(runtime, commit),
            stdin=sys.stdin.buffer,
            stdout=sys.stdout.buffer,
            stderr=sys.stderr.buffer,
            shell=False,
            check=False,
        )
        return process.returncode
    finally:
        shutil.rmtree(runtime, ignore_errors=True)


def _mount(*args: str) -> None:
    result = subprocess.run(
        ("mount", *args),
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        capture_output=True,
        text=True,
        shell=False,
        check=False,
    )
    if result.returncode != 0:
        raise SupervisorAgentError(f"sandbox mount failed: {result.stderr[:256].strip()}")


def _limit_child() -> None:
    if _resource is None:
        raise RuntimeError("resource limits are unavailable")
    _resource.setrlimit(_resource.RLIMIT_CORE, (0, 0))
    _resource.setrlimit(_resource.RLIMIT_NOFILE, (64, 64))
    _resource.setrlimit(_resource.RLIMIT_FSIZE, (_MAX_OUTPUT_BYTES, _MAX_OUTPUT_BYTES))
    _resource.setrlimit(_resource.RLIMIT_CPU, (3600, 3600))
    memory = 2 * 1024 * 1024 * 1024
    _resource.setrlimit(_resource.RLIMIT_AS, (memory, memory))


def _trusted_env(commit: str) -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "AEGIS_EXECUTED_COMMIT": commit,
        # This is the stable installed supervisor package, never the candidate
        # worktree.  The sandbox child replaces it before candidate import.
        "PYTHONPATH": str(Path(__file__).resolve().parents[2]),
        "PYTHONNOUSERSITE": "1",
    }


def _candidate_env(worktree: Path, commit: str) -> dict[str, str]:
    env = _trusted_env(commit)
    env["PYTHONPATH"] = str(worktree / "src")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONNOUSERSITE"] = "1"
    return env


def _handshake(stdout: bytes, commit: str) -> tuple[bool, bool]:
    imported = False
    heartbeat = False
    for line in stdout.splitlines():
        if len(line) > 16_384:
            continue
        try:
            event = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(event, Mapping):
            continue
        if event.get("event") == "import" and event.get("ok") is True:
            imported = True
        if event.get("event") == "heartbeat" and event.get("commit") == commit:
            heartbeat = True
    return imported, heartbeat


def _summary(stdout: bytes, stderr: bytes) -> str:
    text = canonical_json(
        {
            "stdout": stdout[:4096].decode("utf-8", errors="replace"),
            "stderr": stderr[:2048].decode("utf-8", errors="replace"),
        }
    )
    return text.encode("utf-8")[:_MAX_SUMMARY_BYTES].decode("utf-8", errors="ignore")


def _git(cwd: Path, *args: str) -> str:
    result = subprocess.run(
        ("git", *args),
        cwd=cwd,
        env={
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
        },
        capture_output=True,
        text=True,
        shell=False,
        timeout=120,
        check=False,
    )
    if result.returncode != 0:
        raise SupervisorAgentError(f"Git operation failed: {result.stderr[:512].strip()}")
    return result.stdout


def _read_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SupervisorAgentError(f"invalid state file: {path.name}") from exc
    if not isinstance(value, dict):
        raise SupervisorAgentError(f"state file is not an object: {path.name}")
    return value


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(canonical_json(value))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _required(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise SupervisorAgentError(f"{name} must be non-empty text")
    if len(value.encode("utf-8")) > maximum:
        raise SupervisorAgentError(f"{name} exceeds its size limit")
    return value


def _validate_payload_shape(value: object, *, depth: int = 0) -> None:
    if depth > 8:
        raise SupervisorAgentError("request_payload exceeds its nesting limit")
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, float):
        if value != value or abs(value) == float("inf"):
            raise SupervisorAgentError("request_payload contains a non-finite number")
        return
    if isinstance(value, str):
        if "\x00" in value or len(value.encode("utf-8")) > 8192:
            raise SupervisorAgentError("request_payload contains invalid text")
        return
    if isinstance(value, Mapping):
        if len(value) > 128:
            raise SupervisorAgentError("request_payload object is too large")
        forbidden = {"argv", "command", "cwd", "executable", "module", "path"}
        for key, item in value.items():
            if not isinstance(key, str) or not key or len(key.encode("utf-8")) > 128:
                raise SupervisorAgentError("request_payload keys must be bounded text")
            if key.casefold() in forbidden:
                raise SupervisorAgentError(f"request_payload may not select {key!r}")
            _validate_payload_shape(item, depth=depth + 1)
        return
    if isinstance(value, list):
        if len(value) > 256:
            raise SupervisorAgentError("request_payload array is too large")
        for item in value:
            _validate_payload_shape(item, depth=depth + 1)
        return
    raise SupervisorAgentError("request_payload must contain only JSON values")


def _commit(value: object, name: str) -> str:
    if not isinstance(value, str) or _COMMIT.fullmatch(value) is None:
        raise SupervisorAgentError(f"{name} must be a full Git commit id")
    return value


def _optional_commit(value: object, name: str) -> str | None:
    return None if value is None else _commit(value, name)


def _write_response(response: Mapping[str, Any], stream: TextIO) -> None:
    encoded = canonical_json(response)
    if len(encoded.encode("utf-8")) > 1_048_576:
        encoded = canonical_json(
            {"ok": False, "error": "SupervisorAgentError", "message": "response exceeded limit"}
        )
    stream.write(encoded + "\n")
    stream.flush()


def main() -> int:
    if len(sys.argv) == 5 and sys.argv[1] == "--sandbox-child":
        try:
            return _sandbox_child(sys.argv[2], sys.argv[3], _commit(sys.argv[4], "commit"))
        except Exception as exc:
            print(f"sandbox boot failed: {exc}", file=sys.stderr)
            return 125
    if len(sys.argv) != 1:
        _write_response(
            {"ok": False, "error": "SupervisorAgentError", "message": "arguments are forbidden"},
            sys.stdout,
        )
        return 2
    try:
        raw = sys.stdin.buffer.read(_MAX_REQUEST_BYTES + 1)
        if len(raw) > _MAX_REQUEST_BYTES:
            raise SupervisorAgentError("request exceeded its size limit")
        value = json.loads(raw)
        if not isinstance(value, Mapping):
            raise SupervisorAgentError("request must be an object")
        response = SupervisorAgent().handle(value)
        _write_response(response, sys.stdout)
        return 0
    except Exception as exc:
        _write_response(
            {
                "ok": False,
                "error": type(exc).__name__[:128],
                "message": str(exc)[:1024],
            },
            sys.stdout,
        )
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
