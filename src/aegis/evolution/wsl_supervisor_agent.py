"""Trusted Linux supervisor that boots exactly ``refs/aegis/champion``.

Install this module's ``main`` as ``/usr/local/bin/aegis-supervisor-agent``.
The public JSON protocol accepts data only.  Repository locations, the Python
module, interpreter arguments, and sandbox construction are fixed here.

Launch is two-tiered: a strict boot probe (namespace-isolated child, tiny
rlimits) proves the champion entrypoint imports, then the real cycle runs as
a detached executor whose relay traffic flows through the fixed credential
sidecar and whose status transitions are persisted by the fixed bootstrap
below and read back through the ``cycle_status`` operation.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
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
_CREDENTIAL_KEYS = frozenset({"base_url", "api_key", "user_agent", "timeout_seconds"})

# Tier 1: strict boot probe.  Imports the champion entrypoint and proves the
# handshake without executing a cycle.
_BOOTSTRAP = r"""
import importlib, json, os, sys
payload = json.loads(sys.stdin.read())
module = importlib.import_module("aegis.evolution.cycle_entrypoint")
if not callable(getattr(module, "run_cycle", None)):
    raise RuntimeError("champion entrypoint exposes no callable run_cycle")
print(json.dumps({"event": "import", "ok": True}, sort_keys=True), flush=True)
print(json.dumps({"event": "heartbeat", "commit": os.environ["AEGIS_EXECUTED_COMMIT"]}, sort_keys=True), flush=True)
""".strip()

# Tier 2: real cycle executor.  Fixed code owns the status file; the champion
# entrypoint owns only the run_cycle call.  Status writes reuse the same
# mkstemp/fsync/os.replace atomic pattern as every other supervisor artifact.
_CYCLE_BOOTSTRAP = r'''
import importlib, json, os, sys, tempfile, time
status_path = os.environ["AEGIS_CYCLE_STATUS_PATH"]
parent = os.path.dirname(status_path)
if not os.path.isabs(status_path) or os.pardir in status_path.split(os.sep):
    raise RuntimeError("cycle status path failed validation")
def _write_status(**extra):
    payload = {"updated": time.time()}
    payload.update(extra)
    handle, tmp = tempfile.mkstemp(prefix=".status.", dir=parent)
    with os.fdopen(handle, "w", encoding="utf-8") as stream:
        json.dump(payload, stream, ensure_ascii=False, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(tmp, status_path)
payload = json.loads(sys.stdin.read())
_write_status(status="running")
try:
    module = importlib.import_module("aegis.evolution.cycle_entrypoint")
    result = module.run_cycle(payload)
    encoded = json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > 245760:
        raise RuntimeError("cycle result exceeded the supervisor relay limit")
    _write_status(status="completed", exit_code=0, cycle_result=result)
    print(json.dumps({"event": "complete"}, sort_keys=True), flush=True)
except BaseException as exc:
    _write_status(status="failed", error=f"{type(exc).__name__}: {exc}"[:1024])
    raise
'''.strip()

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
        sidecar_launcher: Any | None = None,
    ) -> None:
        if not root.is_absolute() or ".." in root.parts:
            raise ValueError("campaign root must be an absolute traversal-free path")
        if _fcntl is None:
            raise RuntimeError("the supervisor requires Linux flock support")
        if _resource is None:
            raise RuntimeError("the supervisor requires Linux resource limits")
        if isinstance(timeout_seconds, bool) or not 1 <= timeout_seconds <= 3600:
            raise ValueError("timeout_seconds must be in [1, 3600]")
        self.root = root
        self.use_mount_namespace = use_mount_namespace
        self.timeout_seconds = float(timeout_seconds)
        # Injectable for hermetic tests; production uses the real sidecar.
        self._sidecar_launcher = sidecar_launcher or self._start_sidecar

    def handle(self, request: Mapping[str, Any]) -> dict[str, Any]:
        operation = request.get("operation")
        if operation == "cycle_status":
            return self._cycle_status(request)
        if operation == "cancel_cycle":
            return self._cancel_cycle(request)
        if operation != "launch_cycle":
            raise SupervisorAgentError("unsupported supervisor operation")
        if set(request) != {
            "version",
            "operation",
            "operation_id",
            "campaign_id",
            "expected_commit",
            "request_payload",
            "gateway_credentials",
        }:
            raise SupervisorAgentError("request has missing or unknown fields")
        if request.get("version") != 1:
            raise SupervisorAgentError("unsupported supervisor protocol version")
        operation_id = _required(request.get("operation_id"), "operation_id", 128)
        campaign_id = _required(request.get("campaign_id"), "campaign_id", 512)
        expected = _commit(request.get("expected_commit"), "expected_commit")
        payload = request.get("request_payload")
        credentials = request.get("gateway_credentials")
        if _OPERATION_ID.fullmatch(operation_id) is None:
            raise SupervisorAgentError("unsafe operation_id")
        if not isinstance(payload, Mapping):
            raise SupervisorAgentError("request_payload must be an object")
        _validate_payload_shape(payload)
        _validate_credentials(credentials)
        # Credentials participate in transport confidentiality but never in the
        # persisted binding: receipts hash the credential-free request.
        encoded_request = canonical_json(
            {key: value for key, value in request.items() if key != "gateway_credentials"}
        ).encode("utf-8")
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
            self._ensure_no_active_cycle(campaign)
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
            generation = self._next_generation(campaign)
            probe = self._launch_probe(worktree, champion)
            receipt_values = {
                "operation_id": operation_id,
                "campaign_id": campaign_id,
                "campaign_key": campaign_key,
                "executed_commit": champion,
                "tree_hash": tree_hash,
                "previous_champion": previous if previous != champion else None,
                "last_known_good": previous,
                "request_sha256": request_sha256,
                **probe,
            }
            if probe["status"] != "boot_failed":
                cycle_payload = dict(payload)
                cycle_payload["generation"] = generation
                cycle_payload["data_root"] = str(campaign / "data")
                cycle_payload["source_commit"] = champion
                spawn = self._launch_cycle(
                    campaign, worktree, champion, cycle_payload, credentials, generation
                )
                receipt_values["cycle_generation"] = generation
                receipt_values["cycle_pid"] = spawn["pid"]
            receipt = self._receipt(**receipt_values)
            receipt_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            _atomic_json(receipt_path, receipt)
            return {"ok": True, "receipt": receipt}

    # -- real-cycle lifecycle ------------------------------------------------

    @staticmethod
    def _cycle_dir(campaign: Path, generation: int) -> Path:
        return campaign / "cycles" / f"gen-{generation}"

    @staticmethod
    def _next_generation(campaign: Path) -> int:
        """Launch ordinal: one past the highest existing cycle directory."""
        cycles = campaign / "cycles"
        highest = 0
        if cycles.is_dir():
            for entry in cycles.iterdir():
                match = re.fullmatch(r"gen-([0-9]{1,6})", entry.name)
                if match:
                    highest = max(highest, int(match.group(1)))
        return highest + 1

    @staticmethod
    def _ensure_no_active_cycle(campaign: Path) -> None:
        cycles = campaign / "cycles"
        if not cycles.is_dir():
            return
        for status_path in sorted(cycles.glob("gen-*/status.json")):
            try:
                status = _read_object(status_path)
            except SupervisorAgentError:
                continue
            if status.get("status") in {"launched", "running"} and not _cycle_pid_exited(status):
                raise SupervisorAgentError(
                    "another campaign cycle is still active; cancel it first"
                )

    def _launch_cycle(
        self,
        campaign: Path,
        worktree: Path,
        champion: str,
        cycle_payload: Mapping[str, Any],
        credentials: Any,
        generation: int,
    ) -> dict[str, Any]:
        """Start the credential sidecar, then the detached cycle executor."""
        if not isinstance(credentials, Mapping):
            raise SupervisorAgentError("gateway credentials are required for a cycle launch")
        cycle_dir = self._cycle_dir(campaign, generation)
        cycle_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        status_path = cycle_dir / "status.json"
        metering_path = campaign / "data" / "metering" / f"gen-{generation}.jsonl"
        sidecar = self._sidecar_launcher(credentials, metering_path)
        try:
            child_env = _cycle_env(worktree, champion)
            child_env["AEGIS_OPENAI_BASE_URL"] = f"http://127.0.0.1:{sidecar['port']}/v1"
            child_env["AEGIS_CYCLE_STATUS_PATH"] = str(status_path)
            wire = canonical_json(cycle_payload).encode("utf-8")
            if len(wire) > 32_768:
                raise SupervisorAgentError("cycle payload exceeds its size limit")
            _write_status(
                status_path,
                status="launched",
                generation=generation,
                champion=champion,
            )
            process = subprocess.Popen(
                (sys.executable, "-c", _CYCLE_BOOTSTRAP),
                cwd=str(campaign / "data"),
                env=child_env,
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
                start_new_session=True,
                preexec_fn=_limit_cycle_child,
            )
            assert process.stdin is not None
            try:
                process.stdin.write(wire)
                process.stdin.close()
            except (OSError, ValueError):
                pass
            _write_status(
                status_path,
                status="launched",
                generation=generation,
                champion=champion,
                pid=process.pid,
            )
        finally:
            try:
                sidecar["process"].stdin.close()
            except (OSError, AttributeError):
                pass
        return {"pid": process.pid}

    def _start_sidecar(self, credentials: Mapping[str, Any], metering_path: Path) -> dict[str, Any]:
        env = _trusted_env("0" * 64)
        env["AEGIS_SIDECAR_UPSTREAM_BASE_URL"] = str(credentials.get("base_url", ""))
        env["AEGIS_SIDECAR_API_KEY"] = str(credentials.get("api_key", ""))
        user_agent = credentials.get("user_agent")
        timeout = credentials.get("timeout_seconds")
        if isinstance(user_agent, str) and user_agent:
            env["AEGIS_SIDECAR_USER_AGENT"] = user_agent
        if isinstance(timeout, str) and timeout:
            env["AEGIS_SIDECAR_TIMEOUT_SECONDS"] = timeout
        env["AEGIS_SIDECAR_METERING_PATH"] = str(metering_path)
        metering_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        process = subprocess.Popen(
            (sys.executable, "-m", "aegis.gateway_sidecar"),
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            shell=False,
            start_new_session=True,
        )
        assert process.stdout is not None
        try:
            line = process.stdout.readline()
        except OSError as exc:
            process.kill()
            raise SupervisorAgentError(f"sidecar failed to announce: {exc}") from exc
        try:
            announcement = json.loads(line)
        except (json.JSONDecodeError, ValueError) as exc:
            process.kill()
            raise SupervisorAgentError("sidecar produced no valid announcement") from exc
        if (
            not isinstance(announcement, Mapping)
            or announcement.get("event") != "listening"
            or not isinstance(announcement.get("port"), int)
        ):
            process.kill()
            raise SupervisorAgentError("sidecar announcement is invalid")
        return {"process": process, "port": announcement["port"]}

    def _cycle_status(self, request: Mapping[str, Any]) -> dict[str, Any]:
        if set(request) != {
            "version",
            "operation",
            "operation_id",
            "campaign_id",
            "generation",
        }:
            raise SupervisorAgentError("cycle status request has missing or unknown fields")
        if request.get("version") != 1:
            raise SupervisorAgentError("unsupported supervisor protocol version")
        _required(request.get("operation_id"), "operation_id", 128)
        campaign_id = _required(request.get("campaign_id"), "campaign_id", 512)
        generation = request.get("generation")
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
            raise SupervisorAgentError("generation must be a positive integer")
        campaign = self.root / hashlib.sha256(campaign_id.encode()).hexdigest()
        status_path = self._cycle_dir(campaign, generation) / "status.json"
        if not status_path.is_file():
            return {"ok": True, "status": "unknown"}
        try:
            status: Mapping[str, Any] = _read_object(status_path)
        except SupervisorAgentError:
            # A partially written status read is retried by the host poller.
            return {"ok": True, "status": "running"}
        if status.get("status") in {"launched", "running"} and _cycle_pid_exited(status):
            updated = dict(status)
            updated["status"] = "failed"
            updated["error"] = "cycle executor exited without a terminal status"
            _atomic_json(status_path, updated)
            status = updated
        metering = campaign / "data" / "metering" / f"gen-{generation}.jsonl"
        response: dict[str, Any] = {
            "ok": True,
            "status": str(status.get("status", "unknown")),
            "metering": _metering_summary(metering),
        }
        result = status.get("cycle_result")
        if isinstance(result, Mapping):
            response["cycle_result"] = result
        if isinstance(status.get("error"), str):
            response["error"] = status["error"]
        if isinstance(status.get("exit_code"), int):
            response["exit_code"] = status["exit_code"]
        return response

    def _cancel_cycle(self, request: Mapping[str, Any]) -> dict[str, Any]:
        if set(request) != {
            "version",
            "operation",
            "operation_id",
            "campaign_id",
            "generation",
        }:
            raise SupervisorAgentError("cancel request has missing or unknown fields")
        if request.get("version") != 1:
            raise SupervisorAgentError("unsupported supervisor protocol version")
        _required(request.get("operation_id"), "operation_id", 128)
        campaign_id = _required(request.get("campaign_id"), "campaign_id", 512)
        generation = request.get("generation")
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
            raise SupervisorAgentError("generation must be a positive integer")
        campaign = self.root / hashlib.sha256(campaign_id.encode()).hexdigest()
        status_path = self._cycle_dir(campaign, generation) / "status.json"
        if not status_path.is_file():
            return {"ok": True, "cancelled": False, "reason": "no such cycle"}
        status = _read_object(status_path)
        if status.get("status") in {"completed", "failed", "cancelled"}:
            return {"ok": True, "cancelled": False, "reason": "cycle already terminal"}
        pid = status.get("pid")
        if isinstance(pid, int) and _pid_matches_cycle(pid, str(status_path)):
            try:
                os.killpg(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass
        updated = dict(status)
        updated["status"] = "cancelled"
        updated["updated"] = time.time()
        _atomic_json(status_path, updated)
        return {"ok": True, "cancelled": True}

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

    def _launch_probe(self, worktree: Path, commit: str) -> dict[str, Any]:
        """Tier 1: import-and-handshake probe inside the strict sandbox child."""
        wire = canonical_json({"action": "boot_probe"}).encode("utf-8")
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
                    preexec_fn=_limit_probe_child,
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
            status, failure = "boot_failed", "probe_runtime_failed" if not oversized else "output_limit"
        else:
            status, failure = "launched", None
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


def _limit_probe_child() -> None:
    if _resource is None:
        raise RuntimeError("resource limits are unavailable")
    _resource.setrlimit(_resource.RLIMIT_CORE, (0, 0))
    _resource.setrlimit(_resource.RLIMIT_NOFILE, (64, 64))
    _resource.setrlimit(_resource.RLIMIT_FSIZE, (_MAX_OUTPUT_BYTES, _MAX_OUTPUT_BYTES))
    _resource.setrlimit(_resource.RLIMIT_CPU, (600, 600))
    memory = 2 * 1024 * 1024 * 1024
    _resource.setrlimit(_resource.RLIMIT_AS, (memory, memory))


def _limit_cycle_child() -> None:
    """Real-cycle executor limits: generous, still bounded by the volume."""
    if _resource is None:
        raise RuntimeError("resource limits are unavailable")
    _resource.setrlimit(_resource.RLIMIT_CORE, (0, 0))
    _resource.setrlimit(_resource.RLIMIT_NOFILE, (256, 256))
    fsize = 4 * 1024 * 1024 * 1024
    _resource.setrlimit(_resource.RLIMIT_FSIZE, (fsize, fsize))
    cpu = 3600 * 8
    _resource.setrlimit(_resource.RLIMIT_CPU, (cpu, cpu))
    memory = 4 * 1024 * 1024 * 1024
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


def _cycle_env(worktree: Path, commit: str) -> dict[str, str]:
    """Environment for the detached Tier 2 cycle executor.

    Deliberately absent: every ``AEGIS_SIDECAR_*`` variable — relay
    credentials live only in the sidecar process.
    """
    env = _candidate_env(worktree, commit)
    env["PATH"] = "/usr/local/bin:/usr/bin:/bin"
    home = os.environ.get("HOME")
    if home:
        env["HOME"] = home
    return env


def _pid_matches_cycle(pid: int, status_path: str) -> bool:
    """True only when the recorded pid still runs this cycle's bootstrap."""
    try:
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().decode("utf-8", errors="replace")
    except OSError:
        return False
    return status_path in cmdline


def _cycle_pid_exited(status: Mapping[str, Any]) -> bool:
    pid = status.get("pid")
    if not isinstance(pid, int) or pid <= 1:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except (PermissionError, OSError):
        return False
    return False


def _metering_summary(metering_path: Path) -> dict[str, Any]:
    total: dict[str, Any] = {
        "requests": 0,
        "request_bytes": 0,
        "response_bytes": 0,
        "errors": 0,
    }
    try:
        with metering_path.open("r", encoding="utf-8") as stream:
            for line in stream:
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(record, dict):
                    continue
                total["requests"] += 1
                total["request_bytes"] += int(record.get("request_bytes", 0))
                total["response_bytes"] += int(record.get("response_bytes", 0))
                if record.get("outcome") != "forwarded":
                    total["errors"] += 1
    except OSError:
        pass
    return total


def _write_status(status_path: Path, **values: Any) -> None:
    payload = dict(values)
    payload["updated"] = time.time()
    _atomic_json(status_path, payload)


def _validate_credentials(value: object) -> None:
    if value is None:
        return
    if not isinstance(value, Mapping):
        raise SupervisorAgentError("gateway_credentials must be an object")
    unknown = set(value) - _CREDENTIAL_KEYS
    if unknown:
        raise SupervisorAgentError("gateway_credentials has unknown fields")
    if not isinstance(value.get("base_url"), str) or not isinstance(value.get("api_key"), str):
        raise SupervisorAgentError("gateway_credentials require base_url and api_key")
    for key in ("base_url", "api_key", "user_agent", "timeout_seconds"):
        item = value.get(key)
        if item is None:
            continue
        if not isinstance(item, str) or "\x00" in item or len(item) > 2048:
            raise SupervisorAgentError(f"gateway credential {key} is invalid")
    if not str(value.get("base_url", "")).startswith("https://"):
        raise SupervisorAgentError("gateway credential base_url must be HTTPS")


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
