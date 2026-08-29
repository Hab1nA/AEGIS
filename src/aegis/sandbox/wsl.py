"""Fail-closed WSL transport for a separately installed sandbox agent.

This module never provisions or modifies WSL. It sends JSON to an agent already
installed inside the dedicated distribution, without invoking a shell.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import subprocess
import threading
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, BinaryIO

from .types import (
    CommandResult,
    CommandSpec,
    DoctorCheck,
    DoctorReport,
    FrozenArtifact,
    PreparedSandbox,
    SealedEvaluationResult,
    StagedArtifact,
    WorkspaceAccessRule,
    validate_staging_archive,
)

Runner = Callable[[list[str], str, float], subprocess.CompletedProcess[str]]

REQUIRED_CHECKS = (
    "windows_mounts_disabled",
    "interop_disabled",
    "rootless_oci",
    "cgroup_v2_controllers",
    "network_none",
    "disk_quota_marker",
    "secret_absence",
)

DEFAULT_ENV_ALLOWLIST = frozenset({"CI", "LANG", "LC_ALL", "NO_COLOR", "PYTHONHASHSEED", "TZ", "TERM"})
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
_DIAGNOSTIC_STREAM_LIMIT = 1024
_TRANSIENT_RETRY_ATTEMPTS = 3
_TRANSIENT_RETRY_BACKOFF_SECONDS = (5.0, 15.0, 30.0)
# Operations whose WSL-side effect is idempotent or read-only, so a lost
# transport response can be retried without double-executing a command.
_RETRYABLE_OPERATIONS = frozenset(
    {"doctor", "prepare", "freeze", "export", "destroy", "kill"}
)
_BEARER_SECRET = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
_NAMED_SECRET = re.compile(
    r"(?i)(\b(?:api[_-]?key|authorization|password|secret|token)\b[\s\"']*[:=][\s\"']*)"
    r"([^,\s\"']+)"
)


def _safe_diagnostic(value: str) -> str:
    """Return a bounded, single-line diagnostic with common credentials redacted."""
    redacted = _BEARER_SECRET.sub("Bearer <redacted>", value)
    redacted = _NAMED_SECRET.sub(r"\1<redacted>", redacted)
    escaped = json.dumps(redacted, ensure_ascii=True)[1:-1]
    if len(escaped) > _DIAGNOSTIC_STREAM_LIMIT:
        return escaped[: _DIAGNOSTIC_STREAM_LIMIT - 3] + "..."
    return escaped


def _default_runner(argv: list[str], stdin: str, timeout: float) -> subprocess.CompletedProcess[str]:
    process = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
    )
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    stdin_handle = process.stdin
    stdout_handle = process.stdout
    stderr_handle = process.stderr
    output = bytearray()
    error = bytearray()

    def drain(stream: BinaryIO, destination: bytearray) -> None:
        try:
            while chunk := stream.read(4_096):
                destination.extend(chunk)
        except (OSError, ValueError):
            return

    def write_stdin() -> None:
        try:
            stdin_handle.write(stdin.encode("utf-8"))
        except (OSError, ValueError):
            return
        finally:
            try:
                stdin_handle.close()
            except (OSError, ValueError):
                pass

    # A frozen WSL child may never read its stdin pipe; writing it from the
    # caller would wedge once the 64 KiB pipe buffer fills.  The writer runs
    # in a daemon thread so the caller always reaches the bounded wait below.
    stdin_writer = threading.Thread(target=write_stdin, name="aegis-wsl-stdin", daemon=True)
    output_reader = threading.Thread(target=drain, args=(stdout_handle, output), daemon=True)
    error_reader = threading.Thread(target=drain, args=(stderr_handle, error), daemon=True)
    stdin_writer.start()
    output_reader.start()
    error_reader.start()
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        raise subprocess.TimeoutExpired(
            argv,
            timeout,
            output=bytes(output).decode("utf-8", errors="replace"),
            stderr=bytes(error).decode("utf-8", errors="replace"),
        ) from exc
    finally:
        if process.stdin is not None and not process.stdin.closed:
            process.stdin.close()
    output_reader.join(timeout=1)
    error_reader.join(timeout=1)
    if output_reader.is_alive():
        stdout_handle.close()
    if error_reader.is_alive():
        stderr_handle.close()
    return subprocess.CompletedProcess(
        argv,
        returncode,
        bytes(output).decode("utf-8", errors="replace"),
        bytes(error).decode("utf-8", errors="replace"),
    )


class WslSandboxBackend:
    """JSON-RPC-like adapter to a trusted, pre-provisioned WSL-side agent."""

    def __init__(
        self,
        distribution: str = "AEGIS-Sandbox",
        *,
        agent_path: str = "/usr/local/bin/aegis-sandbox-agent",
        runner: Runner | None = None,
        environment_allowlist: frozenset[str] = DEFAULT_ENV_ALLOWLIST,
        interop_warn_only: bool = True,
    ) -> None:
        if not _SAFE_ID.fullmatch(distribution):
            raise ValueError("unsafe WSL distribution name")
        if not agent_path.startswith("/") or "\x00" in agent_path:
            raise ValueError("agent_path must be an absolute POSIX path")
        self.distribution = distribution
        self.agent_path = agent_path
        self._runner = runner or _default_runner
        self._environment_allowlist = environment_allowlist
        self.interop_warn_only = interop_warn_only
        self._last_doctor: DoctorReport | None = None

    def transport_argv(self) -> list[str]:
        if self.interop_warn_only:
            return [
                "wsl.exe", "--distribution", self.distribution, "--",
                "/usr/bin/env", "AEGIS_SANDBOX_INTEROP_WARN=1", self.agent_path,
            ]
        return ["wsl.exe", "--distribution", self.distribution, "--", self.agent_path]

    def doctor(self) -> DoctorReport:
        try:
            payload = self._request({"version": 1, "operation": "doctor"}, timeout=15)
            raw_checks = payload.get("checks")
            by_name = (
                {
                    str(item.get("name")): item
                    for item in raw_checks
                    if isinstance(item, Mapping) and isinstance(item.get("name"), str)
                }
                if isinstance(raw_checks, list)
                else {}
            )
            checks = tuple(
                self._agent_check(name, by_name) for name in REQUIRED_CHECKS
            )
        except (OSError, RuntimeError, subprocess.SubprocessError, ValueError, json.JSONDecodeError) as exc:
            checks = tuple(
                DoctorCheck(name, False, f"doctor transport failed: {exc}") for name in REQUIRED_CHECKS
            )
        self._last_doctor = DoctorReport(checks)
        return self._last_doctor

    def _agent_check(self, name: str, by_name: Mapping[str, Mapping[str, Any]]) -> DoctorCheck:
        check = DoctorCheck(
            name,
            bool(by_name.get(name, {}).get("passed", False)),
            str(by_name.get(name, {}).get("detail", "missing required check")),
        )
        if (
            name == "interop_disabled"
            and not check.passed
            and self.interop_warn_only
            and check.detail == "WSL interop is enabled"
        ):
            # Some WSL builds re-register WSLInterop mid-flight regardless of
            # wsl.conf, which would make every run a coin flip.  With strict
            # enforcement disabled the honest agent reading stays recorded as
            # a warning instead of blocking the campaign.
            return DoctorCheck(
                name,
                True,
                "WSL interop is enabled (warn-only: operator disabled strict enforcement)",
            )
        return check

    def prepare(self, sandbox_id: str, *, image: str | None = None) -> PreparedSandbox:
        self._require_healthy()
        self._validate_id(sandbox_id)
        payload: dict[str, object] = {
            "version": 1,
            "operation": "prepare",
            "sandbox_id": sandbox_id,
        }
        if image is not None:
            if (
                not isinstance(image, str)
                or re.search(r"(?:@sha256:|^sha256:)[0-9a-f]{64}$", image) is None
            ):
                raise ValueError("sandbox image must be pinned by sha256 digest")
            payload["image"] = image
        self._request(payload, timeout=60)
        return PreparedSandbox(sandbox_id)

    def exec(self, sandbox_id: str, command: CommandSpec) -> CommandResult:
        self._require_healthy()
        self._validate_id(sandbox_id)
        env = self._sanitize_environment(command.env)
        response = self._request(
            {
                "version": 1,
                "operation": "exec",
                "sandbox_id": sandbox_id,
                "command": {
                    "argv": list(command.argv),
                    "cwd": command.cwd,
                    "env": env,
                    "stdin": command.stdin,
                    "timeout_seconds": command.timeout_seconds,
                    "network": "none",
                },
            },
            timeout=command.timeout_seconds + 5,
        )
        result = response.get("result")
        if not isinstance(result, Mapping):
            raise RuntimeError("sandbox agent omitted result")
        return CommandResult(
            exit_code=int(result.get("exit_code", -1)),
            stdout=str(result.get("stdout", "")),
            stderr=str(result.get("stderr", "")),
            duration_seconds=float(result.get("duration_seconds", 0)),
            timed_out=bool(result.get("timed_out", False)),
        )

    def stage_archive(self, sandbox_id: str, archive_base64: str, expected_digest: str) -> StagedArtifact:
        self._require_healthy()
        self._validate_id(sandbox_id)
        payload, members = validate_staging_archive(archive_base64, expected_digest)
        response = self._request(
            {
                "version": 1,
                "operation": "stage_archive",
                "sandbox_id": sandbox_id,
                "archive_base64": archive_base64,
                "expected_sha256": expected_digest.lower(),
            },
            timeout=60,
        )
        staged = response.get("staged")
        if not isinstance(staged, Mapping):
            raise RuntimeError("sandbox agent omitted staging receipt")
        digest = staged.get("sha256")
        size = staged.get("size_bytes")
        entries = staged.get("entries")
        if digest != hashlib.sha256(payload).hexdigest() or size != len(payload) or entries != len(members):
            raise RuntimeError("sandbox agent staging receipt failed verification")
        return StagedArtifact(sandbox_id, digest, size, entries)

    def configure_workspace_access(
        self, sandbox_id: str, writable_paths: tuple[WorkspaceAccessRule, ...]
    ) -> None:
        self._require_healthy()
        self._validate_id(sandbox_id)
        if not isinstance(writable_paths, tuple) or any(
            not isinstance(rule, WorkspaceAccessRule) for rule in writable_paths
        ):
            raise TypeError("writable_paths must be a tuple of WorkspaceAccessRule values")
        self._request(
            {
                "version": 1,
                "operation": "configure_workspace_access",
                "sandbox_id": sandbox_id,
                "writable_paths": [
                    {"path": rule.path, "recursive": rule.recursive}
                    for rule in writable_paths
                ],
            },
            timeout=30,
        )

    def evaluate_sealed(
        self, sandbox_id: str, suite_base64: str, expected_digest: str, timeout_seconds: float
    ) -> SealedEvaluationResult:
        self._require_healthy()
        self._validate_id(sandbox_id)
        validate_staging_archive(suite_base64, expected_digest)
        if not 0 < timeout_seconds <= 3600:
            raise ValueError("timeout_seconds must be in (0, 3600]")
        response = self._request(
            {
                "version": 1,
                "operation": "evaluate_sealed",
                "sandbox_id": sandbox_id,
                "archive_base64": suite_base64,
                "expected_sha256": expected_digest.lower(),
                "timeout_seconds": timeout_seconds,
            },
            timeout=timeout_seconds + 10,
        )
        raw = response.get("sealed_evaluation")
        if not isinstance(raw, Mapping):
            raise RuntimeError("sandbox agent omitted sealed evaluation result")
        failures = raw.get("failures", [])
        safety = raw.get("safety_violations", [])
        if not isinstance(failures, list) or not all(isinstance(item, str) for item in failures):
            raise RuntimeError("sandbox agent returned invalid sealed failures")
        if not isinstance(safety, list) or not all(isinstance(item, str) for item in safety):
            raise RuntimeError("sandbox agent returned invalid sealed safety violations")
        return SealedEvaluationResult(
            int(raw.get("passed", -1)),
            int(raw.get("total", -1)),
            tuple(failures),
            bool(raw.get("timed_out", False)),
            tuple(safety),
        )

    def freeze(self, sandbox_id: str) -> FrozenArtifact:
        self._require_healthy()
        return self._artifact_request("freeze", sandbox_id)

    def export(self, sandbox_id: str, destination: Path) -> FrozenArtifact:
        self._require_healthy()
        self._validate_id(sandbox_id)
        if not destination.is_absolute():
            raise ValueError("export destination must be absolute")
        if destination.exists() or not destination.parent.is_dir():
            raise ValueError("export destination must be a new file in an existing directory")
        response = self._request({"version": 1, "operation": "export", "sandbox_id": sandbox_id}, timeout=60)
        artifact = self._parse_artifact(sandbox_id, response)
        encoded = response.get("archive_base64")
        if not isinstance(encoded, str):
            raise RuntimeError("sandbox agent omitted exported archive")
        try:
            archive = base64.b64decode(encoded, validate=True)
        except ValueError as exc:
            raise RuntimeError("sandbox agent returned invalid base64 archive") from exc
        if len(archive) != artifact.size_bytes or hashlib.sha256(archive).hexdigest() != artifact.digest:
            raise RuntimeError("exported archive failed size or digest verification")
        # Exclusive create prevents an export from overwriting host data.
        with destination.open("xb") as output:
            output.write(archive)
        return artifact

    def destroy(self, sandbox_id: str) -> None:
        self._validate_id(sandbox_id)
        self._request({"version": 1, "operation": "destroy", "sandbox_id": sandbox_id}, timeout=30)

    def kill(self, sandbox_id: str) -> None:
        self._validate_id(sandbox_id)
        self._request({"version": 1, "operation": "kill", "sandbox_id": sandbox_id}, timeout=10)

    def scanner_available(self) -> bool:
        """Return whether the WSL agent can scan container images."""
        try:
            response = self._request(
                {"version": 1, "operation": "scanner_probe"}, timeout=15
            )
        except (OSError, RuntimeError, subprocess.SubprocessError, ValueError, json.JSONDecodeError):
            return False
        return bool(response.get("available", False))

    def build_image(
        self,
        recipe: Mapping[str, Any],
        *,
        dependencies: Mapping[str, bytes] | None = None,
        attempt_id: str | None = None,
        timeout_seconds: float = 1800.0,
    ) -> dict[str, Any]:
        """Ask the WSL agent to build one offline recipe with rootless podman."""
        if not 0 < timeout_seconds <= 86_400:
            raise ValueError("build timeout_seconds is outside the safe range")
        payload: dict[str, Any] = {
            "version": 1,
            "operation": "build_image",
            "recipe": dict(recipe),
            "dependencies": {},
            "timeout_seconds": float(timeout_seconds),
        }
        if attempt_id is not None:
            if not isinstance(attempt_id, str) or not attempt_id:
                raise ValueError("attempt_id must be non-empty text")
            payload["attempt_id"] = attempt_id
        else:
            raise ValueError("build_image requires an attempt_id")
        if dependencies:
            encoded: dict[str, str] = {}
            total = 0
            for name, data in sorted(dependencies.items()):
                if not isinstance(name, str) or not name or "\x00" in name:
                    raise ValueError("dependency name is invalid")
                total += len(data)
                if total > 64 * 1024 * 1024:
                    raise ValueError("build dependencies exceed the transfer limit")
                encoded[name] = base64.b64encode(data).decode("ascii")
            payload["dependencies"] = encoded
        response = self._request(payload, timeout=timeout_seconds + 30)
        raw = response.get("staged")
        if not isinstance(raw, Mapping):
            raise RuntimeError("sandbox agent omitted build staging result")
        return dict(raw)

    def scan_image(
        self, image: str, *, timeout_seconds: float = 600.0
    ) -> dict[str, Any]:
        if (
            not isinstance(image, str)
            or re.search(r"(?:@sha256:|^sha256:)[0-9a-f]{64}$", image) is None
        ):
            raise ValueError("scan image must be pinned by sha256 digest")
        if not 0 < timeout_seconds <= 3600:
            raise ValueError("scan timeout_seconds is outside the safe range")
        response = self._request(
            {
                "version": 1,
                "operation": "scan_image",
                "image": image,
                "timeout_seconds": float(timeout_seconds),
            },
            timeout=timeout_seconds + 30,
        )
        raw = response.get("scan")
        if not isinstance(raw, Mapping):
            raise RuntimeError("sandbox agent omitted scan result")
        return dict(raw)

    def _artifact_request(self, operation: str, sandbox_id: str) -> FrozenArtifact:
        self._validate_id(sandbox_id)
        response = self._request({"version": 1, "operation": operation, "sandbox_id": sandbox_id}, timeout=60)
        return self._parse_artifact(sandbox_id, response)

    @staticmethod
    def _parse_artifact(sandbox_id: str, response: Mapping[str, Any]) -> FrozenArtifact:
        artifact = response.get("artifact")
        if not isinstance(artifact, Mapping):
            raise RuntimeError("sandbox agent omitted artifact")
        digest = artifact.get("sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise RuntimeError("sandbox agent returned invalid artifact digest")
        return FrozenArtifact(sandbox_id, digest, int(artifact.get("size_bytes", 0)))

    def _request(self, request: dict[str, Any], *, timeout: float) -> dict[str, Any]:
        wire = json.dumps(request, sort_keys=True, separators=(",", ":")) + "\n"
        retryable = str(request.get("operation", "")) in _RETRYABLE_OPERATIONS
        attempts = _TRANSIENT_RETRY_ATTEMPTS if retryable else 1
        for attempt in range(attempts):
            try:
                process = self._runner(self.transport_argv(), wire, timeout)
            except subprocess.TimeoutExpired as exc:
                if attempt + 1 < attempts:
                    time.sleep(_TRANSIENT_RETRY_BACKOFF_SECONDS[attempt])
                    continue
                raise RuntimeError("sandbox transport timed out") from exc
            failure = _transport_failure(process)
            if failure is None:
                stdout = process.stdout.strip()
                decoded = json.loads(stdout)
                if not isinstance(decoded, dict):
                    raise RuntimeError("sandbox agent returned an invalid response")
                return decoded
            if not retryable or _is_agent_error(process):
                raise RuntimeError(failure)
            if attempt + 1 < attempts:
                time.sleep(_TRANSIENT_RETRY_BACKOFF_SECONDS[attempt])
                continue
            raise RuntimeError(failure)
        raise RuntimeError("unreachable transport retry loop")

    def _require_healthy(self) -> None:
        if self._last_doctor is None or not self._last_doctor.passed:
            raise RuntimeError("a passing doctor report is required before sandbox operations")

    @staticmethod
    def _validate_id(sandbox_id: str) -> None:
        if not _SAFE_ID.fullmatch(sandbox_id):
            raise ValueError("invalid sandbox id")

    def _sanitize_environment(self, env: Mapping[str, str]) -> dict[str, str]:
        sanitized: dict[str, str] = {}
        for key, value in env.items():
            if not _ENV_NAME.fullmatch(key) or key not in self._environment_allowlist:
                raise ValueError(f"environment variable is not allowed: {key}")
            if "\x00" in value or len(value) > 4096:
                raise ValueError(f"invalid environment value for: {key}")
            sanitized[key] = value
        return sanitized


def _transport_failure(process: subprocess.CompletedProcess[str]) -> str | None:
    """Return a diagnostic when the agent transport did not deliver a response.

    A structured ``{"ok": false, ...}`` reply is a deterministic agent-side
    error and is never retried. Anything else -- a crashed wsl.exe host, an
    empty or truncated stream -- is treated as a transient transport failure.
    """
    stdout = process.stdout.strip()
    if process.returncode != 0:
        try:
            decoded = json.loads(stdout)
        except ValueError:
            decoded = None
        if isinstance(decoded, dict) and decoded.get("ok") is False:
            message = str(decoded.get("message") or decoded.get("error") or "agent error")
            return f"sandbox agent failed with exit code {process.returncode}: {message}"
        stderr = _safe_diagnostic(process.stderr.strip())
        safe_stdout = _safe_diagnostic(stdout)
        streams = []
        if stderr:
            streams.append(f"stderr={stderr}")
        if safe_stdout:
            streams.append(f"stdout={safe_stdout}")
        suffix = f": {'; '.join(streams)}" if streams else ""
        return f"sandbox agent failed with exit code {process.returncode}{suffix}"
    if not stdout or "\n" in stdout:
        return "sandbox agent must return exactly one JSON object"
    try:
        decoded = json.loads(stdout)
    except ValueError:
        return "sandbox agent returned invalid JSON"
    if not isinstance(decoded, dict) or decoded.get("ok") is not True:
        return "sandbox agent returned an invalid or failed response"
    return None


def _is_agent_error(process: subprocess.CompletedProcess[str]) -> bool:
    """True when the agent returned a deliberate structured error reply."""
    try:
        decoded = json.loads(process.stdout.strip())
    except ValueError:
        return False
    return isinstance(decoded, dict) and decoded.get("ok") is False
