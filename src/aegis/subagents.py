"""Minimal real subagent runtime for the Warrior.

``SubagentManager`` spawns one bounded Python subprocess per subagent
(``python -m aegis.subagent_worker``) with its own workspace, input spec, and
output file.  The parent never touches the worker's filesystem directly; it
polls status and reclaims the result through the process boundary.  Resource
quotas (steps, timeout, result size, concurrency) are enforced by the manager
and the worker, so a runaway subagent is killed and its partial output is
discarded.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

import aegis
from aegis.models import canonical_json

MAX_SUBAGENT_OBJECTIVE_BYTES = 4_096
MAX_SUBAGENT_CONTEXT_BYTES = 64 * 1024
MAX_SUBAGENT_INPUT_REFS = 16


class SubagentRuntimeError(RuntimeError):
    """A quota, lifecycle, or boundary failure in the subagent runtime."""


def _text(value: object, name: str, *, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value.encode("utf-8")) > maximum
    ):
        raise SubagentRuntimeError(f"{name} must be bounded, non-empty, trimmed text")
    return value


@dataclass(frozen=True, slots=True)
class SubagentLimits:
    max_steps: int = 8
    timeout_seconds: float = 180.0
    max_result_bytes: int = 65_536

    def __post_init__(self) -> None:
        if isinstance(self.max_steps, bool) or not isinstance(self.max_steps, int):
            raise SubagentRuntimeError("subagent max_steps must be an integer")
        if not 1 <= self.max_steps <= 1000:
            raise SubagentRuntimeError("subagent max_steps must be in [1, 1000]")
        if isinstance(self.timeout_seconds, bool) or not isinstance(
            self.timeout_seconds, (int, float)
        ):
            raise SubagentRuntimeError("subagent timeout must be numeric")
        if not 1 <= float(self.timeout_seconds) <= 3600:
            raise SubagentRuntimeError("subagent timeout must be in [1, 3600]")
        if isinstance(self.max_result_bytes, bool) or not isinstance(
            self.max_result_bytes, int
        ):
            raise SubagentRuntimeError("subagent result size must be an integer")
        if not 1 <= self.max_result_bytes <= 4 * 1024 * 1024:
            raise SubagentRuntimeError("subagent result size is outside the safe range")
        object.__setattr__(self, "timeout_seconds", float(self.timeout_seconds))


@dataclass(frozen=True, slots=True)
class SubagentSpec:
    subagent_id: str
    role: str
    objective: str
    context: Mapping[str, Any]
    executor: str
    script: str | None
    input_refs: tuple[str, ...]
    limits: SubagentLimits
    model: str | None = None
    max_output_tokens: int = 4096

    def __post_init__(self) -> None:
        if not isinstance(self.subagent_id, str) or not self.subagent_id.startswith(
            "subagent-sha256:"
        ):
            raise SubagentRuntimeError("subagent_id must be a content address")
        if self.role not in {"warrior", "judge", "prosecutor"}:
            raise SubagentRuntimeError("subagent role must be warrior, judge, or prosecutor")
        _text(self.objective, "subagent objective", maximum=MAX_SUBAGENT_OBJECTIVE_BYTES)
        if self.executor not in {"script", "runtime"}:
            raise SubagentRuntimeError("subagent executor must be script or runtime")
        if self.executor == "script" and (
            not isinstance(self.script, str) or not self.script or len(self.script) > 16_384
        ):
            raise SubagentRuntimeError("script executor requires a bounded script")
        if self.executor == "runtime" and not isinstance(self.script, str) and self.script is not None:
            raise SubagentRuntimeError("runtime executor must not carry a script")
        if len(self.input_refs) > MAX_SUBAGENT_INPUT_REFS:
            raise SubagentRuntimeError("subagent input_refs exceeds the limit")
        if not isinstance(self.max_output_tokens, int) or not 1 <= self.max_output_tokens <= 1_048_576:
            raise SubagentRuntimeError("subagent max_output_tokens is invalid")
        try:
            encoded = canonical_json(self.to_mapping(include_id=False)).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise SubagentRuntimeError("subagent spec contains non-JSON context") from exc
        if len(encoded) > MAX_SUBAGENT_CONTEXT_BYTES:
            raise SubagentRuntimeError("subagent spec exceeds the context size bound")
        expected = "subagent-sha256:" + hashlib.sha256(encoded).hexdigest()
        if self.subagent_id != expected:
            raise SubagentRuntimeError("subagent_id does not match the spec content")

    @classmethod
    def create(
        cls,
        *,
        role: str,
        objective: str,
        context: Mapping[str, Any],
        executor: str,
        script: str | None,
        input_refs: Sequence[str],
        limits: SubagentLimits,
        model: str | None = None,
        max_output_tokens: int = 4096,
    ) -> SubagentSpec:
        payload = {
            "role": role,
            "objective": objective,
            "context": dict(context),
            "executor": executor,
            "script": script,
            "input_refs": tuple(input_refs),
            "limits": {
                "max_steps": limits.max_steps,
                "timeout_seconds": limits.timeout_seconds,
                "max_result_bytes": limits.max_result_bytes,
            },
            "model": model,
            "max_output_tokens": max_output_tokens,
        }
        return cls(
            "subagent-sha256:"
            + hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest(),
            role,
            objective,
            dict(context),
            executor,
            script,
            tuple(input_refs),
            limits,
            model,
            max_output_tokens,
        )

    def to_mapping(self, *, include_id: bool = True) -> dict[str, Any]:
        payload = {
            "role": self.role,
            "objective": self.objective,
            "context": dict(self.context),
            "executor": self.executor,
            "script": self.script,
            "input_refs": list(self.input_refs),
            "limits": {
                "max_steps": self.limits.max_steps,
                "timeout_seconds": self.limits.timeout_seconds,
                "max_result_bytes": self.limits.max_result_bytes,
            },
            "model": self.model,
            "max_output_tokens": self.max_output_tokens,
        }
        return {"subagent_id": self.subagent_id, **payload} if include_id else payload


@dataclass(frozen=True, slots=True)
class SubagentResult:
    subagent_id: str
    exit_code: int
    summary: str
    output: Mapping[str, Any]
    timed_out: bool
    evidence_id: str

    def to_mapping(self) -> dict[str, Any]:
        return {
            "subagent_id": self.subagent_id,
            "exit_code": self.exit_code,
            "summary": self.summary[:4096],
            "output": self.output,
            "timed_out": self.timed_out,
            "evidence_id": self.evidence_id,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> SubagentResult:
        expected = {"subagent_id", "exit_code", "summary", "output", "timed_out", "evidence_id"}
        if set(value) != expected:
            raise SubagentRuntimeError("subagent result has missing or unknown fields")
        return cls(
            value["subagent_id"],
            value["exit_code"],
            value["summary"],
            value["output"],
            value["timed_out"],
            value["evidence_id"],
        )


class SubagentManager:
    """Spawn, poll, and reclaim bounded subagent processes."""

    def __init__(
        self,
        *,
        python: str | None = None,
        limits: SubagentLimits = SubagentLimits(),
        max_concurrency: int = 2,
    ) -> None:
        if isinstance(max_concurrency, bool) or not isinstance(max_concurrency, int):
            raise SubagentRuntimeError("max_concurrency must be an integer")
        if not 1 <= max_concurrency <= 16:
            raise SubagentRuntimeError("max_concurrency must be in [1, 16]")
        self._python = python or sys.executable
        self._limits = limits
        self._max_concurrency = max_concurrency
        self._running: dict[str, subprocess.Popen[str]] = {}
        self._outputs: dict[str, Path] = {}
        self._workspaces: dict[str, Path] = {}
        self._results: dict[str, Mapping[str, Any]] = {}

    def spawn(self, spec: SubagentSpec) -> Mapping[str, Any]:
        if spec.subagent_id in self._running:
            raise SubagentRuntimeError("subagent is already running")
        if len(self._running) >= self._max_concurrency:
            raise SubagentRuntimeError("subagent concurrency limit reached")
        workspace = Path(tempfile.mkdtemp(prefix=f"aegis-subagent-{spec.subagent_id[16:24]}-"))
        spec_path = workspace / "spec.json"
        output_path = workspace / "result.json"
        spec_path.write_text(
            json.dumps(spec.to_mapping(), ensure_ascii=False, sort_keys=True),
            encoding="utf-8",
        )
        process = subprocess.Popen(
            (
                self._python,
                "-m",
                "aegis.subagent_worker",
                str(spec_path),
                str(workspace / "work"),
                str(output_path),
            ),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=self._worker_env(),
        )
        self._running[spec.subagent_id] = process
        self._outputs[spec.subagent_id] = output_path
        self._workspaces[spec.subagent_id] = workspace
        return {
            "subagent_id": spec.subagent_id,
            "status": "running",
            "executor": spec.executor,
            "role": spec.role,
            "limits": {
                "max_steps": spec.limits.max_steps,
                "timeout_seconds": spec.limits.timeout_seconds,
                "max_result_bytes": spec.limits.max_result_bytes,
            },
        }

    def _worker_env(self) -> dict[str, str]:
        environment = dict(os.environ)
        package_root = str(Path(aegis.__file__).resolve().parent.parent)
        existing = environment.get("PYTHONPATH", "")
        environment["PYTHONPATH"] = (
            package_root if not existing else package_root + os.pathsep + existing
        )
        return environment

    def status(self, subagent_id: str) -> Mapping[str, Any]:
        process = self._running.get(subagent_id)
        if process is None:
            raise SubagentRuntimeError("subagent is not running")
        poll = process.poll()
        if poll is None:
            return {"subagent_id": subagent_id, "status": "running"}
        finished = self._finish(subagent_id, poll, timed_out=False)
        return {"subagent_id": subagent_id, "status": "finished", **finished}

    def reclaim(self, subagent_id: str, *, timeout_seconds: float) -> Mapping[str, Any]:
        cached = self._results.get(subagent_id)
        if cached is not None:
            return cached
        process = self._running.get(subagent_id)
        if process is None:
            raise SubagentRuntimeError("subagent is not running")
        try:
            exit_code = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            return self._finish(subagent_id, -9, timed_out=True)
        return self._finish(subagent_id, exit_code, timed_out=False)

    def _finish(
        self, subagent_id: str, exit_code: int, *, timed_out: bool
    ) -> Mapping[str, Any]:
        process = self._running.pop(subagent_id, None)
        output_path = self._outputs.pop(subagent_id, None)
        workspace = self._workspaces.pop(subagent_id, None)
        payload: dict[str, Any] = {}
        if output_path is not None and output_path.is_file():
            try:
                payload = json.loads(output_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                payload = {"error": "subagent result file is malformed"}
        if workspace is not None:
            import shutil

            shutil.rmtree(workspace, ignore_errors=True)
        if not isinstance(payload, Mapping):
            payload = {"error": "subagent result is not an object"}
        if "subagent_id" not in payload:
            payload["subagent_id"] = subagent_id
        result = self._build_result(
            subagent_id, exit_code, timed_out, payload
        )
        mapping = result.to_mapping()
        self._results[subagent_id] = mapping
        return mapping

    @staticmethod
    def _build_result(
        subagent_id: str,
        exit_code: int,
        timed_out: bool,
        payload: Mapping[str, Any],
    ) -> SubagentResult:
        error = payload.get("error")
        summary = (
            str(error)
            if isinstance(error, str)
            else str(payload.get("summary", "subagent finished"))
        )
        output = payload.get("output")
        if not isinstance(output, Mapping):
            output = {"error": summary}
        if payload.get("timed_out") is True:
            timed_out = True
        payload_exit = payload.get("exit_code")
        if isinstance(payload_exit, int) and not isinstance(payload_exit, bool):
            exit_code = payload_exit
        evidence_id = "subagent-result-sha256:" + hashlib.sha256(
            canonical_json(
                {
                    "subagent_id": subagent_id,
                    "exit_code": exit_code,
                    "summary": summary,
                    "output": output,
                    "timed_out": timed_out,
                }
            ).encode("utf-8")
        ).hexdigest()
        return SubagentResult(
            subagent_id,
            exit_code,
            summary,
            output,
            timed_out,
            evidence_id,
        )


__all__ = [
    "MAX_SUBAGENT_CONTEXT_BYTES",
    "MAX_SUBAGENT_OBJECTIVE_BYTES",
    "SubagentLimits",
    "SubagentManager",
    "SubagentResult",
    "SubagentRuntimeError",
    "SubagentSpec",
]
