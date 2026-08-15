"""Bounded subagent worker process.

Run as ``python -m aegis.subagent_worker <spec.json> <workdir> <result.json>``.
The worker reads a strict ``SubagentSpec``, executes it under its own
``LocalWorkspaceSandbox`` (real host commands confined to the workdir, no
network), and writes a bounded JSON result atomically.  ``runtime`` executors
run the real ``RoleAgentRuntime`` against the configured gateway; ``script``
executors run a bounded Python script for hermetic verification.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping, cast

from aegis.sandbox.types import CommandResult, CommandSpec
from aegis.subagents import SubagentLimits, SubagentRuntimeError, SubagentSpec

_MAX_CAPTURE_BYTES = 1_048_576


class LocalWorkspaceSandbox:
    """Real, restricted command executor confined to one subagent workdir."""

    def __init__(self, workdir: Path) -> None:
        self._workdir = workdir
        workdir.mkdir(parents=True, exist_ok=True)

    def prepare(self, sandbox_id: str, image: object = None) -> None:
        del image
        if not sandbox_id:
            raise SubagentRuntimeError("sandbox id is required")

    def destroy(self, sandbox_id: str) -> None:
        del sandbox_id

    def exec(self, sandbox_id: str, command: CommandSpec) -> CommandResult:
        del sandbox_id
        resolved = self._workdir.resolve()
        environment = dict(os.environ)
        environment.pop("PYTHONPATH", None)
        try:
            process = subprocess.run(
                tuple(command.argv),
                cwd=resolved,
                env=environment,
                capture_output=True,
                timeout=command.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return CommandResult(127, "", str(exc)[:2000], 0.0)
        stdout = process.stdout[: _MAX_CAPTURE_BYTES].decode(
            "utf-8", errors="replace"
        )
        stderr = process.stderr[: _MAX_CAPTURE_BYTES].decode(
            "utf-8", errors="replace"
        )
        return CommandResult(
            process.returncode,
            stdout,
            stderr,
            command.timeout_seconds,
            timed_out=False,
        )


def _load_spec(spec_path: Path) -> SubagentSpec:
    try:
        raw = json.loads(spec_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SubagentRuntimeError(f"cannot read subagent spec: {exc}") from exc
    if not isinstance(raw, Mapping):
        raise SubagentRuntimeError("subagent spec must be an object")
    try:
        limits = SubagentLimits(
            max_steps=raw["limits"]["max_steps"],
            timeout_seconds=raw["limits"]["timeout_seconds"],
            max_result_bytes=raw["limits"]["max_result_bytes"],
        )
        spec = SubagentSpec(
            subagent_id=raw["subagent_id"],
            role=raw["role"],
            objective=raw["objective"],
            context=raw["context"],
            executor=raw["executor"],
            script=raw.get("script"),
            input_refs=tuple(raw.get("input_refs", ())),
            limits=limits,
            model=raw.get("model"),
            max_output_tokens=raw.get("max_output_tokens", 4096),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise SubagentRuntimeError(f"subagent spec is invalid: {exc}") from exc
    return spec


def _run_script(spec: SubagentSpec, workdir: Path) -> tuple[str, Mapping[str, Any], int, bool]:
    workdir.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ)
    environment["AEGIS_SUBAGENT_WORKDIR"] = str(workdir)
    try:
        process = subprocess.run(
            (sys.executable, "-c", spec.script or ""),
            cwd=workdir,
            env=environment,
            capture_output=True,
            timeout=spec.limits.timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return "subagent script timed out", {}, 124, True
    except (OSError, subprocess.SubprocessError) as exc:
        return f"subagent script failed to start: {exc}", {}, 127, False
    stdout = process.stdout[: _MAX_CAPTURE_BYTES].decode("utf-8", errors="replace")
    stderr = process.stderr[: _MAX_CAPTURE_BYTES].decode("utf-8", errors="replace")
    summary = (stdout or stderr).strip()[:4096] or "subagent script finished"
    output = {
        "stdout": stdout[-4096:],
        "stderr": stderr[-4096:],
        "returncode": process.returncode,
    }
    return summary, output, process.returncode, False


def _run_runtime(spec: SubagentSpec, workdir: Path) -> tuple[str, Mapping[str, Any], int, bool]:
    from aegis.agent_runtime import (
        _PERMISSIONS,
        Research,
        RoleAgentRuntime,
        RuntimeLimits,
        ToolDispatcher,
    )
    from aegis.gateway.client import GatewayConfig, ModelGateway
    from aegis.gateway.protocols import Role
    from aegis.sandbox.backend import SandboxBackend

    if spec.model is None:
        raise SubagentRuntimeError("runtime executor requires a model in the spec")
    try:
        gateway_config = GatewayConfig.from_env()
        gateway = ModelGateway(gateway_config)
    except (ValueError, OSError) as exc:
        raise SubagentRuntimeError(f"runtime executor gateway is unavailable: {exc}") from exc
    accounting_store = None
    raw_binding = os.environ.get("AEGIS_SUBAGENT_ACCOUNTING_BINDING")
    if raw_binding:
        try:
            from aegis.artifacts import ContentAddressedArtifactStore
            from aegis.event_store import EventStore
            from aegis.runtime_ledger import AccountingContext, GatewayAttemptObserver
            from aegis.runtime_policy import RuntimePolicyRegistry

            binding = json.loads(raw_binding)
            if not isinstance(binding, Mapping) or set(binding) != {
                "event_store_path", "artifact_root", "policy_campaign_id", "parent_context"
            }:
                raise ValueError("invalid accounting binding schema")
            parent = AccountingContext.from_mapping(binding["parent_context"])
            accounting_store = EventStore(Path(binding["event_store_path"]))
            registry = RuntimePolicyRegistry(
                accounting_store,
                ContentAddressedArtifactStore(Path(binding["artifact_root"])),
                binding["policy_campaign_id"],
            )
            child_context = AccountingContext(
                campaign_id=parent.campaign_id,
                cycle=parent.cycle,
                stage=f"subagent:{spec.subagent_id}",
                stage_ordinal=parent.stage_ordinal,
                role=parent.role,
                invocation_id=f"{parent.invocation_id}/{spec.subagent_id}",
                paired_design_id=parent.paired_design_id,
            )
            gateway.bind_attempt_observer(
                GatewayAttemptObserver(accounting_store, registry, lambda _request: child_context)
            )
            gateway.bind_runtime_policy_provider(
                lambda: cast(
                    Mapping[str, object],
                    registry.effective_for_stage(
                        registry.stage_boundary(child_context.cycle, child_context.stage_ordinal, child_context.stage)
                    ).values
                    if child_context.paired_design_id is None
                    else registry.policy_for_paired_design(child_context.paired_design_id).values,
                )
            )
        except Exception as exc:
            if accounting_store is not None:
                accounting_store.close()
            raise SubagentRuntimeError(f"runtime accounting binding is invalid: {exc}") from exc
    sandbox = LocalWorkspaceSandbox(workdir)
    allowed = frozenset({"workspace.read", "workspace.write", "submit"})
    dispatcher = ToolDispatcher(
        cast(SandboxBackend, sandbox),
        cast(Research, None),  # research is intentionally unavailable to subagents
        "subagent-runtime",
        limits=RuntimeLimits(max_steps=spec.limits.max_steps),
        disabled_actions=frozenset(_PERMISSIONS[Role.WARRIOR] - allowed),
    )
    runtime = RoleAgentRuntime(
        gateway,
        dispatcher,
        spec.model,
        limits=RuntimeLimits(max_steps=spec.limits.max_steps),
        max_output_tokens=spec.max_output_tokens,
    )
    try:
        result = runtime.run(
            Role.WARRIOR,
            objective=spec.objective,
            context=dict(spec.context),
        )
    finally:
        if accounting_store is not None:
            accounting_store.close()
    payload = dict(result.submission)
    summary = result.summary[:4096]
    return summary, {"submission": payload}, 0, False


def _run(spec: SubagentSpec, workdir: Path) -> tuple[str, Mapping[str, Any], int, bool]:
    if spec.executor == "script":
        return _run_script(spec, workdir)
    if spec.executor == "runtime":
        return _run_runtime(spec, workdir)
    raise SubagentRuntimeError(f"unknown subagent executor: {spec.executor}")


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 3:
        print(json.dumps({"error": "worker requires spec, workdir, result paths"}))
        return 2
    spec_path = Path(args[0])
    workdir = Path(args[1])
    result_path = Path(args[2])
    payload: dict[str, Any] = {}
    try:
        spec = _load_spec(spec_path)
        summary, output, exit_code, timed_out = _run(spec, workdir)
        payload = {
            "subagent_id": spec.subagent_id,
            "summary": summary,
            "output": output,
            "timed_out": timed_out,
            "exit_code": exit_code,
        }
    except SubagentRuntimeError as exc:
        payload = {"error": str(exc)}
        exit_code = 1
    except Exception as exc:  # pragma: no cover - worker must never die silently
        payload = {"error": f"{type(exc).__name__}: {exc}"}
        exit_code = 1
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    if "spec" in locals() and len(encoded) > spec.limits.max_result_bytes:
        payload = {
            "subagent_id": spec.subagent_id,
            "error": "subagent result exceeds max_result_bytes",
            "exit_code": 1,
        }
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        exit_code = 1
        if len(encoded) > spec.limits.max_result_bytes:
            encoded = b'{"error":"result limit too small"}'
    result_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix="result-", dir=str(result_path.parent)
    )
    try:
        with os.fdopen(descriptor, "wb") as output_file:
            output_file.write(encoded)
        os.replace(temporary, result_path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
