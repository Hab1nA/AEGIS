"""Source-driven plugin manifests and the sandbox executor dispatch protocol."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

import pytest

from aegis.agent_runtime import PluginRuntimeError, SandboxPluginExecutor
from aegis.models import Role as GenerationRole, canonical_json
from aegis.plugins import (
    ActionSpec,
    EffectClass,
    Idempotency,
    NetworkAccess,
    PluginCapabilities,
    PluginManifest,
    PluginSource,
)
from aegis.sandbox.fake import FakeSandboxBackend
from aegis.sandbox.types import CommandResult, CommandSpec

INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {"text": {"type": "string"}},
    "required": ["text"],
}
OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {"echo": {"type": "string"}},
    "required": ["echo"],
}

PLUGIN_SOURCE = (
    "def handle(action, arguments):\n"
    "    return {'echo': arguments['text'], 'action': action}\n"
)


def source_manifest() -> PluginManifest:
    content = base64.b64encode(PLUGIN_SOURCE.encode("utf-8")).decode("ascii")
    digest = hashlib.sha256(PLUGIN_SOURCE.encode("utf-8")).hexdigest()
    return PluginManifest.create(
        plugin_id="org.example/source-tool",
        version="1.0.0",
        abi_version=1,
        image_digest="",
        entrypoint=("python3", "tool.py"),
        roles=(GenerationRole.WARRIOR,),
        actions=(
            ActionSpec(
                "demo.echo",
                INPUT_SCHEMA,
                OUTPUT_SCHEMA,
                EffectClass.PURE,
                Idempotency.READ_ONLY,
                requires_operation_id=False,
            ),
        ),
        capabilities=PluginCapabilities(NetworkAccess.NONE),
        provenance_sha256="0" * 64,
        sources=(PluginSource("tool.py", content, digest),),
    )


class SourceRequest:
    def __init__(self, action: str, arguments: dict[str, object]) -> None:
        self.action = action
        self.arguments = arguments
        self.request_id = "req-1"


@dataclass
class StageTrace:
    staged_paths: list[str] = field(default_factory=list)
    staged_bodies: list[str] = field(default_factory=list)
    run_commands: list[CommandSpec] = field(default_factory=list)


def make_recorder(trace: StageRecorderAlias):
    """Scripted sandbox stand-in: verify staging, answer the run call.

    The real sandbox writes each source file and executes the entry module;
    this fixture checks the exact protocol the executor drives without
    running dynamic code inside the test process.
    """

    def executor(sandbox_id: str, command: CommandSpec) -> CommandResult:
        argv = command.argv
        is_stage = len(argv) > 4 and "hashlib" in argv[2]
        is_run = len(argv) > 4 and "importlib" in argv[2]
        if is_stage:
            payload = base64.b64decode(argv[4].encode("ascii"), validate=True)
            trace.staged_paths.append(argv[3])
            trace.staged_bodies.append(payload.decode("utf-8"))
            digest_line = hashlib.sha256(payload).hexdigest() + "\n"
            return CommandResult(0, digest_line, "", 0.0)
        if is_run:
            trace.run_commands.append(command)
            arguments = json.loads(command.stdin) if command.stdin else {}
            reply = {"echo": arguments.get("text"), "action": argv[5]}
            return CommandResult(0, json.dumps(reply), "", 0.0)
        raise AssertionError("unexpected sandbox command shape")

    return executor


StageRecorderAlias = StageTrace


def test_source_manifest_identity_covers_embedded_code() -> None:
    first = source_manifest()
    second = source_manifest()
    assert first.artifact_id == second.artifact_id
    expected_digest = hashlib.sha256(PLUGIN_SOURCE.encode("utf-8")).hexdigest()
    assert first.sources[0].content_sha256 == expected_digest


def test_source_manifest_rejects_digest_mismatch() -> None:
    content = base64.b64encode(PLUGIN_SOURCE.encode("utf-8")).decode("ascii")
    with pytest.raises(ValueError, match="content_sha256"):
        PluginSource("tool.py", content, "0" * 64)


def test_source_plugin_rejects_workspace_write_effect() -> None:
    from aegis.evolution.surfaces import EvolutionSurfaceError, validate_plugin_content

    manifest_one = source_manifest()
    write_manifest = PluginManifest.create(
        plugin_id=manifest_one.plugin_id,
        version=manifest_one.version,
        abi_version=manifest_one.abi_version,
        image_digest="",
        entrypoint=manifest_one.entrypoint,
        roles=manifest_one.roles,
        actions=(
            ActionSpec(
                "demo.write",
                INPUT_SCHEMA,
                OUTPUT_SCHEMA,
                EffectClass.WORKSPACE_WRITE,
                Idempotency.IDEMPOTENT,
                requires_operation_id=True,
            ),
        ),
        capabilities=manifest_one.capabilities,
        provenance_sha256=manifest_one.provenance_sha256,
        sources=manifest_one.sources,
    )
    with pytest.raises(EvolutionSurfaceError, match="workspace_write"):
        validate_plugin_content(write_manifest.to_dict(), target_role=GenerationRole.WARRIOR)


def test_source_manifest_requires_entrypoint_to_name_a_source() -> None:
    manifest_one = source_manifest()
    with pytest.raises(ValueError, match="entrypoint"):
        PluginManifest.create(
            plugin_id=manifest_one.plugin_id,
            version=manifest_one.version,
            abi_version=manifest_one.abi_version,
            image_digest="",
            entrypoint=("python3", "missing.py"),
            roles=manifest_one.roles,
            actions=manifest_one.actions,
            capabilities=manifest_one.capabilities,
            provenance_sha256=manifest_one.provenance_sha256,
            sources=manifest_one.sources,
        )


def test_source_plugin_action_stages_then_dispatches() -> None:
    trace = StageTrace()
    sandbox = FakeSandboxBackend()
    sandbox.prepare("sb-1")
    sandbox.executor = make_recorder(trace)
    executor = SandboxPluginExecutor(sandbox, "sb-1")
    receipt = executor.execute(
        source_manifest(), None, SourceRequest("demo.echo", {"text": "hi"})
    )
    assert receipt["output"] == {"echo": "hi", "action": "demo.echo"}
    assert receipt["timed_out"] is False
    assert len(trace.staged_paths) == 1
    tool_path = trace.staged_paths[0]
    assert tool_path.startswith("/tmp/aegis-plugin-")
    assert tool_path.endswith("/tool.py")
    assert trace.staged_bodies[0] == PLUGIN_SOURCE
    run_command = trace.run_commands[0]
    assert run_command.argv[5] == "demo.echo"
    assert json.loads(run_command.stdin) == {"text": "hi"}


def test_source_plugin_rejects_undeclared_action_without_staging() -> None:
    trace = StageTrace()
    sandbox = FakeSandboxBackend()
    sandbox.prepare("sb-2")
    sandbox.executor = make_recorder(trace)
    executor = SandboxPluginExecutor(sandbox, "sb-2")
    with pytest.raises(PluginRuntimeError, match="not declared"):
        executor.execute(
            source_manifest(), None, SourceRequest("other.action", {"text": "x"})
        )
    assert trace.staged_paths == []


def test_source_plugin_arguments_must_fit_the_input_limit() -> None:
    trace = StageTrace()
    sandbox = FakeSandboxBackend()
    sandbox.prepare("sb-3")
    sandbox.executor = make_recorder(trace)
    executor = SandboxPluginExecutor(sandbox, "sb-3")
    oversized = {"text": "x" * (65 * 1024)}
    with pytest.raises(PluginRuntimeError, match="input limit"):
        executor.execute(source_manifest(), None, SourceRequest("demo.echo", oversized))
    assert trace.staged_paths == []


def test_canonical_json_arguments_are_stable() -> None:
    payload = canonical_json({"text": "hi"})
    assert json.loads(payload) == {"text": "hi"}
