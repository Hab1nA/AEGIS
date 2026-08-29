from __future__ import annotations

import json
from typing import Any

import pytest

from aegis.agent_runtime import Action, ActionError, RoleAgentRuntime, RuntimeLimits, SandboxPluginExecutor, ToolDispatcher
from aegis.gateway.protocols import Role
from aegis.gateway.types import GatewayRequest, GatewayResponse, TokenUsage
from aegis.models import Role as GenerationRole, canonical_json
from aegis.plugins import (
    ActionSpec,
    EffectClass,
    Idempotency,
    NetworkAccess,
    PluginCapabilities,
    PluginManifest,
    PluginPolicy,
    PluginSource,
    ToolBroker,
    WorkspaceGrant,
    WorkspaceMode,
)
from aegis.roles import GenerationBundle, RoleGeneration
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


class Research:
    def search(self, query: str, *, limit: int = 10) -> list[Any]:
        return []

    def fetch(self, url: str, *, validate_as_archive: bool = False) -> Any:
        raise AssertionError("not used")


class Gateway:
    def __init__(self, actions: list[dict[str, object]]) -> None:
        self.actions = list(actions)
        self.requests: list[GatewayRequest] = []

    def complete(self, request: GatewayRequest, *, cancel: object = None) -> GatewayResponse:
        self.requests.append(request)
        return GatewayResponse(
            json.dumps(self.actions.pop(0)),
            TokenUsage(5, 2),
            "fake",
        )


class Executor:
    def __init__(self) -> None:
        self.calls: list[object] = []

    def execute(self, manifest: PluginManifest, grant: object, request: object) -> object:
        self.calls.append(request)
        arguments = getattr(request, "arguments")
        return {
            "output": {"echo": arguments["text"]},
            "elapsed_seconds": 0.01,
            "timed_out": False,
            "workspace_diff": None,
            "external_receipt": None,
        }


def action_spec(
    *,
    name: str = "demo.echo",
    effect: EffectClass = EffectClass.PURE,
) -> ActionSpec:
    return ActionSpec(
        name,
        INPUT_SCHEMA,
        OUTPUT_SCHEMA,
        effect,
        Idempotency.READ_ONLY if effect is EffectClass.PURE else Idempotency.IDEMPOTENT,
        requires_operation_id=effect is not EffectClass.PURE,
    )


def manifest(
    *,
    roles: tuple[GenerationRole, ...] = (GenerationRole.WARRIOR,),
    spec: ActionSpec | None = None,
) -> PluginManifest:
    selected = spec or action_spec()
    capabilities = PluginCapabilities(NetworkAccess.NONE)
    if selected.effect is EffectClass.WORKSPACE_WRITE:
        capabilities = PluginCapabilities(
            NetworkAccess.NONE,
            (WorkspaceGrant("output", WorkspaceMode.READ_WRITE, True),),
        )
    return PluginManifest.create(
        plugin_id="com.example/agent-plugin",
        version="1.0.0",
        abi_version=1,
        image_digest="registry.example/plugin@sha256:" + "a" * 64,
        entrypoint=("plugin-server",),
        roles=roles,
        actions=(selected,),
        capabilities=capabilities,
        provenance_sha256="b" * 64,
    )


def role_item(role: GenerationRole, marker: str, plugins: tuple[str, ...]) -> RoleGeneration:
    return RoleGeneration(
        role=role,
        model_profile_sha256=marker * 64,
        workflow_artifact_id="sha256:" + marker * 64,
        subject_artifact_id="sha256:" + marker * 64,
        runtime_image=f"registry.example/{role.value}@sha256:{marker * 64}",
        plugin_artifact_ids=plugins,
        budget_policy_sha256=marker * 64,
    )


def generation(plugin: PluginManifest, assigned_role: GenerationRole = GenerationRole.WARRIOR) -> GenerationBundle:
    plugin_ids = {
        role: (plugin.artifact_id,) if role is assigned_role else ()
        for role in GenerationRole
    }
    return GenerationBundle.create(
        parent_generation_id=None,
        controller_abi=1,
        source_commit="c" * 40,
        roles=(
            role_item(GenerationRole.WARRIOR, "1", plugin_ids[GenerationRole.WARRIOR]),
            role_item(GenerationRole.JUDGE, "2", plugin_ids[GenerationRole.JUDGE]),
            role_item(GenerationRole.PROSECUTOR, "3", plugin_ids[GenerationRole.PROSECUTOR]),
        ),
        evidence_manifest_sha256="d" * 64,
    )


def dispatcher(
    plugin: PluginManifest | None = None,
    *,
    assigned_role: GenerationRole = GenerationRole.WARRIOR,
    executor: Executor | None = None,
) -> tuple[ToolDispatcher, Executor, GenerationBundle | None]:
    selected_executor = executor or Executor()
    if plugin is None:
        return ToolDispatcher(FakeSandboxBackend(), Research(), "box"), selected_executor, None
    bundle = generation(plugin, assigned_role)
    policy = PluginPolicy(allowed_effects=frozenset({item.effect for item in plugin.actions}))
    broker = ToolBroker(
        bundle,
        (plugin,),
        selected_executor,
        policy=policy,
        nonce_factory=lambda: "e" * 32,
    )
    return (
        ToolDispatcher(
            FakeSandboxBackend(),
            Research(),
            "box",
            role_generation_id=bundle.generation_id,
            plugin_manifests=(plugin,),
            tool_broker=broker,
        ),
        selected_executor,
        bundle,
    )


def call(name: str, **arguments: object) -> dict[str, object]:
    return {"action": name, "arguments": arguments}


def test_dynamic_action_is_advertised_dispatched_and_receipt_is_returned_to_model() -> None:
    plugin = manifest()
    tools, executor, bundle = dispatcher(plugin)
    gateway = Gateway(
        [
            call("demo.echo", text="hello"),
            call("submit", summary="done", payload={}),
        ]
    )
    result = RoleAgentRuntime(gateway, tools, "model").run(
        Role.WARRIOR,
        objective="use plugin",
        context={},
    )

    assert bundle is not None
    assert len(executor.calls) == 1
    assert result.summary == "done"
    first_envelope = json.loads(gateway.requests[0].messages[1].content)
    assert "demo.echo" in first_envelope["allowed_actions"]
    assert first_envelope["plugin_action_schemas"]["demo.echo"]["input_schema"] == INPUT_SCHEMA
    response_schema = gateway.requests[0].output_schema
    assert response_schema is not None
    assert "demo.echo" in response_schema["properties"]["action"]["enum"]
    second_envelope = json.loads(gateway.requests[1].messages[1].content)
    receipt = second_envelope["observations"][0]["result"]["action_receipt"]
    assert receipt["generation_id"] == bundle.generation_id
    assert receipt["plugin_artifact_id"] == plugin.artifact_id
    assert receipt["action"] == "demo.echo"
    assert receipt["output"] == {"echo": "hello"}
    assert receipt["receipt_id"].startswith("sha256:")


def test_plugin_action_does_not_bypass_required_action_gate() -> None:
    plugin = manifest()
    tools, _, _ = dispatcher(plugin)
    gateway = Gateway(
        [
            call("submit", summary="early", payload={}),
            call("demo.echo", text="required"),
            call("submit", summary="done", payload={}),
        ]
    )
    result = RoleAgentRuntime(gateway, tools, "model", limits=RuntimeLimits(max_steps=5)).run(
        Role.WARRIOR,
        objective="must use plugin",
        context={},
        required_action_groups=(frozenset({"demo.echo"}),),
    )

    assert result.summary == "done"
    assert result.observations[0].action == "submit"
    assert result.observations[0].result["accepted"] is False
    assert result.observations[1].action == "demo.echo"


def test_manifest_role_and_generation_assignment_both_gate_dynamic_permissions() -> None:
    plugin = manifest(roles=(GenerationRole.WARRIOR, GenerationRole.JUDGE))
    tools, _, _ = dispatcher(plugin, assigned_role=GenerationRole.WARRIOR)
    assert "demo.echo" in tools.allowed_actions(Role.WARRIOR)
    assert "demo.echo" not in tools.allowed_actions(Role.JUDGE)
    with pytest.raises(ActionError, match="not allowed"):
        tools.dispatch(Role.JUDGE, Action("demo.echo", {"text": "forbidden"}))


def test_judge_plugin_cannot_extend_role_to_workspace_write() -> None:
    plugin = manifest(
        roles=(GenerationRole.JUDGE,),
        spec=action_spec(name="demo.mutate", effect=EffectClass.WORKSPACE_WRITE),
    )
    with pytest.raises(ValueError, match="judge role ceiling"):
        dispatcher(plugin, assigned_role=GenerationRole.JUDGE)


def test_plugin_cannot_override_builtin_action() -> None:
    plugin = manifest(spec=action_spec(name="workspace.read"))
    with pytest.raises(ValueError, match="override a built-in"):
        dispatcher(plugin)


def test_invalid_plugin_arguments_fail_at_broker_and_do_not_call_executor() -> None:
    plugin = manifest()
    executor = Executor()
    tools, _, _ = dispatcher(plugin, executor=executor)
    with pytest.raises(ActionError, match="failed closed"):
        tools.dispatch(Role.WARRIOR, Action("demo.echo", {"unknown": True}))
    assert executor.calls == []


def test_no_plugin_injection_preserves_legacy_actions_and_request_shape() -> None:
    tools, _, _ = dispatcher()
    gateway = Gateway([call("submit", summary="done", payload={})])
    RoleAgentRuntime(gateway, tools, "model").run(Role.WARRIOR, objective="legacy", context={})
    envelope = json.loads(gateway.requests[0].messages[1].content)
    assert "plugin_action_schemas" not in envelope
    assert "demo.echo" not in tools.allowed_actions(Role.WARRIOR)
