from __future__ import annotations

import hashlib
from dataclasses import replace
from typing import Any

import pytest

from aegis.models import Role, canonical_json
from aegis.plugins import (
    ActionSpec,
    CapabilityDenied,
    EffectClass,
    ExternalEffectReceipt,
    ExternalIntent,
    Idempotency,
    MalformedPluginResult,
    NetworkAccess,
    PluginCapabilities,
    PluginExecutionError,
    PluginManifest,
    PluginPolicy,
    ToolBroker,
    WorkspaceDiffReceipt,
    WorkspaceGrant,
    WorkspaceMode,
)
from aegis.roles import GenerationBundle, RoleGeneration

EMPTY = {"type": "object", "additionalProperties": False, "properties": {}}
INPUT = {
    "type": "object",
    "additionalProperties": False,
    "properties": {"value": {"type": "integer", "minimum": 0}},
    "required": ["value"],
}
OUTPUT = {
    "type": "object",
    "additionalProperties": False,
    "properties": {"ok": {"type": "boolean"}},
    "required": ["ok"],
}


def action(
    effect: EffectClass, *, max_input_bytes: int = 1024, max_output_bytes: int = 1024
) -> ActionSpec:
    return ActionSpec(
        f"example.{effect.value}",
        INPUT,
        OUTPUT,
        effect,
        Idempotency.READ_ONLY if effect in {EffectClass.PURE, EffectClass.WORKSPACE_READ} else Idempotency.IDEMPOTENT,
        requires_operation_id=effect not in {EffectClass.PURE, EffectClass.WORKSPACE_READ},
        max_input_bytes=max_input_bytes,
        max_output_bytes=max_output_bytes,
        timeout_seconds=5,
    )


def plugin(
    effect: EffectClass, *, max_input_bytes: int = 1024, max_output_bytes: int = 1024
) -> PluginManifest:
    workspace: tuple[WorkspaceGrant, ...] = ()
    network = NetworkAccess.NONE
    if effect is EffectClass.WORKSPACE_READ:
        workspace = (WorkspaceGrant("src", WorkspaceMode.READ_ONLY, True),)
    elif effect is EffectClass.WORKSPACE_WRITE:
        workspace = (WorkspaceGrant("src", WorkspaceMode.READ_WRITE, True),)
    elif effect is EffectClass.EXTERNAL:
        network = NetworkAccess.BROKERED_PUBLIC
    return PluginManifest.create(
        plugin_id="com.example/runtime",
        version="1.0.0",
        abi_version=1,
        image_digest="registry.example/runtime@sha256:" + "a" * 64,
        entrypoint=("plugin-server",),
        roles=(Role.WARRIOR,),
        actions=(action(effect, max_input_bytes=max_input_bytes, max_output_bytes=max_output_bytes),),
        capabilities=PluginCapabilities(network, workspace),
        provenance_sha256="b" * 64,
    )


def generation(manifest: PluginManifest) -> GenerationBundle:
    def role_item(role: Role, marker: str, plugins: tuple[str, ...]) -> RoleGeneration:
        return RoleGeneration(
            role=role,
            model_profile_sha256=marker * 64,
            workflow_artifact_id="sha256:" + marker * 64,
            subject_artifact_id="sha256:" + marker * 64,
            runtime_image=f"registry.example/{role.value}@sha256:{marker * 64}",
            plugin_artifact_ids=plugins,
            budget_policy_sha256=marker * 64,
        )

    return GenerationBundle.create(
        parent_generation_id=None,
        controller_abi=1,
        source_commit="c" * 40,
        roles=(
            role_item(Role.WARRIOR, "1", (manifest.artifact_id,)),
            role_item(Role.JUDGE, "2", ()),
            role_item(Role.PROSECUTOR, "3", ()),
        ),
        evidence_manifest_sha256="d" * 64,
    )


def result(
    *,
    output: object | None = None,
    elapsed_seconds: object = 0.1,
    timed_out: object = False,
    workspace_diff: object = None,
    external_receipt: object = None,
) -> dict[str, object]:
    return {
        "output": {"ok": True} if output is None else output,
        "elapsed_seconds": elapsed_seconds,
        "timed_out": timed_out,
        "workspace_diff": workspace_diff,
        "external_receipt": external_receipt,
    }


class Executor:
    def __init__(self, raw: object) -> None:
        self.raw = raw
        self.calls = 0

    def execute(self, manifest: PluginManifest, grant: object, request: object) -> object:
        assert manifest.artifact_id
        self.calls += 1
        return self.raw


def broker_for(manifest: PluginManifest, executor: Executor, **kwargs: Any) -> ToolBroker:
    policy = PluginPolicy(
        allowed_effects=frozenset({item.effect for item in manifest.actions}),
        allow_brokered_public_network=manifest.capabilities.network is NetworkAccess.BROKERED_PUBLIC,
    )
    return ToolBroker(
        generation(manifest),
        (manifest,),
        executor,
        policy=policy,
        nonce_factory=lambda: "f" * 32,
        **kwargs,
    )


def test_pure_call_is_schema_checked_content_addressed_and_single_use() -> None:
    manifest = plugin(EffectClass.PURE)
    executor = Executor(result())
    broker = broker_for(manifest, executor)
    grant = broker.issue_grant(Role.WARRIOR, manifest.artifact_id, "example.pure")
    request = broker.create_request(grant, {"value": 1})
    receipt = broker.execute(request)

    assert grant.grant_id.startswith("sha256:")
    assert request.request_id.startswith("sha256:")
    assert receipt.receipt_id.startswith("sha256:")
    assert receipt.output["ok"] is True
    with pytest.raises(CapabilityDenied, match="already consumed"):
        broker.execute(request)

    with pytest.raises(ValueError, match="request content"):
        replace(request, action="example.forged")


def test_input_and_output_byte_limits_are_enforced_at_the_broker_boundary() -> None:
    input_limited = plugin(EffectClass.PURE, max_input_bytes=8)
    input_broker = broker_for(input_limited, Executor(result()))
    input_grant = input_broker.issue_grant(Role.WARRIOR, input_limited.artifact_id, "example.pure")
    with pytest.raises(CapabilityDenied, match="max_input_bytes"):
        input_broker.create_request(input_grant, {"value": 100})

    output_limited = plugin(EffectClass.PURE, max_output_bytes=5)
    output_broker = broker_for(output_limited, Executor(result()))
    output_grant = output_broker.issue_grant(Role.WARRIOR, output_limited.artifact_id, "example.pure")
    output_request = output_broker.create_request(output_grant, {"value": 1})
    with pytest.raises(MalformedPluginResult, match="max_output_bytes"):
        output_broker.execute(output_request)


def test_role_action_operation_schema_and_timeout_are_denied_before_execution() -> None:
    manifest = plugin(EffectClass.WORKSPACE_WRITE)
    executor = Executor(result())
    broker = broker_for(manifest, executor)
    with pytest.raises(CapabilityDenied, match="not pinned"):
        broker.issue_grant(Role.JUDGE, manifest.artifact_id, "example.workspace_write", operation_id="op-1")
    with pytest.raises(CapabilityDenied, match="not declared"):
        broker.issue_grant(Role.WARRIOR, manifest.artifact_id, "example.unknown", operation_id="op-1")
    with pytest.raises(ValueError, match="required"):
        broker.issue_grant(Role.WARRIOR, manifest.artifact_id, "example.workspace_write")
    with pytest.raises(CapabilityDenied, match="timeout"):
        broker.issue_grant(
            Role.WARRIOR, manifest.artifact_id, "example.workspace_write", operation_id="op-1", timeout_seconds=6
        )

    grant = broker.issue_grant(Role.WARRIOR, manifest.artifact_id, "example.workspace_write", operation_id="op-1")
    with pytest.raises(CapabilityDenied, match="minimum"):
        broker.create_request(grant, {"value": -1})
    assert executor.calls == 0


def test_workspace_write_requires_matching_content_addressed_diff_receipt() -> None:
    manifest = plugin(EffectClass.WORKSPACE_WRITE)
    executor = Executor(result())
    broker = broker_for(manifest, executor)
    grant = broker.issue_grant(Role.WARRIOR, manifest.artifact_id, "example.workspace_write", operation_id="op-2")
    request = broker.create_request(grant, {"value": 2})
    diff = WorkspaceDiffReceipt.create(
        request_id=request.request_id,
        before_sha256="1" * 64,
        after_sha256="2" * 64,
        diff_sha256="3" * 64,
        changed_paths=("src/main.py",),
    )
    executor.raw = result(workspace_diff=diff.to_dict())
    receipt = broker.execute(request)
    assert receipt.diff_receipt_id == diff.diff_receipt_id

    second = broker_for(manifest, Executor(result()))
    second_grant = second.issue_grant(
        Role.WARRIOR, manifest.artifact_id, "example.workspace_write", operation_id="op-3"
    )
    second_request = second.create_request(second_grant, {"value": 3})
    with pytest.raises(MalformedPluginResult, match="diff receipt"):
        second.execute(second_request)


class Journal:
    def __init__(self) -> None:
        self.events: list[str] = []

    def record_intent(self, intent: ExternalIntent) -> None:
        self.events.append("intent:" + intent.intent_id)

    def record_receipt(self, receipt: ExternalEffectReceipt) -> None:
        self.events.append("receipt:" + receipt.external_receipt_id)


class Connector:
    connector_id = "public-http"

    def __init__(self, journal: Journal) -> None:
        self.journal = journal
        self.calls = 0

    def execute(self, manifest: object, grant: object, request: object, intent: ExternalIntent) -> object:
        assert self.journal.events == ["intent:" + intent.intent_id]
        self.calls += 1
        output = {"ok": True}
        output_sha256 = hashlib.sha256(canonical_json(output).encode("utf-8")).hexdigest()
        receipt = ExternalEffectReceipt.create(
            intent_id=intent.intent_id,
            request_id=intent.request_id,
            connector_id=self.connector_id,
            operation_id=intent.operation_id,
            output_sha256=output_sha256,
            remote_receipt_sha256="e" * 64,
        )
        return result(output=output, external_receipt=receipt.to_dict())


def test_external_action_uses_only_dedicated_connector_and_journals_intent_first() -> None:
    manifest = plugin(EffectClass.EXTERNAL)
    executor = Executor(result())
    journal = Journal()
    connector = Connector(journal)
    broker = broker_for(manifest, executor, external_connector=connector, external_journal=journal)
    grant = broker.issue_grant(Role.WARRIOR, manifest.artifact_id, "example.external", operation_id="publish-1")
    receipt = broker.execute(broker.create_request(grant, {"value": 4}))

    assert executor.calls == 0
    assert connector.calls == 1
    assert journal.events[0].startswith("intent:")
    assert journal.events[1] == "receipt:" + receipt.external_receipt_id


def test_external_action_without_connector_is_denied_before_grant_issuance() -> None:
    manifest = plugin(EffectClass.EXTERNAL)
    broker = broker_for(manifest, Executor(result()))
    with pytest.raises(CapabilityDenied, match="connector"):
        broker.issue_grant(Role.WARRIOR, manifest.artifact_id, "example.external", operation_id="publish-2")


def test_workspace_diff_must_stay_within_writable_manifest_grants() -> None:
    manifest = plugin(EffectClass.WORKSPACE_WRITE)
    executor = Executor(result())
    broker = broker_for(manifest, executor)
    grant = broker.issue_grant(Role.WARRIOR, manifest.artifact_id, "example.workspace_write", operation_id="op-4")
    request = broker.create_request(grant, {"value": 4})
    diff = WorkspaceDiffReceipt.create(
        request_id=request.request_id,
        before_sha256="1" * 64,
        after_sha256="2" * 64,
        diff_sha256="3" * 64,
        changed_paths=("control-plane.py",),
    )
    executor.raw = result(workspace_diff=diff.to_dict())
    with pytest.raises(MalformedPluginResult, match="outside writable grants"):
        broker.execute(request)


@pytest.mark.parametrize(
    ("raw", "error"),
    [
        ({"output": {"ok": True}}, "missing or unknown"),
        (result(output={"unexpected": True}), "properties"),
        (result(timed_out=True), "timeout"),
        (result(elapsed_seconds=float("nan")), "elapsed_seconds"),
    ],
)
def test_malformed_or_timed_out_executor_results_fail_closed(raw: object, error: str) -> None:
    manifest = plugin(EffectClass.PURE)
    broker = broker_for(manifest, Executor(raw))
    grant = broker.issue_grant(Role.WARRIOR, manifest.artifact_id, "example.pure")
    request = broker.create_request(grant, {"value": 1})
    with pytest.raises((MalformedPluginResult, PluginExecutionError, CapabilityDenied), match=error):
        broker.execute(request)
    with pytest.raises(CapabilityDenied, match="already consumed"):
        broker.execute(request)
