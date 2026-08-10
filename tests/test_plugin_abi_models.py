from __future__ import annotations

import pytest

from aegis.models import Role
from aegis.plugins import (
    ActionSpec,
    EffectClass,
    Idempotency,
    NetworkAccess,
    PluginCapabilities,
    PluginManifest,
    PluginPolicy,
    WorkspaceGrant,
    WorkspaceMode,
    validate_plugin_manifest,
)

STRICT_SCHEMA = {"type": "object", "additionalProperties": False, "properties": {}}


def action(
    name: str = "workspace.format",
    effect: EffectClass = EffectClass.WORKSPACE_WRITE,
    idempotency: Idempotency = Idempotency.IDEMPOTENT,
) -> ActionSpec:
    return ActionSpec(
        name,
        STRICT_SCHEMA,
        STRICT_SCHEMA,
        effect,
        idempotency,
        requires_operation_id=idempotency is not Idempotency.READ_ONLY,
    )


def manifest(
    *,
    actions: tuple[ActionSpec, ...] | None = None,
    capabilities: PluginCapabilities | None = None,
) -> PluginManifest:
    return PluginManifest.create(
        plugin_id="com.example/formatter",
        version="1.2.3",
        abi_version=1,
        image_digest="registry.example/formatter@sha256:" + "a" * 64,
        entrypoint=("plugin-server", "--stdio"),
        roles=(Role.WARRIOR,),
        actions=actions or (action(),),
        capabilities=capabilities
        or PluginCapabilities(
            NetworkAccess.NONE,
            (WorkspaceGrant("src", WorkspaceMode.READ_WRITE, True),),
        ),
        provenance_sha256="b" * 64,
    )


def test_plugin_manifest_is_content_addressed_and_policy_validated() -> None:
    created = manifest()
    assert created.artifact_id == "sha256:" + created.compute_digest()
    assert validate_plugin_manifest(created) is created


def test_action_schema_and_idempotency_fail_closed() -> None:
    with pytest.raises(ValueError, match="strict object"):
        ActionSpec(
            "workspace.read",
            {"type": "object"},
            STRICT_SCHEMA,
            EffectClass.WORKSPACE_READ,
            Idempotency.READ_ONLY,
            False,
        )
    with pytest.raises(ValueError, match="operation id"):
        ActionSpec(
            "workspace.write",
            STRICT_SCHEMA,
            STRICT_SCHEMA,
            EffectClass.WORKSPACE_WRITE,
            Idempotency.NON_RETRYABLE,
            False,
        )


def test_plugin_capabilities_must_match_effects() -> None:
    external = manifest(
        actions=(action("external.publish", EffectClass.EXTERNAL, Idempotency.NON_RETRYABLE),),
        capabilities=PluginCapabilities(NetworkAccess.BROKERED_PUBLIC),
    )
    with pytest.raises(ValueError, match="forbidden effect"):
        validate_plugin_manifest(external)
    allowed = PluginPolicy(
        allowed_effects=frozenset({EffectClass.EXTERNAL}),
        allow_brokered_public_network=True,
    )
    assert validate_plugin_manifest(external, allowed) is external

    mismatched = manifest(capabilities=PluginCapabilities(NetworkAccess.NONE))
    with pytest.raises(ValueError, match="writable grants"):
        validate_plugin_manifest(mismatched)

    read_without_grant = manifest(
        actions=(action("workspace.inspect", EffectClass.WORKSPACE_READ, Idempotency.READ_ONLY),),
        capabilities=PluginCapabilities(NetworkAccess.NONE),
    )
    with pytest.raises(ValueError, match="workspace effects"):
        validate_plugin_manifest(read_without_grant)


def test_plugin_secrets_are_references_and_default_denied() -> None:
    created = manifest(
        capabilities=PluginCapabilities(
            NetworkAccess.NONE,
            (WorkspaceGrant("src", WorkspaceMode.READ_WRITE, True),),
            ("PUBLISH_TOKEN",),
        )
    )
    with pytest.raises(ValueError, match="unapproved secret"):
        validate_plugin_manifest(created)
