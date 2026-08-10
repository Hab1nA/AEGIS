"""Content-addressed plugin manifest for the role-facing checkpoint action."""

from __future__ import annotations

import hashlib
from typing import Mapping

from aegis.models import JsonValue, Role
from aegis.plugins.abi import (
    ActionSpec,
    EffectClass,
    Idempotency,
    NetworkAccess,
    PluginCapabilities,
    PluginManifest,
)
from aegis.roles.generation import GenerationBundle, RoleGeneration

from .git_checkpoint import CHECKPOINT_ACTION

_PLUGIN_ID = "aegis.inprocess/git-checkpoint"
_PLUGIN_VERSION = "1.0.0"
_RUNTIME_IMAGE = "aegis-inprocess@sha256:" + "0" * 64
_ZERO_DIGEST = "0" * 64
_ENTRYPOINT = ("aegis-connector", "git-checkpoint", "v1")

_INPUT_SCHEMA: Mapping[str, JsonValue] = {
    "type": "object",
    "additionalProperties": False,
    "required": ("base_commit", "message", "changes"),
    "properties": {
        "base_commit": {"type": "string", "minLength": 40, "maxLength": 64, "pattern": "^[0-9a-f]{40}$"},
        "message": {"type": "string", "minLength": 1, "maxLength": 512},
        "changes": {
            "type": "array",
            "minItems": 1,
            "maxItems": 64,
            "uniqueItems": True,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ("path", "delete", "content_base64", "executable"),
                "properties": {
                    "path": {"type": "string", "minLength": 1, "maxLength": 512},
                    "delete": {"type": "boolean"},
                    "content_base64": {"type": "string", "minLength": 0, "maxLength": 1048576},
                    "executable": {"type": "boolean"},
                },
            },
        },
    },
}

_OUTPUT_SCHEMA: Mapping[str, JsonValue] = {
    "type": "object",
    "additionalProperties": False,
    "required": ("request_id", "new_commit", "ref"),
    "properties": {
        "request_id": {"type": "string", "minLength": 10, "maxLength": 200},
        "new_commit": {"type": "string", "minLength": 40, "maxLength": 64},
        "ref": {"type": "string", "minLength": 1, "maxLength": 256},
    },
}


__all__ = [
    "CHECKPOINT_ACTION",
    "build_checkpoint_plugin",
    "checkpoint_generation",
]


def checkpoint_action_spec() -> ActionSpec:
    return ActionSpec(
        name=CHECKPOINT_ACTION,
        input_schema=_INPUT_SCHEMA,
        output_schema=_OUTPUT_SCHEMA,
        effect=EffectClass.EXTERNAL,
        idempotency=Idempotency.IDEMPOTENT,
        requires_operation_id=True,
        max_input_bytes=1024 * 1024,
        max_output_bytes=256 * 1024,
        timeout_seconds=300.0,
    )


def build_checkpoint_plugin(*, provenance_sha256: str | None = None) -> PluginManifest:
    """Return the immutable manifest; roles cannot alter its capability grants."""
    if provenance_sha256 is None:
        from pathlib import Path

        source = Path(__file__).with_name("git_checkpoint.py").read_bytes()
        provenance_sha256 = hashlib.sha256(source).hexdigest()
    capabilities = PluginCapabilities(
        network=NetworkAccess.BROKERED_PUBLIC,
        workspace=(),
        secret_names=(),
        max_pids=1,
    )
    return PluginManifest.create(
        plugin_id=_PLUGIN_ID,
        version=_PLUGIN_VERSION,
        abi_version=1,
        image_digest=_RUNTIME_IMAGE,
        entrypoint=_ENTRYPOINT,
        roles=(Role.WARRIOR,),
        actions=(checkpoint_action_spec(),),
        capabilities=capabilities,
        provenance_sha256=provenance_sha256,
    )


def _role_generation(role: Role, *, plugin_artifact_id: str | None) -> RoleGeneration:
    return RoleGeneration(
        role=role,
        model_profile_sha256=_ZERO_DIGEST,
        workflow_artifact_id="sha256:" + _ZERO_DIGEST,
        subject_artifact_id="sha256:" + _ZERO_DIGEST,
        runtime_image=_RUNTIME_IMAGE,
        plugin_artifact_ids=(plugin_artifact_id,) if plugin_artifact_id is not None else (),
        budget_policy_sha256=_ZERO_DIGEST,
    )


def checkpoint_generation(*, source_commit: str, parent_generation_id: str | None = None) -> GenerationBundle:
    """Pin the checkpoint plugin to the Warrior for one immutable generation."""
    manifest = build_checkpoint_plugin()
    return GenerationBundle.create(
        parent_generation_id=parent_generation_id,
        controller_abi=2,
        source_commit=source_commit,
        roles=(
            _role_generation(Role.WARRIOR, plugin_artifact_id=manifest.artifact_id),
            _role_generation(Role.JUDGE, plugin_artifact_id=None),
            _role_generation(Role.PROSECUTOR, plugin_artifact_id=None),
        ),
        evidence_manifest_sha256=manifest.compute_digest(),
    )
