"""Explicit evolvable-surface contract for the AEGIS v2 loop.

Every surface has a strict JSON shape, a grant rule (which role may propose
it), and a content validator.  Candidate content is materialized into the
content-addressed artifact store before it is allowed to enter the evolution
registry, and it is always consumed as untrusted data.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from aegis.environments.models import (
    BuilderNetworkPolicy,
    BuildStep,
    DependencyArtifact,
    DependencyKind,
    EnvironmentRecipe,
)
from aegis.models import Role
from aegis.plugins.abi import (
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

SURFACE_SCHEMA_VERSION = 2

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_OCI_DIGEST = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}\Z")
_PLUGIN_ID = re.compile(r"[a-z][a-z0-9-]{0,63}-sha256:[0-9a-f]{64}\Z")


class EvolutionSurface(StrEnum):
    WORKFLOW = "workflow"
    SUBJECT = "subject"
    PLUGIN = "plugin"
    ENVIRONMENT = "environment"


class EvolutionSurfaceError(RuntimeError):
    """Raised when an untrusted evolution proposal violates the contract."""


def _text(value: object, name: str, *, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value.encode("utf-8")) > maximum
    ):
        raise EvolutionSurfaceError(f"{name} must be bounded, non-empty, trimmed text")
    return value


def _strict_object(
    value: object,
    expected: set[str],
    name: str,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise EvolutionSurfaceError(f"{name} must be a string-keyed object")
    if set(value) != expected:
        raise EvolutionSurfaceError(f"{name} has missing or unknown fields")
    return value


def _string_list(value: object, name: str, *, maximum: int = 16) -> tuple[str, ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= maximum:
        raise EvolutionSurfaceError(f"{name} must be a list of 1..{maximum} items")
    items: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item or item != item.strip():
            raise EvolutionSurfaceError(f"{name}[{index}] must be trimmed non-empty text")
        if len(item.encode("utf-8")) > 2000:
            raise EvolutionSurfaceError(f"{name}[{index}] exceeds 2000 UTF-8 bytes")
        items.append(item)
    return tuple(items)


def validate_workflow_content(value: object) -> Mapping[str, Any]:
    """Validate a structured workflow artifact with the same shape as the
    runtime's ``WORKFLOW_ARTIFACT_SCHEMA``."""
    data = _strict_object(
        value,
        {
            "stage_plan",
            "research_query_templates",
            "tool_selection_rules",
            "stop_conditions",
            "verification_checklist",
            "skill_references",
            "max_steps",
        },
        "workflow",
    )
    payload: dict[str, Any] = {
        "stage_plan": _string_list(data["stage_plan"], "workflow.stage_plan"),
        "research_query_templates": _string_list(
            data["research_query_templates"], "workflow.research_query_templates"
        ),
        "tool_selection_rules": _string_list(
            data["tool_selection_rules"], "workflow.tool_selection_rules"
        ),
        "stop_conditions": _string_list(
            data["stop_conditions"], "workflow.stop_conditions"
        ),
        "verification_checklist": _string_list(
            data["verification_checklist"], "workflow.verification_checklist"
        ),
        "skill_references": _string_list(
            data["skill_references"], "workflow.skill_references"
        ),
    }
    raw_steps = data["max_steps"]
    if raw_steps is not None:
        if (
            isinstance(raw_steps, bool)
            or not isinstance(raw_steps, int)
            or not 1 <= raw_steps <= 1000
        ):
            raise EvolutionSurfaceError("workflow.max_steps must be null or an integer in [1,1000]")
    payload["max_steps"] = raw_steps
    return payload


MAX_SUBJECT_MARKDOWN_BYTES = 16 * 1024
MAX_SUBJECT_RATIONALE_BYTES = 2 * 1024


def validate_subject_content(value: object) -> Mapping[str, Any]:
    """Validate a bounded, advisory role subject artifact."""
    data = _strict_object(
        value,
        {"content_markdown", "rationale"},
        "subject",
    )
    markdown = _text(
        data["content_markdown"],
        "subject.content_markdown",
        maximum=MAX_SUBJECT_MARKDOWN_BYTES,
    )
    rationale = _text(
        data["rationale"],
        "subject.rationale",
        maximum=MAX_SUBJECT_RATIONALE_BYTES,
    )
    return {"content_markdown": markdown, "rationale": rationale}


PLUGIN_ALLOWED_EFFECTS = frozenset(
    {EffectClass.PURE, EffectClass.WORKSPACE_READ, EffectClass.WORKSPACE_WRITE}
)


def validate_plugin_content(
    value: object, *, target_role: Role
) -> PluginManifest:
    """Validate a plugin manifest and bind it to one role slot.

    Plugin candidates are sandbox-executed tools only: they may not declare
    EXTERNAL effects, install permissions, or require a network.
    """
    if not isinstance(value, Mapping):
        raise EvolutionSurfaceError("plugin content must be an object")
    try:
        manifest = _plugin_manifest_from_mapping(value)
    except (TypeError, ValueError) as exc:
        raise EvolutionSurfaceError(f"plugin manifest is invalid: {exc}") from exc
    if target_role.value not in manifest.roles:
        raise EvolutionSurfaceError("plugin manifest does not grant the target role")
    for spec in manifest.actions:
        if spec.effect not in PLUGIN_ALLOWED_EFFECTS:
            raise EvolutionSurfaceError(
                f"plugin action {spec.name} has a forbidden effect {spec.effect.value}"
            )
    policy = PluginPolicy(allowed_effects=PLUGIN_ALLOWED_EFFECTS)
    try:
        validate_plugin_manifest(manifest, policy)
    except (TypeError, ValueError) as exc:
        raise EvolutionSurfaceError(f"plugin manifest failed policy validation: {exc}") from exc
    return manifest


def _plugin_manifest_from_mapping(value: Mapping[str, Any]) -> PluginManifest:
    expected = {
        "plugin_id",
        "version",
        "abi_version",
        "image_digest",
        "entrypoint",
        "roles",
        "actions",
        "capabilities",
        "provenance_sha256",
    }
    if set(value) not in (expected, expected | {"artifact_id"}):
        raise ValueError("plugin manifest has missing or unknown fields")
    roles = tuple(Role(item) for item in value["roles"])
    actions: list[ActionSpec] = []
    for raw in value["actions"]:
        actions.append(
            ActionSpec(
                name=raw["name"],
                input_schema=raw["input_schema"],
                output_schema=raw["output_schema"],
                effect=EffectClass(raw["effect"]),
                idempotency=Idempotency(raw["idempotency"]),
                requires_operation_id=raw["requires_operation_id"],
                max_input_bytes=raw.get("max_input_bytes", 64 * 1024),
                max_output_bytes=raw.get("max_output_bytes", 256 * 1024),
                timeout_seconds=raw.get("timeout_seconds", 30.0),
            )
        )
    capabilities_raw = value["capabilities"]
    capabilities = PluginCapabilities(
        network=NetworkAccess(capabilities_raw["network"]),
        workspace=tuple(
            WorkspaceGrant(
                path=item["path"],
                mode=WorkspaceMode(item["mode"]),
                recursive=item["recursive"],
            )
            for item in capabilities_raw.get("workspace", ())
        ),
        secret_names=tuple(capabilities_raw.get("secret_names", ())),
        max_memory_bytes=capabilities_raw.get("max_memory_bytes", 512 * 1024 * 1024),
        max_pids=capabilities_raw.get("max_pids", 64),
    )
    manifest = PluginManifest.create(
        plugin_id=value["plugin_id"],
        version=value["version"],
        abi_version=value["abi_version"],
        image_digest=value["image_digest"],
        entrypoint=tuple(value["entrypoint"]),
        roles=roles,
        actions=tuple(actions),
        capabilities=capabilities,
        provenance_sha256=value["provenance_sha256"],
    )
    declared = value.get("artifact_id")
    if declared is not None:
        if not isinstance(declared, str) or declared != "sha256:" + manifest.compute_digest():
            raise ValueError("artifact_id does not match plugin manifest content")
    return manifest


def validate_environment_content(value: object) -> EnvironmentRecipe:
    """Validate an environment recipe.

    Only pinned parent images and either offline or brokered-public recipes are
    accepted; dependencies are always digest-pinned HTTPS artifacts.
    """
    if not isinstance(value, Mapping):
        raise EvolutionSurfaceError("environment content must be an object")
    try:
        recipe = _environment_recipe_from_mapping(value)
    except (TypeError, ValueError) as exc:
        raise EvolutionSurfaceError(f"environment recipe is invalid: {exc}") from exc
    if _OCI_DIGEST.fullmatch(recipe.parent_image) is None:
        raise EvolutionSurfaceError("environment parent_image must be digest-pinned")
    if recipe.network_policy is BuilderNetworkPolicy.OFFLINE and recipe.dependencies:
        raise EvolutionSurfaceError("offline environment recipes cannot request dependencies")
    return recipe


def _environment_recipe_from_mapping(value: Mapping[str, Any]) -> EnvironmentRecipe:
    dependencies = tuple(
        DependencyArtifact(
            name=item["name"],
            version=item["version"],
            kind=DependencyKind(item["kind"]),
            source_url=item["source_url"],
            sha256=item["sha256"],
        )
        for item in value["dependencies"]
    )
    build_steps = tuple(
        BuildStep(
            argv=tuple(item["argv"]),
            cwd=item.get("cwd", "."),
            timeout_seconds=item.get("timeout_seconds", 300.0),
        )
        for item in value["build_steps"]
    )
    recipe = EnvironmentRecipe.create(
        parent_image=value["parent_image"],
        network_policy=BuilderNetworkPolicy(value["network_policy"]),
        dependencies=dependencies,
        build_steps=build_steps,
        max_output_bytes=value["max_output_bytes"],
    )
    declared = value.get("recipe_id")
    if declared is not None and declared != recipe.recipe_id:
        raise ValueError("recipe_id does not match recipe content")
    return recipe


def validate_surface_content(
    surface: EvolutionSurface, value: object, *, target_role: Role
) -> Mapping[str, Any] | PluginManifest | EnvironmentRecipe:
    if surface is EvolutionSurface.WORKFLOW:
        return validate_workflow_content(value)
    if surface is EvolutionSurface.SUBJECT:
        return validate_subject_content(value)
    if surface is EvolutionSurface.PLUGIN:
        return validate_plugin_content(value, target_role=target_role)
    if surface is EvolutionSurface.ENVIRONMENT:
        return validate_environment_content(value)
    raise AssertionError("unreachable")


def _surface_from_text(value: object) -> EvolutionSurface:
    if not isinstance(value, str):
        raise EvolutionSurfaceError("proposal surface must be text")
    try:
        return EvolutionSurface(value)
    except ValueError as exc:
        raise EvolutionSurfaceError("proposal surface is not one of the evolvable surfaces") from exc


def _role_from_text(value: object, name: str) -> Role:
    if not isinstance(value, str):
        raise EvolutionSurfaceError(f"{name} must be text")
    try:
        return Role(value)
    except ValueError as exc:
        raise EvolutionSurfaceError(f"{name} is not a valid role") from exc


@dataclass(frozen=True, slots=True)
class EvolutionProposal:
    surface: EvolutionSurface
    target_role: Role
    content: Mapping[str, Any] | PluginManifest | EnvironmentRecipe

    def content_to_json(self) -> Mapping[str, Any]:
        if isinstance(self.content, PluginManifest):
            return self.content.to_dict()
        if isinstance(self.content, EnvironmentRecipe):
            return self.content.to_dict()
        return dict(self.content)


def validate_evolution_proposal(
    value: object, *, proposer: Role
) -> EvolutionProposal:
    """Validate one untrusted ``evolution.request`` proposal envelope."""
    data = _strict_object(
        value,
        {"surface", "target_role", "content"},
        "evolution proposal",
    )
    surface = _surface_from_text(data["surface"])
    target_role = _role_from_text(data["target_role"], "proposal.target_role")
    if proposer is not Role.WARRIOR:
        raise EvolutionSurfaceError(
            "only the Warrior may submit evolution.request proposals"
        )
    if surface is EvolutionSurface.PLUGIN and target_role is not Role.WARRIOR:
        raise EvolutionSurfaceError("plugin proposals may only target the Warrior")
    if surface is EvolutionSurface.ENVIRONMENT and target_role is not Role.WARRIOR:
        raise EvolutionSurfaceError("environment proposals may only target the Warrior")
    if surface is EvolutionSurface.SUBJECT and target_role is not Role.WARRIOR:
        raise EvolutionSurfaceError("subject proposals may only target the Warrior")
    if surface is EvolutionSurface.WORKFLOW and target_role is not proposer:
        raise EvolutionSurfaceError(
            "workflow proposals through evolution.request may only target the proposer"
        )
    content = validate_surface_content(surface, data["content"], target_role=target_role)
    return EvolutionProposal(surface, target_role, content)


EVOLUTION_PROTOCOL_SCHEMA: Mapping[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["surface", "target_role", "content"],
    "properties": {
        "surface": {"type": "string", "enum": [item.value for item in EvolutionSurface]},
        "target_role": {"type": "string", "enum": [role.value for role in Role]},
        "content": {"type": "object"},
    },
}


def canonical_artifact_digest(kind: str, payload: Mapping[str, Any]) -> str:
    """Return the canonical sha256 digest of surface artifact JSON."""
    from aegis.models import canonical_json

    return canonical_json(payload)


def content_digest(kind: str, payload: Mapping[str, Any]) -> str:
    """Return the typed content address for a surface artifact."""
    import hashlib

    from aegis.models import canonical_json

    digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    return f"{kind}-sha256:{digest}"


__all__ = [
    "EVOLUTION_PROTOCOL_SCHEMA",
    "MAX_SUBJECT_MARKDOWN_BYTES",
    "MAX_SUBJECT_RATIONALE_BYTES",
    "PLUGIN_ALLOWED_EFFECTS",
    "SURFACE_SCHEMA_VERSION",
    "EvolutionProposal",
    "EvolutionSurface",
    "EvolutionSurfaceError",
    "content_digest",
    "validate_environment_content",
    "validate_evolution_proposal",
    "validate_plugin_content",
    "validate_subject_content",
    "validate_surface_content",
    "validate_workflow_content",
]
