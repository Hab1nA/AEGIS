"""Fail-closed manifest types for sandboxed out-of-process action plugins."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any, Mapping, cast

from aegis.models import JsonValue, Role, canonical_json, freeze_json, thaw_json

_SHA256 = re.compile(r"[0-9a-f]{64}")
_OCI_DIGEST = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}")
_PLUGIN_ID = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,126}[a-z0-9])?/[a-z0-9][a-z0-9_-]{0,63}")
_ACTION = re.compile(r"[a-z][a-z0-9_]{0,63}(?:\.[a-z][a-z0-9_]{0,63})+")
_ENTRY = re.compile(r"[^\x00\s]{1,1024}")
_SECRET = re.compile(r"[A-Z][A-Z0-9_]{0,127}")
_MAX_SOURCE_BYTES = 64 * 1024
_MAX_SOURCES = 8
_MAX_SOURCES_TOTAL_BYTES = 192 * 1024


def _digest(value: object, name: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _artifact_id(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise ValueError(f"{name} must be a sha256 content address")
    _digest(value.removeprefix("sha256:"), name)
    return value


def _safe_relative(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ValueError(f"{name} must be a safe POSIX relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"{name} must be a safe POSIX relative path")
    return value


def _strict_schema(value: object, name: str) -> Mapping[str, JsonValue]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{name} must be a JSON object")
    frozen = cast(Mapping[str, JsonValue], freeze_json(value, path=name))
    thawed = thaw_json(frozen)
    if (
        not isinstance(thawed, dict)
        or thawed.get("type") != "object"
        or thawed.get("additionalProperties") is not False
        or not isinstance(thawed.get("properties", {}), dict)
    ):
        raise ValueError(f"{name} must be a strict object JSON schema")
    if len(canonical_json(cast(Mapping[str, Any], thawed)).encode("utf-8")) > 64 * 1024:
        raise ValueError(f"{name} exceeds the schema size limit")
    return frozen


class EffectClass(StrEnum):
    PURE = "pure"
    WORKSPACE_READ = "workspace_read"
    WORKSPACE_WRITE = "workspace_write"
    EXTERNAL = "external"


class Idempotency(StrEnum):
    READ_ONLY = "read_only"
    IDEMPOTENT = "idempotent"
    NON_RETRYABLE = "non_retryable"


class NetworkAccess(StrEnum):
    NONE = "none"
    BROKERED_PUBLIC = "brokered_public"


class WorkspaceMode(StrEnum):
    READ_ONLY = "ro"
    READ_WRITE = "rw"


@dataclass(frozen=True, slots=True)
class WorkspaceGrant:
    path: str
    mode: WorkspaceMode
    recursive: bool = False

    def __post_init__(self) -> None:
        _safe_relative(self.path, "workspace grant path")
        if not isinstance(self.mode, WorkspaceMode):
            raise TypeError("workspace grant mode must be a WorkspaceMode")
        if not isinstance(self.recursive, bool):
            raise TypeError("workspace grant recursive must be a bool")

    def to_dict(self) -> dict[str, object]:
        return {"path": self.path, "mode": self.mode.value, "recursive": self.recursive}


@dataclass(frozen=True, slots=True)
class ActionSpec:
    name: str
    input_schema: Mapping[str, JsonValue]
    output_schema: Mapping[str, JsonValue]
    effect: EffectClass
    idempotency: Idempotency
    requires_operation_id: bool
    max_input_bytes: int = 64 * 1024
    max_output_bytes: int = 256 * 1024
    timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or _ACTION.fullmatch(self.name) is None:
            raise ValueError("action name must be a namespaced lowercase identifier")
        object.__setattr__(self, "input_schema", _strict_schema(self.input_schema, "input_schema"))
        object.__setattr__(self, "output_schema", _strict_schema(self.output_schema, "output_schema"))
        if not isinstance(self.effect, EffectClass) or not isinstance(self.idempotency, Idempotency):
            raise TypeError("effect and idempotency must use their enum types")
        if not isinstance(self.requires_operation_id, bool):
            raise TypeError("requires_operation_id must be a bool")
        if self.effect in {EffectClass.PURE, EffectClass.WORKSPACE_READ} and self.idempotency is not Idempotency.READ_ONLY:
            raise ValueError("pure and workspace-read actions must be read-only")
        if self.effect is EffectClass.WORKSPACE_WRITE and self.idempotency is Idempotency.READ_ONLY:
            raise ValueError("workspace-write actions cannot claim read-only idempotency")
        if self.idempotency is not Idempotency.READ_ONLY and not self.requires_operation_id:
            raise ValueError("mutating actions require an operation id")
        for field_name, maximum in (("max_input_bytes", 1024 * 1024), ("max_output_bytes", 4 * 1024 * 1024)):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
                raise ValueError(f"{field_name} is outside the safe range")
        if isinstance(self.timeout_seconds, bool) or not isinstance(self.timeout_seconds, (int, float)):
            raise TypeError("timeout_seconds must be numeric")
        if not 0 < float(self.timeout_seconds) <= 300:
            raise ValueError("timeout_seconds is outside the safe range")
        object.__setattr__(self, "timeout_seconds", float(self.timeout_seconds))

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "input_schema": thaw_json(self.input_schema),
            "output_schema": thaw_json(self.output_schema),
            "effect": self.effect.value,
            "idempotency": self.idempotency.value,
            "requires_operation_id": self.requires_operation_id,
            "max_input_bytes": self.max_input_bytes,
            "max_output_bytes": self.max_output_bytes,
            "timeout_seconds": self.timeout_seconds,
        }


@dataclass(frozen=True, slots=True)
class PluginCapabilities:
    network: NetworkAccess
    workspace: tuple[WorkspaceGrant, ...] = ()
    secret_names: tuple[str, ...] = ()
    max_memory_bytes: int = 512 * 1024 * 1024
    max_pids: int = 64

    def __post_init__(self) -> None:
        if not isinstance(self.network, NetworkAccess):
            raise TypeError("network must be a NetworkAccess")
        if not isinstance(self.workspace, tuple) or any(not isinstance(item, WorkspaceGrant) for item in self.workspace):
            raise TypeError("workspace must be a tuple of WorkspaceGrant values")
        keys = tuple((item.path, item.mode.value, item.recursive) for item in self.workspace)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("workspace grants must be unique and canonically sorted")
        if not isinstance(self.secret_names, tuple) or any(
            not isinstance(item, str) or _SECRET.fullmatch(item) is None for item in self.secret_names
        ):
            raise ValueError("secret_names must contain canonical secret references")
        if self.secret_names != tuple(sorted(set(self.secret_names))):
            raise ValueError("secret_names must be unique and canonically sorted")
        if (
            isinstance(self.max_memory_bytes, bool)
            or not isinstance(self.max_memory_bytes, int)
            or not 16 * 1024 * 1024 <= self.max_memory_bytes <= 4 * 1024 * 1024 * 1024
        ):
            raise ValueError("max_memory_bytes is outside the safe range")
        if isinstance(self.max_pids, bool) or not isinstance(self.max_pids, int) or not 1 <= self.max_pids <= 512:
            raise ValueError("max_pids is outside the safe range")

    def to_dict(self) -> dict[str, object]:
        return {
            "network": self.network.value,
            "workspace": [item.to_dict() for item in self.workspace],
            "secret_names": list(self.secret_names),
            "max_memory_bytes": self.max_memory_bytes,
            "max_pids": self.max_pids,
        }


@dataclass(frozen=True, slots=True)
class PluginSource:
    """One Python source file embedded in a source-driven plugin manifest.

    Source plugins carry their code inside the content-addressed manifest so
    the manifest digest covers the code itself; the executor stages these
    files into the sandbox and dispatches declared actions to them.
    """

    path: str
    content_base64: str
    content_sha256: str

    def __post_init__(self) -> None:
        _safe_relative(self.path, "plugin source path")
        if not self.path.endswith(".py"):
            raise ValueError("plugin source path must end with .py")
        if not isinstance(self.content_base64, str):
            raise TypeError("plugin source content_base64 must be a string")
        try:
            content = base64.b64decode(self.content_base64.encode("ascii"), validate=True)
        except (ValueError, UnicodeEncodeError, binascii.Error) as exc:
            raise ValueError("plugin source content_base64 is invalid") from exc
        if not content:
            raise ValueError("plugin source content must not be empty")
        if len(content) > _MAX_SOURCE_BYTES:
            raise ValueError("plugin source content exceeds the 64KiB per-file limit")
        _digest(self.content_sha256, "plugin source content_sha256")
        if self.content_sha256 != hashlib.sha256(content).hexdigest():
            raise ValueError("plugin source content_sha256 does not match its content")

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "content_base64": self.content_base64,
            "content_sha256": self.content_sha256,
        }


@dataclass(frozen=True, slots=True)
class PluginManifest:
    artifact_id: str
    plugin_id: str
    version: str
    abi_version: int
    image_digest: str
    entrypoint: tuple[str, ...]
    roles: tuple[Role, ...]
    actions: tuple[ActionSpec, ...]
    capabilities: PluginCapabilities
    provenance_sha256: str
    sources: tuple[PluginSource, ...] = ()

    def __post_init__(self) -> None:
        _artifact_id(self.artifact_id, "artifact_id")
        if not isinstance(self.plugin_id, str) or _PLUGIN_ID.fullmatch(self.plugin_id) is None:
            raise ValueError("plugin_id must be a canonical reverse-domain/name identifier")
        if not isinstance(self.version, str) or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", self.version) is None:
            raise ValueError("version must use strict major.minor.patch syntax")
        if isinstance(self.abi_version, bool) or not isinstance(self.abi_version, int) or not 1 <= self.abi_version <= 1000:
            raise ValueError("abi_version must be a positive bounded integer")
        if not isinstance(self.image_digest, str):
            raise ValueError("image_digest must be a string")
        if self.sources:
            if self.image_digest != "":
                raise ValueError("source plugins must leave image_digest empty")
        elif _OCI_DIGEST.fullmatch(self.image_digest) is None:
            raise ValueError("image_digest must be pinned by sha256")
        if len(self.sources) > _MAX_SOURCES:
            raise ValueError("source plugins may declare at most 8 source files")
        if len({item.path for item in self.sources}) != len(self.sources):
            raise ValueError("plugin source paths must be unique")
        if (
            sum(
                len(base64.b64decode(item.content_base64.encode("ascii"), validate=True))
                for item in self.sources
            )
            > _MAX_SOURCES_TOTAL_BYTES
        ):
            raise ValueError("plugin sources exceed the 192KiB total size limit")
        if not isinstance(self.entrypoint, tuple) or not 1 <= len(self.entrypoint) <= 32 or any(
            not isinstance(item, str) or _ENTRY.fullmatch(item) is None for item in self.entrypoint
        ):
            raise ValueError("entrypoint must be a bounded argv tuple")
        if self.sources:
            if len(self.entrypoint) != 2 or self.entrypoint[0] != "python3":
                raise ValueError(
                    "source plugins must use entrypoint ('python3', '<source path>')"
                )
            if self.entrypoint[1] not in {item.path for item in self.sources}:
                raise ValueError("source plugin entrypoint must name a declared source file")
        if not isinstance(self.roles, tuple) or not self.roles or any(not isinstance(item, Role) for item in self.roles):
            raise TypeError("roles must be a non-empty tuple of Role values")
        if self.roles != tuple(role for role in Role if role in self.roles):
            raise ValueError("roles must be unique and canonically ordered")
        if not isinstance(self.actions, tuple) or not self.actions or any(not isinstance(item, ActionSpec) for item in self.actions):
            raise TypeError("actions must be a non-empty tuple of ActionSpec values")
        if tuple(item.name for item in self.actions) != tuple(sorted({item.name for item in self.actions})):
            raise ValueError("actions must be unique and canonically sorted")
        if not isinstance(self.capabilities, PluginCapabilities):
            raise TypeError("capabilities must be PluginCapabilities")
        _digest(self.provenance_sha256, "provenance_sha256")
        if self.artifact_id != "sha256:" + self.compute_digest():
            raise ValueError("artifact_id does not match plugin manifest content")

    def _identity_payload(self) -> dict[str, object]:
        return {
            "plugin_id": self.plugin_id,
            "version": self.version,
            "abi_version": self.abi_version,
            "image_digest": self.image_digest,
            "entrypoint": list(self.entrypoint),
            "roles": [role.value for role in self.roles],
            "actions": [item.to_dict() for item in self.actions],
            "capabilities": self.capabilities.to_dict(),
            "provenance_sha256": self.provenance_sha256,
            "sources": [item.to_dict() for item in self.sources],
        }

    def compute_digest(self) -> str:
        return hashlib.sha256(canonical_json(self._identity_payload()).encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, object]:
        return {"artifact_id": self.artifact_id, **self._identity_payload()}

    @classmethod
    def create(cls, **values: Any) -> PluginManifest:
        payload = {
            "plugin_id": values["plugin_id"],
            "version": values["version"],
            "abi_version": values["abi_version"],
            "image_digest": values["image_digest"],
            "entrypoint": list(values["entrypoint"]),
            "roles": [role.value for role in values["roles"]],
            "actions": [item.to_dict() for item in values["actions"]],
            "capabilities": values["capabilities"].to_dict(),
            "provenance_sha256": values["provenance_sha256"],
            "sources": [
                item.to_dict() if isinstance(item, PluginSource) else dict(item)
                for item in values.get("sources", ())
            ],
        }
        digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
        create_values = dict(values)
        create_values["sources"] = tuple(
            item if isinstance(item, PluginSource) else PluginSource(**item)
            for item in create_values.get("sources", ())
        )
        return cls(artifact_id="sha256:" + digest, **create_values)


@dataclass(frozen=True, slots=True)
class PluginPolicy:
    allowed_abi_versions: frozenset[int] = frozenset({1})
    allowed_effects: frozenset[EffectClass] = frozenset(
        {EffectClass.PURE, EffectClass.WORKSPACE_READ, EffectClass.WORKSPACE_WRITE}
    )
    allow_brokered_public_network: bool = False
    allowed_secret_names: frozenset[str] = frozenset()
    max_actions: int = 32

    def __post_init__(self) -> None:
        if not self.allowed_abi_versions or any(
            isinstance(item, bool) or not isinstance(item, int) or item < 1 for item in self.allowed_abi_versions
        ):
            raise ValueError("allowed_abi_versions must contain positive integers")
        if any(not isinstance(item, EffectClass) for item in self.allowed_effects):
            raise TypeError("allowed_effects must contain EffectClass values")
        if not isinstance(self.allow_brokered_public_network, bool):
            raise TypeError("allow_brokered_public_network must be a bool")
        if any(_SECRET.fullmatch(item) is None for item in self.allowed_secret_names):
            raise ValueError("allowed_secret_names contains an invalid reference")
        if isinstance(self.max_actions, bool) or not isinstance(self.max_actions, int) or not 1 <= self.max_actions <= 128:
            raise ValueError("max_actions is outside the safe range")


def validate_plugin_manifest(manifest: PluginManifest, policy: PluginPolicy = PluginPolicy()) -> PluginManifest:
    """Apply aggregate capability policy after structural manifest validation."""
    if not isinstance(manifest, PluginManifest) or not isinstance(policy, PluginPolicy):
        raise TypeError("manifest and policy must use plugin ABI types")
    if manifest.abi_version not in policy.allowed_abi_versions:
        raise ValueError("plugin ABI version is not allowed")
    if len(manifest.actions) > policy.max_actions:
        raise ValueError("plugin action count exceeds policy")
    effects = {item.effect for item in manifest.actions}
    if not effects <= policy.allowed_effects:
        raise ValueError("plugin requests a forbidden effect class")
    writable = any(item.mode is WorkspaceMode.READ_WRITE for item in manifest.capabilities.workspace)
    if (EffectClass.WORKSPACE_WRITE in effects) != writable:
        raise ValueError("workspace-write actions and writable grants must agree")
    workspace_effect = bool(effects & {EffectClass.WORKSPACE_READ, EffectClass.WORKSPACE_WRITE})
    if workspace_effect != bool(manifest.capabilities.workspace):
        raise ValueError("workspace effects and workspace grants must agree")
    external = EffectClass.EXTERNAL in effects
    if external != (manifest.capabilities.network is NetworkAccess.BROKERED_PUBLIC):
        raise ValueError("external actions require brokered public network and no other action may request it")
    if manifest.capabilities.network is NetworkAccess.BROKERED_PUBLIC and not policy.allow_brokered_public_network:
        raise ValueError("brokered public network is disabled by policy")
    if not set(manifest.capabilities.secret_names) <= policy.allowed_secret_names:
        raise ValueError("plugin requests an unapproved secret reference")
    return manifest
