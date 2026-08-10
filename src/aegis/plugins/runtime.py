"""Non-evolvable, fail-closed broker for out-of-process action plugins.

The broker never imports plugin code.  Executors and external connectors are
control-plane dependencies and all values crossing those boundaries are
revalidated as untrusted JSON.
"""

from __future__ import annotations

import hashlib
import math
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Mapping, Protocol, cast

from aegis.models import JsonValue, Role, canonical_json, freeze_json, thaw_json
from aegis.roles import GenerationBundle

from .abi import ActionSpec, EffectClass, PluginManifest, PluginPolicy, validate_plugin_manifest

_CONTENT_ADDRESS = re.compile(r"sha256:[0-9a-f]{64}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_OPERATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_CONNECTOR_ID = re.compile(r"[a-z][a-z0-9_.-]{0,63}")
_NONCE = re.compile(r"[0-9a-f]{32,128}")


class PluginRuntimeError(RuntimeError):
    """Base class for broker denials and untrusted execution failures."""


class CapabilityDenied(PluginRuntimeError):
    """The request is not authorized by the pinned generation and manifest."""


class MalformedPluginResult(PluginRuntimeError):
    """An executor or connector returned an invalid boundary object."""


class PluginExecutionError(PluginRuntimeError):
    """An authorized action failed or exceeded its deadline."""


def _content_address(value: object, name: str) -> str:
    if not isinstance(value, str) or _CONTENT_ADDRESS.fullmatch(value) is None:
        raise ValueError(f"{name} must be a sha256 content address")
    return value


def _digest(value: object, name: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _operation_id(value: object, *, required: bool) -> str | None:
    if value is None:
        if required:
            raise ValueError("operation_id is required for this action")
        return None
    if not isinstance(value, str) or _OPERATION_ID.fullmatch(value) is None:
        raise ValueError("operation_id must be a canonical bounded identifier")
    if not required:
        raise ValueError("read-only actions must not carry an operation_id")
    return value


def _strict_mapping(value: object, fields: set[str], name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields or any(not isinstance(key, str) for key in value):
        raise MalformedPluginResult(f"{name} has missing or unknown fields")
    return cast(Mapping[str, object], value)


def _json_object(value: object, name: str) -> Mapping[str, JsonValue]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{name} must be a JSON object")
    return cast(Mapping[str, JsonValue], freeze_json(value, path=name))


def _json_bytes(value: Mapping[str, JsonValue]) -> bytes:
    return canonical_json(cast(Mapping[str, Any], value)).encode("utf-8")


def _identity(payload: Mapping[str, object]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _safe_path(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ValueError(f"{name} must be a safe POSIX relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"{name} must be a safe POSIX relative path")
    return value


@dataclass(frozen=True, slots=True)
class CapabilityGrant:
    grant_id: str
    generation_id: str
    plugin_artifact_id: str
    role: Role
    action: str
    effect: EffectClass
    operation_id: str | None
    timeout_seconds: float
    nonce: str

    def __post_init__(self) -> None:
        _content_address(self.grant_id, "grant_id")
        _content_address(self.generation_id, "generation_id")
        _content_address(self.plugin_artifact_id, "plugin_artifact_id")
        if not isinstance(self.role, Role) or not isinstance(self.effect, EffectClass):
            raise TypeError("grant role and effect must use their enum types")
        if not isinstance(self.action, str) or not self.action:
            raise ValueError("grant action must be non-empty")
        _operation_id(self.operation_id, required=self.effect not in {EffectClass.PURE, EffectClass.WORKSPACE_READ})
        if isinstance(self.timeout_seconds, bool) or not isinstance(self.timeout_seconds, (int, float)):
            raise TypeError("timeout_seconds must be numeric")
        if not math.isfinite(float(self.timeout_seconds)) or not 0 < float(self.timeout_seconds) <= 300:
            raise ValueError("timeout_seconds is outside the safe range")
        object.__setattr__(self, "timeout_seconds", float(self.timeout_seconds))
        if not isinstance(self.nonce, str) or _NONCE.fullmatch(self.nonce) is None:
            raise ValueError("grant nonce must be bounded lowercase hexadecimal")
        if self.grant_id != _identity(self._identity_payload()):
            raise ValueError("grant_id does not match grant content")

    def _identity_payload(self) -> dict[str, object]:
        return {
            "generation_id": self.generation_id,
            "plugin_artifact_id": self.plugin_artifact_id,
            "role": self.role.value,
            "action": self.action,
            "effect": self.effect.value,
            "operation_id": self.operation_id,
            "timeout_seconds": self.timeout_seconds,
            "nonce": self.nonce,
        }

    def to_dict(self) -> dict[str, object]:
        return {"grant_id": self.grant_id, **self._identity_payload()}

    @classmethod
    def create(cls, **values: Any) -> CapabilityGrant:
        payload = {
            "generation_id": values["generation_id"],
            "plugin_artifact_id": values["plugin_artifact_id"],
            "role": values["role"].value,
            "action": values["action"],
            "effect": values["effect"].value,
            "operation_id": values["operation_id"],
            "timeout_seconds": float(values["timeout_seconds"]),
            "nonce": values["nonce"],
        }
        return cls(grant_id=_identity(payload), **values)


@dataclass(frozen=True, slots=True)
class ActionRequest:
    request_id: str
    grant_id: str
    generation_id: str
    plugin_artifact_id: str
    role: Role
    action: str
    effect: EffectClass
    operation_id: str | None
    timeout_seconds: float
    arguments: Mapping[str, JsonValue]

    def __post_init__(self) -> None:
        for name in ("request_id", "grant_id", "generation_id", "plugin_artifact_id"):
            _content_address(getattr(self, name), name)
        if not isinstance(self.role, Role) or not isinstance(self.effect, EffectClass):
            raise TypeError("request role and effect must use their enum types")
        if not isinstance(self.action, str) or not self.action:
            raise ValueError("request action must be non-empty")
        _operation_id(self.operation_id, required=self.effect not in {EffectClass.PURE, EffectClass.WORKSPACE_READ})
        if isinstance(self.timeout_seconds, bool) or not isinstance(self.timeout_seconds, (int, float)):
            raise TypeError("timeout_seconds must be numeric")
        if not math.isfinite(float(self.timeout_seconds)) or not 0 < float(self.timeout_seconds) <= 300:
            raise ValueError("timeout_seconds is outside the safe range")
        object.__setattr__(self, "timeout_seconds", float(self.timeout_seconds))
        object.__setattr__(self, "arguments", _json_object(self.arguments, "arguments"))
        if self.request_id != _identity(self._identity_payload()):
            raise ValueError("request_id does not match request content")

    def _identity_payload(self) -> dict[str, object]:
        return {
            "grant_id": self.grant_id,
            "generation_id": self.generation_id,
            "plugin_artifact_id": self.plugin_artifact_id,
            "role": self.role.value,
            "action": self.action,
            "effect": self.effect.value,
            "operation_id": self.operation_id,
            "timeout_seconds": self.timeout_seconds,
            "arguments": thaw_json(self.arguments),
        }

    def to_dict(self) -> dict[str, object]:
        return {"request_id": self.request_id, **self._identity_payload()}

    @classmethod
    def create(cls, grant: CapabilityGrant, arguments: Mapping[str, JsonValue]) -> ActionRequest:
        frozen = _json_object(arguments, "arguments")
        payload = {
            "grant_id": grant.grant_id,
            "generation_id": grant.generation_id,
            "plugin_artifact_id": grant.plugin_artifact_id,
            "role": grant.role.value,
            "action": grant.action,
            "effect": grant.effect.value,
            "operation_id": grant.operation_id,
            "timeout_seconds": grant.timeout_seconds,
            "arguments": thaw_json(frozen),
        }
        return cls(
            request_id=_identity(payload),
            grant_id=grant.grant_id,
            generation_id=grant.generation_id,
            plugin_artifact_id=grant.plugin_artifact_id,
            role=grant.role,
            action=grant.action,
            effect=grant.effect,
            operation_id=grant.operation_id,
            timeout_seconds=grant.timeout_seconds,
            arguments=frozen,
        )


@dataclass(frozen=True, slots=True)
class WorkspaceDiffReceipt:
    diff_receipt_id: str
    request_id: str
    before_sha256: str
    after_sha256: str
    diff_sha256: str
    changed_paths: tuple[str, ...]

    def __post_init__(self) -> None:
        _content_address(self.diff_receipt_id, "diff_receipt_id")
        _content_address(self.request_id, "request_id")
        for name in ("before_sha256", "after_sha256", "diff_sha256"):
            _digest(getattr(self, name), name)
        if self.before_sha256 == self.after_sha256:
            raise ValueError("workspace write receipt must change the workspace digest")
        if not isinstance(self.changed_paths, tuple) or not self.changed_paths:
            raise ValueError("workspace write receipt must list changed paths")
        for path in self.changed_paths:
            _safe_path(path, "changed path")
        if self.changed_paths != tuple(sorted(set(self.changed_paths))):
            raise ValueError("changed paths must be unique and canonically sorted")
        if self.diff_receipt_id != _identity(self._identity_payload()):
            raise ValueError("diff_receipt_id does not match receipt content")

    def _identity_payload(self) -> dict[str, object]:
        return {
            "request_id": self.request_id,
            "before_sha256": self.before_sha256,
            "after_sha256": self.after_sha256,
            "diff_sha256": self.diff_sha256,
            "changed_paths": list(self.changed_paths),
        }

    def to_dict(self) -> dict[str, object]:
        return {"diff_receipt_id": self.diff_receipt_id, **self._identity_payload()}

    @classmethod
    def create(cls, **values: Any) -> WorkspaceDiffReceipt:
        payload = {
            "request_id": values["request_id"],
            "before_sha256": values["before_sha256"],
            "after_sha256": values["after_sha256"],
            "diff_sha256": values["diff_sha256"],
            "changed_paths": list(values["changed_paths"]),
        }
        return cls(diff_receipt_id=_identity(payload), **values)

    @classmethod
    def from_mapping(cls, value: object) -> WorkspaceDiffReceipt:
        data = _strict_mapping(
            value,
            {"diff_receipt_id", "request_id", "before_sha256", "after_sha256", "diff_sha256", "changed_paths"},
            "workspace diff receipt",
        )
        paths = data["changed_paths"]
        if not isinstance(paths, list) or any(not isinstance(path, str) for path in paths):
            raise MalformedPluginResult("changed_paths must be an array of strings")
        try:
            return cls(
                diff_receipt_id=cast(str, data["diff_receipt_id"]),
                request_id=cast(str, data["request_id"]),
                before_sha256=cast(str, data["before_sha256"]),
                after_sha256=cast(str, data["after_sha256"]),
                diff_sha256=cast(str, data["diff_sha256"]),
                changed_paths=tuple(paths),
            )
        except (TypeError, ValueError) as exc:
            raise MalformedPluginResult("invalid workspace diff receipt") from exc


@dataclass(frozen=True, slots=True)
class ExternalIntent:
    intent_id: str
    request_id: str
    connector_id: str
    operation_id: str

    def __post_init__(self) -> None:
        _content_address(self.intent_id, "intent_id")
        _content_address(self.request_id, "request_id")
        if not isinstance(self.connector_id, str) or _CONNECTOR_ID.fullmatch(self.connector_id) is None:
            raise ValueError("connector_id must be a canonical identifier")
        if _operation_id(self.operation_id, required=True) is None:
            raise AssertionError("unreachable")
        if self.intent_id != _identity(self._identity_payload()):
            raise ValueError("intent_id does not match intent content")

    def _identity_payload(self) -> dict[str, object]:
        return {
            "request_id": self.request_id,
            "connector_id": self.connector_id,
            "operation_id": self.operation_id,
        }

    def to_dict(self) -> dict[str, object]:
        return {"intent_id": self.intent_id, **self._identity_payload()}

    @classmethod
    def create(cls, *, request_id: str, connector_id: str, operation_id: str) -> ExternalIntent:
        payload = {"request_id": request_id, "connector_id": connector_id, "operation_id": operation_id}
        return cls(intent_id=_identity(payload), **payload)


@dataclass(frozen=True, slots=True)
class ExternalEffectReceipt:
    external_receipt_id: str
    intent_id: str
    request_id: str
    connector_id: str
    operation_id: str
    output_sha256: str
    remote_receipt_sha256: str

    def __post_init__(self) -> None:
        for name in ("external_receipt_id", "intent_id", "request_id"):
            _content_address(getattr(self, name), name)
        if not isinstance(self.connector_id, str) or _CONNECTOR_ID.fullmatch(self.connector_id) is None:
            raise ValueError("connector_id must be a canonical identifier")
        if _operation_id(self.operation_id, required=True) is None:
            raise AssertionError("unreachable")
        _digest(self.output_sha256, "output_sha256")
        _digest(self.remote_receipt_sha256, "remote_receipt_sha256")
        if self.external_receipt_id != _identity(self._identity_payload()):
            raise ValueError("external_receipt_id does not match receipt content")

    def _identity_payload(self) -> dict[str, object]:
        return {
            "intent_id": self.intent_id,
            "request_id": self.request_id,
            "connector_id": self.connector_id,
            "operation_id": self.operation_id,
            "output_sha256": self.output_sha256,
            "remote_receipt_sha256": self.remote_receipt_sha256,
        }

    def to_dict(self) -> dict[str, object]:
        return {"external_receipt_id": self.external_receipt_id, **self._identity_payload()}

    @classmethod
    def create(cls, **values: Any) -> ExternalEffectReceipt:
        payload = dict(values)
        return cls(external_receipt_id=_identity(payload), **values)

    @classmethod
    def from_mapping(cls, value: object) -> ExternalEffectReceipt:
        fields = {
            "external_receipt_id",
            "intent_id",
            "request_id",
            "connector_id",
            "operation_id",
            "output_sha256",
            "remote_receipt_sha256",
        }
        data = _strict_mapping(value, fields, "external effect receipt")
        try:
            return cls(**cast(Any, dict(data)))
        except (TypeError, ValueError) as exc:
            raise MalformedPluginResult("invalid external effect receipt") from exc


@dataclass(frozen=True, slots=True)
class ActionReceipt:
    receipt_id: str
    request_id: str
    grant_id: str
    generation_id: str
    plugin_artifact_id: str
    role: Role
    action: str
    effect: EffectClass
    operation_id: str | None
    output: Mapping[str, JsonValue]
    elapsed_seconds: float
    diff_receipt_id: str | None = None
    intent_id: str | None = None
    external_receipt_id: str | None = None

    def __post_init__(self) -> None:
        for name in ("receipt_id", "request_id", "grant_id", "generation_id", "plugin_artifact_id"):
            _content_address(getattr(self, name), name)
        if not isinstance(self.role, Role) or not isinstance(self.effect, EffectClass):
            raise TypeError("receipt role and effect must use their enum types")
        _operation_id(self.operation_id, required=self.effect not in {EffectClass.PURE, EffectClass.WORKSPACE_READ})
        object.__setattr__(self, "output", _json_object(self.output, "output"))
        if isinstance(self.elapsed_seconds, bool) or not isinstance(self.elapsed_seconds, (int, float)):
            raise TypeError("elapsed_seconds must be numeric")
        if not math.isfinite(float(self.elapsed_seconds)) or float(self.elapsed_seconds) < 0:
            raise ValueError("elapsed_seconds must be finite and non-negative")
        object.__setattr__(self, "elapsed_seconds", float(self.elapsed_seconds))
        evidence = (self.diff_receipt_id, self.intent_id, self.external_receipt_id)
        for index, value in enumerate(evidence):
            if value is not None:
                _content_address(value, ("diff_receipt_id", "intent_id", "external_receipt_id")[index])
        if self.effect is EffectClass.WORKSPACE_WRITE:
            if self.diff_receipt_id is None or self.intent_id is not None or self.external_receipt_id is not None:
                raise ValueError("workspace-write receipt requires only diff evidence")
        elif self.effect is EffectClass.EXTERNAL:
            if self.diff_receipt_id is not None or self.intent_id is None or self.external_receipt_id is None:
                raise ValueError("external receipt requires intent and connector evidence")
        elif any(value is not None for value in evidence):
            raise ValueError("read-only receipt must not carry side-effect evidence")
        if self.receipt_id != _identity(self._identity_payload()):
            raise ValueError("receipt_id does not match receipt content")

    def _identity_payload(self) -> dict[str, object]:
        return {
            "request_id": self.request_id,
            "grant_id": self.grant_id,
            "generation_id": self.generation_id,
            "plugin_artifact_id": self.plugin_artifact_id,
            "role": self.role.value,
            "action": self.action,
            "effect": self.effect.value,
            "operation_id": self.operation_id,
            "output": thaw_json(self.output),
            "elapsed_seconds": self.elapsed_seconds,
            "diff_receipt_id": self.diff_receipt_id,
            "intent_id": self.intent_id,
            "external_receipt_id": self.external_receipt_id,
        }

    def to_dict(self) -> dict[str, object]:
        return {"receipt_id": self.receipt_id, **self._identity_payload()}

    @classmethod
    def create(cls, **values: Any) -> ActionReceipt:
        payload = {
            **values,
            "role": values["role"].value,
            "effect": values["effect"].value,
            "output": thaw_json(_json_object(values["output"], "output")),
            "elapsed_seconds": float(values["elapsed_seconds"]),
        }
        return cls(receipt_id=_identity(payload), **values)


class PluginExecutor(Protocol):
    def execute(self, manifest: PluginManifest, grant: CapabilityGrant, request: ActionRequest) -> object: ...


class ExternalConnector(Protocol):
    @property
    def connector_id(self) -> str: ...

    def execute(
        self,
        manifest: PluginManifest,
        grant: CapabilityGrant,
        request: ActionRequest,
        intent: ExternalIntent,
    ) -> object: ...


class ExternalJournal(Protocol):
    def record_intent(self, intent: ExternalIntent) -> None: ...

    def record_receipt(self, receipt: ExternalEffectReceipt) -> None: ...


def _validate_instance(value: JsonValue, schema: Mapping[str, JsonValue], path: str = "$") -> None:
    raw = thaw_json(schema)
    if not isinstance(raw, dict):
        raise CapabilityDenied("action schema is not an object")
    common = {"type", "enum", "const", "title", "description"}
    schema_type = raw.get("type")
    type_keywords: dict[str, set[str]] = {
        "object": {"properties", "required", "additionalProperties", "minProperties", "maxProperties"},
        "array": {"items", "minItems", "maxItems", "uniqueItems"},
        "string": {"minLength", "maxLength", "pattern"},
        "integer": {"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"},
        "number": {"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"},
        "boolean": set(),
        "null": set(),
    }
    if not isinstance(schema_type, str) or schema_type not in type_keywords:
        raise CapabilityDenied(f"unsupported schema type at {path}")
    unknown = set(raw) - common - type_keywords[schema_type]
    if unknown:
        raise CapabilityDenied(f"unsupported schema keyword at {path}: {sorted(unknown)[0]}")
    if "enum" in raw and (not isinstance(raw["enum"], list) or value not in raw["enum"]):
        raise CapabilityDenied(f"value at {path} is outside enum")
    if "const" in raw and value != raw["const"]:
        raise CapabilityDenied(f"value at {path} does not match const")

    if schema_type == "object":
        if not isinstance(value, Mapping):
            raise CapabilityDenied(f"value at {path} must be an object")
        properties = raw.get("properties", {})
        required = raw.get("required", [])
        additional = raw.get("additionalProperties")
        if not isinstance(properties, dict) or not isinstance(required, list) or any(not isinstance(x, str) for x in required):
            raise CapabilityDenied(f"invalid object schema at {path}")
        if additional is not False:
            raise CapabilityDenied(f"object schema at {path} must reject additional properties")
        if not set(required) <= set(properties) or len(set(required)) != len(required):
            raise CapabilityDenied(f"invalid required properties at {path}")
        if not set(value) <= set(properties) or not set(required) <= set(value):
            raise CapabilityDenied(f"object properties at {path} do not match schema")
        size = len(value)
        _bounded_size(size, raw, "Properties", path)
        for key, item in value.items():
            child = properties[key]
            if not isinstance(child, dict):
                raise CapabilityDenied(f"invalid property schema at {path}.{key}")
            _validate_instance(item, cast(Mapping[str, JsonValue], freeze_json(child)), f"{path}.{key}")
        return
    if schema_type == "array":
        if not isinstance(value, tuple):
            raise CapabilityDenied(f"value at {path} must be an array")
        items = raw.get("items")
        if not isinstance(items, dict):
            raise CapabilityDenied(f"array schema at {path} must define items")
        _bounded_size(len(value), raw, "Items", path)
        if raw.get("uniqueItems", False) and len({repr(item) for item in value}) != len(value):
            raise CapabilityDenied(f"array at {path} must contain unique items")
        for index, item in enumerate(value):
            _validate_instance(item, cast(Mapping[str, JsonValue], freeze_json(items)), f"{path}[{index}]")
        return
    if schema_type == "string":
        if not isinstance(value, str):
            raise CapabilityDenied(f"value at {path} must be a string")
        _bounded_size(len(value), raw, "Length", path)
        pattern = raw.get("pattern")
        if pattern is not None:
            if not isinstance(pattern, str):
                raise CapabilityDenied(f"invalid string pattern at {path}")
            try:
                matched = re.search(pattern, value) is not None
            except re.error as exc:
                raise CapabilityDenied(f"invalid string pattern at {path}") from exc
            if not matched:
                raise CapabilityDenied(f"string at {path} does not match pattern")
        return
    if schema_type == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            raise CapabilityDenied(f"value at {path} must be an integer")
        _validate_number(float(value), raw, path)
        return
    if schema_type == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
            raise CapabilityDenied(f"value at {path} must be a finite number")
        _validate_number(float(value), raw, path)
        return
    if schema_type == "boolean" and not isinstance(value, bool):
        raise CapabilityDenied(f"value at {path} must be a boolean")
    if schema_type == "null" and value is not None:
        raise CapabilityDenied(f"value at {path} must be null")


def _bounded_size(size: int, schema: Mapping[str, object], suffix: str, path: str) -> None:
    minimum = schema.get("min" + suffix)
    maximum = schema.get("max" + suffix)
    if minimum is not None and (isinstance(minimum, bool) or not isinstance(minimum, int) or size < minimum):
        raise CapabilityDenied(f"value at {path} is below its minimum size")
    if maximum is not None and (isinstance(maximum, bool) or not isinstance(maximum, int) or size > maximum):
        raise CapabilityDenied(f"value at {path} exceeds its maximum size")


def _validate_number(value: float, schema: Mapping[str, object], path: str) -> None:
    for keyword in ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"):
        bound = schema.get(keyword)
        if bound is not None:
            if isinstance(bound, bool) or not isinstance(bound, (int, float)) or not math.isfinite(float(bound)):
                raise CapabilityDenied(f"invalid numeric bound at {path}")
            numeric = float(bound)
            allowed = (
                (keyword == "minimum" and value >= numeric)
                or (keyword == "maximum" and value <= numeric)
                or (keyword == "exclusiveMinimum" and value > numeric)
                or (keyword == "exclusiveMaximum" and value < numeric)
            )
            if not allowed:
                raise CapabilityDenied(f"number at {path} violates {keyword}")


class ToolBroker:
    """Authorize and mediate one-shot action calls for a pinned generation."""

    def __init__(
        self,
        generation: GenerationBundle,
        manifests: tuple[PluginManifest, ...],
        executor: PluginExecutor,
        *,
        policy: PluginPolicy = PluginPolicy(),
        external_connector: ExternalConnector | None = None,
        external_journal: ExternalJournal | None = None,
        nonce_factory: Callable[[], str] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if not isinstance(generation, GenerationBundle):
            raise TypeError("generation must be a GenerationBundle")
        if not isinstance(manifests, tuple) or any(not isinstance(item, PluginManifest) for item in manifests):
            raise TypeError("manifests must be a tuple of PluginManifest values")
        if len({item.artifact_id for item in manifests}) != len(manifests):
            raise ValueError("plugin manifests must have unique artifact ids")
        referenced = {plugin for role in generation.roles for plugin in role.plugin_artifact_ids}
        supplied = {item.artifact_id for item in manifests}
        if supplied != referenced:
            raise ValueError("plugin manifests must exactly match the generation bundle")
        for manifest in manifests:
            validate_plugin_manifest(manifest, policy)
            for spec in manifest.actions:
                mutating = spec.effect in {EffectClass.WORKSPACE_WRITE, EffectClass.EXTERNAL}
                if spec.requires_operation_id != mutating:
                    raise ValueError("action operation-id contract does not match its effect class")
            for role in generation.roles:
                if manifest.artifact_id in role.plugin_artifact_ids and role.role not in manifest.roles:
                    raise ValueError("generation assigns a plugin to a role not allowed by its manifest")
        if (external_connector is None) != (external_journal is None):
            raise ValueError("external connector and journal must be configured together")
        if external_connector is not None and _CONNECTOR_ID.fullmatch(external_connector.connector_id) is None:
            raise ValueError("external connector has an invalid connector_id")
        self._generation = generation
        self._manifests = {item.artifact_id: item for item in manifests}
        self._executor = executor
        self._external_connector = external_connector
        self._external_journal = external_journal
        self._nonce_factory = nonce_factory or (lambda: secrets.token_hex(32))
        self._monotonic = monotonic
        self._issued: dict[str, CapabilityGrant] = {}
        self._consumed: set[str] = set()

    @property
    def generation_id(self) -> str:
        return self._generation.generation_id

    @property
    def plugin_artifact_ids(self) -> frozenset[str]:
        return frozenset(self._manifests)

    def role_plugin_artifact_ids(self, role: Role) -> frozenset[str]:
        if not isinstance(role, Role):
            raise TypeError("role must be a Role")
        role_generation = next(item for item in self._generation.roles if item.role is role)
        return frozenset(role_generation.plugin_artifact_ids)

    def issue_grant(
        self,
        role: Role,
        plugin_artifact_id: str,
        action: str,
        *,
        operation_id: str | None = None,
        timeout_seconds: float | None = None,
    ) -> CapabilityGrant:
        manifest, spec = self._resolve(role, plugin_artifact_id, action)
        if spec.effect is EffectClass.EXTERNAL and (
            self._external_connector is None or self._external_journal is None
        ):
            raise CapabilityDenied("external action has no dedicated connector and journal")
        operation_id = _operation_id(operation_id, required=spec.requires_operation_id)
        timeout = spec.timeout_seconds if timeout_seconds is None else timeout_seconds
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < float(timeout) <= spec.timeout_seconds:
            raise CapabilityDenied("requested timeout exceeds the action limit")
        nonce = self._nonce_factory()
        grant = CapabilityGrant.create(
            generation_id=self._generation.generation_id,
            plugin_artifact_id=manifest.artifact_id,
            role=role,
            action=spec.name,
            effect=spec.effect,
            operation_id=operation_id,
            timeout_seconds=float(timeout),
            nonce=nonce,
        )
        if grant.grant_id in self._issued:
            raise CapabilityDenied("grant nonce was reused")
        self._issued[grant.grant_id] = grant
        return grant

    def create_request(self, grant: CapabilityGrant, arguments: Mapping[str, JsonValue]) -> ActionRequest:
        self._known_unconsumed_grant(grant)
        _, spec = self._resolve(grant.role, grant.plugin_artifact_id, grant.action)
        frozen = _json_object(arguments, "arguments")
        if len(_json_bytes(frozen)) > spec.max_input_bytes:
            raise CapabilityDenied("action input exceeds max_input_bytes")
        _validate_instance(cast(JsonValue, frozen), spec.input_schema)
        return ActionRequest.create(grant, frozen)

    def execute(self, request: ActionRequest) -> ActionReceipt:
        if not isinstance(request, ActionRequest):
            raise TypeError("request must be an ActionRequest")
        grant = self._issued.get(request.grant_id)
        if grant is None or request.grant_id in self._consumed:
            raise CapabilityDenied("grant is unknown or already consumed")
        if not self._request_matches_grant(request, grant):
            raise CapabilityDenied("request does not match its capability grant")
        manifest, spec = self._resolve(request.role, request.plugin_artifact_id, request.action)
        if request.timeout_seconds != grant.timeout_seconds or request.timeout_seconds > spec.timeout_seconds:
            raise CapabilityDenied("request timeout does not match its grant")
        if len(_json_bytes(request.arguments)) > spec.max_input_bytes:
            raise CapabilityDenied("action input exceeds max_input_bytes")
        _validate_instance(cast(JsonValue, request.arguments), spec.input_schema)

        # Consume before crossing the trust boundary.  Failure never restores it.
        self._consumed.add(grant.grant_id)
        start = self._monotonic()
        intent: ExternalIntent | None = None
        try:
            if spec.effect is EffectClass.EXTERNAL:
                raw, intent = self._execute_external(manifest, grant, request)
            else:
                raw = self._executor.execute(manifest, grant, request)
        except PluginRuntimeError:
            raise
        except Exception as exc:
            raise PluginExecutionError("action boundary raised an exception") from exc
        wall_elapsed = self._monotonic() - start
        output, reported_elapsed, timed_out, diff, external = self._parse_execution(raw)
        elapsed = max(wall_elapsed, reported_elapsed)
        if timed_out or elapsed > request.timeout_seconds:
            raise PluginExecutionError("action exceeded its timeout")
        if len(_json_bytes(output)) > spec.max_output_bytes:
            raise MalformedPluginResult("action output exceeds max_output_bytes")
        _validate_instance(cast(JsonValue, output), spec.output_schema)

        if spec.effect is EffectClass.WORKSPACE_WRITE:
            if diff is None or diff.request_id != request.request_id or external is not None:
                raise MalformedPluginResult("workspace write requires a matching diff receipt")
            if not self._diff_within_writable_grants(diff, manifest):
                raise MalformedPluginResult("workspace diff contains a path outside writable grants")
        elif spec.effect is EffectClass.EXTERNAL:
            if diff is not None or intent is None or external is None:
                raise MalformedPluginResult("external action requires matching intent and receipt")
            self._validate_external_receipt(external, intent, request, output)
            assert self._external_journal is not None
            try:
                self._external_journal.record_receipt(external)
            except Exception as exc:
                raise PluginExecutionError("external receipt could not be journaled") from exc
        elif diff is not None or external is not None:
            raise MalformedPluginResult("read-only action returned side-effect evidence")

        return ActionReceipt.create(
            request_id=request.request_id,
            grant_id=grant.grant_id,
            generation_id=request.generation_id,
            plugin_artifact_id=manifest.artifact_id,
            role=request.role,
            action=spec.name,
            effect=spec.effect,
            operation_id=request.operation_id,
            output=output,
            elapsed_seconds=elapsed,
            diff_receipt_id=diff.diff_receipt_id if diff else None,
            intent_id=intent.intent_id if intent else None,
            external_receipt_id=external.external_receipt_id if external else None,
        )

    def _execute_external(
        self, manifest: PluginManifest, grant: CapabilityGrant, request: ActionRequest
    ) -> tuple[object, ExternalIntent]:
        if self._external_connector is None or self._external_journal is None or request.operation_id is None:
            raise CapabilityDenied("external action has no dedicated connector and journal")
        intent = ExternalIntent.create(
            request_id=request.request_id,
            connector_id=self._external_connector.connector_id,
            operation_id=request.operation_id,
        )
        try:
            self._external_journal.record_intent(intent)
        except Exception as exc:
            raise PluginExecutionError("external intent could not be journaled") from exc
        return self._external_connector.execute(manifest, grant, request, intent), intent

    def _parse_execution(
        self, value: object
    ) -> tuple[
        Mapping[str, JsonValue],
        float,
        bool,
        WorkspaceDiffReceipt | None,
        ExternalEffectReceipt | None,
    ]:
        data = _strict_mapping(
            value,
            {"output", "elapsed_seconds", "timed_out", "workspace_diff", "external_receipt"},
            "execution result",
        )
        try:
            output = _json_object(data["output"], "output")
        except (TypeError, ValueError) as exc:
            raise MalformedPluginResult("execution output is not strict JSON") from exc
        elapsed = data["elapsed_seconds"]
        if isinstance(elapsed, bool) or not isinstance(elapsed, (int, float)) or not math.isfinite(float(elapsed)) or elapsed < 0:
            raise MalformedPluginResult("elapsed_seconds must be finite and non-negative")
        timed_out = data["timed_out"]
        if not isinstance(timed_out, bool):
            raise MalformedPluginResult("timed_out must be a bool")
        diff_raw = data["workspace_diff"]
        external_raw = data["external_receipt"]
        diff = None if diff_raw is None else WorkspaceDiffReceipt.from_mapping(diff_raw)
        external = None if external_raw is None else ExternalEffectReceipt.from_mapping(external_raw)
        return output, float(elapsed), timed_out, diff, external

    def _resolve(self, role: Role, plugin_artifact_id: str, action: str) -> tuple[PluginManifest, ActionSpec]:
        if not isinstance(role, Role):
            raise CapabilityDenied("role is invalid")
        role_generation = next(item for item in self._generation.roles if item.role is role)
        if plugin_artifact_id not in role_generation.plugin_artifact_ids:
            raise CapabilityDenied("plugin is not pinned for this role and generation")
        manifest = self._manifests.get(plugin_artifact_id)
        if manifest is None or role not in manifest.roles:
            raise CapabilityDenied("plugin manifest does not authorize this role")
        spec = next((item for item in manifest.actions if item.name == action), None)
        if spec is None:
            raise CapabilityDenied("action is not declared by the plugin manifest")
        return manifest, spec

    def _known_unconsumed_grant(self, grant: CapabilityGrant) -> None:
        if not isinstance(grant, CapabilityGrant):
            raise TypeError("grant must be a CapabilityGrant")
        if self._issued.get(grant.grant_id) != grant or grant.grant_id in self._consumed:
            raise CapabilityDenied("grant is unknown or already consumed")

    @staticmethod
    def _request_matches_grant(request: ActionRequest, grant: CapabilityGrant) -> bool:
        return (
            request.grant_id == grant.grant_id
            and request.generation_id == grant.generation_id
            and request.plugin_artifact_id == grant.plugin_artifact_id
            and request.role is grant.role
            and request.action == grant.action
            and request.effect is grant.effect
            and request.operation_id == grant.operation_id
        )

    @staticmethod
    def _validate_external_receipt(
        receipt: ExternalEffectReceipt,
        intent: ExternalIntent,
        request: ActionRequest,
        output: Mapping[str, JsonValue],
    ) -> None:
        output_digest = hashlib.sha256(_json_bytes(output)).hexdigest()
        if (
            receipt.intent_id != intent.intent_id
            or receipt.request_id != request.request_id
            or receipt.connector_id != intent.connector_id
            or receipt.operation_id != request.operation_id
            or receipt.output_sha256 != output_digest
        ):
            raise MalformedPluginResult("external receipt does not match intent, request, and output")

    @staticmethod
    def _diff_within_writable_grants(receipt: WorkspaceDiffReceipt, manifest: PluginManifest) -> bool:
        writable = tuple(item for item in manifest.capabilities.workspace if item.mode.value == "rw")
        for changed in receipt.changed_paths:
            path = PurePosixPath(changed)
            covered = any(
                path == PurePosixPath(grant.path)
                or (grant.recursive and PurePosixPath(grant.path) in path.parents)
                for grant in writable
            )
            if not covered:
                return False
        return True
