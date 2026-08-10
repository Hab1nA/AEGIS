"""Isolated loader and strict JSON execution adapter for role generations."""

from __future__ import annotations

import hashlib
import json
import math
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Mapping, Protocol, cast

from aegis.models import JsonValue, Role, canonical_json, freeze_json, thaw_json
from aegis.plugins import EffectClass
from aegis.sandbox import CommandResult, CommandSpec, WorkspaceAccessRule
from aegis.sandbox.owned import OwnedSandboxBackend

from .generation import GenerationBundle, RoleGeneration

_CONTENT_ADDRESS = re.compile(r"sha256:[0-9a-f]{64}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_OCI_DIGEST = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}")
_SANDBOX_NONCE = re.compile(r"[a-z0-9]{16,48}")
_RUNNER = "/opt/aegis/bin/role-generation-runner"
_MAX_CONTEXT_BYTES = 128 * 1024
_MAX_RESULT_BYTES = 256 * 1024

DEFAULT_ROLE_OBJECTIVES: Mapping[Role, str] = {
    Role.WARRIOR: "Solve the assigned engineering task using only brokered capabilities and staged artifacts.",
    Role.JUDGE: "Evaluate the candidate result independently using only provided evidence; do not modify it.",
    Role.PROSECUTOR: "Audit claims and execution evidence for safety or integrity violations; do not modify them.",
}


class RoleGenerationRuntimeError(RuntimeError):
    """The generation could not be safely loaded, executed, attested, or destroyed."""


class RoleGenerationProtocolError(RoleGenerationRuntimeError):
    """The sandbox runner returned malformed or mismatched strict JSON."""


def _address(value: object, name: str) -> str:
    if not isinstance(value, str) or _CONTENT_ADDRESS.fullmatch(value) is None:
        raise ValueError(f"{name} must be a sha256 content address")
    return value


def _digest(value: object, name: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _identity(payload: Mapping[str, object]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _strict(value: object, fields: set[str], name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields or any(not isinstance(key, str) for key in value):
        raise RoleGenerationProtocolError(f"{name} has missing or unknown fields")
    return cast(Mapping[str, object], value)


def _json_object(value: object, name: str) -> Mapping[str, JsonValue]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{name} must be a JSON object")
    try:
        frozen = freeze_json(value, path=name)
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError(f"{name} must contain bounded strict JSON") from exc
    return cast(Mapping[str, JsonValue], frozen)


def _json_size(value: Mapping[str, JsonValue]) -> int:
    return len(canonical_json(cast(Mapping[str, Any], value)).encode("utf-8"))


@dataclass(frozen=True, slots=True)
class SandboxArtifactPackage:
    artifact_id: str
    kind: str
    archive_base64: str
    archive_sha256: str
    module_sha256: str

    def __post_init__(self) -> None:
        _address(self.artifact_id, "artifact_id")
        if self.kind not in {"subject", "workflow", "plugin"}:
            raise ValueError("artifact kind must be subject, workflow, or plugin")
        if not isinstance(self.archive_base64, str) or not self.archive_base64:
            raise ValueError("artifact archive_base64 must be non-empty")
        _digest(self.archive_sha256, "archive_sha256")
        _digest(self.module_sha256, "module_sha256")
        if self.module_sha256 != self.artifact_id.removeprefix("sha256:"):
            raise ValueError("artifact module digest must match its generation content address")


class GenerationArtifactStore(Protocol):
    def load(self, artifact_id: str, kind: str) -> SandboxArtifactPackage: ...


class OwnedSandboxFactory(Protocol):
    def create(self, runtime_image: str) -> OwnedSandboxBackend: ...


@dataclass(frozen=True, slots=True)
class BrokerRolePolicy:
    policy_sha256: str
    generation_id: str
    role: Role
    plugin_artifact_ids: tuple[str, ...]
    allowed_effects: tuple[EffectClass, ...]
    direct_plugin_execution: bool = False

    def __post_init__(self) -> None:
        _digest(self.policy_sha256, "policy_sha256")
        _address(self.generation_id, "generation_id")
        if not isinstance(self.role, Role):
            raise TypeError("broker policy role must be a Role")
        if not isinstance(self.plugin_artifact_ids, tuple):
            raise TypeError("broker policy plugin ids must be a tuple")
        for item in self.plugin_artifact_ids:
            _address(item, "plugin_artifact_id")
        if self.plugin_artifact_ids != tuple(sorted(set(self.plugin_artifact_ids))):
            raise ValueError("broker policy plugin ids must be unique and canonically sorted")
        canonical_effects = tuple(effect for effect in EffectClass if effect in self.allowed_effects)
        if (
            not isinstance(self.allowed_effects, tuple)
            or any(not isinstance(item, EffectClass) for item in self.allowed_effects)
            or self.allowed_effects != canonical_effects
        ):
            raise ValueError("broker policy effects must be unique and canonically ordered")
        if self.direct_plugin_execution is not False:
            raise ValueError("generation plugins must be executable only through the broker")
        if self.role in {Role.JUDGE, Role.PROSECUTOR} and not set(self.allowed_effects) <= {
            EffectClass.PURE,
            EffectClass.WORKSPACE_READ,
        }:
            raise ValueError("judge and prosecutor broker policy must remain read-only")
        if self.policy_sha256 != self.compute_digest():
            raise ValueError("policy_sha256 does not match broker policy content")

    def _identity_payload(self) -> dict[str, object]:
        return {
            "generation_id": self.generation_id,
            "role": self.role.value,
            "plugin_artifact_ids": list(self.plugin_artifact_ids),
            "allowed_effects": [item.value for item in self.allowed_effects],
            "direct_plugin_execution": self.direct_plugin_execution,
        }

    def compute_digest(self) -> str:
        return hashlib.sha256(canonical_json(self._identity_payload()).encode("utf-8")).hexdigest()

    @classmethod
    def create(
        cls,
        *,
        generation_id: str,
        role: Role,
        plugin_artifact_ids: tuple[str, ...],
        allowed_effects: tuple[EffectClass, ...],
    ) -> BrokerRolePolicy:
        payload = {
            "generation_id": generation_id,
            "role": role.value,
            "plugin_artifact_ids": list(plugin_artifact_ids),
            "allowed_effects": [item.value for item in allowed_effects],
            "direct_plugin_execution": False,
        }
        return cls(
            hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest(),
            generation_id,
            role,
            plugin_artifact_ids,
            allowed_effects,
        )

    def to_dict(self) -> dict[str, object]:
        return {"policy_sha256": self.policy_sha256, **self._identity_payload()}


@dataclass(frozen=True, slots=True)
class RoleExecutionRequest:
    request_id: str
    generation_id: str
    role: Role
    objective: str
    context: Mapping[str, JsonValue]
    runtime_image: str
    model_profile_sha256: str
    budget_policy_sha256: str
    subject_artifact_id: str
    workflow_artifact_id: str
    plugin_artifact_ids: tuple[str, ...]
    broker_policy_sha256: str

    def __post_init__(self) -> None:
        for name in ("request_id", "generation_id", "subject_artifact_id", "workflow_artifact_id"):
            _address(getattr(self, name), name)
        if not isinstance(self.role, Role):
            raise TypeError("request role must be a Role")
        if not isinstance(self.objective, str) or not self.objective or self.objective.strip() != self.objective:
            raise ValueError("objective must be bounded non-empty text")
        if len(self.objective.encode("utf-8")) > 4096:
            raise ValueError("objective exceeds the byte limit")
        object.__setattr__(self, "context", _json_object(self.context, "context"))
        if _json_size(self.context) > _MAX_CONTEXT_BYTES:
            raise ValueError("role context exceeds the byte limit")
        if not isinstance(self.runtime_image, str) or _OCI_DIGEST.fullmatch(self.runtime_image) is None:
            raise ValueError("runtime_image must be pinned by sha256")
        _digest(self.model_profile_sha256, "model_profile_sha256")
        _digest(self.budget_policy_sha256, "budget_policy_sha256")
        if not isinstance(self.plugin_artifact_ids, tuple):
            raise TypeError("plugin_artifact_ids must be a tuple")
        for item in self.plugin_artifact_ids:
            _address(item, "plugin_artifact_id")
        if self.plugin_artifact_ids != tuple(sorted(set(self.plugin_artifact_ids))):
            raise ValueError("plugin artifact ids must be unique and canonically sorted")
        _digest(self.broker_policy_sha256, "broker_policy_sha256")
        if self.request_id != _identity(self._identity_payload()):
            raise ValueError("request_id does not match role execution request content")

    def _identity_payload(self) -> dict[str, object]:
        return {
            "generation_id": self.generation_id,
            "role": self.role.value,
            "objective": self.objective,
            "context": thaw_json(self.context),
            "runtime_image": self.runtime_image,
            "model_profile_sha256": self.model_profile_sha256,
            "budget_policy_sha256": self.budget_policy_sha256,
            "subject_artifact_id": self.subject_artifact_id,
            "workflow_artifact_id": self.workflow_artifact_id,
            "plugin_artifact_ids": list(self.plugin_artifact_ids),
            "broker_policy_sha256": self.broker_policy_sha256,
        }

    @classmethod
    def create(
        cls,
        *,
        generation_id: str,
        role_generation: RoleGeneration,
        objective: str,
        context: Mapping[str, JsonValue],
        broker_policy_sha256: str,
    ) -> RoleExecutionRequest:
        frozen = _json_object(context, "context")
        payload = {
            "generation_id": generation_id,
            "role": role_generation.role.value,
            "objective": objective,
            "context": thaw_json(frozen),
            "runtime_image": role_generation.runtime_image,
            "model_profile_sha256": role_generation.model_profile_sha256,
            "budget_policy_sha256": role_generation.budget_policy_sha256,
            "subject_artifact_id": role_generation.subject_artifact_id,
            "workflow_artifact_id": role_generation.workflow_artifact_id,
            "plugin_artifact_ids": list(role_generation.plugin_artifact_ids),
            "broker_policy_sha256": broker_policy_sha256,
        }
        return cls(
            request_id=_identity(payload),
            generation_id=generation_id,
            role=role_generation.role,
            objective=objective,
            context=frozen,
            runtime_image=role_generation.runtime_image,
            model_profile_sha256=role_generation.model_profile_sha256,
            budget_policy_sha256=role_generation.budget_policy_sha256,
            subject_artifact_id=role_generation.subject_artifact_id,
            workflow_artifact_id=role_generation.workflow_artifact_id,
            plugin_artifact_ids=role_generation.plugin_artifact_ids,
            broker_policy_sha256=broker_policy_sha256,
        )

    def to_dict(self) -> dict[str, object]:
        return {"request_id": self.request_id, **self._identity_payload()}


@dataclass(frozen=True, slots=True)
class RoleExecutionReceipt:
    receipt_id: str
    request_id: str
    generation_id: str
    sandbox_id: str
    role: Role
    runtime_image: str
    model_profile_sha256: str
    budget_policy_sha256: str
    subject_module_sha256: str
    workflow_module_sha256: str
    plugin_module_sha256: tuple[str, ...]
    artifact_ids: tuple[str, ...]
    artifact_archive_sha256: tuple[str, ...]
    broker_policy_sha256: str
    result: Mapping[str, JsonValue]
    duration_seconds: float

    def __post_init__(self) -> None:
        for name in ("receipt_id", "request_id", "generation_id"):
            _address(getattr(self, name), name)
        if not isinstance(self.sandbox_id, str) or not self.sandbox_id:
            raise ValueError("sandbox_id must be non-empty")
        if not isinstance(self.role, Role):
            raise TypeError("receipt role must be a Role")
        if not isinstance(self.runtime_image, str) or _OCI_DIGEST.fullmatch(self.runtime_image) is None:
            raise ValueError("receipt runtime_image must be digest-pinned")
        for name in (
            "model_profile_sha256",
            "budget_policy_sha256",
            "subject_module_sha256",
            "workflow_module_sha256",
            "broker_policy_sha256",
        ):
            _digest(getattr(self, name), name)
        for values, name in (
            (self.plugin_module_sha256, "plugin_module_sha256"),
            (self.artifact_archive_sha256, "artifact_archive_sha256"),
        ):
            if not isinstance(values, tuple):
                raise TypeError(f"{name} must be a tuple")
            for value in values:
                _digest(value, name)
        if not isinstance(self.artifact_ids, tuple) or not self.artifact_ids:
            raise ValueError("artifact_ids must contain the staged generation artifacts")
        for artifact_id in self.artifact_ids:
            _address(artifact_id, "artifact_id")
        object.__setattr__(self, "result", _json_object(self.result, "result"))
        if _json_size(self.result) > _MAX_RESULT_BYTES:
            raise ValueError("role result exceeds the byte limit")
        if isinstance(self.duration_seconds, bool) or not isinstance(self.duration_seconds, (int, float)):
            raise TypeError("duration_seconds must be numeric")
        if not math.isfinite(float(self.duration_seconds)) or float(self.duration_seconds) < 0:
            raise ValueError("duration_seconds must be finite and non-negative")
        object.__setattr__(self, "duration_seconds", float(self.duration_seconds))
        if self.receipt_id != _identity(self._identity_payload()):
            raise ValueError("receipt_id does not match role execution receipt content")

    def _identity_payload(self) -> dict[str, object]:
        return {
            "request_id": self.request_id,
            "generation_id": self.generation_id,
            "sandbox_id": self.sandbox_id,
            "role": self.role.value,
            "runtime_image": self.runtime_image,
            "model_profile_sha256": self.model_profile_sha256,
            "budget_policy_sha256": self.budget_policy_sha256,
            "subject_module_sha256": self.subject_module_sha256,
            "workflow_module_sha256": self.workflow_module_sha256,
            "plugin_module_sha256": list(self.plugin_module_sha256),
            "artifact_ids": list(self.artifact_ids),
            "artifact_archive_sha256": list(self.artifact_archive_sha256),
            "broker_policy_sha256": self.broker_policy_sha256,
            "result": thaw_json(self.result),
            "duration_seconds": self.duration_seconds,
        }

    @classmethod
    def create(cls, **values: Any) -> RoleExecutionReceipt:
        payload = {
            **values,
            "role": values["role"].value,
            "plugin_module_sha256": list(values["plugin_module_sha256"]),
            "artifact_ids": list(values["artifact_ids"]),
            "artifact_archive_sha256": list(values["artifact_archive_sha256"]),
            "result": thaw_json(_json_object(values["result"], "result")),
            "duration_seconds": float(values["duration_seconds"]),
        }
        return cls(receipt_id=_identity(payload), **values)

    def to_dict(self) -> dict[str, object]:
        return {"receipt_id": self.receipt_id, **self._identity_payload()}


@dataclass(frozen=True, slots=True)
class _RunnerAttestation:
    sandbox_id: str
    generation_id: str
    role: Role
    runtime_image: str
    model_profile_sha256: str
    budget_policy_sha256: str
    subject_module_sha256: str
    workflow_module_sha256: str
    plugin_module_sha256: tuple[str, ...]
    artifact_ids: tuple[str, ...]
    broker_policy_sha256: str
    direct_plugin_execution: bool


class RoleGenerationRuntime:
    """Load and execute exactly one pinned role generation in a fresh sandbox."""

    def __init__(
        self,
        *,
        sandbox_factory: OwnedSandboxFactory,
        artifact_store: GenerationArtifactStore,
        objectives: Mapping[Role, str] = DEFAULT_ROLE_OBJECTIVES,
        nonce_factory: Callable[[], str] | None = None,
        runner_path: str = _RUNNER,
    ) -> None:
        if set(objectives) != set(Role):
            raise ValueError("objectives must define exactly one objective for every role")
        normalized: dict[Role, str] = {}
        for role, objective in objectives.items():
            if not isinstance(role, Role) or not isinstance(objective, str) or not objective.strip():
                raise ValueError("role objectives must be non-empty text")
            normalized[role] = objective.strip()
        if runner_path != _RUNNER:
            raise ValueError("role runner path is a fixed control-plane ABI")
        self._sandbox_factory = sandbox_factory
        self._artifact_store = artifact_store
        self._objectives = normalized
        self._nonce_factory = nonce_factory or (lambda: secrets.token_hex(12))
        self._sandbox_ids: set[str] = set()

    def execute(
        self,
        bundle: GenerationBundle,
        role: Role,
        context: Mapping[str, JsonValue],
        broker_policy: BrokerRolePolicy,
        *,
        timeout_seconds: float = 300,
    ) -> RoleExecutionReceipt:
        if not isinstance(bundle, GenerationBundle) or not isinstance(role, Role):
            raise TypeError("bundle and role must use generation model types")
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
            raise TypeError("timeout_seconds must be numeric")
        timeout = float(timeout_seconds)
        if not math.isfinite(timeout) or not 0 < timeout <= 3600:
            raise ValueError("timeout_seconds is outside the safe range")
        role_generation = next(item for item in bundle.roles if item.role is role)
        self._validate_broker_policy(bundle, role_generation, broker_policy)
        request = RoleExecutionRequest.create(
            generation_id=bundle.generation_id,
            role_generation=role_generation,
            objective=self._objectives[role],
            context=context,
            broker_policy_sha256=broker_policy.policy_sha256,
        )
        packages = self._load_packages(role_generation)
        nonce = self._nonce_factory()
        if not isinstance(nonce, str) or _SANDBOX_NONCE.fullmatch(nonce) is None:
            raise RoleGenerationRuntimeError("sandbox nonce factory returned an invalid value")
        sandbox_id = f"role-{role.value}-{nonce}"
        if sandbox_id in self._sandbox_ids:
            raise RoleGenerationRuntimeError("sandbox nonce was reused")
        self._sandbox_ids.add(sandbox_id)

        backend: OwnedSandboxBackend | None = None
        ownership_started = False
        cleaned = False
        receipt: RoleExecutionReceipt | None = None
        primary: BaseException | None = None
        try:
            candidate = self._sandbox_factory.create(role_generation.runtime_image)
            if not isinstance(candidate, OwnedSandboxBackend):
                raise RoleGenerationRuntimeError("sandbox factory must return an OwnedSandboxBackend")
            backend = candidate
            if not backend.doctor().passed:
                raise RoleGenerationRuntimeError("owned sandbox failed its security doctor")
            ownership_started = True
            prepared = backend.prepare(sandbox_id)
            if prepared.sandbox_id != sandbox_id:
                raise RoleGenerationProtocolError("prepared sandbox id does not match the request")
            staged_digests: list[str] = []
            for package in packages:
                staged = backend.stage_archive(sandbox_id, package.archive_base64, package.archive_sha256)
                if (
                    staged.sandbox_id != sandbox_id
                    or staged.digest != package.archive_sha256
                    or isinstance(staged.size_bytes, bool)
                    or not isinstance(staged.size_bytes, int)
                    or staged.size_bytes < 1
                    or isinstance(staged.entries, bool)
                    or not isinstance(staged.entries, int)
                    or staged.entries < 1
                ):
                    raise RoleGenerationProtocolError("staged artifact receipt does not match its package")
                staged_digests.append(staged.digest)
            backend.configure_workspace_access(sandbox_id, self._workspace_rules(role))
            command = CommandSpec(
                (_RUNNER, "--json-abi", "1"),
                env={"LANG": "C.UTF-8", "TZ": "UTC", "PYTHONHASHSEED": "0"},
                stdin=canonical_json(request.to_dict()) + "\n",
                timeout_seconds=timeout,
            )
            result = backend.exec(sandbox_id, command)
            if result.timed_out:
                backend.kill(sandbox_id)
                cleaned = True
                raise RoleGenerationRuntimeError("role generation execution timed out")
            receipt = self._receipt_from_result(
                result,
                request,
                role_generation,
                broker_policy,
                sandbox_id,
                tuple(staged_digests),
                timeout,
            )
        except BaseException as exc:
            primary = exc
        finally:
            if backend is not None and ownership_started and not cleaned:
                try:
                    backend.destroy(sandbox_id)
                    cleaned = True
                except BaseException as cleanup_exc:
                    primary = RoleGenerationRuntimeError("owned sandbox destruction failed")
                    primary.__cause__ = cleanup_exc
        if primary is not None:
            if isinstance(primary, RoleGenerationRuntimeError):
                raise primary
            raise RoleGenerationRuntimeError("role generation execution failed closed") from primary
        if receipt is None or not cleaned:
            raise RoleGenerationRuntimeError("role generation execution did not complete with cleanup")
        return receipt

    def _load_packages(self, role_generation: RoleGeneration) -> tuple[SandboxArtifactPackage, ...]:
        if len(role_generation.plugin_artifact_ids) > 32:
            raise RoleGenerationRuntimeError("role generation exceeds the plugin loading limit")
        requested = (
            (role_generation.subject_artifact_id, "subject"),
            (role_generation.workflow_artifact_id, "workflow"),
            *((artifact_id, "plugin") for artifact_id in role_generation.plugin_artifact_ids),
        )
        packages: list[SandboxArtifactPackage] = []
        for artifact_id, kind in requested:
            package = self._artifact_store.load(artifact_id, kind)
            if (
                not isinstance(package, SandboxArtifactPackage)
                or package.artifact_id != artifact_id
                or package.kind != kind
            ):
                raise RoleGenerationRuntimeError("artifact store returned a mismatched generation package")
            packages.append(package)
        return tuple(packages)

    @staticmethod
    def _workspace_rules(role: Role) -> tuple[WorkspaceAccessRule, ...]:
        if role is Role.WARRIOR:
            return (WorkspaceAccessRule("output", recursive=True),)
        return ()

    @staticmethod
    def _validate_broker_policy(
        bundle: GenerationBundle, role_generation: RoleGeneration, policy: BrokerRolePolicy
    ) -> None:
        if not isinstance(policy, BrokerRolePolicy):
            raise TypeError("broker_policy must be a BrokerRolePolicy")
        if (
            policy.generation_id != bundle.generation_id
            or policy.role is not role_generation.role
            or policy.plugin_artifact_ids != role_generation.plugin_artifact_ids
            or policy.direct_plugin_execution
        ):
            raise RoleGenerationRuntimeError("broker policy does not match the role generation")

    def _receipt_from_result(
        self,
        result: CommandResult,
        request: RoleExecutionRequest,
        role_generation: RoleGeneration,
        broker_policy: BrokerRolePolicy,
        sandbox_id: str,
        staged_digests: tuple[str, ...],
        timeout_seconds: float,
    ) -> RoleExecutionReceipt:
        if result.exit_code != 0:
            raise RoleGenerationRuntimeError("role runner returned a non-zero exit code")
        if (
            isinstance(result.duration_seconds, bool)
            or not isinstance(result.duration_seconds, (int, float))
            or not math.isfinite(float(result.duration_seconds))
            or result.duration_seconds < 0
        ):
            raise RoleGenerationProtocolError("runner duration is invalid")
        if float(result.duration_seconds) > timeout_seconds:
            raise RoleGenerationRuntimeError("role generation execution exceeded its timeout")
        if result.stderr:
            raise RoleGenerationProtocolError("role runner wrote to stderr")
        if len(result.stdout.encode("utf-8")) > _MAX_RESULT_BYTES + 32 * 1024:
            raise RoleGenerationProtocolError("role runner output exceeds the byte limit")
        try:
            raw = json.loads(
                result.stdout,
                object_pairs_hook=self._reject_duplicate_keys,
                parse_constant=self._reject_nonfinite,
            )
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RoleGenerationProtocolError("role runner output is not strict JSON") from exc
        envelope = _strict(raw, {"abi_version", "request_id", "status", "result", "attestation"}, "runner envelope")
        if envelope["abi_version"] != 1 or envelope["request_id"] != request.request_id or envelope["status"] != "ok":
            raise RoleGenerationProtocolError("runner envelope does not match the request ABI")
        output = _json_object(envelope["result"], "runner result")
        attestation = self._parse_attestation(envelope["attestation"])
        expected_artifacts = (
            role_generation.subject_artifact_id,
            role_generation.workflow_artifact_id,
            *role_generation.plugin_artifact_ids,
        )
        if (
            attestation.sandbox_id != sandbox_id
            or attestation.generation_id != request.generation_id
            or attestation.role is not request.role
            or attestation.runtime_image != role_generation.runtime_image
            or attestation.model_profile_sha256 != role_generation.model_profile_sha256
            or attestation.budget_policy_sha256 != role_generation.budget_policy_sha256
            or attestation.subject_module_sha256 != role_generation.subject_artifact_id.removeprefix("sha256:")
            or attestation.workflow_module_sha256 != role_generation.workflow_artifact_id.removeprefix("sha256:")
            or attestation.plugin_module_sha256
            != tuple(item.removeprefix("sha256:") for item in role_generation.plugin_artifact_ids)
            or attestation.artifact_ids != expected_artifacts
            or attestation.broker_policy_sha256 != broker_policy.policy_sha256
            or attestation.direct_plugin_execution
        ):
            raise RoleGenerationProtocolError("runner attestation does not match the pinned generation")
        return RoleExecutionReceipt.create(
            request_id=request.request_id,
            generation_id=request.generation_id,
            sandbox_id=sandbox_id,
            role=request.role,
            runtime_image=attestation.runtime_image,
            model_profile_sha256=attestation.model_profile_sha256,
            budget_policy_sha256=attestation.budget_policy_sha256,
            subject_module_sha256=attestation.subject_module_sha256,
            workflow_module_sha256=attestation.workflow_module_sha256,
            plugin_module_sha256=attestation.plugin_module_sha256,
            artifact_ids=attestation.artifact_ids,
            artifact_archive_sha256=staged_digests,
            broker_policy_sha256=attestation.broker_policy_sha256,
            result=output,
            duration_seconds=float(result.duration_seconds),
        )

    @staticmethod
    def _parse_attestation(value: object) -> _RunnerAttestation:
        fields = {
            "sandbox_id",
            "generation_id",
            "role",
            "runtime_image",
            "model_profile_sha256",
            "budget_policy_sha256",
            "subject_module_sha256",
            "workflow_module_sha256",
            "plugin_module_sha256",
            "artifact_ids",
            "broker_policy_sha256",
            "direct_plugin_execution",
        }
        raw = _strict(value, fields, "runner attestation")
        plugins = raw["plugin_module_sha256"]
        artifacts = raw["artifact_ids"]
        if not isinstance(plugins, list) or any(not isinstance(item, str) for item in plugins):
            raise RoleGenerationProtocolError("attested plugin module digests must be strings")
        if not isinstance(artifacts, list) or any(not isinstance(item, str) for item in artifacts):
            raise RoleGenerationProtocolError("attested artifact ids must be strings")
        try:
            role = Role(cast(str, raw["role"]))
            attestation = _RunnerAttestation(
                sandbox_id=cast(str, raw["sandbox_id"]),
                generation_id=cast(str, raw["generation_id"]),
                role=role,
                runtime_image=cast(str, raw["runtime_image"]),
                model_profile_sha256=cast(str, raw["model_profile_sha256"]),
                budget_policy_sha256=cast(str, raw["budget_policy_sha256"]),
                subject_module_sha256=cast(str, raw["subject_module_sha256"]),
                workflow_module_sha256=cast(str, raw["workflow_module_sha256"]),
                plugin_module_sha256=tuple(plugins),
                artifact_ids=tuple(artifacts),
                broker_policy_sha256=cast(str, raw["broker_policy_sha256"]),
                direct_plugin_execution=cast(bool, raw["direct_plugin_execution"]),
            )
            _address(attestation.generation_id, "attested generation_id")
            if not isinstance(attestation.sandbox_id, str) or not attestation.sandbox_id:
                raise ValueError("attested sandbox_id is invalid")
            if not isinstance(attestation.runtime_image, str) or _OCI_DIGEST.fullmatch(attestation.runtime_image) is None:
                raise ValueError("attested runtime image is invalid")
            for digest in (
                attestation.model_profile_sha256,
                attestation.budget_policy_sha256,
                attestation.subject_module_sha256,
                attestation.workflow_module_sha256,
                attestation.broker_policy_sha256,
                *attestation.plugin_module_sha256,
            ):
                _digest(digest, "attested digest")
            for artifact_id in attestation.artifact_ids:
                _address(artifact_id, "attested artifact id")
            if not isinstance(attestation.direct_plugin_execution, bool):
                raise TypeError("direct_plugin_execution must be a bool")
            return attestation
        except (TypeError, ValueError) as exc:
            raise RoleGenerationProtocolError("runner attestation is structurally invalid") from exc

    @staticmethod
    def _reject_duplicate_keys(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON object key")
            result[key] = value
        return result

    @staticmethod
    def _reject_nonfinite(value: str) -> Any:
        raise ValueError(f"non-finite JSON number: {value}")
