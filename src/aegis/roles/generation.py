"""Strict immutable manifests for one complete three-role generation."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Mapping, cast

from aegis.models import Role, canonical_json

_SHA256 = re.compile(r"[0-9a-f]{64}")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_OCI_DIGEST = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}")


def _digest(value: object, name: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _artifact_id(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise ValueError(f"{name} must be a sha256 content address")
    _digest(value.removeprefix("sha256:"), name)
    return value


def _strict(value: object, fields: set[str], name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields or any(
        not isinstance(key, str) for key in value
    ):
        raise ValueError(f"{name} has missing or unknown fields")
    return cast(Mapping[str, object], value)


@dataclass(frozen=True, slots=True)
class RoleGeneration:
    """Pinned implementation inputs for exactly one model role."""

    role: Role
    model_profile_sha256: str
    workflow_artifact_id: str
    subject_artifact_id: str
    runtime_image: str
    plugin_artifact_ids: tuple[str, ...]
    budget_policy_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.role, Role):
            raise TypeError("role must be a Role")
        _digest(self.model_profile_sha256, "model_profile_sha256")
        _artifact_id(self.workflow_artifact_id, "workflow_artifact_id")
        _artifact_id(self.subject_artifact_id, "subject_artifact_id")
        _digest(self.budget_policy_sha256, "budget_policy_sha256")
        if not isinstance(self.runtime_image, str) or _OCI_DIGEST.fullmatch(self.runtime_image) is None:
            raise ValueError("runtime_image must be pinned by sha256 digest")
        if not isinstance(self.plugin_artifact_ids, tuple):
            raise TypeError("plugin_artifact_ids must be a tuple")
        for value in self.plugin_artifact_ids:
            _artifact_id(value, "plugin_artifact_id")
        if tuple(sorted(set(self.plugin_artifact_ids))) != self.plugin_artifact_ids:
            raise ValueError("plugin_artifact_ids must be unique and canonically sorted")

    def to_dict(self) -> dict[str, object]:
        return {
            "role": self.role.value,
            "model_profile_sha256": self.model_profile_sha256,
            "workflow_artifact_id": self.workflow_artifact_id,
            "subject_artifact_id": self.subject_artifact_id,
            "runtime_image": self.runtime_image,
            "plugin_artifact_ids": list(self.plugin_artifact_ids),
            "budget_policy_sha256": self.budget_policy_sha256,
        }

    @classmethod
    def from_mapping(cls, value: object) -> RoleGeneration:
        data = _strict(
            value,
            {
                "role",
                "model_profile_sha256",
                "workflow_artifact_id",
                "subject_artifact_id",
                "runtime_image",
                "plugin_artifact_ids",
                "budget_policy_sha256",
            },
            "role generation",
        )
        plugins = data["plugin_artifact_ids"]
        if not isinstance(plugins, list) or not all(isinstance(item, str) for item in plugins):
            raise TypeError("plugin_artifact_ids must be an array of strings")
        text_fields = (
            "model_profile_sha256",
            "workflow_artifact_id",
            "subject_artifact_id",
            "runtime_image",
            "budget_policy_sha256",
        )
        if any(not isinstance(data[name], str) for name in text_fields):
            raise TypeError("role generation identity fields must be strings")
        raw_role = data["role"]
        if not isinstance(raw_role, str):
            raise TypeError("role generation role must be a string")
        try:
            role = Role(raw_role)
        except (TypeError, ValueError) as exc:
            raise ValueError("role generation contains an invalid role") from exc
        return cls(
            role=role,
            model_profile_sha256=cast(str, data["model_profile_sha256"]),
            workflow_artifact_id=cast(str, data["workflow_artifact_id"]),
            subject_artifact_id=cast(str, data["subject_artifact_id"]),
            runtime_image=cast(str, data["runtime_image"]),
            plugin_artifact_ids=tuple(plugins),
            budget_policy_sha256=cast(str, data["budget_policy_sha256"]),
        )


@dataclass(frozen=True, slots=True)
class GenerationBundle:
    """Atomic generation containing one immutable bundle for every AEGIS role."""

    generation_id: str
    parent_generation_id: str | None
    controller_abi: int
    source_commit: str
    roles: tuple[RoleGeneration, ...]
    evidence_manifest_sha256: str

    def __post_init__(self) -> None:
        _artifact_id(self.generation_id, "generation_id")
        if self.parent_generation_id is not None:
            _artifact_id(self.parent_generation_id, "parent_generation_id")
        if isinstance(self.controller_abi, bool) or not isinstance(self.controller_abi, int):
            raise TypeError("controller_abi must be an integer")
        if not 1 <= self.controller_abi <= 1_000_000:
            raise ValueError("controller_abi must be positive and bounded")
        if not isinstance(self.source_commit, str) or _COMMIT.fullmatch(self.source_commit) is None:
            raise ValueError("source_commit must be an exact lowercase Git commit")
        if not isinstance(self.roles, tuple) or tuple(item.role for item in self.roles) != tuple(Role):
            raise ValueError("roles must contain warrior, judge, and prosecutor in canonical order")
        if any(not isinstance(item, RoleGeneration) for item in self.roles):
            raise TypeError("roles must contain RoleGeneration values")
        _digest(self.evidence_manifest_sha256, "evidence_manifest_sha256")
        if self.generation_id != "sha256:" + self.compute_digest():
            raise ValueError("generation_id does not match generation content")

    def _identity_payload(self) -> dict[str, object]:
        return {
            "parent_generation_id": self.parent_generation_id,
            "controller_abi": self.controller_abi,
            "source_commit": self.source_commit,
            "roles": [item.to_dict() for item in self.roles],
            "evidence_manifest_sha256": self.evidence_manifest_sha256,
        }

    def compute_digest(self) -> str:
        return hashlib.sha256(canonical_json(self._identity_payload()).encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, object]:
        return {"generation_id": self.generation_id, **self._identity_payload()}

    @classmethod
    def create(
        cls,
        *,
        parent_generation_id: str | None,
        controller_abi: int,
        source_commit: str,
        roles: tuple[RoleGeneration, ...],
        evidence_manifest_sha256: str,
    ) -> GenerationBundle:
        payload = {
            "parent_generation_id": parent_generation_id,
            "controller_abi": controller_abi,
            "source_commit": source_commit,
            "roles": [item.to_dict() for item in roles],
            "evidence_manifest_sha256": evidence_manifest_sha256,
        }
        digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
        return cls("sha256:" + digest, parent_generation_id, controller_abi, source_commit, roles, evidence_manifest_sha256)

    @classmethod
    def from_mapping(cls, value: object) -> GenerationBundle:
        data = _strict(
            value,
            {
                "generation_id",
                "parent_generation_id",
                "controller_abi",
                "source_commit",
                "roles",
                "evidence_manifest_sha256",
            },
            "generation bundle",
        )
        raw_roles = data["roles"]
        if not isinstance(raw_roles, list):
            raise TypeError("roles must be an array")
        parent = data["parent_generation_id"]
        if parent is not None and not isinstance(parent, str):
            raise TypeError("parent_generation_id must be text or null")
        controller_abi = data["controller_abi"]
        if isinstance(controller_abi, bool) or not isinstance(controller_abi, int):
            raise TypeError("controller_abi must be an integer")
        for field_name in ("generation_id", "source_commit", "evidence_manifest_sha256"):
            if not isinstance(data[field_name], str):
                raise TypeError(f"{field_name} must be a string")
        return cls(
            generation_id=cast(str, data["generation_id"]),
            parent_generation_id=parent,
            controller_abi=controller_abi,
            source_commit=cast(str, data["source_commit"]),
            roles=tuple(RoleGeneration.from_mapping(item) for item in raw_roles),
            evidence_manifest_sha256=cast(str, data["evidence_manifest_sha256"]),
        )
