"""Immutable MCP evolution artifacts and their authorization policy."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping, Sequence

from aegis.models import canonical_json

from .bridge import McpServerManifest

_CONTENT_ID = re.compile(r"[a-z][a-z0-9-]{0,63}-sha256:[0-9a-f]{64}\Z")
_NAME = re.compile(r"[a-zA-Z][a-zA-Z0-9_.-]{0,127}\Z")


class McpEvolutionError(RuntimeError):
    """An MCP evolution artifact or lifecycle operation is invalid."""


class McpRiskLevel(StrEnum):
    L0 = "L0"
    L1 = "L1"
    L2 = "L2"
    L3 = "L3"


class McpPermissionStage(StrEnum):
    DISCOVERY = "discovery"
    OBSERVATION = "observation"
    OPERATION = "operation"
    ADMINISTRATION = "administration"


_RISK_RANK = {
    McpRiskLevel.L0: 0,
    McpRiskLevel.L1: 1,
    McpRiskLevel.L2: 2,
    McpRiskLevel.L3: 3,
}
_PERMISSION_RANK = {
    McpPermissionStage.DISCOVERY: 0,
    McpPermissionStage.OBSERVATION: 1,
    McpPermissionStage.OPERATION: 2,
    McpPermissionStage.ADMINISTRATION: 3,
}


def _text(value: object, name: str, *, limit: int = 2000) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > limit
    ):
        raise McpEvolutionError(f"{name} must be bounded non-empty trimmed text")
    return value


def _strict(value: object, fields: set[str], name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise McpEvolutionError(f"{name} must be a string-keyed mapping")
    if set(value) != fields:
        raise McpEvolutionError(f"{name} has missing or unknown fields")
    return value


def _enum(enum_type: type[StrEnum], value: object, name: str) -> StrEnum:
    if not isinstance(value, str):
        raise McpEvolutionError(f"{name} has an invalid value")
    try:
        return enum_type(value)
    except ValueError as exc:
        raise McpEvolutionError(f"{name} has an invalid value") from exc


@dataclass(frozen=True, slots=True)
class McpToolAuthorization:
    """A schema-pinned grant for one MCP tool."""

    tool_name: str
    schema_sha256: str
    schema_summary: str
    risk_level: McpRiskLevel
    permission_stage: McpPermissionStage

    def __post_init__(self) -> None:
        if not isinstance(self.tool_name, str) or _NAME.fullmatch(self.tool_name) is None:
            raise McpEvolutionError("tool_name has an invalid value")
        if re.fullmatch(r"[0-9a-f]{64}", self.schema_sha256) is None:
            raise McpEvolutionError("schema_sha256 must be a lowercase sha256 digest")
        _text(self.schema_summary, "schema_summary", limit=1000)
        if not isinstance(self.risk_level, McpRiskLevel) or not isinstance(
            self.permission_stage, McpPermissionStage
        ):
            raise McpEvolutionError("risk_level and permission_stage must use MCP enums")
        if _RISK_RANK[self.risk_level] > _PERMISSION_RANK[self.permission_stage]:
            raise McpEvolutionError("permission_stage does not authorize the tool risk level")

    @classmethod
    def create(
        cls,
        *,
        tool_name: str,
        input_schema: Mapping[str, Any],
        schema_summary: str,
        risk_level: McpRiskLevel,
        permission_stage: McpPermissionStage,
    ) -> McpToolAuthorization:
        if not isinstance(input_schema, Mapping):
            raise McpEvolutionError("input_schema must be a mapping")
        try:
            digest = hashlib.sha256(canonical_json(input_schema).encode("utf-8")).hexdigest()
        except (TypeError, ValueError) as exc:
            raise McpEvolutionError("input_schema must be strict JSON") from exc
        return cls(tool_name, digest, schema_summary, risk_level, permission_stage)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> McpToolAuthorization:
        payload = _strict(
            value,
            {"tool_name", "schema_sha256", "schema_summary", "risk_level", "permission_stage"},
            "tool authorization",
        )
        return cls(
            payload["tool_name"],
            payload["schema_sha256"],
            payload["schema_summary"],
            _enum(McpRiskLevel, payload["risk_level"], "risk_level"),  # type: ignore[arg-type]
            _enum(McpPermissionStage, payload["permission_stage"], "permission_stage"),  # type: ignore[arg-type]
        )

    def to_mapping(self) -> dict[str, str]:
        return {
            "tool_name": self.tool_name,
            "schema_sha256": self.schema_sha256,
            "schema_summary": self.schema_summary,
            "risk_level": self.risk_level.value,
            "permission_stage": self.permission_stage.value,
        }


@dataclass(frozen=True, slots=True)
class McpBinding:
    """Content-addressed binding between a server manifest and exact tool grants."""

    binding_id: str
    manifest_id: str
    server_name: str
    authorizations: tuple[McpToolAuthorization, ...]

    def __post_init__(self) -> None:
        if _CONTENT_ID.fullmatch(self.manifest_id) is None:
            raise McpEvolutionError("manifest_id must be a content address")
        if not isinstance(self.server_name, str) or _NAME.fullmatch(self.server_name) is None:
            raise McpEvolutionError("server_name has an invalid value")
        if not self.authorizations or len(self.authorizations) > 64:
            raise McpEvolutionError("authorizations must contain between 1 and 64 grants")
        names = tuple(item.tool_name for item in self.authorizations)
        if names != tuple(sorted(names)) or len(set(names)) != len(names):
            raise McpEvolutionError("authorizations must be uniquely sorted by tool_name")
        expected = self._identity(self.manifest_id, self.server_name, self.authorizations)
        if self.binding_id != expected:
            raise McpEvolutionError("binding_id does not match binding content")

    @staticmethod
    def _identity(
        manifest_id: str, server_name: str, authorizations: Sequence[McpToolAuthorization]
    ) -> str:
        payload = {
            "manifest_id": manifest_id,
            "server_name": server_name,
            "authorizations": [item.to_mapping() for item in authorizations],
        }
        digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
        return f"mcp-binding-sha256:{digest}"

    @classmethod
    def create(
        cls,
        *,
        manifest_id: str,
        server_name: str,
        authorizations: Sequence[McpToolAuthorization],
    ) -> McpBinding:
        grants = tuple(sorted(authorizations, key=lambda item: item.tool_name))
        return cls(cls._identity(manifest_id, server_name, grants), manifest_id, server_name, grants)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> McpBinding:
        payload = _strict(
            value,
            {"binding_id", "manifest_id", "server_name", "authorizations"},
            "MCP binding",
        )
        raw = payload["authorizations"]
        if not isinstance(raw, list):
            raise McpEvolutionError("authorizations must be a list")
        return cls(
            payload["binding_id"],
            payload["manifest_id"],
            payload["server_name"],
            tuple(McpToolAuthorization.from_mapping(item) for item in raw),
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "binding_id": self.binding_id,
            "manifest_id": self.manifest_id,
            "server_name": self.server_name,
            "authorizations": [item.to_mapping() for item in self.authorizations],
        }


@dataclass(frozen=True, slots=True)
class McpCandidate:
    """Immutable proposal; lifecycle state lives only in the event projection."""

    candidate_id: str
    manifest: McpServerManifest
    binding: McpBinding
    proposed_by: str
    rationale: str
    parent_candidate_id: str | None = None

    def __post_init__(self) -> None:
        if self.binding.manifest_id != self.manifest.manifest_id:
            raise McpEvolutionError("binding does not reference the embedded manifest")
        if self.binding.server_name != self.manifest.name:
            raise McpEvolutionError("binding server_name does not match the embedded manifest")
        granted = {item.tool_name for item in self.binding.authorizations}
        if granted != set(self.manifest.tool_names):
            raise McpEvolutionError("binding grants must exactly match the embedded manifest tools")
        _text(self.proposed_by, "proposed_by", limit=256)
        _text(self.rationale, "rationale")
        if self.parent_candidate_id is not None and not self.parent_candidate_id.startswith(
            "mcp-candidate-sha256:"
        ):
            raise McpEvolutionError("parent_candidate_id has an invalid value")
        if self.candidate_id != self._identity(
            self.binding.binding_id, self.proposed_by, self.rationale, self.parent_candidate_id
        ):
            raise McpEvolutionError("candidate_id does not match candidate content")

    @staticmethod
    def _identity(
        binding_id: str, proposed_by: str, rationale: str, parent_candidate_id: str | None
    ) -> str:
        payload = {
            "binding_id": binding_id,
            "proposed_by": proposed_by,
            "rationale": rationale,
            "parent_candidate_id": parent_candidate_id,
        }
        digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
        return f"mcp-candidate-sha256:{digest}"

    @classmethod
    def create(
        cls,
        *,
        manifest: McpServerManifest,
        binding: McpBinding,
        proposed_by: str,
        rationale: str,
        parent_candidate_id: str | None = None,
    ) -> McpCandidate:
        return cls(
            cls._identity(binding.binding_id, proposed_by, rationale, parent_candidate_id),
            manifest,
            binding,
            proposed_by,
            rationale,
            parent_candidate_id,
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> McpCandidate:
        payload = _strict(
            value,
            {
                "candidate_id",
                "manifest",
                "binding",
                "proposed_by",
                "rationale",
                "parent_candidate_id",
            },
            "MCP candidate",
        )
        if not isinstance(payload["manifest"], Mapping) or not isinstance(
            payload["binding"], Mapping
        ):
            raise McpEvolutionError("manifest and binding must be mappings")
        return cls(
            payload["candidate_id"],
            McpServerManifest.from_mapping(payload["manifest"]),
            McpBinding.from_mapping(payload["binding"]),
            payload["proposed_by"],
            payload["rationale"],
            payload["parent_candidate_id"],
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "manifest": self.manifest.to_mapping(),
            "binding": self.binding.to_mapping(),
            "proposed_by": self.proposed_by,
            "rationale": self.rationale,
            "parent_candidate_id": self.parent_candidate_id,
        }


__all__ = [
    "McpBinding",
    "McpCandidate",
    "McpEvolutionError",
    "McpPermissionStage",
    "McpRiskLevel",
    "McpToolAuthorization",
]
