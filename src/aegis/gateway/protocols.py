"""Role capabilities and strict structured output protocol."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Iterable, Mapping

from .types import GatewayRequest, Message


class Role(StrEnum):
    WARRIOR = "warrior"
    JUDGE = "judge"
    PROSECUTOR = "prosecutor"


DEFAULT_ROLE_TOOLS: Mapping[Role, frozenset[str]] = {
    Role.WARRIOR: frozenset(
        {"research.search", "research.fetch", "workspace.read", "workspace.write", "sandbox.exec"}
    ),
    Role.JUDGE: frozenset(
        {"research.search", "research.fetch", "submission.read", "sandbox.exec", "evaluation.record"}
    ),
    Role.PROSECUTOR: frozenset(
        {"trace.read", "evaluation.read", "research.search", "research.fetch", "proposal.record"}
    ),
}


@dataclass(frozen=True, slots=True)
class RolePolicy:
    role: Role
    system_prompt: str
    allowed_tools: frozenset[str]

    @classmethod
    def default(cls, role: Role, system_prompt: str) -> RolePolicy:
        return cls(role, system_prompt, DEFAULT_ROLE_TOOLS[role])

    def filter_tools(self, tools: Iterable[Mapping[str, Any]]) -> tuple[Mapping[str, Any], ...]:
        accepted: list[Mapping[str, Any]] = []
        for tool in tools:
            name = tool.get("name")
            if isinstance(name, str) and name in self.allowed_tools:
                accepted.append(tool)
        return tuple(accepted)


ROLE_OUTPUT_SCHEMA: Mapping[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["role", "summary", "actions", "findings", "proposals"],
    "properties": {
        "role": {"type": "string", "enum": [role.value for role in Role]},
        "summary": {"type": "string", "minLength": 1},
        "actions": {"type": "array", "items": {"type": "object"}},
        "findings": {"type": "array", "items": {"type": "object"}},
        "proposals": {"type": "array", "items": {"type": "object"}},
    },
}


@dataclass(frozen=True, slots=True)
class RoleOutput:
    role: Role
    summary: str
    actions: tuple[Mapping[str, Any], ...]
    findings: tuple[Mapping[str, Any], ...]
    proposals: tuple[Mapping[str, Any], ...]


def build_role_request(
    policy: RolePolicy,
    *,
    model: str,
    objective: str,
    context: Mapping[str, Any],
    tools: Iterable[Mapping[str, Any]] = (),
    max_output_tokens: int = 4096,
) -> GatewayRequest:
    if not objective.strip():
        raise ValueError("objective must not be empty")
    envelope = {"protocol_version": 1, "role": policy.role.value, "objective": objective, "context": context}
    return GatewayRequest(
        model=model,
        messages=(
            Message("system", policy.system_prompt),
            Message("user", json.dumps(envelope, sort_keys=True)),
        ),
        max_output_tokens=max_output_tokens,
        tools=policy.filter_tools(tools),
        output_schema=ROLE_OUTPUT_SCHEMA,
    )


def parse_role_output(text: str, expected_role: Role) -> RoleOutput:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("role output is not valid JSON") from exc
    required = {"role", "summary", "actions", "findings", "proposals"}
    if not isinstance(data, dict) or set(data) != required:
        raise ValueError("role output has missing or unknown fields")
    if data["role"] != expected_role.value:
        raise ValueError("role output identity mismatch")
    if not isinstance(data["summary"], str) or not data["summary"].strip():
        raise ValueError("role output summary must not be empty")
    for key in ("actions", "findings", "proposals"):
        if not isinstance(data[key], list) or not all(isinstance(value, dict) for value in data[key]):
            raise ValueError(f"role output {key} must be an array of objects")
    return RoleOutput(
        expected_role,
        data["summary"],
        tuple(data["actions"]),
        tuple(data["findings"]),
        tuple(data["proposals"]),
    )
