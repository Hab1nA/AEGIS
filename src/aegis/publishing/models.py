"""Content-addressed requests and receipts for the public Git boundary."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping, Sequence

_COMMIT = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
_CONTENT_ID = re.compile(r"[a-z][a-z0-9-]*-sha256:[0-9a-f]{64}\Z")
_COMPONENT = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}\Z")


def canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def content_id(prefix: str, value: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()
    return f"{prefix}{digest}"


def _strict_keys(value: Mapping[str, Any], expected: set[str], name: str) -> None:
    if set(value) != expected:
        raise ValueError(f"{name} has missing or unknown fields")


def _text(value: object, name: str, *, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or value.strip() != value or len(value) > maximum:
        raise ValueError(f"{name} must be bounded, non-empty, trimmed text")
    return value


def _component(value: object, name: str) -> str:
    text = _text(value, name, maximum=64)
    if _COMPONENT.fullmatch(text) is None or ".." in text or text.endswith(".lock"):
        raise ValueError(f"{name} is not a safe Git ref component")
    return text


def _commit(value: object, name: str) -> str:
    if not isinstance(value, str) or _COMMIT.fullmatch(value) is None:
        raise ValueError(f"{name} must be a full Git commit id")
    return value


@dataclass(frozen=True, slots=True)
class GitFileChange:
    path: str
    content: bytes | None
    executable: bool = False

    def __post_init__(self) -> None:
        _text(self.path, "path", maximum=512)
        if self.content is not None and not isinstance(self.content, bytes):
            raise TypeError("file content must be bytes or None for deletion")
        if not isinstance(self.executable, bool):
            raise TypeError("executable must be a bool")
        if self.content is None and self.executable:
            raise ValueError("deleted files cannot be executable")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> GitFileChange:
        _strict_keys(value, {"path", "content_base64", "executable"}, "Git file change")
        encoded = value["content_base64"]
        if encoded is not None and not isinstance(encoded, str):
            raise TypeError("content_base64 must be a string or null")
        try:
            content = None if encoded is None else base64.b64decode(encoded, validate=True)
        except ValueError as exc:
            raise ValueError("content_base64 is invalid") from exc
        return cls(value["path"], content, value["executable"])

    def to_mapping(self) -> dict[str, Any]:
        encoded = None if self.content is None else base64.b64encode(self.content).decode("ascii")
        return {"path": self.path, "content_base64": encoded, "executable": self.executable}


@dataclass(frozen=True, slots=True)
class GitCheckpointRequest:
    request_id: str
    role: str
    generation_id: str
    base_commit: str
    changes: tuple[GitFileChange, ...]
    message: str

    def __post_init__(self) -> None:
        if _CONTENT_ID.fullmatch(self.request_id) is None or not self.request_id.startswith(
            "git-checkpoint-sha256:"
        ):
            raise ValueError("request_id must be a Git checkpoint content id")
        _component(self.role, "role")
        _component(self.generation_id, "generation_id")
        _commit(self.base_commit, "base_commit")
        if not self.changes:
            raise ValueError("checkpoint must contain at least one change")
        paths = tuple(item.path for item in self.changes)
        if tuple(sorted(set(paths))) != paths:
            raise ValueError("checkpoint changes must have sorted unique paths")
        _text(self.message, "message")
        expected = content_id("git-checkpoint-sha256:", self.to_mapping(include_id=False))
        if self.request_id != expected:
            raise ValueError("request_id does not match checkpoint content")

    @classmethod
    def create(
        cls,
        *,
        role: str,
        generation_id: str,
        base_commit: str,
        changes: Sequence[GitFileChange],
        message: str,
    ) -> GitCheckpointRequest:
        ordered = tuple(sorted(changes, key=lambda item: item.path))
        payload: dict[str, Any] = {
            "role": role,
            "generation_id": generation_id,
            "base_commit": base_commit,
            "changes": [item.to_mapping() for item in ordered],
            "message": message,
        }
        return cls(content_id("git-checkpoint-sha256:", payload), role, generation_id, base_commit, ordered, message)

    def to_mapping(self, *, include_id: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "role": self.role,
            "generation_id": self.generation_id,
            "base_commit": self.base_commit,
            "changes": [item.to_mapping() for item in self.changes],
            "message": self.message,
        }
        return {"request_id": self.request_id, **payload} if include_id else payload


@dataclass(frozen=True, slots=True)
class PromotionEvidence:
    evidence_id: str
    candidate_commit: str
    qualification_report_id: str
    qualified: bool
    probation_report_id: str
    probation_passed: bool

    def __post_init__(self) -> None:
        if _CONTENT_ID.fullmatch(self.evidence_id) is None or not self.evidence_id.startswith(
            "git-promotion-evidence-sha256:"
        ):
            raise ValueError("evidence_id must be a Git promotion evidence content id")
        _commit(self.candidate_commit, "candidate_commit")
        for value, name in (
            (self.qualification_report_id, "qualification_report_id"),
            (self.probation_report_id, "probation_report_id"),
        ):
            if not isinstance(value, str) or _CONTENT_ID.fullmatch(value) is None:
                raise ValueError(f"{name} must be a content-addressed report id")
        if not isinstance(self.qualified, bool) or not isinstance(self.probation_passed, bool):
            raise TypeError("promotion evidence decisions must be bool values")
        expected = content_id("git-promotion-evidence-sha256:", self.to_mapping(include_id=False))
        if self.evidence_id != expected:
            raise ValueError("evidence_id does not match promotion evidence")

    @classmethod
    def create(
        cls,
        *,
        candidate_commit: str,
        qualification_report_id: str,
        qualified: bool,
        probation_report_id: str,
        probation_passed: bool,
    ) -> PromotionEvidence:
        payload: dict[str, Any] = {
            "candidate_commit": candidate_commit,
            "qualification_report_id": qualification_report_id,
            "qualified": qualified,
            "probation_report_id": probation_report_id,
            "probation_passed": probation_passed,
        }
        return cls(
            content_id("git-promotion-evidence-sha256:", payload),
            candidate_commit,
            qualification_report_id,
            qualified,
            probation_report_id,
            probation_passed,
        )

    def to_mapping(self, *, include_id: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "candidate_commit": self.candidate_commit,
            "qualification_report_id": self.qualification_report_id,
            "qualified": self.qualified,
            "probation_report_id": self.probation_report_id,
            "probation_passed": self.probation_passed,
        }
        return {"evidence_id": self.evidence_id, **payload} if include_id else payload


@dataclass(frozen=True, slots=True)
class StablePromotionRequest:
    request_id: str
    role: str
    generation_id: str
    expected_stable_commit: str
    evidence: PromotionEvidence

    def __post_init__(self) -> None:
        if _CONTENT_ID.fullmatch(self.request_id) is None or not self.request_id.startswith(
            "git-stable-request-sha256:"
        ):
            raise ValueError("request_id must be a stable promotion request content id")
        _component(self.role, "role")
        _component(self.generation_id, "generation_id")
        _commit(self.expected_stable_commit, "expected_stable_commit")
        expected = content_id("git-stable-request-sha256:", self.to_mapping(include_id=False))
        if self.request_id != expected:
            raise ValueError("request_id does not match stable promotion request")

    @classmethod
    def create(
        cls,
        *,
        role: str,
        generation_id: str,
        expected_stable_commit: str,
        evidence: PromotionEvidence,
    ) -> StablePromotionRequest:
        payload: dict[str, Any] = {
            "role": role,
            "generation_id": generation_id,
            "expected_stable_commit": expected_stable_commit,
            "evidence": evidence.to_mapping(),
        }
        return cls(
            content_id("git-stable-request-sha256:", payload),
            role,
            generation_id,
            expected_stable_commit,
            evidence,
        )

    def to_mapping(self, *, include_id: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "role": self.role,
            "generation_id": self.generation_id,
            "expected_stable_commit": self.expected_stable_commit,
            "evidence": self.evidence.to_mapping(),
        }
        return {"request_id": self.request_id, **payload} if include_id else payload


class PublishOperation(StrEnum):
    CANDIDATE = "candidate"
    STABLE = "stable"


@dataclass(frozen=True, slots=True)
class PublishIntent:
    intent_id: str
    operation: PublishOperation
    request_id: str
    remote_id: str
    ref: str
    expected_old_commit: str | None
    new_commit: str

    def __post_init__(self) -> None:
        if _CONTENT_ID.fullmatch(self.intent_id) is None or not self.intent_id.startswith(
            "git-publish-intent-sha256:"
        ):
            raise ValueError("intent_id must be a Git publish intent content id")
        if _CONTENT_ID.fullmatch(self.request_id) is None:
            raise ValueError("intent request_id must be content-addressed")
        _text(self.remote_id, "remote_id")
        _text(self.ref, "ref")
        if self.expected_old_commit is not None:
            _commit(self.expected_old_commit, "expected_old_commit")
        _commit(self.new_commit, "new_commit")
        expected = content_id("git-publish-intent-sha256:", self.to_mapping(include_id=False))
        if self.intent_id != expected:
            raise ValueError("intent_id does not match publish intent")

    @classmethod
    def create(
        cls,
        *,
        operation: PublishOperation,
        request_id: str,
        remote_id: str,
        ref: str,
        expected_old_commit: str | None,
        new_commit: str,
    ) -> PublishIntent:
        payload: dict[str, Any] = {
            "operation": operation.value,
            "request_id": request_id,
            "remote_id": remote_id,
            "ref": ref,
            "expected_old_commit": expected_old_commit,
            "new_commit": new_commit,
        }
        return cls(
            content_id("git-publish-intent-sha256:", payload),
            operation,
            request_id,
            remote_id,
            ref,
            expected_old_commit,
            new_commit,
        )

    def to_mapping(self, *, include_id: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "operation": self.operation.value,
            "request_id": self.request_id,
            "remote_id": self.remote_id,
            "ref": self.ref,
            "expected_old_commit": self.expected_old_commit,
            "new_commit": self.new_commit,
        }
        return {"intent_id": self.intent_id, **payload} if include_id else payload


@dataclass(frozen=True, slots=True)
class PublishReceipt:
    receipt_id: str
    intent_id: str
    operation: PublishOperation
    ref: str
    old_commit: str | None
    new_commit: str

    def __post_init__(self) -> None:
        if _CONTENT_ID.fullmatch(self.receipt_id) is None or not self.receipt_id.startswith(
            "git-publish-receipt-sha256:"
        ):
            raise ValueError("receipt_id must be a Git publish receipt content id")
        if _CONTENT_ID.fullmatch(self.intent_id) is None:
            raise ValueError("receipt intent_id must be content-addressed")
        _text(self.ref, "ref")
        if self.old_commit is not None:
            _commit(self.old_commit, "old_commit")
        _commit(self.new_commit, "new_commit")
        expected = content_id("git-publish-receipt-sha256:", self.to_mapping(include_id=False))
        if self.receipt_id != expected:
            raise ValueError("receipt_id does not match publish receipt")

    @classmethod
    def create(cls, intent: PublishIntent) -> PublishReceipt:
        payload: dict[str, Any] = {
            "intent_id": intent.intent_id,
            "operation": intent.operation.value,
            "ref": intent.ref,
            "old_commit": intent.expected_old_commit,
            "new_commit": intent.new_commit,
        }
        return cls(
            content_id("git-publish-receipt-sha256:", payload),
            intent.intent_id,
            intent.operation,
            intent.ref,
            intent.expected_old_commit,
            intent.new_commit,
        )

    def to_mapping(self, *, include_id: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "intent_id": self.intent_id,
            "operation": self.operation.value,
            "ref": self.ref,
            "old_commit": self.old_commit,
            "new_commit": self.new_commit,
        }
        return {"receipt_id": self.receipt_id, **payload} if include_id else payload


@dataclass(frozen=True, slots=True)
class PublicationResult:
    intent: PublishIntent
    receipt: PublishReceipt

    def __post_init__(self) -> None:
        if self.receipt.intent_id != self.intent.intent_id:
            raise ValueError("publication receipt is bound to another intent")
