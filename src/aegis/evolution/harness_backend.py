"""WSL-only production backend for harness code evolution.

The Windows control plane sends bounded JSON requests to a fixed executable in
the dedicated AEGIS distribution.  It never receives a command line or a path
from candidate code and never imports or executes a candidate on Windows.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol, cast
from urllib.parse import urlsplit

from aegis.models import canonical_json

from .harness import validate_harness_patch_paths

_SAFE_DISTRIBUTION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
_SAFE_OPERATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_PINNED_COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_COMMIT = _PINNED_COMMIT
_MAX_RESPONSE_BYTES = 1_048_576


class HarnessBackendError(RuntimeError):
    """A transport, policy, integrity, or WSL harness-agent failure."""


Transport = Callable[[Mapping[str, Any], float], Mapping[str, Any]]


@dataclass(frozen=True, slots=True)
class HarnessReceipt:
    """Durable, idempotent receipt returned by the WSL harness agent."""

    operation: str
    operation_id: str
    campaign_id: str
    campaign_key: str
    status: str
    champion_commit: str | None
    candidate_commit: str | None
    previous_champion: str | None
    detail: str
    request_sha256: str
    receipt_sha256: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> HarnessReceipt:
        fields = {
            "operation",
            "operation_id",
            "campaign_id",
            "campaign_key",
            "status",
            "champion_commit",
            "candidate_commit",
            "previous_champion",
            "detail",
            "request_sha256",
            "receipt_sha256",
        }
        if set(value) != fields:
            raise HarnessBackendError("harness receipt has missing or unknown fields")
        receipt = cls(
            operation=_text(value["operation"], "operation"),
            operation_id=_text(value["operation_id"], "operation_id"),
            campaign_id=_text(value["campaign_id"], "campaign_id"),
            campaign_key=_digest(value["campaign_key"], "campaign_key"),
            status=_text(value["status"], "status"),
            champion_commit=_optional_commit(value["champion_commit"], "champion_commit"),
            candidate_commit=_optional_commit(value["candidate_commit"], "candidate_commit"),
            previous_champion=_optional_commit(value["previous_champion"], "previous_champion"),
            detail=_detail(value["detail"]),
            request_sha256=_digest(value["request_sha256"], "request_sha256"),
            receipt_sha256=_digest(value["receipt_sha256"], "receipt_sha256"),
        )
        expected = _receipt_digest(receipt.to_mapping(include_digest=False))
        if receipt.receipt_sha256 != expected:
            raise HarnessBackendError("harness receipt digest mismatch")
        return receipt

    def to_mapping(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "operation": self.operation,
            "operation_id": self.operation_id,
            "campaign_id": self.campaign_id,
            "campaign_key": self.campaign_key,
            "status": self.status,
            "champion_commit": self.champion_commit,
            "candidate_commit": self.candidate_commit,
            "previous_champion": self.previous_champion,
            "detail": self.detail,
            "request_sha256": self.request_sha256,
        }
        if include_digest:
            payload["receipt_sha256"] = self.receipt_sha256
        return payload


class HarnessBackend(Protocol):
    """Storage and activation boundary used by the evolution control plane."""

    def ensure_campaign(
        self, campaign_id: str, source_url: str, source_ref: str, operation_id: str
    ) -> HarnessReceipt: ...

    def status(self, campaign_id: str, operation_id: str) -> HarnessReceipt: ...

    def checkpoint(
        self,
        campaign_id: str,
        candidate_id: str,
        base_commit: str,
        changes: Sequence[Mapping[str, Any]],
        operation_id: str,
    ) -> HarnessReceipt: ...

    def validate(
        self, campaign_id: str, candidate_id: str, candidate_commit: str, operation_id: str
    ) -> HarnessReceipt: ...

    def activate(
        self,
        campaign_id: str,
        candidate_id: str,
        candidate_commit: str,
        expected_champion: str,
        operation_id: str,
    ) -> HarnessReceipt: ...

    def rollback(
        self,
        campaign_id: str,
        failed_commit: str,
        target_commit: str,
        operation_id: str,
    ) -> HarnessReceipt: ...

    def cleanup_candidate(
        self, campaign_id: str, candidate_id: str, operation_id: str
    ) -> HarnessReceipt: ...


class WslHarnessBackend:
    """Fail-closed adapter to the trusted WSL harness agent."""

    def __init__(
        self,
        distribution: str = "AEGIS-Sandbox",
        *,
        agent_path: str = "/usr/local/bin/aegis-harness-agent",
        transport: Transport | None = None,
        timeout_seconds: float = 3600.0,
    ) -> None:
        if _SAFE_DISTRIBUTION.fullmatch(distribution) is None:
            raise ValueError("unsafe WSL distribution name")
        if agent_path != "/usr/local/bin/aegis-harness-agent":
            raise ValueError("harness agent path is fixed by the host safety envelope")
        if isinstance(timeout_seconds, bool) or not 1 <= timeout_seconds <= 3600:
            raise ValueError("timeout_seconds must be in [1, 3600]")
        self.distribution = distribution
        self.agent_path = agent_path
        self._transport = transport or self._wsl_transport
        self._timeout = float(timeout_seconds)

    def transport_argv(self) -> tuple[str, ...]:
        return (
            "wsl.exe",
            "--distribution",
            self.distribution,
            "--",
            self.agent_path,
        )

    def ensure_campaign(
        self, campaign_id: str, source_url: str, source_ref: str, operation_id: str
    ) -> HarnessReceipt:
        _validate_source_url(source_url)
        if _PINNED_COMMIT.fullmatch(source_ref) is None:
            raise ValueError("source_ref must be a full pinned Git commit id")
        return self._request(
            "ensure_campaign",
            campaign_id,
            operation_id,
            source_url=source_url,
            source_ref=source_ref,
        )

    def status(self, campaign_id: str, operation_id: str) -> HarnessReceipt:
        return self._request("status", campaign_id, operation_id)

    def checkpoint(
        self,
        campaign_id: str,
        candidate_id: str,
        base_commit: str,
        changes: Sequence[Mapping[str, Any]],
        operation_id: str,
    ) -> HarnessReceipt:
        _commit(base_commit, "base_commit")
        if not candidate_id or len(candidate_id.encode("utf-8")) > 256:
            raise ValueError("candidate_id must be bounded non-empty text")
        normalized = [dict(item) for item in changes]
        if not normalized or len(normalized) > 128:
            raise ValueError("changes must be a bounded non-empty sequence")
        try:
            validate_harness_patch_paths([str(item.get("path", "")) for item in normalized])
        except (TypeError, RuntimeError) as exc:
            raise ValueError(str(exc)) from exc
        return self._request(
            "checkpoint",
            campaign_id,
            operation_id,
            candidate_id=candidate_id,
            base_commit=base_commit,
            changes=normalized,
        )

    def validate(
        self, campaign_id: str, candidate_id: str, candidate_commit: str, operation_id: str
    ) -> HarnessReceipt:
        _commit(candidate_commit, "candidate_commit")
        return self._request(
            "validate",
            campaign_id,
            operation_id,
            candidate_id=candidate_id,
            candidate_commit=candidate_commit,
        )

    def activate(
        self,
        campaign_id: str,
        candidate_id: str,
        candidate_commit: str,
        expected_champion: str,
        operation_id: str,
    ) -> HarnessReceipt:
        _commit(candidate_commit, "candidate_commit")
        _commit(expected_champion, "expected_champion")
        return self._request(
            "activate",
            campaign_id,
            operation_id,
            candidate_id=candidate_id,
            candidate_commit=candidate_commit,
            expected_champion=expected_champion,
        )

    def rollback(
        self,
        campaign_id: str,
        failed_commit: str,
        target_commit: str,
        operation_id: str,
    ) -> HarnessReceipt:
        _commit(failed_commit, "failed_commit")
        _commit(target_commit, "target_commit")
        return self._request(
            "rollback",
            campaign_id,
            operation_id,
            failed_commit=failed_commit,
            target_commit=target_commit,
        )

    def cleanup_candidate(
        self, campaign_id: str, candidate_id: str, operation_id: str
    ) -> HarnessReceipt:
        return self._request(
            "cleanup_candidate", campaign_id, operation_id, candidate_id=candidate_id
        )

    def _request(
        self, operation: str, campaign_id: str, operation_id: str, **payload: Any
    ) -> HarnessReceipt:
        _bounded_text(campaign_id, "campaign_id", 512)
        if _SAFE_OPERATION_ID.fullmatch(operation_id) is None:
            raise ValueError("operation_id is unsafe")
        request = {
            "version": 1,
            "operation": operation,
            "operation_id": operation_id,
            "campaign_id": campaign_id,
            **payload,
        }
        response = self._transport(request, self._timeout)
        if not isinstance(response, Mapping):
            raise HarnessBackendError("harness agent response must be an object")
        if response.get("ok") is not True:
            error = str(response.get("error", "HarnessAgentError"))[:128]
            message = str(response.get("message", "harness operation failed"))[:1024]
            raise HarnessBackendError(f"{error}: {message}")
        raw_receipt = response.get("receipt")
        if not isinstance(raw_receipt, Mapping):
            raise HarnessBackendError("harness agent omitted receipt")
        receipt = HarnessReceipt.from_mapping(cast(Mapping[str, Any], raw_receipt))
        expected_request = hashlib.sha256(canonical_json(request).encode()).hexdigest()
        if (
            receipt.operation != operation
            or receipt.operation_id != operation_id
            or receipt.campaign_id != campaign_id
            or receipt.request_sha256 != expected_request
        ):
            raise HarnessBackendError("harness receipt is bound to another request")
        return receipt

    def _wsl_transport(
        self, request: Mapping[str, Any], timeout: float
    ) -> Mapping[str, Any]:
        wire = canonical_json(request) + "\n"
        try:
            result = subprocess.run(
                self.transport_argv(),
                input=wire,
                capture_output=True,
                text=True,
                shell=False,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise HarnessBackendError(f"WSL harness transport failed: {exc}") from exc
        if len(result.stdout.encode("utf-8", errors="replace")) > _MAX_RESPONSE_BYTES:
            raise HarnessBackendError("WSL harness response exceeded limit")
        try:
            decoded = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise HarnessBackendError("WSL harness agent returned invalid JSON") from exc
        if result.returncode != 0 and not isinstance(decoded, Mapping):
            raise HarnessBackendError("WSL harness agent failed without a JSON response")
        if not isinstance(decoded, Mapping):
            raise HarnessBackendError("WSL harness agent response must be an object")
        return cast(Mapping[str, Any], decoded)


def _validate_source_url(value: str) -> None:
    _bounded_text(value, "source_url", 2048)
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in {None, 443}
        or parsed.query
        or parsed.fragment
        or "\\" in value
    ):
        raise ValueError("source_url must be credential-free HTTPS")
    lowered_path = parsed.path.lower()
    if lowered_path.startswith("/mnt/") or ":" in parsed.path:
        raise ValueError("Windows, UNC, and DrvFS source paths are forbidden")
    _reject_private_hostname(parsed.hostname)


def _reject_private_hostname(hostname: str) -> None:
    lowered = hostname.rstrip(".").lower()
    if lowered == "localhost" or lowered.endswith((".localhost", ".local", ".internal")):
        raise ValueError("source_url must name a public HTTPS host")
    try:
        address = ipaddress.ip_address(lowered.strip("[]"))
    except ValueError:
        return
    if not address.is_global:
        raise ValueError("source_url must not use a private or reserved IP address")


def _bounded_text(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{name} must be non-empty text")
    if len(value.encode("utf-8")) > maximum:
        raise ValueError(f"{name} exceeds its size limit")
    return value


def _text(value: object, name: str) -> str:
    return _bounded_text(value, name, 4096)


def _detail(value: object) -> str:
    if not isinstance(value, str) or "\x00" in value or len(value.encode("utf-8")) > 4096:
        raise HarnessBackendError("receipt detail must be bounded text")
    return value


def _commit(value: object, name: str) -> str:
    if not isinstance(value, str) or _COMMIT.fullmatch(value) is None:
        raise ValueError(f"{name} must be a full Git commit id")
    return value


def _optional_commit(value: object, name: str) -> str | None:
    return None if value is None else _commit(value, name)


def _digest(value: object, name: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise HarnessBackendError(f"{name} must be a SHA-256 digest")
    return value


def _receipt_digest(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
