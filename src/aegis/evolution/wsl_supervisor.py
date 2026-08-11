"""Windows control-plane adapter for launching the active WSL champion.

The adapter has one fixed executable boundary.  Callers provide data, never a
command, module name, executable, or filesystem location.  The Linux-side
supervisor resolves ``refs/aegis/champion`` and returns a digest-bound receipt
that proves which commit was actually imported and started.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, cast

from aegis.models import canonical_json

_SAFE_DISTRIBUTION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
_SAFE_OPERATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_GIT_OBJECT = _COMMIT
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_MAX_REQUEST_BYTES = 65_536
_MAX_RESPONSE_BYTES = 1_048_576


class WslSupervisorError(RuntimeError):
    """A transport, protocol, integrity, or trusted-supervisor failure."""


Transport = Callable[[Mapping[str, Any], float], Mapping[str, Any]]


@dataclass(frozen=True, slots=True)
class CycleLaunchReceipt:
    """Durable evidence for one attempt to boot the active champion."""

    operation_id: str
    campaign_id: str
    campaign_key: str
    status: str
    failure_kind: str | None
    executed_commit: str
    tree_hash: str
    previous_champion: str | None
    last_known_good: str | None
    import_ok: bool
    heartbeat_ok: bool
    exit_code: int | None
    output_sha256: str
    output_summary: str
    request_sha256: str
    receipt_sha256: str

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> CycleLaunchReceipt:
        fields = {
            "operation_id",
            "campaign_id",
            "campaign_key",
            "status",
            "failure_kind",
            "executed_commit",
            "tree_hash",
            "previous_champion",
            "last_known_good",
            "import_ok",
            "heartbeat_ok",
            "exit_code",
            "output_sha256",
            "output_summary",
            "request_sha256",
            "receipt_sha256",
        }
        if set(raw) != fields:
            raise WslSupervisorError("cycle launch receipt has missing or unknown fields")
        receipt = cls(
            operation_id=_text(raw["operation_id"], "operation_id", 128),
            campaign_id=_text(raw["campaign_id"], "campaign_id", 512),
            campaign_key=_digest(raw["campaign_key"], "campaign_key"),
            status=_status(raw["status"]),
            failure_kind=_optional_failure(raw["failure_kind"]),
            executed_commit=_commit(raw["executed_commit"], "executed_commit"),
            tree_hash=_git_object(raw["tree_hash"], "tree_hash"),
            previous_champion=_optional_commit(raw["previous_champion"], "previous_champion"),
            last_known_good=_optional_commit(raw["last_known_good"], "last_known_good"),
            import_ok=_boolean(raw["import_ok"], "import_ok"),
            heartbeat_ok=_boolean(raw["heartbeat_ok"], "heartbeat_ok"),
            exit_code=_optional_exit_code(raw["exit_code"]),
            output_sha256=_digest(raw["output_sha256"], "output_sha256"),
            output_summary=_bounded_summary(raw["output_summary"]),
            request_sha256=_digest(raw["request_sha256"], "request_sha256"),
            receipt_sha256=_digest(raw["receipt_sha256"], "receipt_sha256"),
        )
        if receipt.receipt_sha256 != _sha256(receipt.to_mapping(include_digest=False)):
            raise WslSupervisorError("cycle launch receipt digest mismatch")
        if receipt.status == "completed" and (
            not receipt.import_ok or not receipt.heartbeat_ok or receipt.exit_code != 0
        ):
            raise WslSupervisorError("completed receipt lacks a successful boot handshake")
        if receipt.status == "boot_failed" and receipt.failure_kind not in {
            "launch_failed",
            "import_failed",
            "heartbeat_failed",
        }:
            raise WslSupervisorError("boot_failed receipt lacks a typed boot failure")
        return receipt

    def to_mapping(self, *, include_digest: bool = True) -> dict[str, Any]:
        value: dict[str, Any] = {
            "operation_id": self.operation_id,
            "campaign_id": self.campaign_id,
            "campaign_key": self.campaign_key,
            "status": self.status,
            "failure_kind": self.failure_kind,
            "executed_commit": self.executed_commit,
            "tree_hash": self.tree_hash,
            "previous_champion": self.previous_champion,
            "last_known_good": self.last_known_good,
            "import_ok": self.import_ok,
            "heartbeat_ok": self.heartbeat_ok,
            "exit_code": self.exit_code,
            "output_sha256": self.output_sha256,
            "output_summary": self.output_summary,
            "request_sha256": self.request_sha256,
        }
        if include_digest:
            value["receipt_sha256"] = self.receipt_sha256
        return value


class WslSupervisor:
    """Launches cycles through the fixed trusted supervisor installed in WSL."""

    def __init__(
        self,
        distribution: str = "AEGIS-Sandbox",
        *,
        agent_path: str = "/usr/local/bin/aegis-supervisor-agent",
        transport: Transport | None = None,
        timeout_seconds: float = 3600.0,
    ) -> None:
        if _SAFE_DISTRIBUTION.fullmatch(distribution) is None:
            raise ValueError("unsafe WSL distribution name")
        if agent_path != "/usr/local/bin/aegis-supervisor-agent":
            raise ValueError("supervisor agent path is fixed by the host safety envelope")
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

    def launch_cycle(
        self,
        campaign_id: str,
        expected_commit: str,
        operation_id: str,
        request_payload: Mapping[str, Any],
    ) -> CycleLaunchReceipt:
        _text(campaign_id, "campaign_id", 512)
        _commit(expected_commit, "expected_commit")
        if _SAFE_OPERATION_ID.fullmatch(operation_id) is None:
            raise ValueError("operation_id is unsafe")
        payload = _validate_payload(request_payload)
        request = {
            "version": 1,
            "operation": "launch_cycle",
            "operation_id": operation_id,
            "campaign_id": campaign_id,
            "expected_commit": expected_commit,
            "request_payload": payload,
        }
        encoded = canonical_json(request).encode("utf-8")
        if len(encoded) > _MAX_REQUEST_BYTES:
            raise ValueError("cycle launch request exceeds its size limit")
        response = self._transport(request, self._timeout)
        if not isinstance(response, Mapping):
            raise WslSupervisorError("supervisor response must be an object")
        if response.get("ok") is not True:
            error = str(response.get("error", "SupervisorAgentError"))[:128]
            message = str(response.get("message", "cycle launch failed"))[:1024]
            raise WslSupervisorError(f"{error}: {message}")
        raw_receipt = response.get("receipt")
        if not isinstance(raw_receipt, Mapping):
            raise WslSupervisorError("supervisor omitted the launch receipt")
        receipt = CycleLaunchReceipt.from_mapping(cast(Mapping[str, Any], raw_receipt))
        if (
            receipt.operation_id != operation_id
            or receipt.campaign_id != campaign_id
            or receipt.executed_commit != expected_commit
            or receipt.request_sha256 != hashlib.sha256(encoded).hexdigest()
        ):
            raise WslSupervisorError("cycle launch receipt is bound to another request")
        return receipt

    def _wsl_transport(self, request: Mapping[str, Any], timeout: float) -> Mapping[str, Any]:
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
            raise WslSupervisorError(f"WSL supervisor transport failed: {exc}") from exc
        if len(result.stdout.encode("utf-8", errors="replace")) > _MAX_RESPONSE_BYTES:
            raise WslSupervisorError("WSL supervisor response exceeded its size limit")
        try:
            decoded = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise WslSupervisorError("WSL supervisor returned invalid JSON") from exc
        if not isinstance(decoded, Mapping):
            raise WslSupervisorError("WSL supervisor response must be an object")
        return cast(Mapping[str, Any], decoded)


def _validate_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError("request_payload must be an object")
    normalized = _json_value(value, depth=0)
    assert isinstance(normalized, dict)
    if len(canonical_json(normalized).encode("utf-8")) > 32_768:
        raise ValueError("request_payload exceeds its size limit")
    return normalized


def _json_value(value: object, *, depth: int) -> object:
    if depth > 8:
        raise ValueError("request_payload exceeds its nesting limit")
    if value is None or isinstance(value, (str, int, float, bool)):
        if isinstance(value, str) and ("\x00" in value or len(value.encode()) > 8192):
            raise ValueError("request_payload contains oversized or invalid text")
        if isinstance(value, float) and (value != value or abs(value) == float("inf")):
            raise ValueError("request_payload contains a non-finite number")
        return value
    if isinstance(value, Mapping):
        if len(value) > 128:
            raise ValueError("request_payload object is too large")
        result: dict[str, object] = {}
        forbidden = {"argv", "command", "cwd", "executable", "module", "path"}
        for key, item in value.items():
            if not isinstance(key, str) or not key or len(key.encode()) > 128:
                raise ValueError("request_payload keys must be bounded text")
            if key.casefold() in forbidden:
                raise ValueError(f"request_payload may not select {key!r}")
            result[key] = _json_value(item, depth=depth + 1)
        return result
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if len(value) > 256:
            raise ValueError("request_payload array is too large")
        return [_json_value(item, depth=depth + 1) for item in value]
    raise TypeError("request_payload must contain only JSON values")


def _text(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{name} must be non-empty text")
    if len(value.encode("utf-8")) > maximum:
        raise ValueError(f"{name} exceeds its size limit")
    return value


def _commit(value: object, name: str) -> str:
    if not isinstance(value, str) or _COMMIT.fullmatch(value) is None:
        raise ValueError(f"{name} must be a full Git commit id")
    return value


def _git_object(value: object, name: str) -> str:
    if not isinstance(value, str) or _GIT_OBJECT.fullmatch(value) is None:
        raise WslSupervisorError(f"{name} must be a full Git object id")
    return value


def _optional_commit(value: object, name: str) -> str | None:
    return None if value is None else _commit(value, name)


def _digest(value: object, name: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise WslSupervisorError(f"{name} must be a SHA-256 digest")
    return value


def _boolean(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise WslSupervisorError(f"{name} must be a boolean")
    return value


def _status(value: object) -> str:
    if value not in {"completed", "boot_failed", "failed"}:
        raise WslSupervisorError("invalid cycle launch status")
    assert isinstance(value, str)
    return value


def _optional_failure(value: object) -> str | None:
    if value is None:
        return None
    return _text(value, "failure_kind", 64)


def _optional_exit_code(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not -255 <= value <= 255:
        raise WslSupervisorError("exit_code is invalid")
    return value


def _bounded_summary(value: object) -> str:
    if not isinstance(value, str) or "\x00" in value or len(value.encode()) > 8192:
        raise WslSupervisorError("output_summary must be bounded text")
    return value


def _sha256(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
