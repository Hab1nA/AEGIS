"""Dependency-free gateway value objects."""

from __future__ import annotations

from dataclasses import dataclass, field
from threading import Event
from typing import Any, Mapping, Protocol


class GatewayError(RuntimeError):
    """Base model gateway error."""


class GatewayCancelled(GatewayError):
    """Raised when a caller cancels a request."""


class GatewayHTTPError(GatewayError):
    """HTTP failure with retry and fallback metadata."""

    def __init__(self, status: int, body: str, *, retryable: bool = False) -> None:
        super().__init__(f"model relay returned HTTP {status}")
        self.status = status
        self.body = body[:1000]
        self.retryable = retryable


class GatewayTruncationError(GatewayError):
    """The relay returned a successful HTTP response but the model output was cut off
    before a complete action could be produced (for example, a hidden-reasoning model
    consumed the whole output budget and left the content field empty).
    """

    def __init__(self, message: str, *, usage: TokenUsage | None = None) -> None:
        super().__init__(message)
        self.usage = usage


@dataclass(slots=True)
class CancelToken:
    _event: Event = field(default_factory=Event)

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def raise_if_cancelled(self) -> None:
        if self.cancelled:
            raise GatewayCancelled("model request cancelled")


@dataclass(frozen=True, slots=True)
class Message:
    role: str
    content: str

    def __post_init__(self) -> None:
        if self.role not in {"system", "developer", "user", "assistant"}:
            raise ValueError(f"unsupported message role: {self.role}")
        if not self.content:
            raise ValueError("message content must not be empty")


@dataclass(frozen=True, slots=True)
class GatewayRequest:
    model: str
    messages: tuple[Message, ...]
    max_output_tokens: int
    temperature: float = 0.0
    tools: tuple[Mapping[str, Any], ...] = ()
    output_schema: Mapping[str, Any] | None = None
    seed: int | None = None
    reasoning_effort: str | None = None

    def __post_init__(self) -> None:
        if not self.model or not self.messages:
            raise ValueError("model and messages are required")
        if self.max_output_tokens <= 0:
            raise ValueError("max_output_tokens must be positive")
        if not 0.0 <= self.temperature <= 2.0:
            raise ValueError("temperature must be between 0 and 2")
        if self.seed is not None and (
            isinstance(self.seed, bool)
            or not isinstance(self.seed, int)
            or not 0 <= self.seed <= 2_147_483_647
        ):
            raise ValueError("seed must be null or an integer in [0, 2147483647]")
        if self.reasoning_effort not in {None, "none", "low", "medium", "high"}:
            raise ValueError("unsupported reasoning_effort")


@dataclass(frozen=True, slots=True)
class TokenUsage:
    input_tokens: int
    output_tokens: int
    cached_tokens: int = 0
    reasoning_tokens: int = 0
    verified: bool = True

    def __post_init__(self) -> None:
        if min(self.input_tokens, self.output_tokens, self.cached_tokens, self.reasoning_tokens) < 0:
            raise ValueError("token counts cannot be negative")

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass(frozen=True, slots=True)
class GatewayResponse:
    text: str
    usage: TokenUsage
    protocol: str
    request_id: str | None = None
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False)
    status: int = 200

    def __post_init__(self) -> None:
        if not 100 <= self.status <= 299:
            raise ValueError("gateway response status must be successful")


@dataclass(frozen=True, slots=True)
class GatewayAttempt:
    """One transport attempt, exposed before any network I/O for reservation."""

    protocol: str
    attempt_number: int
    request: GatewayRequest
    conservative_usage: TokenUsage

    def __post_init__(self) -> None:
        if self.protocol not in {"responses", "chat"}:
            raise ValueError("unsupported gateway attempt protocol")
        if self.attempt_number < 1:
            raise ValueError("attempt_number must be positive")
        if self.conservative_usage.verified:
            raise ValueError("conservative attempt usage must be unverified")


@dataclass(frozen=True, slots=True)
class GatewayAttemptResult:
    """Accounting result emitted exactly once after a started HTTP attempt."""

    succeeded: bool
    usage: TokenUsage
    status: int | None = None
    error_type: str | None = None

    def __post_init__(self) -> None:
        if self.status is not None and not 100 <= self.status <= 599:
            raise ValueError("attempt status is invalid")
        if self.succeeded:
            if self.error_type is not None:
                raise ValueError("successful attempt cannot have an error_type")
        elif not self.error_type:
            raise ValueError("failed attempt requires error_type")


class GatewayAttemptObserver(Protocol):
    """Transactional hook used by the controller for per-attempt accounting.

    ``before_attempt`` runs before transport I/O and may raise to deny the
    attempt. If it returns, ``after_attempt`` is called exactly once, including
    for HTTP, network, cancellation, decoding, and response-schema failures.
    """

    def before_attempt(self, attempt: GatewayAttempt) -> None: ...

    def after_attempt(self, attempt: GatewayAttempt, result: GatewayAttemptResult) -> None: ...
