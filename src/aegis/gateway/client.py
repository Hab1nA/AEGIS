"""DeepSeek native Responses API gateway forcing json_object output."""

from __future__ import annotations

import ipaddress
import json
import math
import os
import socket
import time
import urllib.error
import urllib.parse
from dataclasses import dataclass
from typing import Callable, Mapping, cast

from .transport import HTTPTransport, StdlibHTTPTransport
from .types import (
    CancelToken,
    GatewayAttempt,
    GatewayAttemptObserver,
    GatewayAttemptResult,
    GatewayError,
    GatewayHTTPError,
    GatewayRequest,
    GatewayResponse,
    GatewayTruncationError,
    TokenUsage,
)


@dataclass(frozen=True, slots=True)
class GatewayConfig:
    base_url: str
    api_key: str
    timeout_seconds: float = 900.0
    allow_insecure_loopback: bool = False

    def __post_init__(self) -> None:
        parsed = urllib.parse.urlsplit(self.base_url)
        if parsed.scheme not in {"https", "http"} or not parsed.hostname:
            raise ValueError("base_url must be an HTTP(S) URL with a host")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("base_url must not contain credentials")
        if parsed.scheme == "http":
            loopback = parsed.hostname.lower() == "localhost"
            if not loopback:
                try:
                    loopback = ipaddress.ip_address(parsed.hostname).is_loopback
                except ValueError:
                    loopback = False
            if not (self.allow_insecure_loopback and loopback):
                raise ValueError(
                    "base_url must use HTTPS; insecure HTTP is allowed only for explicit loopback development"
                )
        if not self.api_key.strip():
            raise ValueError("api_key must not be empty")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")

    def __repr__(self) -> str:
        return (
            f"GatewayConfig(base_url={self.base_url!r}, api_key='<redacted>', "
            f"timeout_seconds={self.timeout_seconds!r}, "
            f"allow_insecure_loopback={self.allow_insecure_loopback!r})"
        )

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> GatewayConfig:
        source = os.environ if env is None else env
        base_url = source.get("AEGIS_OPENAI_BASE_URL", "").strip().rstrip("/")
        api_key = source.get("AEGIS_OPENAI_API_KEY", "").strip()
        missing = [
            name
            for name, value in (
                ("AEGIS_OPENAI_BASE_URL", base_url),
                ("AEGIS_OPENAI_API_KEY", api_key),
            )
            if not value
        ]
        if missing:
            raise ValueError(f"missing required environment variable(s): {', '.join(missing)}")
        raw_timeout = source.get("AEGIS_OPENAI_TIMEOUT_SECONDS", "900")
        try:
            timeout = float(raw_timeout)
        except ValueError as exc:
            raise ValueError("AEGIS_OPENAI_TIMEOUT_SECONDS must be numeric") from exc
        raw_insecure = source.get("AEGIS_ALLOW_INSECURE_LOOPBACK", "false").strip().lower()
        if raw_insecure not in {"true", "false"}:
            raise ValueError("AEGIS_ALLOW_INSECURE_LOOPBACK must be true or false")
        return cls(
            base_url,
            api_key,
            timeout,
            raw_insecure == "true",
        )


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    max_attempts: int = 6
    base_delay_seconds: float = 0.5
    max_delay_seconds: float = 4.0

    def __post_init__(self) -> None:
        if self.max_attempts < 1 or self.base_delay_seconds < 0 or self.max_delay_seconds < 0:
            raise ValueError("invalid retry policy")


_RESPONSES_PATH = "/responses"
_DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)


def _user_agent() -> str:
    """Browser-like identity for Cloudflare-fronted relays; overridable."""
    return os.environ.get("AEGIS_OPENAI_USER_AGENT") or _DEFAULT_USER_AGENT
# 5xx (including 501) is always retryable, matching the transport layer.
_NON_RETRYABLE_STATUSES = frozenset({400, 404, 405, 415, 422})


class ModelGateway:
    def __init__(
        self,
        config: GatewayConfig,
        *,
        transport: HTTPTransport | None = None,
        retry: RetryPolicy | None = None,
        sleeper: Callable[[float], None] = time.sleep,
        attempt_observer: GatewayAttemptObserver | None = None,
    ) -> None:
        self._config = config
        self._transport = transport or StdlibHTTPTransport()
        self._retry = retry or RetryPolicy()
        self._sleep = sleeper
        self._attempt_observer = attempt_observer
        self._runtime_policy_provider: Callable[[], Mapping[str, object]] | None = None

    def complete(self, request: GatewayRequest, *, cancel: CancelToken | None = None) -> GatewayResponse:
        token = cancel or CancelToken()
        retry = self._retry
        timeout = self._config.timeout_seconds
        if self._runtime_policy_provider is not None:
            values = self._runtime_policy_provider()
            retry = RetryPolicy(
                max_attempts=int(cast(int, values["gateway_max_attempts"])),
                base_delay_seconds=float(cast(float | int, values["gateway_base_delay_seconds"])),
                max_delay_seconds=float(cast(float | int, values["gateway_max_delay_seconds"])),
            )
            timeout = float(cast(float | int, values["gateway_timeout_seconds"]))
        return self._call_with_retry(request, token, retry=retry, timeout_seconds=timeout)

    def bind_runtime_policy_provider(
        self, provider: Callable[[], Mapping[str, object]]
    ) -> None:
        if not callable(provider):
            raise TypeError("runtime policy provider must be callable")
        if self._runtime_policy_provider is not None:
            raise RuntimeError("gateway runtime policy provider is already bound")
        self._runtime_policy_provider = provider

    def bind_attempt_observer(self, observer: GatewayAttemptObserver) -> None:
        """Bind accounting exactly once before the gateway is used.

        Replacing an observer could create unaccounted attempts or commit one
        attempt into two campaigns, so rebinding is always rejected. Passing an
        invalid object also fails before any HTTP request is possible.
        """
        if not callable(getattr(observer, "before_attempt", None)) or not callable(
            getattr(observer, "after_attempt", None)
        ):
            raise TypeError("attempt observer must implement before_attempt and after_attempt")
        if self._attempt_observer is not None:
            raise RuntimeError("gateway attempt observer is already bound")
        self._attempt_observer = observer

    def _call_with_retry(
        self,
        request: GatewayRequest,
        cancel: CancelToken,
        *,
        retry: RetryPolicy,
        timeout_seconds: float,
    ) -> GatewayResponse:
        last_error: BaseException | None = None
        for attempt in range(retry.max_attempts):
            cancel.raise_if_cancelled()
            lifecycle = GatewayAttempt(
                "responses",
                attempt + 1,
                request,
                self._conservative_attempt_usage(request),
            )
            if self._attempt_observer is not None:
                self._attempt_observer.before_attempt(lifecycle)
            try:
                result = self._call(request, cancel, timeout_seconds=timeout_seconds)
            except GatewayHTTPError as exc:
                self._finish_attempt(lifecycle, None, exc)
                last_error = exc
                if not exc.retryable or attempt + 1 >= retry.max_attempts:
                    raise
            except (
                urllib.error.URLError,
                TimeoutError,
                socket.timeout,
                ConnectionError,
                # Windows can surface transient local socket/provider failures
                # (for example FileNotFoundError from getaddrinfo during a DNS
                # service blip) as bare OSError instances.  Nothing in the HTTP
                # transport legitimately touches the filesystem, so retrying
                # OSError keeps a single OS-level flap from killing a campaign.
                OSError,
            ) as exc:
                self._finish_attempt(lifecycle, None, exc)
                last_error = exc
                if attempt + 1 >= retry.max_attempts:
                    raise GatewayError("model relay unavailable after retries") from exc
            except GatewayTruncationError as exc:
                self._finish_attempt(lifecycle, None, exc)
                last_error = exc
                if attempt + 1 >= retry.max_attempts:
                    raise
            except Exception as exc:
                self._finish_attempt(lifecycle, None, exc)
                raise
            else:
                self._finish_attempt(lifecycle, result, None)
                return result
            delay = min(retry.max_delay_seconds, retry.base_delay_seconds * (2**attempt))
            cancel.raise_if_cancelled()
            self._sleep(delay)
        raise GatewayError("model request failed") from last_error

    def _call(
        self,
        request: GatewayRequest,
        cancel: CancelToken,
        *,
        timeout_seconds: float,
    ) -> GatewayResponse:
        payload = self._payload(request)
        response = self._transport.post(
            f"{self._config.base_url}{_RESPONSES_PATH}",
            headers={
                "Authorization": f"Bearer {self._config.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": _user_agent(),
            },
            body=json.dumps(payload, separators=(",", ":")).encode(),
            timeout=timeout_seconds,
            cancel=cancel,
        )
        if response.status >= 300:
            body = response.body.decode("utf-8", "replace")
            raise GatewayHTTPError(
                response.status,
                body,
                retryable=(
                    response.status in {408, 409, 429}
                    or response.status >= 500
                    and response.status not in _NON_RETRYABLE_STATUSES
                ),
            )
        try:
            data = json.loads(response.body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GatewayError("model relay returned invalid JSON") from exc
        if self._is_truncated(data):
            usage = self._extract_usage(data, request, "")
            raise GatewayTruncationError(
                "model response was truncated before a complete JSON action was produced",
                usage=usage,
            )
        text = self._extract_text(data)
        usage = self._extract_usage(data, request, text)
        return GatewayResponse(
            text, usage, "responses", response.headers.get("x-request-id"), data, response.status
        )

    @staticmethod
    def _is_truncated(data: Mapping[str, object]) -> bool:
        """Detect outputs cut short by the native Responses API.

        An unfinished response carries ``status: "incomplete"`` and/or an
        ``incomplete_details`` payload; it must never be handed back as model
        output because it cannot contain a complete JSON action.
        """
        incomplete = data.get("incomplete_details")
        return data.get("status") == "incomplete" or (
            isinstance(incomplete, Mapping) and bool(incomplete)
        )

    @staticmethod
    def _conservative_attempt_usage(request: GatewayRequest) -> TokenUsage:
        # UTF-8 bytes are a safe tokenizer-independent upper bound for input;
        # compatibility relays may report prompt or hidden-reasoning volume in
        # completion dimensions, so reserve the same combined upper bound used
        # by the controller's legacy request-level accounting path.
        input_upper = sum(len(message.content.encode("utf-8")) for message in request.messages)
        output_upper = input_upper + request.max_output_tokens
        return TokenUsage(
            input_upper,
            output_upper,
            cached_tokens=input_upper,
            reasoning_tokens=output_upper,
            verified=False,
        )

    def _finish_attempt(
        self,
        attempt: GatewayAttempt,
        response: GatewayResponse | None,
        error: Exception | None,
    ) -> None:
        if self._attempt_observer is None:
            return
        if response is not None:
            result = GatewayAttemptResult(True, response.usage, status=response.status)
        else:
            assert error is not None
            status = error.status if isinstance(error, GatewayHTTPError) else None
            result = GatewayAttemptResult(
                False,
                attempt.conservative_usage,
                status=status,
                error_type=type(error).__name__,
            )
        self._attempt_observer.after_attempt(attempt, result)

    @staticmethod
    def _payload(request: GatewayRequest) -> dict[str, object]:
        payload: dict[str, object] = {
            "model": request.model,
            "input": [{"role": m.role, "content": m.content} for m in request.messages],
            "max_output_tokens": request.max_output_tokens,
            "temperature": request.temperature,
        }
        if request.tools:
            payload["tools"] = list(request.tools)
        payload["text"] = {"format": {"type": "json_object"}}
        if request.seed is not None:
            payload["seed"] = request.seed
        if request.reasoning_effort is not None:
            payload["reasoning_effort"] = request.reasoning_effort
        return payload

    @staticmethod
    def _extract_text(data: Mapping[str, object]) -> str:
        try:
            if isinstance(data.get("output_text"), str):
                text = data["output_text"]
            else:
                output = data["output"]
                assert isinstance(output, list)
                # Reasoning items precede the final message; output_text may be
                # absent.  Take the last message item's text, falling back to
                # the first text item.
                text = ""
                first_text = ""
                for item in reversed(output):
                    if not isinstance(item, Mapping):
                        continue
                    content = item.get("content")
                    if not isinstance(content, list) or not content:
                        continue
                    candidate = content[0]
                    candidate_text = (
                        candidate.get("text")
                        if isinstance(candidate, Mapping)
                        else None
                    )
                    if not isinstance(candidate_text, str) or not candidate_text:
                        continue
                    if not first_text:
                        first_text = candidate_text
                    if item.get("type") == "message":
                        text = candidate_text
                        break
                if not text:
                    text = first_text
            if not text:
                raise GatewayError("model relay response contains no text output")
            if not isinstance(text, str):
                raise TypeError
            return text
        except (KeyError, IndexError, TypeError, AssertionError) as exc:
            raise GatewayError("model relay response contains no text output") from exc

    @staticmethod
    def _extract_usage(
        data: Mapping[str, object], request: GatewayRequest, text: str
    ) -> TokenUsage:
        usage = data.get("usage")
        if isinstance(usage, Mapping):
            input_tokens = usage.get("input_tokens")
            output_tokens = usage.get("output_tokens")
            if isinstance(input_tokens, int) and isinstance(output_tokens, int):
                cached = 0
                reasoning = 0
                details = usage.get("input_tokens_details")
                if isinstance(details, Mapping) and isinstance(details.get("cached_tokens"), int):
                    cached = int(details["cached_tokens"])
                out_details = usage.get("output_tokens_details")
                if isinstance(out_details, Mapping) and isinstance(out_details.get("reasoning_tokens"), int):
                    reasoning = int(out_details["reasoning_tokens"])
                return TokenUsage(input_tokens, output_tokens, cached, reasoning, True)
        # Conservative, explicitly unverified approximation for relays omitting usage.
        input_chars = sum(len(m.content) for m in request.messages)
        return TokenUsage(math.ceil(input_chars / 3), math.ceil(len(text) / 3), verified=False)
