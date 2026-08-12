"""OpenAI-compatible Responses-first gateway with Chat fallback."""

from __future__ import annotations

import ipaddress
import json
import math
import os
import socket
import time
import urllib.error
import urllib.parse
from dataclasses import dataclass, replace
from threading import RLock
from typing import Callable, Literal, Mapping, cast

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
    protocol: Literal["auto", "responses", "chat"] = "auto"
    structured_format: Literal["auto", "json_schema", "json_object"] = "auto"

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
        if self.protocol not in {"auto", "responses", "chat"}:
            raise ValueError("protocol must be 'auto', 'responses', or 'chat'")
        if self.structured_format not in {"auto", "json_schema", "json_object"}:
            raise ValueError("structured_format must be 'auto', 'json_schema', or 'json_object'")

    def __repr__(self) -> str:
        return (
            f"GatewayConfig(base_url={self.base_url!r}, api_key='<redacted>', "
            f"timeout_seconds={self.timeout_seconds!r}, "
            f"allow_insecure_loopback={self.allow_insecure_loopback!r}, "
            f"protocol={self.protocol!r}, "
            f"structured_format={self.structured_format!r})"
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
        protocol = source.get("AEGIS_OPENAI_PROTOCOL", "auto").strip().lower()
        if protocol not in {"auto", "responses", "chat"}:
            raise ValueError("AEGIS_OPENAI_PROTOCOL must be auto, responses, or chat")
        checked_protocol = cast(Literal["auto", "responses", "chat"], protocol)
        structured_format = source.get("AEGIS_OPENAI_STRUCTURED_FORMAT", "auto").strip().lower()
        if structured_format not in {"auto", "json_schema", "json_object"}:
            raise ValueError("AEGIS_OPENAI_STRUCTURED_FORMAT must be auto, json_schema, or json_object")
        checked_format = cast(Literal["auto", "json_schema", "json_object"], structured_format)
        return cls(
            base_url,
            api_key,
            timeout,
            raw_insecure == "true",
            checked_protocol,
            checked_format,
        )


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    max_attempts: int = 6
    base_delay_seconds: float = 0.5
    max_delay_seconds: float = 4.0

    def __post_init__(self) -> None:
        if self.max_attempts < 1 or self.base_delay_seconds < 0 or self.max_delay_seconds < 0:
            raise ValueError("invalid retry policy")


_GatewayMode = Literal["responses", "chat_json_schema", "chat_json_object", "chat_plain"]
_ENDPOINT_CAPABILITY_STATUSES = frozenset({400, 404, 405, 415, 422, 501})
_FORMAT_CAPABILITY_STATUSES = frozenset({400, 415, 422})


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
        self._capability_lock = RLock()
        self._preferred_modes: dict[bool, _GatewayMode] = {}

    def complete(self, request: GatewayRequest, *, cancel: CancelToken | None = None) -> GatewayResponse:
        token = cancel or CancelToken()
        structured = request.output_schema is not None
        # Capability discovery mutates per-instance state. Serializing it also
        # prevents concurrent first calls from repeating expensive probes. An
        # RLock avoids deadlock if an observer performs a diagnostic re-entry.
        with self._capability_lock:
            preferred = self._preferred_modes.get(structured)
            if preferred is not None:
                try:
                    return self._call_mode(preferred, request, token)
                except GatewayHTTPError as exc:
                    if not self._is_capability_failure(preferred, exc):
                        raise
                    self._preferred_modes.pop(structured, None)

            modes = list(self._candidate_modes(structured))
            if preferred is not None:
                # The cached mode just failed. Reprobe every alternative before
                # retrying it once at the end in case the rejection was transient.
                modes = [mode for mode in modes if mode != preferred] + [preferred]
            for index, mode in enumerate(modes):
                try:
                    response = self._call_mode(mode, request, token)
                except GatewayHTTPError as exc:
                    if index + 1 >= len(modes) or not self._is_capability_failure(mode, exc):
                        raise
                    continue
                self._preferred_modes[structured] = mode
                return response
        raise GatewayError("model request failed without a gateway mode")

    def _candidate_modes(self, structured: bool) -> tuple[_GatewayMode, ...]:
        if self._config.protocol == "responses":
            return ("responses",)
        chat_structured: tuple[_GatewayMode, ...] = (
            ("chat_json_object", "chat_json_schema", "chat_plain")
            if self._config.structured_format == "json_object"
            else ("chat_json_schema", "chat_json_object", "chat_plain")
        )
        if self._config.protocol == "chat":
            return chat_structured if structured else ("chat_plain",)
        if structured:
            return ("responses", *chat_structured)
        return ("responses", "chat_plain")

    @staticmethod
    def _is_capability_failure(mode: _GatewayMode, error: GatewayHTTPError) -> bool:
        statuses = (
            _FORMAT_CAPABILITY_STATUSES
            if mode in {"chat_json_schema", "chat_json_object"}
            else _ENDPOINT_CAPABILITY_STATUSES
        )
        return error.status in statuses

    def _call_mode(
        self,
        mode: _GatewayMode,
        request: GatewayRequest,
        token: CancelToken,
    ) -> GatewayResponse:
        if mode == "responses":
            return self._call_with_retry(
                "responses",
                request,
                token,
                responses_json_object=(
                    self._config.structured_format == "json_object"
                ),
            )
        if mode == "chat_json_schema":
            return self._call_with_retry("chat", request, token)
        if mode == "chat_json_object":
            return self._call_with_retry("chat", request, token, chat_json_object=True)
        return self._call_with_retry("chat", replace(request, output_schema=None), token)

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
        with self._capability_lock:
            if self._attempt_observer is not None:
                raise RuntimeError("gateway attempt observer is already bound")
            self._attempt_observer = observer

    def _call_with_retry(
        self,
        protocol: str,
        request: GatewayRequest,
        cancel: CancelToken,
        *,
        chat_json_object: bool = False,
        responses_json_object: bool = False,
    ) -> GatewayResponse:
        last_error: BaseException | None = None
        for attempt in range(self._retry.max_attempts):
            cancel.raise_if_cancelled()
            lifecycle = GatewayAttempt(
                protocol,
                attempt + 1,
                request,
                self._conservative_attempt_usage(request),
            )
            if self._attempt_observer is not None:
                self._attempt_observer.before_attempt(lifecycle)
            try:
                result = self._call(
                    protocol,
                    request,
                    cancel,
                    chat_json_object=chat_json_object,
                    responses_json_object=responses_json_object,
                )
            except GatewayHTTPError as exc:
                self._finish_attempt(lifecycle, None, exc)
                last_error = exc
                if not exc.retryable or attempt + 1 >= self._retry.max_attempts:
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
                if attempt + 1 >= self._retry.max_attempts:
                    raise GatewayError("model relay unavailable after retries") from exc
            except GatewayTruncationError as exc:
                self._finish_attempt(lifecycle, None, exc)
                last_error = exc
                if attempt + 1 >= self._retry.max_attempts:
                    raise
            except Exception as exc:
                self._finish_attempt(lifecycle, None, exc)
                raise
            else:
                self._finish_attempt(lifecycle, result, None)
                return result
            delay = min(self._retry.max_delay_seconds, self._retry.base_delay_seconds * (2**attempt))
            cancel.raise_if_cancelled()
            self._sleep(delay)
        raise GatewayError("model request failed") from last_error

    def _call(
        self,
        protocol: str,
        request: GatewayRequest,
        cancel: CancelToken,
        *,
        chat_json_object: bool = False,
        responses_json_object: bool = False,
    ) -> GatewayResponse:
        if protocol == "responses":
            path = "/responses"
            payload = self._responses_payload(
                request, json_object=responses_json_object
            )
        else:
            path = "/chat/completions"
            payload = self._chat_payload(request, json_object=chat_json_object)
        response = self._transport.post(
            f"{self._config.base_url}{path}",
            headers={
                "Authorization": f"Bearer {self._config.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "AEGIS/0.1",
            },
            body=json.dumps(payload, separators=(",", ":")).encode(),
            timeout=self._config.timeout_seconds,
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
                    and response.status not in _ENDPOINT_CAPABILITY_STATUSES
                ),
            )
        try:
            data = json.loads(response.body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GatewayError("model relay returned invalid JSON") from exc
        if self._is_truncated(protocol, data):
            usage = self._extract_usage(protocol, data, request, "")
            raise GatewayTruncationError(
                "model relay response was truncated before a complete JSON action was produced",
                usage=usage,
            )
        text = self._extract_text(protocol, data)
        usage = self._extract_usage(protocol, data, request, text)
        return GatewayResponse(
            text, usage, protocol, response.headers.get("x-request-id"), data, response.status
        )

    @staticmethod
    def _is_truncated(protocol: str, data: Mapping[str, object]) -> bool:
        """Detect outputs cut short by the relay's own token budget.

        Hidden-reasoning relays may consume every completion token on
        ``reasoning_content`` and return an empty ``content`` field with
        ``finish_reason: "length"``.  Such a body is a successful HTTP response
        but cannot be parsed as an action, so it must never be handed back as
        model output.
        """
        if protocol != "chat":
            return False
        try:
            choices = data["choices"]
            assert isinstance(choices, list) and choices
            choice = choices[0]
            assert isinstance(choice, Mapping)
            finish = choice.get("finish_reason")
            if isinstance(finish, str) and finish.lower() == "length":
                return True
            message = choice.get("message")
            if not isinstance(message, Mapping):
                return False
            content = message.get("content")
            if not (isinstance(content, str) and content.strip()):
                usage = data.get("usage")
                if isinstance(usage, Mapping) and isinstance(usage.get("completion_tokens"), int):
                    return True
        except (KeyError, IndexError, TypeError, AssertionError):
            return False
        return False

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
    def _responses_payload(
        request: GatewayRequest, *, json_object: bool = False
    ) -> dict[str, object]:
        payload: dict[str, object] = {
            "model": request.model,
            "input": [{"role": m.role, "content": m.content} for m in request.messages],
            "max_output_tokens": request.max_output_tokens,
            "temperature": request.temperature,
        }
        if request.tools:
            payload["tools"] = list(request.tools)
        if request.output_schema:
            if json_object:
                payload["text"] = {"format": {"type": "json_object"}}
            else:
                payload["text"] = {
                    "format": {
                        "type": "json_schema",
                        "name": "role_output",
                        "strict": True,
                        "schema": request.output_schema,
                    }
                }
        if request.seed is not None:
            payload["seed"] = request.seed
        if request.reasoning_effort is not None:
            payload["reasoning_effort"] = request.reasoning_effort
        return payload

    @staticmethod
    def _chat_payload(
        request: GatewayRequest,
        *,
        json_object: bool = False,
    ) -> dict[str, object]:
        payload: dict[str, object] = {
            "model": request.model,
            "messages": [{"role": m.role, "content": m.content} for m in request.messages],
            "max_tokens": request.max_output_tokens,
            "temperature": request.temperature,
        }
        if request.tools:
            payload["tools"] = list(request.tools)
        if request.output_schema and json_object:
            payload["response_format"] = {"type": "json_object"}
        elif request.output_schema:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "role_output", "strict": True, "schema": request.output_schema},
            }
        if request.seed is not None:
            payload["seed"] = request.seed
        if request.reasoning_effort is not None:
            payload["reasoning_effort"] = request.reasoning_effort
        return payload

    @staticmethod
    def _extract_text(protocol: str, data: Mapping[str, object]) -> str:
        try:
            if protocol == "chat":
                choices = data["choices"]
                assert isinstance(choices, list)
                message = choices[0]["message"]
                text = message["content"]
            else:
                if isinstance(data.get("output_text"), str):
                    text = data["output_text"]
                else:
                    output = data["output"]
                    assert isinstance(output, list)
                    # Hidden-reasoning relays emit a reasoning item before the
                    # final message; output_text may be absent.  Take the last
                    # message item's text, falling back to the first text item.
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
            if not isinstance(text, str):
                raise TypeError
            return text
        except (KeyError, IndexError, TypeError, AssertionError) as exc:
            raise GatewayError("model relay response contains no text output") from exc

    @staticmethod
    def _extract_usage(
        protocol: str, data: Mapping[str, object], request: GatewayRequest, text: str
    ) -> TokenUsage:
        usage = data.get("usage")
        if isinstance(usage, Mapping):
            input_key = "input_tokens" if protocol == "responses" else "prompt_tokens"
            output_key = "output_tokens" if protocol == "responses" else "completion_tokens"
            input_tokens = usage.get(input_key)
            output_tokens = usage.get(output_key)
            if isinstance(input_tokens, int) and isinstance(output_tokens, int):
                cached = 0
                reasoning = 0
                details = usage.get("input_tokens_details") or usage.get("prompt_tokens_details")
                if isinstance(details, Mapping) and isinstance(details.get("cached_tokens"), int):
                    cached = int(details["cached_tokens"])
                out_details = usage.get("output_tokens_details") or usage.get("completion_tokens_details")
                if isinstance(out_details, Mapping) and isinstance(out_details.get("reasoning_tokens"), int):
                    reasoning = int(out_details["reasoning_tokens"])
                return TokenUsage(input_tokens, output_tokens, cached, reasoning, True)
        # Conservative, explicitly unverified approximation for relays omitting usage.
        input_chars = sum(len(m.content) for m in request.messages)
        return TokenUsage(math.ceil(input_chars / 3), math.ceil(len(text) / 3), verified=False)
