from __future__ import annotations

import http.client
import io
import json
import socket
import time
import unittest
import urllib.error
from unittest.mock import patch

from aegis.gateway.client import GatewayConfig, ModelGateway, RetryPolicy
from aegis.gateway.protocols import Role, RolePolicy, build_role_request, parse_role_output
from aegis.gateway.transport import HTTPResponse, StdlibHTTPTransport
from aegis.gateway.types import (
    CancelToken,
    GatewayAttempt,
    GatewayAttemptResult,
    GatewayCancelled,
    GatewayHTTPError,
    GatewayRequest,
    GatewayTruncationError,
    Message,
)


class FakeTransport:
    def __init__(self, outcomes: list[object]) -> None:
        self.outcomes = outcomes
        self.calls: list[tuple[str, dict[str, str], dict[str, object]]] = []

    def post(self, url, *, headers, body, timeout, cancel):
        cancel.raise_if_cancelled()
        self.calls.append((url, dict(headers), json.loads(body)))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


class RecordingObserver:
    def __init__(self) -> None:
        self.started: list[GatewayAttempt] = []
        self.finished: list[tuple[GatewayAttempt, GatewayAttemptResult]] = []

    def before_attempt(self, attempt: GatewayAttempt) -> None:
        self.started.append(attempt)

    def after_attempt(self, attempt: GatewayAttempt, result: GatewayAttemptResult) -> None:
        self.finished.append((attempt, result))


def response(data: dict[str, object], status: int = 200) -> HTTPResponse:
    return HTTPResponse(status, json.dumps(data).encode(), {"x-request-id": "req-1"})


class GatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = GatewayConfig("https://relay.invalid/v1", "super-secret", 3)
        self.request = GatewayRequest("model-a", (Message("user", "hello"),), 100)

    def test_responses_is_preferred_and_usage_is_verified(self) -> None:
        transport = FakeTransport(
            [response({"output_text": "ok", "usage": {"input_tokens": 4, "output_tokens": 2}})]
        )
        result = ModelGateway(self.config, transport=transport).complete(self.request)
        self.assertEqual(result.protocol, "responses")
        self.assertEqual(result.usage.total_tokens, 6)
        self.assertTrue(result.usage.verified)
        self.assertTrue(transport.calls[0][0].endswith("/responses"))
        self.assertEqual(transport.calls[0][1]["Authorization"], "Bearer super-secret")

    def test_reasoning_effort_is_forwarded_to_responses_and_chat(self) -> None:
        request = GatewayRequest(
            "model-a", (Message("user", "hello"),), 100, reasoning_effort="low"
        )
        self.assertEqual(ModelGateway._responses_payload(request)["reasoning_effort"], "low")
        self.assertEqual(ModelGateway._chat_payload(request)["reasoning_effort"], "low")
        request_max = GatewayRequest(
            "model-a", (Message("user", "hello"),), 100, reasoning_effort="max"
        )
        self.assertEqual(
            ModelGateway._responses_payload(request_max)["reasoning_effort"], "max"
        )
        self.assertEqual(
            ModelGateway._chat_payload(request_max)["reasoning_effort"], "max"
        )
        with self.assertRaisesRegex(ValueError, "reasoning_effort"):
            GatewayRequest(
                "model-a", (Message("user", "hello"),), 100, reasoning_effort="unbounded"
            )

    def test_responses_json_object_structured_format_sends_json_object(self) -> None:
        config = GatewayConfig(
            "https://relay.invalid/v1",
            "secret",
            protocol="responses",
            structured_format="json_object",
        )
        transport = FakeTransport(
            [
                response(
                    {
                        "output_text": "{}",
                        "usage": {"input_tokens": 2, "output_tokens": 1},
                    }
                )
            ]
        )
        request = GatewayRequest(
            "model-a", (Message("user", "return JSON"),), 100, output_schema={"type": "object"}
        )
        result = ModelGateway(config, transport=transport).complete(request)
        self.assertEqual(result.protocol, "responses")
        self.assertTrue(transport.calls[0][0].endswith("/responses"))
        self.assertEqual(
            transport.calls[0][2]["text"],
            {"format": {"type": "json_object"}},
        )
        direct = ModelGateway._responses_payload(request, json_object=True)
        self.assertEqual(direct["text"], {"format": {"type": "json_object"}})

    def test_responses_extract_text_skips_reasoning_items(self) -> None:
        payload = {
            "output": [
                {
                    "type": "reasoning",
                    "content": [{"type": "reasoning_text", "text": "think think"}],
                },
                {
                    "type": "message",
                    "content": [
                        {
                            "type": "output_text",
                            "text": '{"action":"submit","arguments":{"summary":"OK"}}',
                        }
                    ],
                },
            ]
        }
        self.assertEqual(
            ModelGateway._extract_text("responses", payload),
            '{"action":"submit","arguments":{"summary":"OK"}}',
        )
        only_reasoning = {
            "output": [
                {
                    "type": "reasoning",
                    "content": [{"type": "reasoning_text", "text": "think"}],
                }
            ]
        }
        self.assertEqual(
            ModelGateway._extract_text("responses", only_reasoning),
            "think",
        )

    def test_unsupported_responses_falls_back_to_chat(self) -> None:
        transport = FakeTransport(
            [
                response({"error": "unsupported"}, 404),
                response(
                    {
                        "choices": [{"message": {"content": "fallback"}}],
                        "usage": {"prompt_tokens": 5, "completion_tokens": 2},
                    }
                ),
            ]
        )
        result = ModelGateway(self.config, transport=transport).complete(self.request)
        self.assertEqual(result.protocol, "chat")
        self.assertEqual(
            [call[0].rsplit("/", 1)[-1] for call in transport.calls], ["responses", "completions"]
        )

    def test_explicit_chat_protocol_skips_responses_probe(self) -> None:
        config = GatewayConfig("https://relay.invalid/v1", "secret", protocol="chat")
        transport = FakeTransport(
            [
                response(
                    {
                        "choices": [{"message": {"content": "{}"}}],
                        "usage": {"prompt_tokens": 2, "completion_tokens": 1},
                    }
                )
            ]
        )
        request = GatewayRequest(
            "model-a", (Message("user", "return JSON"),), 100, output_schema={"type": "object"}
        )
        result = ModelGateway(config, transport=transport).complete(request)
        self.assertEqual(result.protocol, "chat")
        self.assertTrue(transport.calls[0][0].endswith("/chat/completions"))

    def test_json_object_structured_format_skips_schema_probe(self) -> None:
        config = GatewayConfig(
            "https://relay.invalid/v1",
            "secret",
            protocol="chat",
            structured_format="json_object",
        )
        transport = FakeTransport(
            [
                response(
                    {
                        "choices": [{"message": {"content": "{}"}}],
                        "usage": {"prompt_tokens": 2, "completion_tokens": 1},
                    }
                )
            ]
        )
        request = GatewayRequest(
            "model-a", (Message("user", "return JSON"),), 100, output_schema={"type": "object"}
        )

        result = ModelGateway(config, transport=transport).complete(request)

        self.assertEqual(result.text, "{}")
        self.assertEqual(len(transport.calls), 1)
        self.assertTrue(transport.calls[0][0].endswith("/chat/completions"))
        self.assertEqual(transport.calls[0][2]["response_format"], {"type": "json_object"})

    def test_finish_reason_length_raises_gateway_truncation_error(self) -> None:
        config = GatewayConfig("https://relay.invalid/v1", "secret", protocol="chat")
        transport = FakeTransport(
            [
                response(
                    {
                        "choices": [
                            {
                                "message": {"content": "", "reasoning_content": "thinking"},
                                "finish_reason": "length",
                            }
                        ],
                        "usage": {"prompt_tokens": 5, "completion_tokens": 200},
                    }
                )
            ]
        )
        request = GatewayRequest(
            "model-a", (Message("user", "return JSON"),), 100, output_schema={"type": "object"}
        )

        with self.assertRaises(GatewayTruncationError) as raised:
            ModelGateway(config, transport=transport).complete(request)

        self.assertIsNotNone(raised.exception.usage)
        self.assertEqual(raised.exception.usage.output_tokens, 200)

    def test_empty_content_with_full_usage_raises_gateway_truncation_error(self) -> None:
        config = GatewayConfig("https://relay.invalid/v1", "secret", protocol="chat")
        transport = FakeTransport(
            [
                response(
                    {
                        "choices": [{"message": {"content": ""}}],
                        "usage": {"prompt_tokens": 5, "completion_tokens": 100},
                    }
                )
            ]
        )
        request = GatewayRequest(
            "model-a", (Message("user", "return JSON"),), 100, output_schema={"type": "object"}
        )

        with self.assertRaises(GatewayTruncationError):
            ModelGateway(config, transport=transport).complete(request)

    def test_explicit_responses_protocol_does_not_fallback(self) -> None:
        config = GatewayConfig("https://relay.invalid/v1", "secret", protocol="responses")
        transport = FakeTransport([response({"error": "unsupported"}, 400)])
        with self.assertRaises(GatewayHTTPError):
            ModelGateway(config, transport=transport).complete(self.request)
        self.assertEqual(len(transport.calls), 1)

    def test_not_implemented_falls_back_without_retrying_the_unsupported_mode(self) -> None:
        transport = FakeTransport(
            [
                response({"error": "not implemented"}, 501),
                response(
                    {
                        "choices": [{"message": {"content": "fallback"}}],
                        "usage": {"prompt_tokens": 5, "completion_tokens": 2},
                    }
                ),
            ]
        )
        result = ModelGateway(self.config, transport=transport).complete(self.request)
        self.assertEqual(result.protocol, "chat")
        self.assertEqual(len(transport.calls), 2)

    def test_unsupported_json_schema_falls_back_to_json_object_and_accounts_attempts(self) -> None:
        observer = RecordingObserver()
        request = GatewayRequest(
            "model-a",
            (Message("user", "return JSON"),),
            100,
            output_schema={"type": "object", "additionalProperties": False},
        )
        transport = FakeTransport(
            [
                response({"error": "responses unsupported"}, 400),
                response({"error": "json_schema unsupported"}, 400),
                response(
                    {
                        "choices": [{"message": {"content": "{}"}}],
                        "usage": {"prompt_tokens": 2, "completion_tokens": 1},
                    }
                ),
            ]
        )

        result = ModelGateway(
            self.config,
            transport=transport,
            attempt_observer=observer,
        ).complete(request)

        self.assertEqual(result.text, "{}")
        self.assertEqual([item.protocol for item in observer.started], ["responses", "chat", "chat"])
        self.assertEqual(transport.calls[1][2]["response_format"]["type"], "json_schema")
        self.assertEqual(transport.calls[2][2]["response_format"], {"type": "json_object"})
        self.assertEqual([item.succeeded for _, item in observer.finished], [False, False, True])

    def test_unsupported_json_object_finally_falls_back_to_plain_chat(self) -> None:
        request = GatewayRequest(
            "model-a",
            (Message("user", "return JSON"),),
            100,
            output_schema={"type": "object"},
        )
        transport = FakeTransport(
            [
                response({"error": "responses unsupported"}, 400),
                response({"error": "json_schema unsupported"}, 400),
                response({"error": "json_object unsupported"}, 400),
                response(
                    {
                        "choices": [{"message": {"content": "{}"}}],
                        "usage": {"prompt_tokens": 2, "completion_tokens": 1},
                    }
                ),
            ]
        )

        result = ModelGateway(self.config, transport=transport).complete(request)

        self.assertEqual(result.text, "{}")
        self.assertNotIn("response_format", transport.calls[3][2])

    def test_successful_fallback_mode_is_cached_for_later_requests(self) -> None:
        request = GatewayRequest(
            "model-a",
            (Message("user", "return JSON"),),
            100,
            output_schema={"type": "object"},
        )
        plain = {
            "choices": [{"message": {"content": "{}"}}],
            "usage": {"prompt_tokens": 2, "completion_tokens": 1},
        }
        transport = FakeTransport(
            [
                response({"error": "responses unsupported"}, 400),
                response({"error": "json_schema unsupported"}, 400),
                response({"error": "json_object unsupported"}, 400),
                response(plain),
                response(plain),
            ]
        )
        gateway = ModelGateway(self.config, transport=transport)

        self.assertEqual(gateway.complete(request).text, "{}")
        self.assertEqual(gateway.complete(request).text, "{}")

        self.assertEqual(len(transport.calls), 5)
        self.assertNotIn("response_format", transport.calls[-1][2])

    def test_cached_capability_failure_reprobes_and_replaces_mode(self) -> None:
        request = GatewayRequest(
            "model-a",
            (Message("user", "return JSON"),),
            100,
            output_schema={"type": "object"},
        )
        plain = {
            "choices": [{"message": {"content": "{}"}}],
            "usage": {"prompt_tokens": 2, "completion_tokens": 1},
        }
        responses = {"output_text": "{}", "usage": {"input_tokens": 2, "output_tokens": 1}}
        transport = FakeTransport(
            [
                response({"error": "responses unsupported"}, 400),
                response({"error": "json_schema unsupported"}, 400),
                response({"error": "json_object unsupported"}, 400),
                response(plain),
                response({"error": "plain chat capability changed"}, 400),
                response(responses),
                response(responses),
            ]
        )
        gateway = ModelGateway(self.config, transport=transport)

        gateway.complete(request)
        gateway.complete(request)
        gateway.complete(request)

        self.assertTrue(transport.calls[4][0].endswith("/chat/completions"))
        self.assertTrue(transport.calls[5][0].endswith("/responses"))
        self.assertTrue(transport.calls[6][0].endswith("/responses"))

    def test_cached_auth_and_quota_failures_do_not_trigger_reprobe(self) -> None:
        successful = response(
            {"output_text": "ok", "usage": {"input_tokens": 1, "output_tokens": 1}}
        )
        for status in (401, 429):
            with self.subTest(status=status):
                transport = FakeTransport([successful, response({"error": "denied"}, status)])
                gateway = ModelGateway(
                    self.config,
                    transport=transport,
                    retry=RetryPolicy(1, 0, 0),
                    sleeper=lambda _: None,
                )
                gateway.complete(self.request)
                with self.assertRaises(GatewayHTTPError) as raised:
                    gateway.complete(self.request)
                self.assertEqual(raised.exception.status, status)
                self.assertEqual(len(transport.calls), 2)

    def test_transient_errors_retry_without_protocol_fallback(self) -> None:
        transport = FakeTransport(
            [
                GatewayHTTPError(429, "slow", retryable=True),
                response({"output_text": "ok", "usage": {"input_tokens": 1, "output_tokens": 1}}),
            ]
        )
        sleeps: list[float] = []
        result = ModelGateway(
            self.config,
            transport=transport,
            retry=RetryPolicy(2, 0.25, 1),
            sleeper=sleeps.append,
        ).complete(self.request)
        self.assertEqual(result.text, "ok")
        self.assertEqual(sleeps, [0.25])
        self.assertTrue(all(call[0].endswith("/responses") for call in transport.calls))

    def test_remote_disconnect_retries_same_protocol(self) -> None:
        transport = FakeTransport(
            [
                http.client.RemoteDisconnected("upstream closed"),
                response({"output_text": "ok", "usage": {"input_tokens": 1, "output_tokens": 1}}),
            ]
        )
        gateway = ModelGateway(
            self.config,
            transport=transport,
            retry=RetryPolicy(2, 0, 0),
            sleeper=lambda _: None,
        )

        self.assertEqual(gateway.complete(self.request).text, "ok")
        self.assertTrue(all(call[0].endswith("/responses") for call in transport.calls))

    def test_oserror_transport_flap_retries_same_protocol(self) -> None:
        transport = FakeTransport(
            [
                FileNotFoundError(2, "No such file or directory"),
                response({"output_text": "ok", "usage": {"input_tokens": 1, "output_tokens": 1}}),
            ]
        )
        gateway = ModelGateway(
            self.config,
            transport=transport,
            retry=RetryPolicy(2, 0, 0),
            sleeper=lambda _: None,
        )

        self.assertEqual(gateway.complete(self.request).text, "ok")
        self.assertTrue(all(call[0].endswith("/responses") for call in transport.calls))

    def test_every_retry_attempt_is_reserved_and_failed_attempt_is_conservatively_charged(self) -> None:
        observer = RecordingObserver()
        transport = FakeTransport(
            [
                GatewayHTTPError(429, "slow", retryable=True),
                response({"output_text": "ok", "usage": {"input_tokens": 3, "output_tokens": 2}}),
            ]
        )
        result = ModelGateway(
            self.config,
            transport=transport,
            retry=RetryPolicy(2, 0, 0),
            sleeper=lambda _: None,
            attempt_observer=observer,
        ).complete(self.request)
        self.assertEqual(result.text, "ok")
        self.assertEqual(
            [(item.protocol, item.attempt_number) for item in observer.started],
            [("responses", 1), ("responses", 2)],
        )
        self.assertEqual(len(observer.finished), 2)
        failed = observer.finished[0][1]
        self.assertFalse(failed.succeeded)
        self.assertFalse(failed.usage.verified)
        self.assertEqual(failed.status, 429)
        self.assertEqual(failed.usage.input_tokens, len("hello".encode()))
        self.assertEqual(
            failed.usage.output_tokens,
            len("hello".encode()) + self.request.max_output_tokens,
        )
        self.assertEqual(failed.usage.reasoning_tokens, failed.usage.output_tokens)
        succeeded = observer.finished[1][1]
        self.assertTrue(succeeded.succeeded)
        self.assertTrue(succeeded.usage.verified)
        self.assertEqual(succeeded.usage.total_tokens, 5)

    def test_protocol_fallback_accounts_both_actual_http_attempts(self) -> None:
        observer = RecordingObserver()
        transport = FakeTransport(
            [
                response({"error": "unsupported"}, 404),
                response(
                    {
                        "choices": [{"message": {"content": "ok"}}],
                        "usage": {"prompt_tokens": 2, "completion_tokens": 1},
                    },
                    201,
                ),
            ]
        )
        result = ModelGateway(self.config, transport=transport, attempt_observer=observer).complete(
            self.request
        )
        self.assertEqual(result.status, 201)
        self.assertEqual([item.protocol for item in observer.started], ["responses", "chat"])
        self.assertEqual([item.succeeded for _, item in observer.finished], [False, True])

    def test_before_attempt_can_deny_without_transport_or_finish_callback(self) -> None:
        transport = FakeTransport([])

        class Deny(RecordingObserver):
            def before_attempt(self, attempt):
                super().before_attempt(attempt)
                raise RuntimeError("budget denied")

        observer = Deny()
        with self.assertRaisesRegex(RuntimeError, "budget denied"):
            ModelGateway(self.config, transport=transport, attempt_observer=observer).complete(self.request)
        self.assertEqual(transport.calls, [])
        self.assertEqual(observer.finished, [])

    def test_attempt_observer_binding_is_validated_and_cannot_be_replaced(self) -> None:
        gateway = ModelGateway(self.config, transport=FakeTransport([]))
        with self.assertRaisesRegex(TypeError, "before_attempt"):
            gateway.bind_attempt_observer(object())
        observer = RecordingObserver()
        gateway.bind_attempt_observer(observer)
        with self.assertRaisesRegex(RuntimeError, "already bound"):
            gateway.bind_attempt_observer(observer)

    def test_network_error_exhaustion_is_wrapped(self) -> None:
        transport = FakeTransport([urllib.error.URLError("offline"), urllib.error.URLError("offline")])
        gateway = ModelGateway(
            self.config, transport=transport, retry=RetryPolicy(2, 0, 0), sleeper=lambda _: None
        )
        with self.assertRaisesRegex(RuntimeError, "unavailable"):
            gateway.complete(self.request)

    def test_oserror_exhaustion_is_wrapped(self) -> None:
        transport = FakeTransport([FileNotFoundError(2, "nope"), FileNotFoundError(2, "nope")])
        gateway = ModelGateway(
            self.config, transport=transport, retry=RetryPolicy(2, 0, 0), sleeper=lambda _: None
        )
        with self.assertRaisesRegex(RuntimeError, "unavailable"):
            gateway.complete(self.request)

    def test_network_failures_each_emit_conservative_accounting(self) -> None:
        observer = RecordingObserver()
        transport = FakeTransport([urllib.error.URLError("offline"), urllib.error.URLError("offline")])
        gateway = ModelGateway(
            self.config,
            transport=transport,
            retry=RetryPolicy(2, 0, 0),
            sleeper=lambda _: None,
            attempt_observer=observer,
        )
        with self.assertRaisesRegex(RuntimeError, "unavailable"):
            gateway.complete(self.request)
        self.assertEqual(len(observer.started), 2)
        self.assertEqual(len(observer.finished), 2)
        self.assertTrue(
            all(not result.succeeded and not result.usage.verified for _, result in observer.finished)
        )

    def test_missing_usage_is_conservative_and_unverified(self) -> None:
        transport = FakeTransport([response({"output_text": "abcdef"})])
        result = ModelGateway(self.config, transport=transport).complete(self.request)
        self.assertFalse(result.usage.verified)
        self.assertEqual(result.usage.input_tokens, 2)
        self.assertEqual(result.usage.output_tokens, 2)

    def test_cancelled_request_never_reaches_transport(self) -> None:
        transport = FakeTransport([])
        token = CancelToken()
        token.cancel()
        with self.assertRaises(GatewayCancelled):
            ModelGateway(self.config, transport=transport).complete(self.request, cancel=token)
        self.assertEqual(transport.calls, [])

    def test_environment_is_strict_and_repr_redacts_secret(self) -> None:
        with self.assertRaisesRegex(ValueError, "AEGIS_OPENAI_API_KEY"):
            GatewayConfig.from_env({"AEGIS_OPENAI_BASE_URL": "https://relay.invalid/v1"})
        config = GatewayConfig.from_env(
            {
                "AEGIS_OPENAI_BASE_URL": "https://relay.invalid/v1/",
                "AEGIS_OPENAI_API_KEY": "secret-value",
            }
        )
        self.assertNotIn("secret-value", repr(config))
        self.assertEqual(config.base_url, "https://relay.invalid/v1")
        self.assertEqual(config.timeout_seconds, 900.0)

    def test_structured_format_env_override(self) -> None:
        config = GatewayConfig.from_env(
            {
                "AEGIS_OPENAI_BASE_URL": "https://relay.invalid/v1",
                "AEGIS_OPENAI_API_KEY": "secret",
                "AEGIS_OPENAI_STRUCTURED_FORMAT": "json_object",
            }
        )
        self.assertEqual(config.structured_format, "json_object")
        with self.assertRaisesRegex(ValueError, "AEGIS_OPENAI_STRUCTURED_FORMAT"):
            GatewayConfig.from_env(
                {
                    "AEGIS_OPENAI_BASE_URL": "https://relay.invalid/v1",
                    "AEGIS_OPENAI_API_KEY": "secret",
                    "AEGIS_OPENAI_STRUCTURED_FORMAT": "bogus",
                }
            )

    def test_plain_http_is_rejected_except_explicit_loopback(self) -> None:
        with self.assertRaisesRegex(ValueError, "must use HTTPS"):
            GatewayConfig("http://relay.invalid/v1", "secret")
        with self.assertRaisesRegex(ValueError, "must use HTTPS"):
            GatewayConfig("http://127.0.0.1:8080/v1", "secret")
        config = GatewayConfig.from_env(
            {
                "AEGIS_OPENAI_BASE_URL": "http://127.0.0.1:8080/v1",
                "AEGIS_OPENAI_API_KEY": "secret",
                "AEGIS_ALLOW_INSECURE_LOOPBACK": "true",
            }
        )
        self.assertTrue(config.allow_insecure_loopback)

    def test_base_url_rejects_embedded_credentials_and_bad_boolean(self) -> None:
        with self.assertRaisesRegex(ValueError, "must not contain credentials"):
            GatewayConfig("https://user:pass@relay.invalid/v1", "secret")
        with self.assertRaisesRegex(ValueError, "must be true or false"):
            GatewayConfig.from_env(
                {
                    "AEGIS_OPENAI_BASE_URL": "https://relay.invalid/v1",
                    "AEGIS_OPENAI_API_KEY": "secret",
                    "AEGIS_ALLOW_INSECURE_LOOPBACK": "yes",
                }
            )

    def test_seed_is_strict_and_serialized_for_responses_and_chat(self) -> None:
        with self.assertRaisesRegex(ValueError, "seed"):
            GatewayRequest("m", (Message("user", "x"),), 10, seed=True)
        with self.assertRaisesRegex(ValueError, "seed"):
            GatewayRequest("m", (Message("user", "x"),), 10, seed=-1)
        request = GatewayRequest("m", (Message("user", "x"),), 10, seed=42)
        self.assertEqual(ModelGateway._responses_payload(request)["seed"], 42)
        self.assertEqual(ModelGateway._chat_payload(request)["seed"], 42)
        no_seed = GatewayRequest("m", (Message("user", "x"),), 10)
        self.assertNotIn("seed", ModelGateway._responses_payload(no_seed))


class StdlibTransportTests(unittest.TestCase):
    def test_default_opener_installs_no_redirect_handler(self) -> None:
        sentinel = object()
        with patch("aegis.gateway.transport.urllib.request.build_opener", return_value=sentinel) as build:
            transport = StdlibHTTPTransport()
        self.assertIs(transport._opener, sentinel)
        self.assertEqual(len(build.call_args.args), 2)
        self.assertIsInstance(build.call_args.args[0], StdlibHTTPTransport._NoRedirect)
        self.assertIsInstance(build.call_args.args[1], urllib.request.ProxyHandler)

    def test_redirect_is_explicit_error_and_authorization_is_never_replayed(self) -> None:
        class RedirectingOpener:
            def __init__(self):
                self.requests = []

            def open(self, request, timeout):
                self.requests.append((request, timeout))
                raise urllib.error.HTTPError(
                    request.full_url,
                    302,
                    "Found",
                    {"Location": "https://evil.invalid/steal"},
                    io.BytesIO(b"redirect"),
                )

        opener = RedirectingOpener()
        transport = StdlibHTTPTransport(opener=opener)
        with self.assertRaises(GatewayHTTPError) as raised:
            transport.post(
                "https://relay.invalid/v1/responses",
                headers={"Authorization": "Bearer secret"},
                body=b"{}",
                timeout=1,
                cancel=CancelToken(),
            )
        self.assertEqual(raised.exception.status, 302)
        self.assertFalse(raised.exception.retryable)
        self.assertEqual(len(opener.requests), 1)
        self.assertEqual(opener.requests[0][0].full_url, "https://relay.invalid/v1/responses")

    def test_total_wall_clock_deadline_caps_slow_streaming_response(self) -> None:
        class SlowStreamingResponse:
            status = 200
            headers = {"content-type": "application/json"}

            def read(self, size: int) -> bytes:
                time.sleep(0.1)
                return b"x"

            def __enter__(self) -> "SlowStreamingResponse":
                return self

            def __exit__(self, *_: object) -> None:
                return None

            def close(self) -> None:
                return None

        class SlowOpener:
            def open(self, request, timeout):
                return SlowStreamingResponse()

        transport = StdlibHTTPTransport(opener=SlowOpener())
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            transport.post(
                "https://relay.invalid/v1/responses",
                headers={},
                body=b"{}",
                timeout=0.5,
                cancel=CancelToken(),
            )
        self.assertLess(time.monotonic() - started, 5.0)

    def test_child_process_bounds_hung_network_call(self) -> None:
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        transport = StdlibHTTPTransport()
        started = time.monotonic()
        try:
            with patch.dict(
                "os.environ",
                {"NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost"},
            ):
                with self.assertRaises(TimeoutError):
                    transport.post(
                        f"http://127.0.0.1:{port}/v1/responses",
                        headers={},
                        body=b"{}",
                        timeout=0.5,
                        cancel=CancelToken(),
                    )
            self.assertLess(time.monotonic() - started, 10.0)
        finally:
            listener.close()

    def test_child_process_propagates_http_error(self) -> None:
        from http.server import BaseHTTPRequestHandler, HTTPServer

        class Slow429(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                self.send_response(429)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"no")

            def log_message(self, *_: object) -> None:
                return

        server = HTTPServer(("127.0.0.1", 0), Slow429)
        port = server.server_address[1]
        import threading

        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        transport = StdlibHTTPTransport()
        try:
            with patch.dict(
                "os.environ",
                {"NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost"},
            ):
                with self.assertRaises(GatewayHTTPError) as raised:
                    transport.post(
                        f"http://127.0.0.1:{port}/v1/responses",
                        headers={},
                        body=b"{}",
                        timeout=5,
                        cancel=CancelToken(),
                    )
            self.assertEqual(raised.exception.status, 429)
            self.assertTrue(raised.exception.retryable)
        finally:
            server.shutdown()
            server.server_close()

    def test_large_response_does_not_deadlock_child_pipe(self) -> None:
        from http.server import BaseHTTPRequestHandler, HTTPServer

        body = b'{"content":"' + b"a" * 262144 + b'"}'

        class LargeResponse(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_: object) -> None:
                return

        server = HTTPServer(("127.0.0.1", 0), LargeResponse)
        port = server.server_address[1]
        import threading

        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        transport = StdlibHTTPTransport()
        try:
            with patch.dict(
                "os.environ",
                {"NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost"},
            ):
                response = transport.post(
                    f"http://127.0.0.1:{port}/v1/responses",
                    headers={},
                    body=b"{}",
                    timeout=15,
                    cancel=CancelToken(),
                )
            self.assertEqual(response.status, 200)
            self.assertEqual(response.body, body)
        finally:
            server.shutdown()
            server.server_close()


class RoleProtocolTests(unittest.TestCase):
    def test_policy_filters_disallowed_tools_and_builds_schema_request(self) -> None:
        policy = RolePolicy.default(Role.WARRIOR, "Improve code safely.")
        request = build_role_request(
            policy,
            model="m",
            objective="fix bug",
            context={"task": "t1"},
            tools=({"name": "workspace.write"}, {"name": "evaluation.record"}),
        )
        self.assertEqual([tool["name"] for tool in request.tools], ["workspace.write"])
        self.assertIsNotNone(request.output_schema)

    def test_role_output_is_exact_and_identity_checked(self) -> None:
        raw = json.dumps(
            {"role": "judge", "summary": "bad edge case", "actions": [], "findings": [{}], "proposals": []}
        )
        output = parse_role_output(raw, Role.JUDGE)
        self.assertEqual(output.role, Role.JUDGE)
        with self.assertRaisesRegex(ValueError, "identity"):
            parse_role_output(raw, Role.WARRIOR)
        with self.assertRaisesRegex(ValueError, "unknown"):
            parse_role_output(raw[:-1] + ', "extra": 1}', Role.JUDGE)


if __name__ == "__main__":
    unittest.main()
