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
    GatewayError,
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

    def test_complete_uses_native_responses_json_object(self) -> None:
        transport = FakeTransport(
            [response({"output_text": "ok", "usage": {"input_tokens": 4, "output_tokens": 2}})]
        )
        result = ModelGateway(self.config, transport=transport).complete(self.request)
        self.assertEqual(result.protocol, "responses")
        self.assertEqual(result.usage.total_tokens, 6)
        self.assertTrue(result.usage.verified)
        self.assertTrue(transport.calls[0][0].endswith("/responses"))
        self.assertEqual(transport.calls[0][1]["Authorization"], "Bearer super-secret")
        self.assertEqual(transport.calls[0][2]["text"], {"format": {"type": "json_object"}})

    def test_reasoning_effort_is_forwarded(self) -> None:
        request = GatewayRequest(
            "model-a", (Message("user", "hello"),), 100, reasoning_effort="low"
        )
        self.assertEqual(ModelGateway._payload(request)["reasoning_effort"], "low")
        request_max = GatewayRequest(
            "model-a", (Message("user", "hello"),), 100, reasoning_effort="max"
        )
        self.assertEqual(ModelGateway._payload(request_max)["reasoning_effort"], "max")
        with self.assertRaisesRegex(ValueError, "reasoning_effort"):
            GatewayRequest(
                "model-a", (Message("user", "hello"),), 100, reasoning_effort="unbounded"
            )

    def test_payload_always_forces_json_object(self) -> None:
        schema_less = GatewayRequest("model-a", (Message("user", "hello"),), 100)
        with_schema = GatewayRequest(
            "model-a", (Message("user", "return JSON"),), 100, output_schema={"type": "object"}
        )
        for request in (schema_less, with_schema):
            self.assertEqual(
                ModelGateway._payload(request)["text"],
                {"format": {"type": "json_object"}},
            )

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
            ModelGateway._extract_text(payload),
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
        self.assertEqual(ModelGateway._extract_text(only_reasoning), "think")

    def test_incomplete_status_raises_gateway_truncation_error(self) -> None:
        transport = FakeTransport(
            [
                response(
                    {
                        "status": "incomplete",
                        "incomplete_details": {"reason": "max_output_tokens"},
                        "output": [],
                        "usage": {"input_tokens": 5, "output_tokens": 200},
                    }
                )
            ]
        )
        with self.assertRaises(GatewayTruncationError) as raised:
            ModelGateway(
                self.config,
                transport=transport,
                retry=RetryPolicy(max_attempts=1),
            ).complete(self.request)
        self.assertIsNotNone(raised.exception.usage)
        self.assertEqual(raised.exception.usage.output_tokens, 200)

    def test_completed_response_without_text_raises_gateway_error(self) -> None:
        transport = FakeTransport(
            [
                response(
                    {
                        "status": "completed",
                        "output": [],
                        "usage": {"input_tokens": 5, "output_tokens": 1},
                    }
                )
            ]
        )
        with self.assertRaisesRegex(GatewayError, "no text output"):
            ModelGateway(
                self.config,
                transport=transport,
                retry=RetryPolicy(max_attempts=1),
            ).complete(self.request)

    def test_non_retryable_http_error_is_not_retried(self) -> None:
        transport = FakeTransport([response({"error": "bad request"}, 400)])
        with self.assertRaises(GatewayHTTPError) as raised:
            ModelGateway(
                self.config,
                transport=transport,
                retry=RetryPolicy(3, 0, 0),
                sleeper=lambda _: None,
            ).complete(self.request)
        self.assertEqual(raised.exception.status, 400)
        self.assertEqual(len(transport.calls), 1)

    def test_transient_errors_retry_same_endpoint(self) -> None:
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

    def test_remote_disconnect_retries_same_endpoint(self) -> None:
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

    def test_oserror_transport_flap_retries_same_endpoint(self) -> None:
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

    def test_obsolete_protocol_and_format_env_vars_are_ignored(self) -> None:
        config = GatewayConfig.from_env(
            {
                "AEGIS_OPENAI_BASE_URL": "https://relay.invalid/v1",
                "AEGIS_OPENAI_API_KEY": "secret",
                "AEGIS_OPENAI_PROTOCOL": "chat",
                "AEGIS_OPENAI_STRUCTURED_FORMAT": "json_schema",
            }
        )
        self.assertFalse(hasattr(config, "protocol"))
        self.assertFalse(hasattr(config, "structured_format"))

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

    def test_seed_is_strict_and_serialized(self) -> None:
        with self.assertRaisesRegex(ValueError, "seed"):
            GatewayRequest("m", (Message("user", "x"),), 10, seed=True)
        with self.assertRaisesRegex(ValueError, "seed"):
            GatewayRequest("m", (Message("user", "x"),), 10, seed=-1)
        request = GatewayRequest("m", (Message("user", "x"),), 10, seed=42)
        self.assertEqual(ModelGateway._payload(request)["seed"], 42)
        no_seed = GatewayRequest("m", (Message("user", "x"),), 10)
        self.assertNotIn("seed", ModelGateway._payload(no_seed))


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
