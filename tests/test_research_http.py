from __future__ import annotations

import subprocess
import unittest
from subprocess import CompletedProcess
from unittest.mock import patch

from aegis.research import (
    LoopbackHTTPFetcher,
    LoopbackProxyTLSTransport,
    PinnedHTTPSFetcher,
    WslLoopbackHTTPFetcher,
)

PUBLIC = "93.184.216.34"


class FakeTLSStream:
    def __init__(self, response: bytes, *, peer: str = PUBLIC, chunk_size: int = 4096) -> None:
        self.response = bytearray(response)
        self.peer = peer
        self.chunk_size = chunk_size
        self.sent = bytearray()
        self.timeout: float | None = None
        self.closed = False

    def sendall(self, data: bytes) -> None:
        self.sent.extend(data)

    def recv(self, size: int) -> bytes:
        take = min(size, self.chunk_size, len(self.response))
        value = bytes(self.response[:take])
        del self.response[:take]
        return value

    def settimeout(self, value: float | None) -> None:
        self.timeout = value

    def getpeername(self) -> tuple[object, ...]:
        return (self.peer, 443)

    def close(self) -> None:
        self.closed = True


class FakeTransport:
    def __init__(self, streams: list[FakeTLSStream]) -> None:
        self.streams = streams
        self.calls: list[tuple[str, int, str, float]] = []

    def __call__(self, address: str, port: int, hostname: str, timeout: float) -> FakeTLSStream:
        self.calls.append((address, port, hostname, timeout))
        return self.streams.pop(0)


class FakePlainSocket(FakeTLSStream):
    def __init__(self, response: bytes, *, peer: str = "127.0.0.1") -> None:
        super().__init__(response, peer=peer)
        self.connected: tuple[object, ...] | None = None

    def connect(self, target: tuple[object, ...]) -> None:
        self.connected = target


class FakeSSLContext:
    def __init__(self, tls_stream: FakeTLSStream) -> None:
        self.tls_stream = tls_stream
        self.calls: list[tuple[object, str | None]] = []

    def wrap_socket(self, raw: object, *, server_hostname: str | None = None) -> FakeTLSStream:
        self.calls.append((raw, server_hostname))
        return self.tls_stream


class LoopbackHTTPFetcherTests(unittest.TestCase):
    def test_direct_loopback_request_ignores_proxy_environment(self) -> None:
        stream = FakePlainSocket(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 14\r\n\r\n{\"results\":[]}"
        )
        with (
            patch("aegis.research.http.socket.socket", return_value=stream),
            patch.dict("os.environ", {"HTTP_PROXY": "http://attacker.invalid:9999"}),
        ):
            response = LoopbackHTTPFetcher().fetch(
                "http://127.0.0.1:8888/search?q=x", allowed_addresses=("127.0.0.1",), max_bytes=100
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(stream.connected, ("127.0.0.1", 8888))
        self.assertNotIn(b"Proxy-Authorization", stream.sent)

    def test_loopback_fetcher_rejects_redirect_peer_and_wrong_approval(self) -> None:
        redirect = FakePlainSocket(
            b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9999/x\r\nContent-Length: 0\r\n\r\n"
        )
        with patch("aegis.research.http.socket.socket", return_value=redirect):
            response = LoopbackHTTPFetcher().fetch(
                "http://127.0.0.1:8888/search", allowed_addresses=("127.0.0.1",), max_bytes=10
            )
        self.assertIsNotNone(response.redirect_url)
        with self.assertRaisesRegex(ValueError, "exact loopback"):
            LoopbackHTTPFetcher().fetch(
                "http://127.0.0.1:8888/search", allowed_addresses=("192.168.1.2",), max_bytes=10
            )
        with self.assertRaisesRegex(ValueError, "exact loopback"):
            LoopbackHTTPFetcher().fetch(
                "http://localhost:8888/search", allowed_addresses=("127.0.0.1",), max_bytes=10
            )
        with self.assertRaisesRegex(ValueError, "approved address set"):
            LoopbackHTTPFetcher().fetch(
                "http://127.0.0.1:8888/search", allowed_addresses=("::1",), max_bytes=10
            )

        wrong_peer = FakePlainSocket(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", peer="127.0.0.2")
        with (
            patch("aegis.research.http.socket.socket", return_value=wrong_peer),
            self.assertRaisesRegex(RuntimeError, "approved loopback"),
        ):
            LoopbackHTTPFetcher().fetch(
                "http://127.0.0.1:8888/search", allowed_addresses=("127.0.0.1",), max_bytes=10
            )


class WslLoopbackHTTPFetcherTests(unittest.TestCase):
    def test_uses_fixed_wsl_curl_argv_and_parses_response(self) -> None:
        calls: list[tuple[object, ...]] = []

        def runner(argv: object, **kwargs: object) -> CompletedProcess[bytes]:
            calls.append((argv, kwargs))
            return CompletedProcess(
                argv,
                0,
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 14\r\n\r\n"
                b'{"results":[]}',
                b"",
            )

        url = "http://127.0.0.1:8888/search?q=x"
        response = WslLoopbackHTTPFetcher(runner=runner).fetch(
            url,
            allowed_addresses=("127.0.0.1",),
            max_bytes=100,
        )
        argv = calls[0][0]
        self.assertIsInstance(argv, tuple)
        self.assertEqual(
            argv,
            (
                "wsl.exe",
                "--distribution",
                "AEGIS-Sandbox",
                "--exec",
                "/usr/bin/curl",
                "--silent",
                "--show-error",
                "--noproxy",
                "*",
                "--proto",
                "=http",
                "--max-time",
                "15.0",
                "--max-filesize",
                "100",
                "--dump-header",
                "-",
                "--output",
                "-",
                url,
            ),
        )
        self.assertEqual(
            calls[0][1],
            {"check": False, "capture_output": True, "timeout": 20.0},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.body, b'{"results":[]}')

    def test_rejects_crlf_in_url_before_spawning(self) -> None:
        fetcher = WslLoopbackHTTPFetcher(
            runner=lambda *_args, **_kwargs: self.fail("must not spawn a process")
        )
        for url in (
            "http://127.0.0.1:8888/search?q=x\r\nHost: attacker.invalid",
            "http://127.0.0.1:8888/search?q=x\nInjected: yes",
        ):
            with self.subTest(url=url), self.assertRaisesRegex(
                ValueError, "invalid approved WSL loopback fetch"
            ):
                fetcher.fetch(
                    url,
                    allowed_addresses=("127.0.0.1",),
                    max_bytes=100,
                )


class LoopbackProxyTLSTransportTests(unittest.TestCase):
    def test_connects_to_literal_loopback_and_tunnels_only_the_approved_ip(self) -> None:
        proxy = FakePlainSocket(
            b"HTTP/1.1 200 Connection established\r\nProxy-Agent: test\r\n\r\n"
        )
        tls = FakeTLSStream(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok"
        )
        context = FakeSSLContext(tls)
        transport = LoopbackProxyTLSTransport(
            "http://127.0.0.1:7897",
            context=context,  # type: ignore[arg-type]
            socket_factory=lambda _family, _kind: proxy,
        )

        response = PinnedHTTPSFetcher(transport=transport.connect).fetch(
            "https://example.com/data", allowed_addresses=(PUBLIC,), max_bytes=10
        )

        self.assertEqual(response.body, b"ok")
        self.assertEqual(proxy.connected, ("127.0.0.1", 7897))
        self.assertIn(f"CONNECT {PUBLIC}:443 HTTP/1.1\r\n".encode(), proxy.sent)
        self.assertNotIn(b"example.com", proxy.sent)
        self.assertEqual(context.calls, [(proxy, "example.com")])
        self.assertIn(b"GET /data HTTP/1.1\r\n", tls.sent)

    def test_rejects_non_loopback_authenticated_or_pathful_proxy_urls(self) -> None:
        for url in (
            "http://example.com:7897",
            "http://user:secret@127.0.0.1:7897",
            "http://127.0.0.1:7897/path",
            "socks5://127.0.0.1:7897",
        ):
            with self.subTest(url=url), self.assertRaisesRegex(ValueError, "literal loopback"):
                LoopbackProxyTLSTransport(url)

class WslLoopbackHTTPFetcherRetryTests(unittest.TestCase):
    def test_retries_startup_and_rejects_non_loopback_before_spawning(self) -> None:
        sleeps: list[float] = []
        results = iter(
            [
                CompletedProcess([], 7, b"", b"refused"),
                CompletedProcess(
                    [], 0, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", b""
                ),
            ]
        )
        fetcher = WslLoopbackHTTPFetcher(
            runner=lambda *_args, **_kwargs: next(results),
            sleeper=sleeps.append,
            startup_attempts=2,
        )
        self.assertEqual(
            fetcher.fetch(
                "http://127.0.0.1:8888/search",
                allowed_addresses=("127.0.0.1",),
                max_bytes=100,
            ).status_code,
            200,
        )
        self.assertEqual(sleeps, [1.0])
        with self.assertRaisesRegex(ValueError, "WSL loopback"):
            fetcher.fetch(
                "http://10.0.0.1:8888/search",
                allowed_addresses=("10.0.0.1",),
                max_bytes=100,
            )

    def test_retries_startup_timeout_expired(self) -> None:
        attempts = iter(
            [
                subprocess.TimeoutExpired(["wsl.exe", "curl"], 20),
                CompletedProcess([], 0, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", b""),
            ]
        )

        def runner(*_args: object, **_kwargs: object) -> CompletedProcess[bytes]:
            value = next(attempts)
            if isinstance(value, BaseException):
                raise value
            return value

        fetcher = WslLoopbackHTTPFetcher(
            runner=runner,
            sleeper=lambda _seconds: None,
            startup_attempts=2,
        )
        response = fetcher.fetch(
            "http://127.0.0.1:8888/search",
            allowed_addresses=("127.0.0.1",),
            max_bytes=100,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.body, b"")


class PinnedHTTPSFetcherTests(unittest.TestCase):
    def test_pins_ip_but_preserves_sni_host_and_request_target(self) -> None:
        stream = FakeTLSStream(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello",
            chunk_size=7,
        )
        transport = FakeTransport([stream])
        fetcher = PinnedHTTPSFetcher(transport=transport, timeout_seconds=3)

        response = fetcher.fetch(
            "https://example.com/a%20b?q=hello%20world",
            allowed_addresses=(PUBLIC,),
            max_bytes=10,
        )

        self.assertEqual(transport.calls, [(PUBLIC, 443, "example.com", 3)])
        self.assertIn(b"GET /a%20b?q=hello%20world HTTP/1.1\r\n", stream.sent)
        self.assertIn(b"Host: example.com\r\n", stream.sent)
        self.assertNotIn(b"Proxy-Authorization", stream.sent)
        self.assertEqual(response.body, b"hello")
        self.assertTrue(stream.closed)

    def test_returns_redirect_without_following_it(self) -> None:
        stream = FakeTLSStream(
            b"HTTP/1.1 302 Found\r\nLocation: https://other.example/x\r\nContent-Length: 0\r\n\r\n"
        )
        transport = FakeTransport([stream])
        response = PinnedHTTPSFetcher(transport=transport).fetch(
            "https://example.com/", allowed_addresses=(PUBLIC,), max_bytes=10
        )
        self.assertEqual(response.redirect_url, "https://other.example/x")
        self.assertEqual(len(transport.calls), 1)

    def test_retries_one_truncated_response_on_the_same_pinned_address(self) -> None:
        truncated = FakeTLSStream(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhe")
        complete = FakeTLSStream(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
        transport = FakeTransport([truncated, complete])

        response = PinnedHTTPSFetcher(transport=transport).fetch(
            "https://example.com/", allowed_addresses=(PUBLIC,), max_bytes=10
        )

        self.assertEqual(response.body, b"hello")
        self.assertEqual(len(transport.calls), 2)
        self.assertTrue(truncated.closed)
        self.assertTrue(complete.closed)

    def test_retries_transient_socket_failure_on_the_same_pinned_address(self) -> None:
        complete = FakeTLSStream(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

        class FlakyTransport:
            def __init__(self) -> None:
                self.calls = 0

            def __call__(
                self, address: str, port: int, hostname: str, timeout: float
            ) -> FakeTLSStream:
                self.calls += 1
                if self.calls < 3:
                    raise OSError("transient connect failure")
                return complete

        transport = FlakyTransport()
        response = PinnedHTTPSFetcher(transport=transport).fetch(
            "https://example.com/", allowed_addresses=(PUBLIC,), max_bytes=10
        )

        self.assertEqual(response.body, b"ok")
        self.assertEqual(transport.calls, 3)

    def test_does_not_retry_non_truncation_parse_failures(self) -> None:
        malformed = FakeTLSStream(b"HTTP/1.1 nope\r\n\r\n")
        transport = FakeTransport([malformed])
        with self.assertRaisesRegex(ValueError, "invalid HTTP status"):
            PinnedHTTPSFetcher(transport=transport).fetch(
                "https://example.com/", allowed_addresses=(PUBLIC,), max_bytes=10
            )
        self.assertEqual(len(transport.calls), 1)

    def test_host_header_retains_explicit_default_port(self) -> None:
        stream = FakeTLSStream(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        PinnedHTTPSFetcher(transport=FakeTransport([stream])).fetch(
            "https://example.com:443/", allowed_addresses=(PUBLIC,), max_bytes=10
        )
        self.assertIn(b"Host: example.com:443\r\n", stream.sent)

    def test_decodes_chunked_body_with_limit(self) -> None:
        response = (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"3\r\nabc\r\n2;ext=x\r\nde\r\n0\r\nX-End: yes\r\n\r\n"
        )
        stream = FakeTLSStream(response, chunk_size=3)
        result = PinnedHTTPSFetcher(transport=FakeTransport([stream])).fetch(
            "https://example.com/", allowed_addresses=(PUBLIC,), max_bytes=5
        )
        self.assertEqual(result.body, b"abcde")

    def test_rejects_unapproved_actual_peer(self) -> None:
        stream = FakeTLSStream(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", peer="1.1.1.1")
        with self.assertRaisesRegex(RuntimeError, "approved address"):
            PinnedHTTPSFetcher(transport=FakeTransport([stream])).fetch(
                "https://example.com/", allowed_addresses=(PUBLIC,), max_bytes=10
            )
        self.assertEqual(stream.sent, b"")
        self.assertTrue(stream.closed)

    def test_refuses_private_addresses_even_if_caller_claims_approval(self) -> None:
        transport = FakeTransport([])
        with self.assertRaisesRegex(ValueError, "must all be public"):
            PinnedHTTPSFetcher(transport=transport).fetch(
                "https://example.com/", allowed_addresses=("127.0.0.1",), max_bytes=10
            )
        self.assertEqual(transport.calls, [])

    def test_enforces_header_and_body_limits(self) -> None:
        oversized_header = FakeTLSStream(
            b"HTTP/1.1 200 OK\r\nX-Fill: " + b"x" * 1100 + b"\r\n\r\n",
            chunk_size=200,
        )
        with self.assertRaisesRegex(ValueError, "headers exceed"):
            PinnedHTTPSFetcher(transport=FakeTransport([oversized_header]), max_header_bytes=1024).fetch(
                "https://example.com/", allowed_addresses=(PUBLIC,), max_bytes=10
            )

        oversized_body = FakeTLSStream(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world")
        with self.assertRaisesRegex(ValueError, "maximum size"):
            PinnedHTTPSFetcher(transport=FakeTransport([oversized_body])).fetch(
                "https://example.com/", allowed_addresses=(PUBLIC,), max_bytes=10
            )

    def test_rejects_ambiguous_or_malformed_framing(self) -> None:
        for raw in (
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n Folded: no\r\n\r\n",
        ):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                PinnedHTTPSFetcher(transport=FakeTransport([FakeTLSStream(raw)])).fetch(
                    "https://example.com/", allowed_addresses=(PUBLIC,), max_bytes=10
                )


if __name__ == "__main__":
    unittest.main()
