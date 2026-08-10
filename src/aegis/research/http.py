"""Small HTTPS/1.1 client which pins connections to policy-approved IPs.

Also provides :class:`LoopbackHTTPFetcher`, a narrow opt-in plain-HTTP
transport restricted to loopback addresses for local SearxNG only.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
import subprocess
import time
from collections.abc import Callable
from typing import Any, Protocol, Sequence, cast
from urllib.parse import urlsplit

from .types import FetchResponse


class HTTPSStream(Protocol):
    def sendall(self, data: bytes) -> None: ...
    def recv(self, size: int) -> bytes: ...
    def settimeout(self, value: float | None) -> None: ...
    def getpeername(self) -> tuple[object, ...]: ...
    def close(self) -> None: ...


class SocketTLSTransport:
    """Create a TLS socket without consulting DNS or proxy environment variables."""

    def __init__(self, context: ssl.SSLContext | None = None) -> None:
        self._context = context or ssl.create_default_context()

    def connect(self, address: str, port: int, hostname: str, timeout: float) -> HTTPSStream:
        parsed = ipaddress.ip_address(address)
        family = socket.AF_INET6 if parsed.version == 6 else socket.AF_INET
        raw = socket.socket(family, socket.SOCK_STREAM)
        raw.settimeout(timeout)
        target: tuple[object, ...]
        target = (str(parsed), port, 0, 0) if parsed.version == 6 else (str(parsed), port)
        try:
            raw.connect(target)
            # server_hostname preserves SNI and enables certificate hostname checks.
            return self._context.wrap_socket(raw, server_hostname=hostname)
        except BaseException:
            raw.close()
            raise


class _ProxySocket(HTTPSStream, Protocol):
    def connect(self, target: tuple[object, ...]) -> None: ...


class _PinnedProxyStream:
    def __init__(self, stream: HTTPSStream, target_address: str, target_port: int) -> None:
        self._stream = stream
        self._peer = (target_address, target_port)

    def sendall(self, data: bytes) -> None:
        self._stream.sendall(data)

    def recv(self, size: int) -> bytes:
        return self._stream.recv(size)

    def settimeout(self, value: float | None) -> None:
        self._stream.settimeout(value)

    def getpeername(self) -> tuple[object, ...]:
        return self._peer

    def close(self) -> None:
        self._stream.close()


class LoopbackProxyTLSTransport:
    """TLS transport through an explicit local HTTP CONNECT proxy."""

    def __init__(
        self,
        proxy_url: str,
        *,
        context: ssl.SSLContext | None = None,
        socket_factory: Callable[[int, int], _ProxySocket] | None = None,
        max_response_bytes: int = 16 * 1024,
    ) -> None:
        parsed = urlsplit(proxy_url)
        if (
            parsed.scheme.lower() != "http"
            or parsed.hostname not in {"127.0.0.1", "::1"}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or parsed.port is None
            or max_response_bytes < 1024
        ):
            raise ValueError("proxy must be an unauthenticated literal loopback HTTP URL with a port")
        self._proxy_address = ipaddress.ip_address(parsed.hostname)
        self._proxy_port = parsed.port
        self._context = context or ssl.create_default_context()
        self._socket_factory = socket_factory or (
            lambda family, kind: cast(_ProxySocket, socket.socket(family, kind))
        )
        self._max_response_bytes = max_response_bytes

    def connect(self, address: str, port: int, hostname: str, timeout: float) -> HTTPSStream:
        target_address = ipaddress.ip_address(address)
        if not target_address.is_global or port != 443 or timeout <= 0:
            raise ValueError("proxy target must be an approved public HTTPS address")
        family = socket.AF_INET6 if self._proxy_address.version == 6 else socket.AF_INET
        raw = self._socket_factory(family, socket.SOCK_STREAM)
        proxy_target: tuple[object, ...] = (
            (str(self._proxy_address), self._proxy_port, 0, 0)
            if self._proxy_address.version == 6
            else (str(self._proxy_address), self._proxy_port)
        )
        display_target = (
            f"[{target_address}]:{port}" if target_address.version == 6 else f"{target_address}:{port}"
        )
        try:
            raw.settimeout(timeout)
            raw.connect(proxy_target)
            peer = ipaddress.ip_address(str(raw.getpeername()[0]).split("%", 1)[0])
            if peer != self._proxy_address:
                raise RuntimeError("connected proxy peer is not the configured loopback address")
            raw.sendall(
                (
                    f"CONNECT {display_target} HTTP/1.1\r\n"
                    f"Host: {display_target}\r\n"
                    "Proxy-Connection: close\r\n\r\n"
                ).encode("ascii")
            )
            response = bytearray()
            while b"\r\n\r\n" not in response:
                if len(response) >= self._max_response_bytes:
                    raise ValueError("proxy CONNECT response headers exceed maximum size")
                chunk = raw.recv(min(4096, self._max_response_bytes - len(response)))
                if not chunk:
                    raise ValueError("truncated proxy CONNECT response")
                response.extend(chunk)
            boundary = response.index(b"\r\n\r\n")
            if response[boundary + 4 :]:
                raise ValueError("proxy sent unexpected bytes before TLS handshake")
            first_line = bytes(response[:boundary]).split(b"\r\n", 1)[0]
            try:
                protocol, status_text, _reason = first_line.decode("ascii").split(" ", 2)
                status = int(status_text)
            except (UnicodeDecodeError, ValueError) as exc:
                raise ValueError("invalid proxy CONNECT status line") from exc
            if protocol not in {"HTTP/1.0", "HTTP/1.1"} or status != 200:
                raise OSError(f"proxy CONNECT failed with HTTP status {status}")
            tls = self._context.wrap_socket(cast(Any, raw), server_hostname=hostname)
            return _PinnedProxyStream(cast(HTTPSStream, tls), str(target_address), port)
        except BaseException:
            raw.close()
            raise


TransportFactory = Callable[[str, int, str, float], HTTPSStream]


class _BufferedStream:
    def __init__(self, stream: HTTPSStream, initial: bytes = b"") -> None:
        self.stream = stream
        self.buffer = bytearray(initial)

    def read_exact(self, size: int) -> bytes:
        while len(self.buffer) < size:
            chunk = self.stream.recv(min(64 * 1024, size - len(self.buffer)))
            if not chunk:
                raise ValueError("truncated HTTP response body")
            self.buffer.extend(chunk)
        value = bytes(self.buffer[:size])
        del self.buffer[:size]
        return value

    def readline(self, limit: int) -> bytes:
        while True:
            marker = self.buffer.find(b"\r\n")
            if marker >= 0:
                if marker + 2 > limit:
                    raise ValueError("HTTP line exceeds maximum size")
                value = bytes(self.buffer[:marker])
                del self.buffer[: marker + 2]
                return value
            if len(self.buffer) >= limit:
                raise ValueError("HTTP line exceeds maximum size")
            chunk = self.stream.recv(min(4096, limit - len(self.buffer)))
            if not chunk:
                raise ValueError("truncated HTTP response")
            self.buffer.extend(chunk)

    def read_to_eof(self, limit: int) -> bytes:
        output = bytearray(self.buffer)
        self.buffer.clear()
        if len(output) > limit:
            raise ValueError("download exceeds maximum size")
        while True:
            chunk = self.stream.recv(min(64 * 1024, limit - len(output) + 1))
            if not chunk:
                return bytes(output)
            output.extend(chunk)
            if len(output) > limit:
                raise ValueError("download exceeds maximum size")


def _read_http_response(
    stream: HTTPSStream, url: str, max_bytes: int, max_header_bytes: int
) -> FetchResponse:
    raw_headers = bytearray()
    while b"\r\n\r\n" not in raw_headers:
        if len(raw_headers) >= max_header_bytes:
            raise ValueError("HTTP response headers exceed maximum size")
        chunk = stream.recv(min(4096, max_header_bytes - len(raw_headers)))
        if not chunk:
            raise ValueError("truncated HTTP response headers")
        raw_headers.extend(chunk)
    boundary = raw_headers.index(b"\r\n\r\n")
    if boundary + 4 > max_header_bytes:
        raise ValueError("HTTP response headers exceed maximum size")
    head = bytes(raw_headers[:boundary])
    initial_body = bytes(raw_headers[boundary + 4 :])
    lines = head.split(b"\r\n")
    try:
        protocol, status_text, _reason = lines[0].decode("ascii").split(" ", 2)
        status = int(status_text)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("invalid HTTP status line") from exc
    if protocol not in {"HTTP/1.0", "HTTP/1.1"} or not 100 <= status <= 599:
        raise ValueError("invalid HTTP status line")

    headers: dict[str, str] = {}
    for raw_line in lines[1:]:
        if raw_line[:1] in {b" ", b"\t"} or b":" not in raw_line:
            raise ValueError("invalid HTTP response header")
        raw_name, raw_value = raw_line.split(b":", 1)
        try:
            name = raw_name.decode("ascii")
            value = raw_value.decode("iso-8859-1").strip()
        except UnicodeDecodeError as exc:
            raise ValueError("invalid HTTP response header") from exc
        if not name or not all(char.isalnum() or char in "!#$%&'*+-.^_`|~" for char in name):
            raise ValueError("invalid HTTP response header name")
        key = name.lower()
        if key in {item.lower() for item in headers}:
            raise ValueError("duplicate HTTP response header")
        headers[name] = value

    lookup = {key.lower(): value for key, value in headers.items()}
    transfer_encoding = lookup.get("transfer-encoding")
    content_length = lookup.get("content-length")
    reader = _BufferedStream(stream, initial_body)
    if transfer_encoding is not None:
        if transfer_encoding.lower() != "chunked" or content_length is not None:
            raise ValueError("unsupported or ambiguous HTTP transfer encoding")
        body = _read_http_chunked(reader, max_bytes, max_header_bytes)
    elif content_length is not None:
        try:
            length = int(content_length)
        except ValueError as exc:
            raise ValueError("invalid HTTP content length") from exc
        if length < 0 or length > max_bytes:
            raise ValueError("download exceeds maximum size")
        body = reader.read_exact(length)
    elif status in {204, 304} or 100 <= status < 200:
        body = b""
    else:
        body = reader.read_to_eof(max_bytes)

    redirect_url = lookup.get("location") if status in {301, 302, 303, 307, 308} else None
    return FetchResponse(url, status, headers, body, redirect_url)


def _read_http_chunked(reader: _BufferedStream, max_bytes: int, max_header_bytes: int) -> bytes:
    output = bytearray()
    while True:
        line = reader.readline(1024)
        size_text = line.split(b";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError as exc:
            raise ValueError("invalid HTTP chunk size") from exc
        if size < 0 or len(output) + size > max_bytes:
            raise ValueError("download exceeds maximum size")
        if size == 0:
            trailer_bytes = 0
            while True:
                trailer = reader.readline(max_header_bytes - trailer_bytes)
                trailer_bytes += len(trailer) + 2
                if not trailer:
                    return bytes(output)
                if b":" not in trailer or trailer[:1] in {b" ", b"\t"}:
                    raise ValueError("invalid HTTP trailer")
        output.extend(reader.read_exact(size))
        if reader.read_exact(2) != b"\r\n":
            raise ValueError("invalid HTTP chunk terminator")


class LoopbackHTTPFetcher:
    """Fetch HTTP responses from the approved loopback SearxNG instance only.

    This is a narrow opt-in exception for local development.  It connects via
    direct TCP to ``127.0.0.1`` or ``::1`` on port 8888, never reads proxy
    environment variables, and never follows redirects.
    """

    LOOPBACK_ADDRESSES = frozenset({"127.0.0.1", "::1"})

    def __init__(
        self,
        *,
        timeout_seconds: float = 15.0,
        max_header_bytes: int = 64 * 1024,
        user_agent: str = "AEGIS-Research/0.1",
    ) -> None:
        if timeout_seconds <= 0 or max_header_bytes < 1024:
            raise ValueError("invalid loopback fetcher limits")
        if not user_agent.isascii() or any(char in user_agent for char in "\r\n"):
            raise ValueError("invalid user agent")
        self.timeout_seconds = timeout_seconds
        self.max_header_bytes = max_header_bytes
        self.user_agent = user_agent

    def fetch(self, url: str, *, allowed_addresses: tuple[str, ...], max_bytes: int) -> FetchResponse:
        parsed = urlsplit(url)
        if parsed.scheme.lower() != "http" or not parsed.hostname:
            raise ValueError("LoopbackHTTPFetcher accepts only HTTP URLs")
        if parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise ValueError("invalid loopback HTTP URL")
        hostname = parsed.hostname.rstrip(".").lower()
        if hostname not in self.LOOPBACK_ADDRESSES:
            raise ValueError("loopback HTTP URL must use an exact loopback address")
        try:
            port = parsed.port or 80
        except ValueError as exc:
            raise ValueError("invalid HTTP port") from exc
        if port != 8888 or max_bytes <= 0 or not allowed_addresses:
            raise ValueError("invalid loopback fetch parameters")

        allowed = set[str]()
        for addr in allowed_addresses:
            normalised = addr.split("%", 1)[0]
            if normalised not in self.LOOPBACK_ADDRESSES:
                raise ValueError("approved address is not an exact loopback address")
            allowed.add(normalised)
        if hostname not in allowed:
            raise ValueError("loopback URL host is not in the approved address set")

        host = f"[{hostname}]" if ":" in hostname else hostname
        host_header = host if parsed.port is None else f"{host}:{port}"
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query
        if any(char in target for char in "\r\n"):
            raise ValueError("invalid HTTP request target")
        request = (
            f"GET {target} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"User-Agent: {self.user_agent}\r\n"
            "Accept: */*\r\n"
            "Accept-Encoding: identity\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")

        errors: list[OSError] = []
        for address in allowed:
            raw_sock: socket.socket | None = None
            try:
                parsed_addr = ipaddress.ip_address(address)
                family = socket.AF_INET6 if parsed_addr.version == 6 else socket.AF_INET
                raw_sock = socket.socket(family, socket.SOCK_STREAM)
                raw_sock.settimeout(self.timeout_seconds)
                connect_target: tuple[object, ...]
                connect_target = (
                    (str(parsed_addr), port, 0, 0)
                    if parsed_addr.version == 6
                    else (str(parsed_addr), port)
                )
                raw_sock.connect(connect_target)
                # Verify connected peer remains the approved loopback address.
                peer_text = str(raw_sock.getpeername()[0]).split("%", 1)[0]
                peer = ipaddress.ip_address(peer_text)
                if str(peer) not in self.LOOPBACK_ADDRESSES:
                    raise RuntimeError("connected peer is not an approved loopback address")
                raw_sock.sendall(request)
                return _read_http_response(raw_sock, url, max_bytes, self.max_header_bytes)
            except OSError as exc:
                errors.append(exc)
            finally:
                if raw_sock is not None:
                    raw_sock.close()
        if errors:
            raise OSError("all approved loopback addresses failed") from errors[-1]
        raise OSError("no approved loopback address was usable")


SubprocessRunner = Callable[..., subprocess.CompletedProcess[bytes]]


class _BytesStream:
    def __init__(self, payload: bytes) -> None:
        self.payload = bytearray(payload)

    def recv(self, size: int) -> bytes:
        value = bytes(self.payload[:size])
        del self.payload[:size]
        return value


class WslLoopbackHTTPFetcher:
    """Fetch the local SearxNG endpoint from inside the dedicated WSL VM.

    WSL localhost forwarding is not a durable contract across VM restarts. This
    transport therefore invokes curl directly, with an argv vector rather than
    a shell, and still accepts only the fixed loopback endpoint. Short retries
    cover systemd starting SearxNG when the distribution is first awakened.
    """

    def __init__(
        self,
        *,
        distribution: str = "AEGIS-Sandbox",
        timeout_seconds: float = 15.0,
        max_header_bytes: int = 64 * 1024,
        startup_attempts: int = 12,
        startup_delay_seconds: float = 1.0,
        runner: SubprocessRunner = subprocess.run,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if (
            not distribution
            or timeout_seconds <= 0
            or max_header_bytes < 1024
            or startup_attempts < 1
            or startup_delay_seconds < 0
        ):
            raise ValueError("invalid WSL loopback fetcher configuration")
        self.distribution = distribution
        self.timeout_seconds = timeout_seconds
        self.max_header_bytes = max_header_bytes
        self.startup_attempts = startup_attempts
        self.startup_delay_seconds = startup_delay_seconds
        self._runner = runner
        self._sleep = sleeper

    def fetch(self, url: str, *, allowed_addresses: tuple[str, ...], max_bytes: int) -> FetchResponse:
        _validate_exact_loopback_fetch(url, allowed_addresses, max_bytes)
        argv: Sequence[str] = (
            "wsl.exe",
            "--distribution",
            self.distribution,
            "--exec",
            "/usr/bin/curl",
            "--silent",
            "--show-error",
            "--noproxy",
            "*",
            "--proto",
            "=http",
            "--max-time",
            str(self.timeout_seconds),
            "--max-filesize",
            str(max_bytes),
            "--dump-header",
            "-",
            "--output",
            "-",
            url,
        )
        last_error: BaseException | None = None
        for attempt in range(self.startup_attempts):
            try:
                completed = self._runner(
                    argv,
                    check=False,
                    capture_output=True,
                    timeout=self.timeout_seconds + 5,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                last_error = exc
            else:
                if completed.returncode == 0:
                    stream = _BytesStream(completed.stdout)
                    return _read_http_response(stream, url, max_bytes, self.max_header_bytes)  # type: ignore[arg-type]
                last_error = OSError(f"WSL loopback curl failed with exit code {completed.returncode}")
            if attempt + 1 < self.startup_attempts:
                self._sleep(self.startup_delay_seconds)
        raise OSError("WSL loopback endpoint unavailable after startup retries") from last_error


def _validate_exact_loopback_fetch(
    url: str, allowed_addresses: tuple[str, ...], max_bytes: int
) -> None:
    if any(char in url for char in "\r\n"):
        raise ValueError("invalid approved WSL loopback fetch")
    parsed = urlsplit(url)
    hostname = parsed.hostname.rstrip(".").lower() if parsed.hostname else ""
    try:
        port = parsed.port or 80
    except ValueError as exc:
        raise ValueError("invalid HTTP port") from exc
    allowed = {item.split("%", 1)[0] for item in allowed_addresses}
    if (
        parsed.scheme.lower() != "http"
        or hostname not in LoopbackHTTPFetcher.LOOPBACK_ADDRESSES
        or port != 8888
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or max_bytes <= 0
        or hostname not in allowed
        or not allowed.issubset(LoopbackHTTPFetcher.LOOPBACK_ADDRESSES)
    ):
        raise ValueError("invalid approved WSL loopback fetch")


class PinnedHTTPSFetcher:
    """Fetch one HTTPS response from an explicitly approved public address.

    Redirects are deliberately returned to :class:`ResearchBroker` instead of
    being followed here, so every new target is resolved and checked again.
    """

    def __init__(
        self,
        *,
        timeout_seconds: float = 15.0,
        max_header_bytes: int = 64 * 1024,
        transport: TransportFactory | None = None,
        user_agent: str = "AEGIS-Research/0.1",
    ) -> None:
        if timeout_seconds <= 0 or max_header_bytes < 1024:
            raise ValueError("invalid HTTPS fetcher limits")
        if not user_agent.isascii() or any(char in user_agent for char in "\r\n"):
            raise ValueError("invalid user agent")
        default_transport = SocketTLSTransport()
        self._transport = transport or default_transport.connect
        self.timeout_seconds = timeout_seconds
        self.max_header_bytes = max_header_bytes
        self.user_agent = user_agent

    def fetch(self, url: str, *, allowed_addresses: tuple[str, ...], max_bytes: int) -> FetchResponse:
        parsed = urlsplit(url)
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            raise ValueError("PinnedHTTPSFetcher accepts only HTTPS URLs")
        if parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise ValueError("invalid HTTPS URL")
        try:
            port = parsed.port or 443
        except ValueError as exc:
            raise ValueError("invalid HTTPS port") from exc
        if port != 443 or max_bytes <= 0 or not allowed_addresses:
            raise ValueError("invalid HTTPS fetch parameters")

        hostname = parsed.hostname.encode("idna").decode("ascii")
        allowed = tuple(ipaddress.ip_address(item.split("%", 1)[0]) for item in allowed_addresses)
        if not all(
            address.is_global
            and not address.is_private
            and not address.is_loopback
            and not address.is_link_local
            and not address.is_multicast
            and not address.is_reserved
            and not address.is_unspecified
            for address in allowed
        ):
            raise ValueError("approved HTTPS addresses must all be public")
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query
        if any(char in target for char in "\r\n"):
            raise ValueError("invalid HTTP request target")
        host = f"[{hostname}]" if ":" in hostname else hostname
        host_header = host if parsed.port is None else f"{host}:{port}"
        request = (
            f"GET {target} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"User-Agent: {self.user_agent}\r\n"
            "Accept: */*\r\n"
            "Accept-Encoding: identity\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")

        errors: list[BaseException] = []
        for address in allowed:
            # A CDN edge may close an otherwise valid pinned TLS response early.
            # Retry only that narrow framing failure; malformed or ambiguous HTTP
            # remains fail-closed and peer validation runs on every connection.
            for attempt in range(3):
                stream: HTTPSStream | None = None
                try:
                    stream = self._transport(str(address), port, hostname, self.timeout_seconds)
                    stream.settimeout(self.timeout_seconds)
                    peer_text = str(stream.getpeername()[0]).split("%", 1)[0]
                    peer = ipaddress.ip_address(peer_text)
                    if peer not in allowed:
                        raise RuntimeError("connected peer is not in the approved address set")
                    stream.sendall(request)
                    return _read_http_response(stream, url, max_bytes, self.max_header_bytes)
                except OSError as exc:
                    errors.append(exc)
                    if attempt == 2:
                        break
                except ValueError as exc:
                    if not str(exc).startswith("truncated HTTP"):
                        raise
                    errors.append(exc)
                    if attempt == 2:
                        break
                finally:
                    if stream is not None:
                        stream.close()
        if errors:
            last = errors[-1]
            if isinstance(last, ValueError):
                raise ValueError(str(last)) from last
            raise OSError("all approved HTTPS addresses failed") from last
        raise OSError("no approved HTTPS address was usable")
