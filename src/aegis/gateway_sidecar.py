"""Trusted in-distro gateway sidecar: the only holder of relay credentials.

The WSL supervisor starts this fixed agent with the campaign's upstream relay
credentials in its environment.  Champion (harness-candidate) code never sees
those credentials; it talks to ``http://127.0.0.1:<port>/v1/responses`` and the
sidecar forwards to the real HTTPS relay while metering every request.

Security envelope:
- listens on the loopback interface only;
- forwards POST ``/v1/responses`` and nothing else, never following redirects;
- the upstream URL must be credential-free HTTPS; the hostname is resolved
  once through the shared SSRF policy (private, loopback, link-local, and
  reserved addresses are rejected) and every connection is pinned to the
  validated address while TLS SNI and certificate checks keep validating the
  original hostname, so DNS rebinding cannot move the target;
- every request appends one bounded metering record (JSONL) so the host can
  reconcile sidecar observations against the runtime ledger.
"""

from __future__ import annotations

import http.client
import json
import os
import socket
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from aegis.research.url_security import SystemResolver, validate_url_target

_MAX_REQUEST_BODY = 64 * 1024 * 1024
_MAX_RESPONSE_BODY = 256 * 1024 * 1024
_DEFAULT_TIMEOUT = 900.0
_METERING_LOCK = threading.Lock()


class GatewaySidecarError(RuntimeError):
    pass


def _env(name: str, *, required: bool = True, maximum: int = 2048) -> str | None:
    value = os.environ.get(name)
    if value is None or not value:
        if required:
            raise GatewaySidecarError(f"sidecar environment is missing {name}")
        return None
    if "\x00" in value or len(value.encode("utf-8")) > maximum:
        raise GatewaySidecarError(f"sidecar environment {name} is invalid")
    return value


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """TLS connection pinned to one validated address; SNI/cert keep the origin."""

    def __init__(self, address: str, origin_host: str, **kwargs: Any) -> None:
        super().__init__(origin_host, **kwargs)
        self._pinned_address = address

    def connect(self) -> None:
        raw = socket.create_connection(
            (self._pinned_address, self.port), timeout=self.timeout
        )
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


class _Upstream:
    """Validated, address-pinned view of the credential-free HTTPS upstream."""

    def __init__(self, base_url: str, api_key: str, user_agent: str | None, timeout: float) -> None:
        if base_url.endswith("/"):
            base_url = base_url[:-1]
        normalized, _addresses = validate_url_target(base_url, SystemResolver())
        parsed = urlsplit(normalized)
        if parsed.path in {"", "/"}:
            raise GatewaySidecarError("sidecar upstream base URL must include a path prefix")
        self.origin_host = parsed.hostname or ""
        self.base_path = parsed.path.rstrip("/")
        self.port = parsed.port or 443
        self.api_key = api_key
        self.user_agent = user_agent or "aegis-gateway-sidecar/1"
        self.timeout = timeout
        self.addresses = _addresses
        self._address_index = 0
        self._lock = threading.Lock()

    def post(self, body: bytes, content_type: str) -> tuple[int, bytes, str]:
        with self._lock:
            address = self.addresses[self._address_index % len(self.addresses)]
            self._address_index += 1
        connection = _PinnedHTTPSConnection(
            address,
            self.origin_host,
            port=self.port,
            timeout=self.timeout,
            context=ssl.create_default_context(),
        )
        headers = {
            "Content-Type": content_type,
            "Authorization": f"Bearer {self.api_key}",
            "User-Agent": self.user_agent,
            "Accept": "application/json",
            "Host": self.origin_host,
        }
        try:
            connection.request("POST", self.base_path + "/responses", body=body, headers=headers)
            response = connection.getresponse()
            payload = response.read(_MAX_RESPONSE_BODY + 1)
            if len(payload) > _MAX_RESPONSE_BODY:
                raise GatewaySidecarError("upstream response exceeded the sidecar bound")
            return response.status, payload, response.getheader("Content-Type") or "application/json"
        finally:
            connection.close()


def _meter(metering_path: str | None, record: dict[str, Any]) -> None:
    if not metering_path:
        return
    line = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
    with _METERING_LOCK:
        with open(metering_path, "a", encoding="utf-8") as stream:
            stream.write(line)


class _ForwardHandler(BaseHTTPRequestHandler):
    server_version = "aegis-gateway-sidecar/1"
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler interface
        upstream: _Upstream = self.server.upstream  # type: ignore[attr-defined]
        metering_path: str | None = self.server.metering_path  # type: ignore[attr-defined]
        if self.path != "/v1/responses":
            self._reply_json(404, {"error": "sidecar only forwards the relay responses path"})
            return
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            length = -1
        if not 0 < length <= _MAX_REQUEST_BODY:
            self._reply_json(413, {"error": "sidecar request body is outside the size bound"})
            return
        body = self.rfile.read(length)
        started = time.time()
        try:
            status, payload, content_type = upstream.post(
                body, self.headers.get("Content-Type", "application/json")
            )
        except GatewaySidecarError as exc:
            _meter(
                metering_path,
                {"ts": started, "outcome": "rejected", "request_bytes": len(body), "response_bytes": 0},
            )
            self._reply_json(502, {"error": str(exc)[:512]})
            return
        except (OSError, http.client.HTTPException) as exc:
            _meter(
                metering_path,
                {
                    "ts": started,
                    "outcome": "transport_error",
                    "request_bytes": len(body),
                    "response_bytes": 0,
                    "detail": str(exc)[:256],
                },
            )
            self._reply_json(502, {"error": f"sidecar upstream transport failed: {exc}"[:512]})
            return
        _meter(
            metering_path,
            {
                "ts": round(started, 3),
                "duration_seconds": round(time.time() - started, 3),
                "outcome": "forwarded",
                "status": status,
                "request_bytes": len(body),
                "response_bytes": len(payload),
            },
        )
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _reply_json(self, status: int, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        # Silence per-request stderr logging; metering is the durable record.
        return


def metering_summary(metering_path: str | None) -> dict[str, Any]:
    total: dict[str, Any] = {"requests": 0, "request_bytes": 0, "response_bytes": 0, "errors": 0}
    if not metering_path:
        return total
    try:
        with open(metering_path, "r", encoding="utf-8") as stream:
            for line in stream:
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(record, dict):
                    continue
                total["requests"] += 1
                total["request_bytes"] += int(record.get("request_bytes", 0))
                total["response_bytes"] += int(record.get("response_bytes", 0))
                if record.get("outcome") != "forwarded":
                    total["errors"] += 1
    except OSError:
        pass
    return total


def main() -> int:
    """Bind loopback, announce the port, serve until stdin closes."""
    api_key = _env("AEGIS_SIDECAR_API_KEY")
    upstream = _Upstream(
        _env("AEGIS_SIDECAR_UPSTREAM_BASE_URL") or "",
        api_key or "",
        _env("AEGIS_SIDECAR_USER_AGENT", required=False),
        float(_env("AEGIS_SIDECAR_TIMEOUT_SECONDS", required=False) or _DEFAULT_TIMEOUT),
    )
    metering_path = _env("AEGIS_SIDECAR_METERING_PATH", required=False)
    if metering_path:
        Path(metering_path).parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ForwardHandler)
    server.upstream = upstream  # type: ignore[attr-defined]
    server.metering_path = metering_path  # type: ignore[attr-defined]
    server.daemon_threads = True
    sys.stdout.write(
        json.dumps({"event": "listening", "port": server.server_address[1]}, sort_keys=True) + "\n"
    )
    sys.stdout.flush()

    stop = threading.Event()

    def watch_stdin() -> None:
        try:
            sys.stdin.buffer.read()
        except (OSError, ValueError):
            pass
        stop.set()

    threading.Thread(target=watch_stdin, name="aegis-sidecar-stdin", daemon=True).start()
    try:
        while not stop.is_set():
            server.timeout = 0.5
            server.handle_request()
    finally:
        sys.stdout.write(
            json.dumps({"event": "summary", **metering_summary(metering_path)}, sort_keys=True) + "\n"
        )
        sys.stdout.flush()
        server.server_close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
