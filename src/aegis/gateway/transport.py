"""Small injectable HTTP layer. Tests can replace it without network access."""

from __future__ import annotations

import multiprocessing
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping, Protocol, cast

from .types import CancelToken, GatewayHTTPError


@dataclass(frozen=True, slots=True)
class HTTPResponse:
    status: int
    body: bytes
    headers: Mapping[str, str]


def _http_child(
    conn: Any,
    url: str,
    headers: Mapping[str, str],
    body: bytes,
    timeout: float,
) -> None:
    """Run one HTTPS request inside a child process.

    A blocked TLS handshake can hold the GIL while OpenSSL waits, which freezes
    the whole controller no matter how the caller bounds a worker thread.  A
    child process isolates that network wait so the controller can enforce a
    hard deadline and terminate the child.
    """
    try:
        opener = urllib.request.build_opener(StdlibHTTPTransport._NoRedirect())
        request = urllib.request.Request(url, data=body, headers=dict(headers), method="POST")
        with opener.open(request, timeout=timeout) as response:
            chunks: list[bytes] = []
            while True:
                chunk = response.read(64 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            conn.send(
                ("response", HTTPResponse(response.status, b"".join(chunks), dict(response.headers.items())))
            )
    except urllib.error.HTTPError as exc:
        # HTTPError embeds an un-picklable response object; forward only the
        # parts the caller needs to classify and surface the error.
        try:
            error_body = exc.read(64 * 1024).decode("utf-8", "replace")
        finally:
            exc.close()
        conn.send(("http_error", exc.code, error_body))
    except BaseException as exc:  # noqa: BLE001 - relayed to the caller
        conn.send(("error", exc))


class HTTPTransport(Protocol):
    def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes,
        timeout: float,
        cancel: CancelToken,
    ) -> HTTPResponse: ...


class StdlibHTTPTransport:
    """urllib transport with cancellation checks around the blocking operation."""

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
            del req, fp, code, msg, headers, newurl
            return None

    def __init__(self, opener: urllib.request.OpenerDirector | None = None) -> None:
        # urllib's default opener follows redirects and may replay Authorization
        # to another origin. Refusing all redirects is the only safe default for
        # an authenticated model POST.
        self._opener = opener or urllib.request.build_opener(self._NoRedirect())

    def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes,
        timeout: float,
        cancel: CancelToken,
    ) -> HTTPResponse:
        cancel.raise_if_cancelled()
        request = urllib.request.Request(url, data=body, headers=dict(headers), method="POST")
        deadline = time.monotonic() + timeout
        if self._opener is not None and not isinstance(
            self._opener, urllib.request.OpenerDirector
        ):
            # Injected test openers are not spawnable; keep the bounded
            # worker-thread path for them.
            return self._post_worker_thread(
                url, headers, body, timeout, deadline, request, cancel
            )
        parent_conn, child_conn = multiprocessing.Pipe(duplex=False)
        child = multiprocessing.Process(
            target=_http_child,
            args=(child_conn, url, dict(headers), body, timeout),
            name="aegis-gateway-http",
            daemon=True,
        )
        child.start()
        child_conn.close()
        child.join(timeout=max(0.0, deadline - time.monotonic()))
        if child.is_alive():
            child.terminate()
            try:
                child.join(timeout=5)
            except Exception:
                pass
            raise TimeoutError("model relay response exceeded total timeout")
        try:
            outcome = parent_conn.recv()
        except EOFError as exc:
            raise RuntimeError("model relay child exited without a response") from exc
        kind = outcome[0]
        if kind == "http_error":
            _, code, error_body = outcome
            raise GatewayHTTPError(
                code,
                error_body,
                retryable=code in {408, 409, 429} or code >= 500,
            )
        if kind == "error":
            raise outcome[1]
        return cast(HTTPResponse, outcome[1])

    def _post_worker_thread(
        self,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout: float,
        deadline: float,
        request: urllib.request.Request,
        cancel: CancelToken,
    ) -> HTTPResponse:
        """Bounded in-process read for injected (non-spawnable) openers."""
        # A blocked SSL read can ignore the socket timeout on Windows, so the
        # whole response read runs in a worker thread and the caller enforces
        # the deadline by closing the connection and abandoning the worker.
        outcomes: list[Any] = []
        responses: list[Any] = []

        def worker() -> None:
            try:
                response = self._opener.open(request, timeout=timeout)
                responses.append(response)
                try:
                    chunks: list[bytes] = []
                    while True:
                        cancel.raise_if_cancelled()
                        chunk = response.read(64 * 1024)
                        if not chunk:
                            break
                        chunks.append(chunk)
                    outcomes.append(
                        HTTPResponse(response.status, b"".join(chunks), dict(response.headers.items()))
                    )
                finally:
                    response.close()
            except BaseException as exc:  # noqa: BLE001 - relayed to the caller
                outcomes.append(exc)

        worker_thread = threading.Thread(
            target=worker, name="aegis-gateway-read", daemon=True
        )
        worker_thread.start()
        worker_thread.join(timeout=max(0.0, deadline - time.monotonic()))
        if worker_thread.is_alive():
            if responses:
                try:
                    responses[0].close()
                except Exception:
                    pass
            raise TimeoutError("model relay response exceeded total timeout")
        outcome = outcomes[0]
        if isinstance(outcome, urllib.error.HTTPError):
            try:
                error_body = outcome.read(64 * 1024).decode("utf-8", "replace")
            finally:
                outcome.close()
            raise GatewayHTTPError(
                outcome.code,
                error_body,
                retryable=outcome.code in {408, 409, 429} or outcome.code >= 500,
            ) from outcome
        if isinstance(outcome, BaseException):
            raise outcome
        return cast(HTTPResponse, outcome)
