"""Configured SearxNG JSON search provider."""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit

from .interfaces import Fetcher, Resolver
from .types import SearchHit
from .url_security import (
    SystemResolver,
    UrlPolicy,
    validate_loopback_url_target,
    validate_url_target,
)


class SearxNGSearchProvider:
    ENVIRONMENT_KEY = "AEGIS_SEARCH_BASE_URL"
    LOOPBACK_ENVIRONMENT_KEY = "AEGIS_ALLOW_INSECURE_SEARCH_LOOPBACK"

    def __init__(
        self,
        base_url: str,
        *,
        fetcher: Fetcher,
        resolver: Resolver | None = None,
        url_policy: UrlPolicy = UrlPolicy(),
        max_response_bytes: int = 2 * 1024 * 1024,
        max_results: int = 100,
        allow_insecure_loopback: bool = False,
        empty_result_attempts: int = 1,
        empty_result_delay_seconds: float = 0.0,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if (
            max_response_bytes <= 0
            or not 1 <= max_results <= 100
            or empty_result_attempts < 1
            or empty_result_delay_seconds < 0
        ):
            raise ValueError("invalid SearxNG limits")
        parsed = urlsplit(base_url)
        if parsed.query or parsed.fragment:
            raise ValueError("SearxNG base URL cannot contain query or fragment")
        endpoint_path = (parsed.path.rstrip("/") + "/search") or "/search"
        endpoint = urlunsplit((parsed.scheme, parsed.netloc, endpoint_path, "", ""))
        self.fetcher = fetcher
        self.resolver = resolver or SystemResolver()
        self.url_policy = url_policy
        self.allow_insecure_loopback = allow_insecure_loopback
        self.endpoint = (
            validate_loopback_url_target(endpoint)[0]
            if allow_insecure_loopback
            else validate_url_target(endpoint, self.resolver, self.url_policy)[0]
        )
        self.max_response_bytes = max_response_bytes
        self.max_results = max_results
        self.empty_result_attempts = empty_result_attempts
        self.empty_result_delay_seconds = empty_result_delay_seconds
        self._sleep = sleeper

    @classmethod
    def from_environment(
        cls,
        *,
        fetcher: Fetcher,
        environ: Mapping[str, str] | None = None,
        resolver: Resolver | None = None,
        url_policy: UrlPolicy = UrlPolicy(),
        max_response_bytes: int = 2 * 1024 * 1024,
        max_results: int = 100,
    ) -> "SearxNGSearchProvider":
        # Read exactly one non-secret setting. Proxy and credential variables are
        # neither copied nor passed to the transport.
        source = os.environ if environ is None else environ
        base_url = source.get(cls.ENVIRONMENT_KEY, "").strip()
        if not base_url:
            raise RuntimeError("no search provider configured: AEGIS_SEARCH_BASE_URL is unset")
        raw_loopback = source.get(cls.LOOPBACK_ENVIRONMENT_KEY, "false").strip().lower()
        if raw_loopback not in {"true", "false"}:
            raise ValueError("AEGIS_ALLOW_INSECURE_SEARCH_LOOPBACK must be true or false")
        allow_insecure_loopback = raw_loopback == "true"
        return cls(
            base_url,
            fetcher=fetcher,
            resolver=resolver,
            url_policy=url_policy,
            max_response_bytes=max_response_bytes,
            max_results=max_results,
            allow_insecure_loopback=allow_insecure_loopback,
            # A newly awakened WSL instance can have the local SearxNG
            # listener ready before its proxy-backed engines are usable.
            # Keep this retry limited to the explicitly approved loopback
            # transport; public providers still receive exactly one request.
            empty_result_attempts=15 if allow_insecure_loopback else 1,
            empty_result_delay_seconds=3.0 if allow_insecure_loopback else 0.0,
        )

    def search(self, query: str, *, limit: int) -> list[SearchHit]:
        if not isinstance(query, str) or not query.strip() or len(query) > 1000:
            raise ValueError("invalid search query")
        if not 1 <= limit <= self.max_results:
            raise ValueError(f"search limit must be in [1, {self.max_results}]")
        separator = "&" if urlsplit(self.endpoint).query else "?"
        request_url = (
            self.endpoint
            + separator
            + urlencode({"q": query, "format": "json"}, encoding="utf-8", errors="strict")
        )
        request_url, allowed_addresses = (
            validate_loopback_url_target(request_url)
            if self.allow_insecure_loopback
            else validate_url_target(request_url, self.resolver, self.url_policy)
        )
        for attempt in range(self.empty_result_attempts):
            response = self.fetcher.fetch(
                request_url,
                allowed_addresses=allowed_addresses,
                max_bytes=self.max_response_bytes,
            )
            hits = self._parse_response(response, request_url, limit)
            if hits or attempt + 1 >= self.empty_result_attempts:
                return hits
            self._sleep(self.empty_result_delay_seconds)
        raise AssertionError("unreachable SearxNG retry state")

    def _parse_response(self, response: Any, request_url: str, limit: int) -> list[SearchHit]:
        if response.url != request_url:
            raise RuntimeError("SearxNG response URL does not match requested URL")
        if response.redirect_url is not None:
            raise RuntimeError("SearxNG endpoint redirects are not allowed")
        if not 200 <= response.status_code < 300:
            raise RuntimeError(f"SearxNG request failed with HTTP status {response.status_code}")
        if len(response.body) > self.max_response_bytes:
            raise ValueError("SearxNG response exceeds maximum size")
        content_type = (
            next((value for key, value in response.headers.items() if key.lower() == "content-type"), "")
            .split(";", 1)[0]
            .strip()
            .lower()
        )
        if content_type != "application/json":
            raise ValueError("SearxNG response is not application/json")
        try:
            payload: Any = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid SearxNG JSON response") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
            raise ValueError("invalid SearxNG response schema")
        results = payload["results"]
        if len(results) > self.max_results:
            raise ValueError("SearxNG response contains too many results")
        hits: list[SearchHit] = []
        for item in results:
            try:
                hit = self._parse_result(item)
            except ValueError:
                continue
            hits.append(hit)
            if len(hits) >= limit:
                break
        return hits

    @staticmethod
    def _parse_result(item: Any) -> SearchHit:
        if not isinstance(item, dict):
            raise ValueError("invalid SearxNG result schema")
        url = item.get("url")
        title = item.get("title")
        summary = item.get("content", "")
        if (
            not isinstance(url, str)
            or not url.strip()
            or len(url) > 2048
            or not isinstance(title, str)
            or not title.strip()
            or len(title) > 2000
            or not isinstance(summary, str)
            or len(summary) > 20_000
        ):
            raise ValueError("invalid SearxNG result schema")
        # Result URLs intentionally remain untrusted; ResearchBroker validates
        # every one against its own resolver and URL policy.
        return SearchHit(url.strip(), title.strip(), summary.strip())
