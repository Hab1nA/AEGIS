"""Policy-enforcing facade for all agent research operations."""

from __future__ import annotations

import hashlib
from urllib.parse import urljoin

from .archive import ArchiveLimits, validate_archive
from .interfaces import Fetcher, NullFetcher, NullSearchProvider, Resolver, SearchProvider
from .types import Provenance, ResearchArtifact, SearchHit
from .url_security import SystemResolver, UrlPolicy, validate_url, validate_url_target


class ResearchBroker:
    def __init__(
        self,
        *,
        search_provider: SearchProvider | None = None,
        fetcher: Fetcher | None = None,
        resolver: Resolver | None = None,
        url_policy: UrlPolicy = UrlPolicy(),
        max_download_bytes: int = 16 * 1024 * 1024,
        max_redirects: int = 5,
    ) -> None:
        if max_download_bytes <= 0 or max_redirects < 0:
            raise ValueError("invalid broker limits")
        self.search_provider = search_provider or NullSearchProvider()
        self.fetcher = fetcher or NullFetcher()
        self.resolver = resolver or SystemResolver()
        self.url_policy = url_policy
        self.max_download_bytes = max_download_bytes
        self.max_redirects = max_redirects

    def search(self, query: str, *, limit: int = 10) -> list[SearchHit]:
        if not query.strip() or len(query) > 1000:
            raise ValueError("invalid search query")
        if not 1 <= limit <= 100:
            raise ValueError("search limit must be in [1, 100]")
        hits = self.search_provider.search(query, limit=limit)
        validated: list[SearchHit] = []
        for hit in hits[:limit]:
            validated.append(
                SearchHit(validate_url(hit.url, self.resolver, self.url_policy), hit.title, hit.summary)
            )
        return validated

    def fetch(
        self, url: str, *, validate_as_archive: bool = False, archive_limits: ArchiveLimits = ArchiveLimits()
    ) -> ResearchArtifact:
        requested = validate_url(url, self.resolver, self.url_policy)
        current = requested
        chain: list[str] = []
        for redirect_count in range(self.max_redirects + 1):
            # Validate immediately before every request to protect against DNS
            # rebinding in resolvers that perform a fresh lookup.
            current, allowed_addresses = validate_url_target(current, self.resolver, self.url_policy)
            response = self.fetcher.fetch(
                current,
                allowed_addresses=allowed_addresses,
                max_bytes=self.max_download_bytes,
            )
            if response.url != current:
                raise RuntimeError("fetcher response URL does not match requested URL")
            if len(response.body) > self.max_download_bytes:
                raise ValueError("download exceeds maximum size")
            if response.redirect_url is not None:
                if redirect_count >= self.max_redirects:
                    raise ValueError("too many redirects")
                next_url = urljoin(current, response.redirect_url)
                current = validate_url(next_url, self.resolver, self.url_policy)
                chain.append(current)
                continue
            if not 200 <= response.status_code < 300:
                raise RuntimeError(f"fetch failed with HTTP status {response.status_code}")
            if validate_as_archive:
                validate_archive(response.body, archive_limits)
            digest = hashlib.sha256(response.body).hexdigest()
            content_type = (
                next(
                    (value for key, value in response.headers.items() if key.lower() == "content-type"),
                    "application/octet-stream",
                )
                .split(";", 1)[0]
                .strip()
                .lower()
            )
            provenance = Provenance.now(
                requested_url=requested,
                final_url=current,
                sha256=digest,
                size_bytes=len(response.body),
                media_type=content_type,
                redirect_chain=tuple(chain),
            )
            return ResearchArtifact(response.body, provenance)
        raise AssertionError("redirect loop exhausted unexpectedly")
