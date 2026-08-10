"""Network capabilities injected into the broker.

Defaults deliberately have no network implementation. Production applications
must supply explicitly reviewed providers.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .types import FetchResponse, SearchHit


@runtime_checkable
class SearchProvider(Protocol):
    def search(self, query: str, *, limit: int) -> list[SearchHit]: ...


@runtime_checkable
class Fetcher(Protocol):
    def fetch(self, url: str, *, allowed_addresses: tuple[str, ...], max_bytes: int) -> FetchResponse:
        """Fetch while pinning connection targets to ``allowed_addresses``.

        Implementations must connect only to one of these validated addresses
        while retaining the URL hostname for TLS SNI and certificate checks.
        """
        ...


@runtime_checkable
class Resolver(Protocol):
    def resolve(self, hostname: str) -> tuple[str, ...]: ...


class NullSearchProvider:
    def search(self, query: str, *, limit: int) -> list[SearchHit]:
        raise RuntimeError("no search provider configured")


class NullFetcher:
    def fetch(self, url: str, *, allowed_addresses: tuple[str, ...], max_bytes: int) -> FetchResponse:
        raise RuntimeError("no fetcher configured")
