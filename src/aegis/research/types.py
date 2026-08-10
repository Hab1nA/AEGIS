"""Types returned by research providers and the broker."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping


@dataclass(frozen=True, slots=True)
class SearchHit:
    url: str
    title: str
    summary: str = ""


@dataclass(frozen=True, slots=True)
class FetchResponse:
    url: str
    status_code: int
    headers: Mapping[str, str]
    body: bytes
    redirect_url: str | None = None


@dataclass(frozen=True, slots=True)
class Provenance:
    requested_url: str
    final_url: str
    retrieved_at: str
    sha256: str
    size_bytes: int
    media_type: str
    redirect_chain: tuple[str, ...]

    @classmethod
    def now(
        cls,
        *,
        requested_url: str,
        final_url: str,
        sha256: str,
        size_bytes: int,
        media_type: str,
        redirect_chain: tuple[str, ...],
    ) -> "Provenance":
        return cls(
            requested_url=requested_url,
            final_url=final_url,
            retrieved_at=datetime.now(timezone.utc).isoformat(),
            sha256=sha256,
            size_bytes=size_bytes,
            media_type=media_type,
            redirect_chain=redirect_chain,
        )


@dataclass(frozen=True, slots=True)
class ResearchArtifact:
    content: bytes
    provenance: Provenance
