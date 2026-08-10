"""Bind broker-fetched bytes to strict research import manifests.

This module is intentionally a pure trust-boundary adapter.  It performs no
fetching, archive extraction, installation, dependency resolution, or code
execution.  A successful result is still only a candidate import description.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Mapping

from aegis.models import canonical_json

from .imports import (
    MAX_IMPORT_BYTES,
    ResearchImportArtifact,
    ResearchImportError,
    validate_research_import,
)
from .types import Provenance, ResearchArtifact


class ResearchImportBindingError(ResearchImportError):
    """Raised when fetched bytes, provenance, and a manifest do not agree."""


def _snapshot_manifest(value: object) -> Mapping[str, Any]:
    """Take a detached strict-JSON snapshot before crossing the boundary."""
    if not isinstance(value, Mapping):
        raise ResearchImportBindingError("research import manifest must be a JSON object")
    try:
        encoded = canonical_json(value)
        snapshot = json.loads(encoded)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ResearchImportBindingError("research import manifest must contain strict finite JSON") from exc
    if not isinstance(snapshot, dict):
        raise ResearchImportBindingError("research import manifest must be a JSON object")
    return snapshot


def _validate_provenance(provenance: object, content: bytes) -> Provenance:
    if not isinstance(provenance, Provenance):
        raise ResearchImportBindingError("fetched artifact must contain broker provenance")
    digest = hashlib.sha256(content).hexdigest()
    if provenance.sha256 != digest:
        raise ResearchImportBindingError("broker provenance digest does not match fetched content")
    if (
        isinstance(provenance.size_bytes, bool)
        or not isinstance(provenance.size_bytes, int)
        or provenance.size_bytes != len(content)
        or not 1 <= provenance.size_bytes <= MAX_IMPORT_BYTES
    ):
        raise ResearchImportBindingError("broker provenance size does not match bounded fetched content")
    if (
        not isinstance(provenance.requested_url, str)
        or not provenance.requested_url
        or not isinstance(provenance.final_url, str)
        or not provenance.final_url
    ):
        raise ResearchImportBindingError("broker provenance URLs must be non-empty text")
    if not isinstance(provenance.redirect_chain, tuple) or any(
        not isinstance(url, str) or not url for url in provenance.redirect_chain
    ):
        raise ResearchImportBindingError("broker redirect chain must be an immutable URL tuple")
    if provenance.redirect_chain and provenance.redirect_chain[-1] != provenance.final_url:
        raise ResearchImportBindingError("broker redirect chain does not terminate at final_url")
    if not isinstance(provenance.media_type, str) or not provenance.media_type.strip():
        raise ResearchImportBindingError("broker provenance media_type must be non-empty text")
    if provenance.media_type != provenance.media_type.strip().lower() or len(provenance.media_type) > 128:
        raise ResearchImportBindingError("broker provenance media_type is not canonical")
    if not isinstance(provenance.retrieved_at, str):
        raise ResearchImportBindingError("broker provenance retrieved_at must be text")
    try:
        retrieved_at = datetime.fromisoformat(provenance.retrieved_at)
    except ValueError as exc:
        raise ResearchImportBindingError("broker provenance retrieved_at is invalid") from exc
    if retrieved_at.tzinfo is None or retrieved_at.utcoffset() is None:
        raise ResearchImportBindingError("broker provenance retrieved_at must be timezone-aware")
    return provenance


def bind_research_import(fetched: ResearchArtifact, manifest: object) -> ResearchImportArtifact:
    """Verify and bind one broker result to a strict immutable import.

    Kind-specific source, commit, license, file, paper-locator, permission, and
    dependency checks are delegated to :func:`validate_research_import` so the
    runtime path cannot drift from the import schema.
    """
    if not isinstance(fetched, ResearchArtifact) or not isinstance(fetched.content, bytes):
        raise ResearchImportBindingError("fetched must be a ResearchArtifact containing immutable bytes")
    if not fetched.content:
        raise ResearchImportBindingError("fetched content must not be empty")
    provenance = _validate_provenance(fetched.provenance, fetched.content)
    snapshot = _snapshot_manifest(manifest)
    try:
        candidate = validate_research_import(snapshot)
    except ResearchImportError:
        raise
    except (TypeError, ValueError) as exc:
        raise ResearchImportBindingError("research import manifest validation failed") from exc
    if candidate.source_url != provenance.final_url:
        raise ResearchImportBindingError("manifest source_url does not match broker final_url")
    if candidate.content_sha256 != provenance.sha256:
        raise ResearchImportBindingError("manifest content_sha256 does not match broker provenance")
    if candidate.size_bytes != provenance.size_bytes:
        raise ResearchImportBindingError("manifest size_bytes does not match broker provenance")
    return candidate


class RuntimeResearchImporter:
    """Stateless callable adapter for dependency-injected runtime composition."""

    def bind(self, fetched: ResearchArtifact, manifest: object) -> ResearchImportArtifact:
        return bind_research_import(fetched, manifest)
