"""Read-only collection of a GitHub repository pinned to one exact commit.

The collector deliberately depends only on the injected research interface. It
does not clone, execute, install, extract, or write any fetched content. Its
output is an immutable in-memory snapshot suitable for a later quarantine
stage, not an execution grant.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import PurePosixPath
from typing import Any, Mapping, Protocol

from aegis.models import canonical_json

from .imports import (
    MAX_FILE_BYTES,
    MAX_FILES,
    MAX_IMPORT_BYTES,
    ResearchImportArtifact,
    ResearchImportError,
    validate_github_import,
)
from .types import Provenance, ResearchArtifact, SearchHit

_COMMIT = re.compile(r"[0-9a-f]{40}")
_OBJECT_SHA = re.compile(r"[0-9a-f]{40}")
_REPOSITORY = re.compile(
    r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/?"
)
_SOURCE_SUFFIXES = frozenset(
    {
        ".c",
        ".cc",
        ".cpp",
        ".cs",
        ".css",
        ".go",
        ".h",
        ".hpp",
        ".html",
        ".java",
        ".js",
        ".json",
        ".jsx",
        ".lock",
        ".md",
        ".ps1",
        ".py",
        ".rs",
        ".rst",
        ".sh",
        ".sql",
        ".toml",
        ".ts",
        ".tsx",
        ".txt",
        ".xml",
        ".yaml",
        ".yml",
    }
)
_SPECIAL_SOURCE_NAMES = frozenset(
    {"dockerfile", "license", "licence", "makefile", "readme", "skill.md"}
)
_JSON_MEDIA_TYPES = frozenset({"application/json", "application/vnd.github+json", "text/json"})
_TEXT_APPLICATION_TYPES = frozenset(
    {
        "application/json",
        "application/toml",
        "application/xml",
        "application/yaml",
        "application/x-sh",
        "application/x-toml",
        "application/x-yaml",
    }
)


class GitHubCollectionError(ResearchImportError):
    """A repository response did not prove the requested immutable snapshot."""


@dataclass(frozen=True, slots=True)
class ResolvedGitHubRef:
    repository_url: str
    requested_ref: str
    commit_sha: str
    provenance: Provenance


class Research(Protocol):
    def search(self, query: str, *, limit: int = 10) -> list[SearchHit]: ...

    def fetch(self, url: str, *, validate_as_archive: bool = False) -> ResearchArtifact: ...


@dataclass(frozen=True, slots=True)
class GitHubCollectorLimits:
    max_files: int = MAX_FILES
    max_file_bytes: int = MAX_FILE_BYTES
    max_total_bytes: int = MAX_IMPORT_BYTES
    max_metadata_bytes: int = 4 * 1024 * 1024

    def __post_init__(self) -> None:
        values = (self.max_files, self.max_file_bytes, self.max_total_bytes, self.max_metadata_bytes)
        if any(isinstance(value, bool) or not isinstance(value, int) or value <= 0 for value in values):
            raise ValueError("GitHub collector limits must be positive integers")
        if (
            self.max_files > MAX_FILES
            or self.max_file_bytes > MAX_FILE_BYTES
            or self.max_total_bytes > MAX_IMPORT_BYTES
        ):
            raise ValueError("GitHub collector limits cannot exceed research import hard limits")


@dataclass(frozen=True, slots=True)
class CollectedGitHubFile:
    path: str
    content: bytes
    size_bytes: int
    sha256: str
    git_blob_sha: str
    media_type: str
    provenance: Provenance


@dataclass(frozen=True, slots=True)
class GitHubSnapshot:
    repository_url: str
    commit_sha: str
    tree_sha: str
    license_spdx: str
    snapshot_sha256: str
    files: tuple[CollectedGitHubFile, ...]
    response_provenance: tuple[Provenance, ...]
    artifact: ResearchImportArtifact
    execution_granted: bool = False


def _repository(value: object) -> tuple[str, str, str]:
    if not isinstance(value, str) or value != value.strip() or len(value) > 2048:
        raise GitHubCollectionError("repository_url must be bounded trimmed text")
    match = _REPOSITORY.fullmatch(value)
    if match is None or match.group(2).endswith(".git"):
        raise GitHubCollectionError("repository_url must identify exactly one owner/repository")
    owner, name = match.groups()
    canonical = f"https://github.com/{owner}/{name}"
    if value.rstrip("/") != canonical:
        raise GitHubCollectionError("repository_url is not canonical")
    return canonical, owner, name


def _quote_path(path: str) -> str:
    """Percent-encode a validated path without using a network client module."""
    safe = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~/"
    return "".join(chr(byte) if byte in safe else f"%{byte:02X}" for byte in path.encode("utf-8"))


def _ref(value: object) -> str:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or not value
        or len(value.encode("utf-8")) > 256
        or value.startswith("/")
        or value.endswith(("/", "."))
        or "//" in value
        or ".." in value
        or "@{" in value
        or any(character in value for character in "\\~^:?*[")
        or any(ord(character) < 33 or ord(character) == 127 for character in value)
    ):
        raise GitHubCollectionError("GitHub ref must be a bounded safe branch, tag, or commit name")
    return value


def _provenance(artifact: object, expected_url: str, *, metadata: bool) -> ResearchArtifact:
    if not isinstance(artifact, ResearchArtifact) or not isinstance(artifact.content, bytes):
        raise GitHubCollectionError("research fetch returned an invalid artifact")
    provenance = artifact.provenance
    if not isinstance(provenance, Provenance):
        raise GitHubCollectionError("research fetch omitted provenance")
    digest = hashlib.sha256(artifact.content).hexdigest()
    if provenance.sha256 != digest or provenance.size_bytes != len(artifact.content):
        raise GitHubCollectionError("response provenance hash or size does not match content")
    if (
        provenance.requested_url != expected_url
        or provenance.final_url != expected_url
        or provenance.redirect_chain
    ):
        raise GitHubCollectionError("response provenance URL does not match the pinned request")
    try:
        retrieved = datetime.fromisoformat(provenance.retrieved_at)
    except (TypeError, ValueError) as exc:
        raise GitHubCollectionError("response provenance time is invalid") from exc
    if retrieved.tzinfo is None or retrieved.utcoffset() is None:
        raise GitHubCollectionError("response provenance time must be timezone-aware")
    media_type = provenance.media_type.lower()
    if metadata:
        if media_type not in _JSON_MEDIA_TYPES:
            raise GitHubCollectionError("GitHub API response must be JSON")
    elif not (media_type.startswith("text/") or media_type in _TEXT_APPLICATION_TYPES):
        raise GitHubCollectionError("GitHub source response is not a permitted text media type")
    return artifact


def _json_response(artifact: ResearchArtifact, name: str, maximum: int) -> Mapping[str, Any]:
    if not artifact.content or len(artifact.content) > maximum:
        raise GitHubCollectionError(f"{name} response is empty or too large")

    def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise GitHubCollectionError(f"{name} response contains duplicate JSON keys")
            result[key] = value
        return result

    try:
        value = json.loads(
            artifact.content.decode("utf-8"),
            object_pairs_hook=reject_duplicate,
            parse_constant=lambda token: (_ for _ in ()).throw(
                GitHubCollectionError(f"{name} response contains non-finite JSON: {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GitHubCollectionError(f"{name} response is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise GitHubCollectionError(f"{name} response must be a JSON object")
    return value


def _required_object(value: object, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise GitHubCollectionError(f"{name} must be a JSON object")
    return value


def _required_sha(value: object, name: str) -> str:
    if not isinstance(value, str) or _OBJECT_SHA.fullmatch(value) is None:
        raise GitHubCollectionError(f"{name} must be a lowercase 40-character object SHA")
    return value


def _safe_source_path(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 512 or value != value.strip():
        raise GitHubCollectionError("tree path must be bounded trimmed text")
    path = PurePosixPath(value)
    if path.is_absolute() or "\\" in value or any(part in {"", ".", ".."} for part in path.parts):
        raise GitHubCollectionError("tree path is not a safe POSIX relative path")
    return path.as_posix()


def _is_source(path: str) -> bool:
    candidate = PurePosixPath(path)
    return candidate.suffix.lower() in _SOURCE_SUFFIXES or candidate.name.lower() in _SPECIAL_SOURCE_NAMES


def _git_blob_sha(content: bytes) -> str:
    header = f"blob {len(content)}\0".encode("ascii")
    return hashlib.sha1(header + content, usedforsecurity=False).hexdigest()


class GitHubCollector:
    """Collect immutable text files from an exact GitHub commit into memory."""

    def __init__(self, research: Research, *, limits: GitHubCollectorLimits = GitHubCollectorLimits()) -> None:
        if not hasattr(research, "fetch"):
            raise TypeError("research must provide the ResearchBroker-compatible interface")
        self._research = research
        self._limits = limits

    def resolve(self, repository_url: str, ref: str = "HEAD") -> ResolvedGitHubRef:
        repository, owner, name = _repository(repository_url)
        requested_ref = _ref(ref)
        api_url = f"https://api.github.com/repos/{owner}/{name}/commits/{_quote_path(requested_ref)}"
        response = _provenance(self._research.fetch(api_url), api_url, metadata=True)
        payload = _json_response(response, "commit ref", self._limits.max_metadata_bytes)
        commit_sha = payload.get("sha")
        if not isinstance(commit_sha, str) or _COMMIT.fullmatch(commit_sha) is None:
            raise GitHubCollectionError("GitHub ref did not resolve to an exact lowercase commit SHA")
        return ResolvedGitHubRef(repository, requested_ref, commit_sha, response.provenance)

    def collect(self, repository_url: str, commit_sha: str) -> GitHubSnapshot:
        repository, owner, name = _repository(repository_url)
        if not isinstance(commit_sha, str) or _COMMIT.fullmatch(commit_sha) is None:
            raise GitHubCollectionError("commit must be a lowercase 40-character SHA")
        api_root = f"https://api.github.com/repos/{owner}/{name}"
        commit_url = f"{api_root}/commits/{commit_sha}"
        commit_response = _provenance(self._research.fetch(commit_url), commit_url, metadata=True)
        commit_json = _json_response(commit_response, "commit", self._limits.max_metadata_bytes)
        if commit_json.get("sha") != commit_sha:
            raise GitHubCollectionError("GitHub commit response drifted from the requested commit")
        commit_data = _required_object(commit_json.get("commit"), "commit.commit")
        tree_ref = _required_object(commit_data.get("tree"), "commit.commit.tree")
        tree_sha = _required_sha(tree_ref.get("sha"), "commit.commit.tree.sha")

        tree_url = f"{api_root}/git/trees/{tree_sha}?recursive=1"
        tree_response = _provenance(self._research.fetch(tree_url), tree_url, metadata=True)
        tree_json = _json_response(tree_response, "tree", self._limits.max_metadata_bytes)
        if tree_json.get("sha") != tree_sha:
            raise GitHubCollectionError("GitHub tree response drifted from the commit tree")
        if tree_json.get("truncated") is not False:
            raise GitHubCollectionError("recursive GitHub tree is truncated or lacks a truncation proof")
        raw_entries = tree_json.get("tree")
        if not isinstance(raw_entries, list):
            raise GitHubCollectionError("GitHub tree entries must be an array")

        license_url = f"{api_root}/license?ref={commit_sha}"
        license_response = _provenance(self._research.fetch(license_url), license_url, metadata=True)
        license_json = _json_response(license_response, "license", self._limits.max_metadata_bytes)
        license_data = _required_object(license_json.get("license"), "license.license")
        spdx = license_data.get("spdx_id")
        if not isinstance(spdx, str) or spdx in {"NOASSERTION", "OTHER"}:
            raise GitHubCollectionError("GitHub did not provide a usable SPDX license identifier")

        entries: list[tuple[str, str, int]] = []
        seen_paths: set[str] = set()
        for raw in raw_entries:
            entry = _required_object(raw, "tree entry")
            entry_type = entry.get("type")
            if entry_type not in {"blob", "tree", "commit"}:
                raise GitHubCollectionError("tree entry has an unsupported object type")
            if entry_type != "blob":
                continue
            path = _safe_source_path(entry.get("path"))
            folded = path.casefold()
            if folded in seen_paths:
                raise GitHubCollectionError("tree contains duplicate case-insensitive paths")
            seen_paths.add(folded)
            if not _is_source(path):
                continue
            if entry.get("mode") not in {"100644", "100755"}:
                raise GitHubCollectionError("source file is not a regular Git blob")
            blob_sha = _required_sha(entry.get("sha"), "tree entry sha")
            size = entry.get("size")
            if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= self._limits.max_file_bytes:
                raise GitHubCollectionError("tree file size is absent or exceeds the configured limit")
            entries.append((path, blob_sha, size))
            if len(entries) > self._limits.max_files:
                raise GitHubCollectionError("source file count exceeds the configured limit")
        if not entries:
            raise GitHubCollectionError("repository contains no allowed text source files")
        if sum(size for _, _, size in entries) > self._limits.max_total_bytes:
            raise GitHubCollectionError("declared source size exceeds the configured total limit")

        files: list[CollectedGitHubFile] = []
        for path, blob_sha, declared_size in sorted(entries):
            raw_url = (
                f"https://raw.githubusercontent.com/{owner}/{name}/{commit_sha}/"
                + _quote_path(path)
            )
            response = _provenance(self._research.fetch(raw_url), raw_url, metadata=False)
            content = response.content
            if len(content) != declared_size or len(content) > self._limits.max_file_bytes:
                raise GitHubCollectionError("raw source size does not match the pinned tree")
            if _git_blob_sha(content) != blob_sha:
                raise GitHubCollectionError("raw source hash does not match the pinned Git blob")
            try:
                decoded = content.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise GitHubCollectionError("raw source is not UTF-8 text") from exc
            if "\x00" in decoded or any(ord(char) < 32 and char not in "\t\n\r" for char in decoded):
                raise GitHubCollectionError("raw source contains binary control bytes")
            files.append(
                CollectedGitHubFile(
                    path,
                    content,
                    len(content),
                    hashlib.sha256(content).hexdigest(),
                    blob_sha,
                    response.provenance.media_type,
                    response.provenance,
                )
            )
        total_size = sum(item.size_bytes for item in files)
        if total_size <= 0 or total_size > self._limits.max_total_bytes:
            raise GitHubCollectionError("collected source size is outside the configured limit")
        file_manifest = [
            {
                "path": item.path,
                "size_bytes": item.size_bytes,
                "sha256": item.sha256,
                "media_type": item.media_type,
            }
            for item in files
        ]
        snapshot_material = {
            "repository_url": repository,
            "commit_sha": commit_sha,
            "tree_sha": tree_sha,
            "files": file_manifest,
        }
        snapshot_sha = hashlib.sha256(canonical_json(snapshot_material).encode("utf-8")).hexdigest()
        manifest = {
            "schema_version": 1,
            "kind": "github",
            "source_url": f"{repository}/tree/{commit_sha}",
            "content_sha256": snapshot_sha,
            "size_bytes": total_size,
            "metadata": {
                "repository_url": repository,
                "commit_sha": commit_sha,
                "license": spdx,
                "files": file_manifest,
            },
        }
        artifact = validate_github_import(manifest)
        return GitHubSnapshot(
            repository,
            commit_sha,
            tree_sha,
            spdx,
            snapshot_sha,
            tuple(files),
            (commit_response.provenance, tree_response.provenance, license_response.provenance),
            artifact,
        )
