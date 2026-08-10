"""Strict, side-effect-free validation for candidate research imports.

Passing these validators does not install or execute an artifact.  It only
produces an immutable, content-addressed description suitable for a later
quarantine, inspection, and promotion pipeline.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit

from aegis.models import canonical_json

SCHEMA_VERSION = 1
MAX_MANIFEST_BYTES = 1_048_576
MAX_IMPORT_BYTES = 64 * 1024 * 1024
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_FILES = 2_048
MAX_AUTHORS = 128
MAX_PROVENANCE_ITEMS = 256
MAX_DEPENDENCIES = 128
MAX_PERMISSIONS = 32

_SHA256 = re.compile(r"[0-9a-f]{64}")
_COMMIT_SHA = re.compile(r"[0-9a-f]{40}")
_GITHUB_REPOSITORY = re.compile(r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)")
_SPDX = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]*(?: WITH [A-Za-z0-9][A-Za-z0-9.+-]*)?")
_SKILL_NAME = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?")
_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}(?:[-+][0-9A-Za-z.-]+)?")
_DEPENDENCY_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?")
_IDENTIFIER = re.compile(
    r"(?:doi:10\.\d{4,9}/[-._;()/:A-Za-z0-9]+|arxiv:\d{4}\.\d{4,5}(?:v\d+)?)",
    re.IGNORECASE,
)

_TEXT_MEDIA_TYPES = frozenset(
    {
        "application/json",
        "application/toml",
        "application/xml",
        "application/yaml",
        "application/x-sh",
        "application/x-toml",
        "application/x-yaml",
        "text/csv",
        "text/html",
        "text/markdown",
        "text/plain",
        "text/x-c",
        "text/x-c++",
        "text/x-csharp",
        "text/x-go",
        "text/x-java-source",
        "text/x-python",
        "text/x-rust",
        "text/x-shellscript",
        "text/x-sql",
        "text/x-typescript",
    }
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
ALLOWED_SKILL_PERMISSIONS = frozenset(
    {"research.fetch", "research.search", "sandbox.exec", "workspace.read", "workspace.write"}
)
_CONTROL_PLANE_WORDS = frozenset(
    {
        "budget",
        "campaign",
        "credential",
        "evaluation",
        "hidden_test",
        "model_gateway",
        "permission_admin",
        "promotion",
        "prosecutor",
        "sandbox_admin",
        "secret",
        "strategy_registry",
    }
)


class ResearchImportKind(StrEnum):
    GITHUB = "github"
    PAPER = "paper"
    SKILL = "skill"


class ResearchImportError(ValueError):
    """Raised when an untrusted import manifest is not safe and canonical."""


def _strict_object(value: object, expected: set[str], name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ResearchImportError(f"{name} must be a JSON object")
    if set(value) != expected:
        raise ResearchImportError(f"{name} has missing or unknown fields")
    return value


def _text(value: object, name: str, *, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise ResearchImportError(f"{name} must be bounded, trimmed text without controls")
    return value


def _bounded_int(value: object, name: str, *, maximum: int, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ResearchImportError(f"{name} must be an integer in [{minimum},{maximum}]")
    return value


def _digest(value: object, name: str = "sha256") -> str:
    text = _text(value, name, maximum=64)
    if _SHA256.fullmatch(text) is None:
        raise ResearchImportError(f"{name} must be a lowercase SHA-256 digest")
    return text


def _public_https_url(value: object, name: str) -> str:
    raw = _text(value, name, maximum=2048)
    parsed = urlsplit(raw)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ResearchImportError(f"{name} must be an HTTPS URL")
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise ResearchImportError(f"{name} must not contain credentials or a fragment")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ResearchImportError(f"{name} has an invalid port") from exc
    if port not in {None, 443}:
        raise ResearchImportError(f"{name} must use port 443")
    hostname = parsed.hostname.rstrip(".").lower()
    if hostname == "localhost" or hostname.endswith((".localhost", ".local", ".internal")):
        raise ResearchImportError(f"{name} must use a public hostname")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        if "." not in hostname:
            raise ResearchImportError(f"{name} must use a qualified public hostname")
    else:
        if not address.is_global:
            raise ResearchImportError(f"{name} must use a public address")
    host_text = f"[{hostname}]" if ":" in hostname else hostname
    return urlunsplit(("https", host_text, parsed.path or "/", parsed.query, ""))


def _safe_path(value: object, name: str) -> str:
    raw = _text(value, name, maximum=512)
    path = PurePosixPath(raw)
    if (
        path.is_absolute()
        or "\\" in raw
        or "\x00" in raw
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ResearchImportError(f"{name} must be a safe POSIX relative path")
    return path.as_posix()


@dataclass(frozen=True, slots=True)
class ImportedFile:
    path: str
    size_bytes: int
    sha256: str
    media_type: str

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "media_type": self.media_type,
        }


@dataclass(frozen=True, slots=True)
class GitHubImportMetadata:
    repository_url: str
    commit_sha: str
    license: str
    files: tuple[ImportedFile, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "repository_url": self.repository_url,
            "commit_sha": self.commit_sha,
            "license": self.license,
            "files": [item.to_dict() for item in self.files],
        }


@dataclass(frozen=True, slots=True)
class PaperProvenance:
    source_url: str
    locator_type: str
    locator: str
    content_sha256: str

    def to_dict(self) -> dict[str, str]:
        return {
            "source_url": self.source_url,
            "locator_type": self.locator_type,
            "locator": self.locator,
            "content_sha256": self.content_sha256,
        }


@dataclass(frozen=True, slots=True)
class PaperImportMetadata:
    title: str
    authors: tuple[str, ...]
    identifier: str
    provenance: tuple[PaperProvenance, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "title": self.title,
            "authors": list(self.authors),
            "identifier": self.identifier,
            "provenance": [item.to_dict() for item in self.provenance],
        }


@dataclass(frozen=True, slots=True)
class SkillDependency:
    name: str
    version: str
    sha256: str

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "version": self.version, "sha256": self.sha256}


@dataclass(frozen=True, slots=True)
class SkillImportMetadata:
    name: str
    version: str
    permissions: tuple[str, ...]
    dependencies: tuple[SkillDependency, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "version": self.version,
            "permissions": list(self.permissions),
            "dependencies": [item.to_dict() for item in self.dependencies],
        }


ImportMetadata = GitHubImportMetadata | PaperImportMetadata | SkillImportMetadata


@dataclass(frozen=True, slots=True)
class ResearchImportArtifact:
    """Immutable, normalized import candidate; never an execution grant."""

    artifact_id: str
    schema_version: int
    kind: ResearchImportKind
    source_url: str
    content_sha256: str
    size_bytes: int
    metadata: ImportMetadata

    def to_dict(self, *, include_artifact_id: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "kind": self.kind.value,
            "source_url": self.source_url,
            "content_sha256": self.content_sha256,
            "size_bytes": self.size_bytes,
            "metadata": self.metadata.to_dict(),
        }
        if include_artifact_id:
            result["artifact_id"] = self.artifact_id
        return result


def _parse_files(value: object) -> tuple[ImportedFile, ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_FILES:
        raise ResearchImportError(f"files must contain between 1 and {MAX_FILES} entries")
    files: list[ImportedFile] = []
    seen: set[str] = set()
    for index, raw in enumerate(value):
        data = _strict_object(raw, {"path", "size_bytes", "sha256", "media_type"}, f"files[{index}]")
        path = _safe_path(data["path"], f"files[{index}].path")
        if path.casefold() in seen:
            raise ResearchImportError("files contains duplicate case-insensitive paths")
        seen.add(path.casefold())
        suffix = PurePosixPath(path).suffix.lower()
        basename = PurePosixPath(path).name.lower()
        if suffix not in _SOURCE_SUFFIXES and basename not in _SPECIAL_SOURCE_NAMES:
            raise ResearchImportError(f"unsupported research file type: {path}")
        media_type = _text(data["media_type"], f"files[{index}].media_type", maximum=128).lower()
        if media_type not in _TEXT_MEDIA_TYPES:
            raise ResearchImportError(f"files[{index}].media_type is not an allowed text type")
        files.append(
            ImportedFile(
                path,
                _bounded_int(data["size_bytes"], f"files[{index}].size_bytes", maximum=MAX_FILE_BYTES),
                _digest(data["sha256"], f"files[{index}].sha256"),
                media_type,
            )
        )
    return tuple(files)


def _base(value: object, expected_kind: ResearchImportKind) -> tuple[Mapping[str, Any], str, str, int]:
    data = _strict_object(
        value,
        {"schema_version", "kind", "source_url", "content_sha256", "size_bytes", "metadata"},
        "research import",
    )
    try:
        encoded = canonical_json(data)
    except (TypeError, ValueError) as exc:
        raise ResearchImportError("research import must contain strict finite JSON") from exc
    if len(encoded.encode("utf-8")) > MAX_MANIFEST_BYTES:
        raise ResearchImportError("research import manifest is too large")
    if data["schema_version"] != SCHEMA_VERSION or isinstance(data["schema_version"], bool):
        raise ResearchImportError(f"schema_version must be {SCHEMA_VERSION}")
    if data["kind"] != expected_kind.value:
        raise ResearchImportError(f"kind must be {expected_kind.value}")
    return (
        data,
        _public_https_url(data["source_url"], "source_url"),
        _digest(data["content_sha256"], "content_sha256"),
        _bounded_int(data["size_bytes"], "size_bytes", maximum=MAX_IMPORT_BYTES, minimum=1),
    )


def _artifact(
    kind: ResearchImportKind,
    source_url: str,
    content_sha256: str,
    size_bytes: int,
    metadata: ImportMetadata,
) -> ResearchImportArtifact:
    material: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "kind": kind.value,
        "source_url": source_url,
        "content_sha256": content_sha256,
        "size_bytes": size_bytes,
        "metadata": metadata.to_dict(),
    }
    artifact_id = hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()
    return ResearchImportArtifact(
        artifact_id, SCHEMA_VERSION, kind, source_url, content_sha256, size_bytes, metadata
    )


def validate_github_import(value: object) -> ResearchImportArtifact:
    """Validate a source snapshot pinned to an exact GitHub commit."""
    data, source_url, content_hash, size_bytes = _base(value, ResearchImportKind.GITHUB)
    metadata = _strict_object(
        data["metadata"], {"repository_url", "commit_sha", "license", "files"}, "github metadata"
    )
    repository_url = _public_https_url(metadata["repository_url"], "repository_url").rstrip("/")
    repository_match = _GITHUB_REPOSITORY.fullmatch(repository_url)
    commit_sha = _text(metadata["commit_sha"], "commit_sha", maximum=40)
    if repository_match is None or _COMMIT_SHA.fullmatch(commit_sha) is None:
        raise ResearchImportError("GitHub repository and lowercase 40-character commit SHA are required")
    expected_source = f"{repository_url}/tree/{commit_sha}"
    if source_url.rstrip("/") != expected_source:
        raise ResearchImportError("source_url must pin the declared GitHub repository and commit SHA")
    license_name = _text(metadata["license"], "license", maximum=128)
    if _SPDX.fullmatch(license_name) is None:
        raise ResearchImportError("license must be one SPDX identifier, optionally with WITH exception")
    files = _parse_files(metadata["files"])
    if sum(item.size_bytes for item in files) != size_bytes:
        raise ResearchImportError("size_bytes must equal the sum of declared GitHub files")
    result = GitHubImportMetadata(repository_url, commit_sha, license_name, files)
    return _artifact(ResearchImportKind.GITHUB, expected_source, content_hash, size_bytes, result)


def validate_paper_import(value: object) -> ResearchImportArtifact:
    """Validate paper metadata with page or paragraph level provenance."""
    data, source_url, content_hash, size_bytes = _base(value, ResearchImportKind.PAPER)
    metadata = _strict_object(
        data["metadata"], {"title", "authors", "identifier", "provenance"}, "paper metadata"
    )
    title = _text(metadata["title"], "title", maximum=1_000)
    authors_raw = metadata["authors"]
    if not isinstance(authors_raw, list) or not 1 <= len(authors_raw) <= MAX_AUTHORS:
        raise ResearchImportError("authors must be a non-empty bounded array")
    authors = tuple(_text(item, "authors[]", maximum=256) for item in authors_raw)
    if len(set(authors)) != len(authors):
        raise ResearchImportError("authors contains duplicates")
    identifier = _text(metadata["identifier"], "identifier", maximum=256)
    if _IDENTIFIER.fullmatch(identifier) is None:
        raise ResearchImportError("identifier must be a DOI or arXiv identifier with an explicit prefix")
    provenance_raw = metadata["provenance"]
    if not isinstance(provenance_raw, list) or not 1 <= len(provenance_raw) <= MAX_PROVENANCE_ITEMS:
        raise ResearchImportError("provenance must be a non-empty bounded array")
    provenance: list[PaperProvenance] = []
    seen: set[tuple[str, str, str]] = set()
    for index, raw in enumerate(provenance_raw):
        item = _strict_object(
            raw,
            {"source_url", "locator_type", "locator", "content_sha256"},
            f"provenance[{index}]",
        )
        item_url = _public_https_url(item["source_url"], f"provenance[{index}].source_url")
        locator_type = _text(item["locator_type"], "locator_type", maximum=16)
        if locator_type not in {"page", "paragraph"}:
            raise ResearchImportError("provenance locator_type must be page or paragraph")
        locator = _text(item["locator"], "locator", maximum=128)
        if locator_type == "page" and re.fullmatch(r"[1-9]\d*(?:-[1-9]\d*)?", locator) is None:
            raise ResearchImportError("page locator must be a positive page or page range")
        if locator_type == "paragraph" and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", locator) is None:
            raise ResearchImportError("paragraph locator is invalid")
        key = (item_url, locator_type, locator)
        if key in seen:
            raise ResearchImportError("provenance contains a duplicate locator")
        seen.add(key)
        provenance.append(
            PaperProvenance(item_url, locator_type, locator, _digest(item["content_sha256"]))
        )
    result = PaperImportMetadata(title, authors, identifier, tuple(provenance))
    return _artifact(ResearchImportKind.PAPER, source_url, content_hash, size_bytes, result)


def _permission(value: object) -> str:
    permission = _text(value, "permissions[]", maximum=128).lower()
    normalized_words = set(re.split(r"[^a-z0-9_]+", permission))
    if normalized_words & _CONTROL_PLANE_WORDS or permission not in ALLOWED_SKILL_PERMISSIONS:
        raise ResearchImportError("skill requests a control-plane or unsupported permission")
    return permission


def validate_skill_import(value: object) -> ResearchImportArtifact:
    """Validate a declarative skill manifest without loading or installing it."""
    data, source_url, content_hash, size_bytes = _base(value, ResearchImportKind.SKILL)
    metadata = _strict_object(
        data["metadata"], {"name", "version", "permissions", "dependencies"}, "skill metadata"
    )
    name = _text(metadata["name"], "name", maximum=64)
    version = _text(metadata["version"], "version", maximum=64)
    if _SKILL_NAME.fullmatch(name) is None or _VERSION.fullmatch(version) is None:
        raise ResearchImportError("skill name or exact version is invalid")
    permissions_raw = metadata["permissions"]
    if not isinstance(permissions_raw, list) or len(permissions_raw) > MAX_PERMISSIONS:
        raise ResearchImportError("permissions must be a bounded JSON array")
    permissions = tuple(_permission(item) for item in permissions_raw)
    if len(set(permissions)) != len(permissions):
        raise ResearchImportError("permissions contains duplicates")
    dependencies_raw = metadata["dependencies"]
    if not isinstance(dependencies_raw, list) or len(dependencies_raw) > MAX_DEPENDENCIES:
        raise ResearchImportError("dependencies must be a bounded JSON array")
    dependencies: list[SkillDependency] = []
    dependency_names: set[str] = set()
    for index, raw in enumerate(dependencies_raw):
        item = _strict_object(raw, {"name", "version", "sha256"}, f"dependencies[{index}]")
        dependency_name = _text(item["name"], "dependency name", maximum=128)
        dependency_version = _text(item["version"], "dependency version", maximum=64)
        if (
            _DEPENDENCY_NAME.fullmatch(dependency_name) is None
            or _VERSION.fullmatch(dependency_version) is None
        ):
            raise ResearchImportError("dependency name or exact version is invalid")
        folded = dependency_name.casefold()
        if folded in dependency_names:
            raise ResearchImportError("dependencies contains duplicate names")
        dependency_names.add(folded)
        dependencies.append(SkillDependency(dependency_name, dependency_version, _digest(item["sha256"])))
    result = SkillImportMetadata(name, version, permissions, tuple(dependencies))
    return _artifact(ResearchImportKind.SKILL, source_url, content_hash, size_bytes, result)


def validate_research_import(value: object) -> ResearchImportArtifact:
    """Dispatch one strict import manifest to its kind-specific validator."""
    if not isinstance(value, Mapping):
        raise ResearchImportError("research import must be a JSON object")
    kind = value.get("kind")
    if kind == ResearchImportKind.GITHUB.value:
        return validate_github_import(value)
    if kind == ResearchImportKind.PAPER.value:
        return validate_paper_import(value)
    if kind == ResearchImportKind.SKILL.value:
        return validate_skill_import(value)
    raise ResearchImportError("kind must be github, paper, or skill")
