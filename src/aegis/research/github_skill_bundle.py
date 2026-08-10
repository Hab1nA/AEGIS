"""Deterministic, inert conversion of pinned GitHub text into Skill v1 content."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Mapping, Sequence

from aegis.models import canonical_json

from .imports import ResearchImportArtifact, validate_skill_import

MAX_BUNDLE_FILES = 64
MAX_BUNDLE_BYTES = 256 * 1024
_ALLOWED_SUFFIXES = frozenset({".json", ".md", ".rst", ".toml", ".txt", ".yaml", ".yml"})
_COMMIT = re.compile(r"[0-9a-f]{40}")
_BLOB = re.compile(r"[0-9a-f]{40}")
_REPOSITORY = re.compile(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")


class GitHubSkillBundleError(ValueError):
    """A pinned snapshot cannot safely become a declarative skill bundle."""


@dataclass(frozen=True, slots=True)
class GitHubSkillSourceFile:
    path: str
    content: bytes
    sha256: str
    git_blob_sha: str
    media_type: str
    provenance: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class GitHubSkillBundleFile:
    path: str
    source_path: str
    size_bytes: int
    sha256: str
    git_blob_sha: str
    media_type: str
    provenance: Mapping[str, object]

    def identity_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "source_path": self.source_path,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "git_blob_sha": self.git_blob_sha,
            "media_type": self.media_type,
        }

    def to_dict(self) -> dict[str, object]:
        return {**self.identity_dict(), "provenance": dict(self.provenance)}


@dataclass(frozen=True, slots=True)
class GitHubSkillBundle:
    artifact: ResearchImportArtifact
    content: bytes
    bundle_sha256: str
    repository_url: str
    commit_sha: str
    root: str
    files: tuple[GitHubSkillBundleFile, ...]

    def descriptor(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "kind": "github-skill-bundle",
            "artifact": self.artifact.to_dict(),
            "bundle_sha256": self.bundle_sha256,
            "repository_url": self.repository_url,
            "commit_sha": self.commit_sha,
            "root": self.root,
            "files": [item.to_dict() for item in self.files],
            "declarative_only": True,
            "execution_granted": False,
            "dependencies_installed": False,
            "permissions_registered": False,
        }


def _root(value: object) -> str:
    if value == ".":
        return "."
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > 512:
        raise GitHubSkillBundleError("skill root must be '.' or a bounded trimmed path")
    path = PurePosixPath(value)
    if path.is_absolute() or "\\" in value or any(part in {"", ".", ".."} for part in path.parts):
        raise GitHubSkillBundleError("skill root must be a safe POSIX repository-relative path")
    return path.as_posix()


def _relative(path: str, root: str) -> str | None:
    source = PurePosixPath(path)
    if root == ".":
        return source.as_posix()
    prefix = PurePosixPath(root)
    try:
        return source.relative_to(prefix).as_posix()
    except ValueError:
        return None


def _indent(content: bytes) -> str:
    try:
        text = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise GitHubSkillBundleError("bundle source is not strict UTF-8") from exc
    return "\n".join("    " + line for line in text.splitlines())


def _verify_source(source: GitHubSkillSourceFile, repository_url: str, commit_sha: str) -> None:
    path = PurePosixPath(source.path)
    if path.is_absolute() or "\\" in source.path or any(part in {"", ".", ".."} for part in path.parts):
        raise GitHubSkillBundleError("bundle source path is invalid")
    if not source.content:
        raise GitHubSkillBundleError("bundle source files must be non-empty")
    if hashlib.sha256(source.content).hexdigest() != source.sha256:
        raise GitHubSkillBundleError("bundle source content hash is invalid")
    expected_blob = hashlib.sha1(
        f"blob {len(source.content)}\0".encode("ascii") + source.content,
        usedforsecurity=False,
    ).hexdigest()
    if _BLOB.fullmatch(source.git_blob_sha) is None or source.git_blob_sha != expected_blob:
        raise GitHubSkillBundleError("bundle source Git blob hash is invalid")
    provenance = source.provenance
    required = {
        "requested_url", "final_url", "retrieved_at", "sha256", "size_bytes", "media_type", "redirect_chain"
    }
    if set(provenance) != required:
        raise GitHubSkillBundleError("bundle source provenance schema is invalid")
    expected_prefix = repository_url.replace("https://github.com/", "https://raw.githubusercontent.com/")
    expected_prefix += f"/{commit_sha}/"
    if (
        provenance["requested_url"] != provenance["final_url"]
        or not isinstance(provenance["requested_url"], str)
        or not provenance["requested_url"].startswith(expected_prefix)
        or provenance["sha256"] != source.sha256
        or provenance["size_bytes"] != len(source.content)
        or provenance["media_type"] != source.media_type
        or provenance["redirect_chain"] not in ([], ())
    ):
        raise GitHubSkillBundleError("bundle source provenance does not bind the pinned blob")


def build_github_skill_bundle(
    *,
    repository_url: str,
    commit_sha: str,
    root: object,
    name: object,
    version: object,
    files: Sequence[GitHubSkillSourceFile],
) -> GitHubSkillBundle:
    """Build one deterministic declarative candidate; never execute source content."""
    if _REPOSITORY.fullmatch(repository_url) is None or _COMMIT.fullmatch(commit_sha) is None:
        raise GitHubSkillBundleError("bundle source must identify a canonical exact-commit GitHub repository")
    selected_root = _root(root)
    selected: list[tuple[str, GitHubSkillSourceFile]] = []
    for source in files:
        relative = _relative(source.path, selected_root)
        if relative is None:
            continue
        candidate = PurePosixPath(relative)
        if candidate.suffix.lower() not in _ALLOWED_SUFFIXES:
            continue
        _verify_source(source, repository_url, commit_sha)
        selected.append((relative, source))
    selected.sort(key=lambda item: item[0])
    if not selected or selected[0][0] != "SKILL.md":
        if not any(relative == "SKILL.md" for relative, _ in selected):
            raise GitHubSkillBundleError("skill root must contain exact file SKILL.md")
    if len(selected) > MAX_BUNDLE_FILES:
        raise GitHubSkillBundleError("skill bundle file count exceeds the limit")
    if sum(len(source.content) for _, source in selected) > MAX_BUNDLE_BYTES:
        raise GitHubSkillBundleError("skill bundle content exceeds the limit")

    bundle_files = tuple(
        GitHubSkillBundleFile(
            relative,
            source.path,
            len(source.content),
            source.sha256,
            source.git_blob_sha,
            source.media_type,
            dict(source.provenance),
        )
        for relative, source in selected
    )
    identity = {
        "schema_version": 1,
        "repository_url": repository_url,
        "commit_sha": commit_sha,
        "root": selected_root,
        "files": [item.identity_dict() for item in bundle_files],
    }
    bundle_sha256 = hashlib.sha256(canonical_json(identity).encode("utf-8")).hexdigest()
    skill_md = next(source.content for relative, source in selected if relative == "SKILL.md")
    sections = [skill_md.decode("utf-8", errors="strict").rstrip(), "", "---", ""]
    sections.extend(
        [
            "AEGIS immutable GitHub bundle provenance:",
            "",
            f"    {canonical_json(identity)}",
        ]
    )
    for relative, source in selected:
        if relative == "SKILL.md":
            continue
        sections.extend(["", f"## Bundled reference: `{relative}`", "", _indent(source.content)])
    content = ("\n".join(sections).rstrip() + "\n").encode("utf-8")
    source_url = f"{repository_url}/tree/{commit_sha}"
    if selected_root != ".":
        source_url += f"/{selected_root}"
    manifest = {
        "schema_version": 1,
        "kind": "skill",
        "source_url": source_url,
        "content_sha256": hashlib.sha256(content).hexdigest(),
        "size_bytes": len(content),
        "metadata": {
            "name": name,
            "version": version,
            "permissions": [],
            "dependencies": [],
        },
    }
    try:
        artifact = validate_skill_import(manifest)
    except (TypeError, ValueError) as exc:
        raise GitHubSkillBundleError(str(exc)) from exc
    return GitHubSkillBundle(
        artifact,
        content,
        bundle_sha256,
        repository_url,
        commit_sha,
        selected_root,
        bundle_files,
    )


__all__ = [
    "GitHubSkillBundle",
    "GitHubSkillBundleError",
    "GitHubSkillBundleFile",
    "GitHubSkillSourceFile",
    "build_github_skill_bundle",
]
