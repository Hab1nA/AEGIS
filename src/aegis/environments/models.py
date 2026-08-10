"""Strict recipes and receipts for an isolated, public-only environment builder."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from aegis.models import canonical_json
from aegis.research.interfaces import Resolver
from aegis.research.url_security import UrlPolicy, validate_url_target

_SHA256 = re.compile(r"[0-9a-f]{64}")
_OCI_DIGEST = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}")
_PACKAGE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_VERSION = re.compile(r"[^\x00\s]{1,128}")
_METADATA_HOSTS = frozenset(
    {
        "instance-data",
        "metadata",
        "metadata.google.internal",
        "metadata.azure.internal",
        "metadata.aws.internal",
    }
)


def _digest(value: object, name: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _artifact_id(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise ValueError(f"{name} must be a sha256 content address")
    _digest(value.removeprefix("sha256:"), name)
    return value


def _safe_relative(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ValueError(f"{name} must be a safe POSIX relative path")
    path = PurePosixPath(value)
    if value != "." and (path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts)):
        raise ValueError(f"{name} must be a safe POSIX relative path")
    return value


class DependencyKind(StrEnum):
    PYTHON_WHEEL = "python_wheel"
    PYTHON_SDIST = "python_sdist"
    SOURCE_ARCHIVE = "source_archive"
    OS_PACKAGE = "os_package"


class BuilderNetworkPolicy(StrEnum):
    OFFLINE = "offline"
    BROKERED_PUBLIC = "brokered_public"


@dataclass(frozen=True, slots=True)
class DependencyArtifact:
    name: str
    version: str
    kind: DependencyKind
    source_url: str
    sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or _PACKAGE_NAME.fullmatch(self.name) is None:
            raise ValueError("dependency name is invalid")
        if not isinstance(self.version, str) or _VERSION.fullmatch(self.version) is None:
            raise ValueError("dependency version is invalid")
        if not isinstance(self.kind, DependencyKind):
            raise TypeError("dependency kind must be a DependencyKind")
        if not isinstance(self.source_url, str) or len(self.source_url) > 2048:
            raise ValueError("dependency source_url is invalid")
        parsed = urlsplit(self.source_url)
        if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise ValueError("dependency source_url must be credential-free HTTPS without fragments")
        _digest(self.sha256, "dependency sha256")

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "version": self.version,
            "kind": self.kind.value,
            "source_url": self.source_url,
            "sha256": self.sha256,
        }


@dataclass(frozen=True, slots=True)
class BuildStep:
    argv: tuple[str, ...]
    cwd: str = "."
    timeout_seconds: float = 300.0

    def __post_init__(self) -> None:
        if not isinstance(self.argv, tuple) or not 1 <= len(self.argv) <= 32 or any(
            not isinstance(item, str) or not item or "\x00" in item or len(item) > 4096 for item in self.argv
        ):
            raise ValueError("build argv must be a bounded tuple of non-empty strings")
        _safe_relative(self.cwd, "build cwd")
        if isinstance(self.timeout_seconds, bool) or not isinstance(self.timeout_seconds, (int, float)):
            raise TypeError("timeout_seconds must be numeric")
        if not 0 < float(self.timeout_seconds) <= 1800:
            raise ValueError("timeout_seconds is outside the safe range")
        object.__setattr__(self, "timeout_seconds", float(self.timeout_seconds))

    def to_dict(self) -> dict[str, object]:
        return {"argv": list(self.argv), "cwd": self.cwd, "timeout_seconds": self.timeout_seconds}


@dataclass(frozen=True, slots=True)
class EnvironmentRecipe:
    recipe_id: str
    parent_image: str
    network_policy: BuilderNetworkPolicy
    dependencies: tuple[DependencyArtifact, ...]
    build_steps: tuple[BuildStep, ...]
    max_output_bytes: int

    def __post_init__(self) -> None:
        _artifact_id(self.recipe_id, "recipe_id")
        if not isinstance(self.parent_image, str) or _OCI_DIGEST.fullmatch(self.parent_image) is None:
            raise ValueError("parent_image must be pinned by sha256")
        if not isinstance(self.network_policy, BuilderNetworkPolicy):
            raise TypeError("network_policy must be BuilderNetworkPolicy")
        if not isinstance(self.dependencies, tuple) or any(
            not isinstance(item, DependencyArtifact) for item in self.dependencies
        ):
            raise TypeError("dependencies must contain DependencyArtifact values")
        dependency_keys = tuple((item.kind.value, item.name, item.version, item.sha256) for item in self.dependencies)
        if dependency_keys != tuple(sorted(set(dependency_keys))):
            raise ValueError("dependencies must be unique and canonically sorted")
        if self.network_policy is BuilderNetworkPolicy.OFFLINE and self.dependencies:
            raise ValueError("offline recipes cannot request remote dependencies")
        if not isinstance(self.build_steps, tuple) or not self.build_steps or any(
            not isinstance(item, BuildStep) for item in self.build_steps
        ):
            raise TypeError("build_steps must contain at least one BuildStep")
        if len(self.build_steps) > 32:
            raise ValueError("build_steps exceeds the safe limit")
        if (
            isinstance(self.max_output_bytes, bool)
            or not isinstance(self.max_output_bytes, int)
            or not 1 <= self.max_output_bytes <= 8 * 1024 * 1024 * 1024
        ):
            raise ValueError("max_output_bytes is outside the safe range")
        if self.recipe_id != "sha256:" + self.compute_digest():
            raise ValueError("recipe_id does not match recipe content")

    def _identity_payload(self) -> dict[str, object]:
        return {
            "parent_image": self.parent_image,
            "network_policy": self.network_policy.value,
            "dependencies": [item.to_dict() for item in self.dependencies],
            "build_steps": [item.to_dict() for item in self.build_steps],
            "max_output_bytes": self.max_output_bytes,
        }

    def compute_digest(self) -> str:
        return hashlib.sha256(canonical_json(self._identity_payload()).encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, object]:
        return {"recipe_id": self.recipe_id, **self._identity_payload()}

    @classmethod
    def create(cls, **values: Any) -> EnvironmentRecipe:
        payload = {
            "parent_image": values["parent_image"],
            "network_policy": values["network_policy"].value,
            "dependencies": [item.to_dict() for item in values["dependencies"]],
            "build_steps": [item.to_dict() for item in values["build_steps"]],
            "max_output_bytes": values["max_output_bytes"],
        }
        digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
        return cls(recipe_id="sha256:" + digest, **values)


@dataclass(frozen=True, slots=True)
class SourceResolution:
    source_sha256: str
    normalized_url: str
    addresses: tuple[str, ...]

    def __post_init__(self) -> None:
        _digest(self.source_sha256, "source_sha256")
        if not isinstance(self.normalized_url, str) or not self.normalized_url:
            raise ValueError("normalized_url must be non-empty")
        if not isinstance(self.addresses, tuple) or not self.addresses:
            raise ValueError("addresses must be a non-empty tuple")
        if self.addresses != tuple(sorted(set(self.addresses))):
            raise ValueError("addresses must be unique and canonically sorted")
        for raw in self.addresses:
            try:
                address = ipaddress.ip_address(raw)
            except ValueError as exc:
                raise ValueError("source resolution contains an invalid IP address") from exc
            if not (
                address.is_global
                and not address.is_private
                and not address.is_loopback
                and not address.is_link_local
                and not address.is_multicast
                and not address.is_reserved
                and not address.is_unspecified
            ):
                raise ValueError("source resolution contains a non-public IP address")

    def to_dict(self) -> dict[str, object]:
        return {
            "source_sha256": self.source_sha256,
            "normalized_url": self.normalized_url,
            "addresses": list(self.addresses),
        }


@dataclass(frozen=True, slots=True)
class BuildReceipt:
    receipt_id: str
    recipe_id: str
    builder_identity_sha256: str
    output_image: str
    output_size_bytes: int
    sbom_sha256: str
    provenance_sha256: str
    vulnerability_report_sha256: str
    sources: tuple[SourceResolution, ...]
    reproducible: bool
    scanner_passed: bool

    def __post_init__(self) -> None:
        _artifact_id(self.receipt_id, "receipt_id")
        _artifact_id(self.recipe_id, "recipe_id")
        for name in (
            "builder_identity_sha256",
            "sbom_sha256",
            "provenance_sha256",
            "vulnerability_report_sha256",
        ):
            _digest(getattr(self, name), name)
        if not isinstance(self.output_image, str) or _OCI_DIGEST.fullmatch(self.output_image) is None:
            raise ValueError("output_image must be pinned by sha256")
        if (
            isinstance(self.output_size_bytes, bool)
            or not isinstance(self.output_size_bytes, int)
            or not 1 <= self.output_size_bytes <= 16 * 1024 * 1024 * 1024
        ):
            raise ValueError("output_size_bytes is outside the safe range")
        if not isinstance(self.sources, tuple) or any(not isinstance(item, SourceResolution) for item in self.sources):
            raise TypeError("sources must contain SourceResolution values")
        source_keys = tuple((item.source_sha256, item.normalized_url) for item in self.sources)
        if source_keys != tuple(sorted(set(source_keys))):
            raise ValueError("sources must be unique and canonically sorted")
        if not isinstance(self.reproducible, bool) or not isinstance(self.scanner_passed, bool):
            raise TypeError("receipt verification flags must be bools")
        if self.receipt_id != "sha256:" + self.compute_digest():
            raise ValueError("receipt_id does not match build receipt content")

    def _identity_payload(self) -> dict[str, object]:
        return {
            "recipe_id": self.recipe_id,
            "builder_identity_sha256": self.builder_identity_sha256,
            "output_image": self.output_image,
            "output_size_bytes": self.output_size_bytes,
            "sbom_sha256": self.sbom_sha256,
            "provenance_sha256": self.provenance_sha256,
            "vulnerability_report_sha256": self.vulnerability_report_sha256,
            "sources": [item.to_dict() for item in self.sources],
            "reproducible": self.reproducible,
            "scanner_passed": self.scanner_passed,
        }

    def compute_digest(self) -> str:
        return hashlib.sha256(canonical_json(self._identity_payload()).encode("utf-8")).hexdigest()

    @classmethod
    def create(cls, **values: Any) -> BuildReceipt:
        payload = {
            "recipe_id": values["recipe_id"],
            "builder_identity_sha256": values["builder_identity_sha256"],
            "output_image": values["output_image"],
            "output_size_bytes": values["output_size_bytes"],
            "sbom_sha256": values["sbom_sha256"],
            "provenance_sha256": values["provenance_sha256"],
            "vulnerability_report_sha256": values["vulnerability_report_sha256"],
            "sources": [item.to_dict() for item in values["sources"]],
            "reproducible": values["reproducible"],
            "scanner_passed": values["scanner_passed"],
        }
        digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
        return cls(receipt_id="sha256:" + digest, **values)

    def to_dict(self) -> dict[str, object]:
        return {"receipt_id": self.receipt_id, **self._identity_payload()}


@dataclass(frozen=True, slots=True)
class BuilderPolicy:
    allow_brokered_public_network: bool = True
    allowed_hosts: frozenset[str] = frozenset()
    require_reproducible: bool = True
    require_scanner_passed: bool = True
    max_dependencies: int = 256

    def __post_init__(self) -> None:
        if not all(
            isinstance(item, bool)
            for item in (
                self.allow_brokered_public_network,
                self.require_reproducible,
                self.require_scanner_passed,
            )
        ):
            raise TypeError("builder policy flags must be bools")
        normalized = frozenset(item.rstrip(".").lower() for item in self.allowed_hosts)
        if any(not item or "/" in item or ":" in item for item in normalized):
            raise ValueError("allowed_hosts contains an invalid hostname")
        object.__setattr__(self, "allowed_hosts", normalized)
        if isinstance(self.max_dependencies, bool) or not isinstance(self.max_dependencies, int) or not 0 <= self.max_dependencies <= 1024:
            raise ValueError("max_dependencies is outside the safe range")


def _reject_metadata_hostname(hostname: str) -> None:
    normalized = hostname.rstrip(".").lower()
    if (
        normalized in _METADATA_HOSTS
        or normalized.endswith((".internal", ".local", ".localhost"))
        or "metadata" in normalized.split(".")
    ):
        raise ValueError("builder source targets a metadata or internal hostname")


def validate_public_source_url(
    url: str,
    source_sha256: str,
    resolver: Resolver,
    policy: BuilderPolicy = BuilderPolicy(),
) -> SourceResolution:
    """Resolve one download hop and return the exact public addresses it may use."""
    _digest(source_sha256, "source_sha256")
    if not isinstance(policy, BuilderPolicy):
        raise TypeError("policy must be a BuilderPolicy")
    parsed = urlsplit(url)
    if not parsed.hostname:
        raise ValueError("builder source URL must contain a hostname")
    hostname = parsed.hostname.rstrip(".").lower()
    _reject_metadata_hostname(hostname)
    if policy.allowed_hosts and hostname not in policy.allowed_hosts:
        raise ValueError("builder source hostname is not allowlisted")
    normalized, addresses = validate_url_target(
        url,
        resolver,
        UrlPolicy(frozenset({"https"}), frozenset({443})),
    )
    return SourceResolution(source_sha256, normalized, tuple(sorted(addresses)))


def validate_environment_recipe(
    recipe: EnvironmentRecipe,
    resolver: Resolver,
    policy: BuilderPolicy = BuilderPolicy(),
) -> tuple[SourceResolution, ...]:
    """Resolve every fetch target and reject private, metadata, or unapproved hosts."""
    if not isinstance(recipe, EnvironmentRecipe) or not isinstance(policy, BuilderPolicy):
        raise TypeError("recipe and policy must use environment model types")
    if len(recipe.dependencies) > policy.max_dependencies:
        raise ValueError("recipe dependency count exceeds policy")
    if recipe.network_policy is BuilderNetworkPolicy.BROKERED_PUBLIC and not policy.allow_brokered_public_network:
        raise ValueError("public builder network is disabled by policy")
    resolutions: list[SourceResolution] = []
    for item in recipe.dependencies:
        resolution = validate_public_source_url(item.source_url, item.sha256, resolver, policy)
        if resolution.normalized_url != item.source_url:
            raise ValueError("builder source_url is not canonical")
        resolutions.append(resolution)
    return tuple(sorted(resolutions, key=lambda item: (item.source_sha256, item.normalized_url)))


def validate_build_receipt(
    recipe: EnvironmentRecipe,
    receipt: BuildReceipt,
    resolutions: tuple[SourceResolution, ...],
    policy: BuilderPolicy = BuilderPolicy(),
) -> BuildReceipt:
    """Bind a verified build receipt to the exact recipe and DNS validation evidence."""
    if not all(
        isinstance(item, expected)
        for item, expected in ((recipe, EnvironmentRecipe), (receipt, BuildReceipt), (policy, BuilderPolicy))
    ):
        raise TypeError("recipe, receipt, and policy must use environment model types")
    if receipt.recipe_id != recipe.recipe_id:
        raise ValueError("build receipt does not bind the recipe")
    if receipt.sources != resolutions:
        raise ValueError("build receipt source evidence does not match validated resolutions")
    expected_sources = {(item.sha256, item.source_url) for item in recipe.dependencies}
    observed_sources = {(item.source_sha256, item.normalized_url) for item in receipt.sources}
    if expected_sources != observed_sources:
        raise ValueError("build receipt does not cover every exact dependency source")
    if receipt.output_size_bytes > recipe.max_output_bytes:
        raise ValueError("build output exceeds recipe limit")
    if policy.require_reproducible and not receipt.reproducible:
        raise ValueError("build receipt lacks reproducibility evidence")
    if policy.require_scanner_passed and not receipt.scanner_passed:
        raise ValueError("build receipt lacks passing scanner evidence")
    return receipt
