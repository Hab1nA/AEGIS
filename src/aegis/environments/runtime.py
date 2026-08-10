"""Fail-closed control plane for reproducible, isolated environment builds."""

from __future__ import annotations

import hashlib
import math
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Mapping, Protocol, cast

from aegis.models import canonical_json
from aegis.research.interfaces import Resolver

from .models import (
    BuilderPolicy,
    BuildReceipt,
    DependencyArtifact,
    EnvironmentRecipe,
    SourceResolution,
    validate_build_receipt,
    validate_environment_recipe,
    validate_public_source_url,
)

_CONTENT_ADDRESS = re.compile(r"sha256:[0-9a-f]{64}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_NONCE = re.compile(r"[0-9a-f]{32,128}")
_REPOSITORY = re.compile(r"[a-z0-9][a-z0-9._/-]{0,254}")
_OCI_DIGEST = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}")


class EnvironmentBuildError(RuntimeError):
    """A build was denied or failed before an image could be published."""


class MalformedBuildResult(EnvironmentBuildError):
    """An injected boundary returned malformed or mismatched evidence."""


def _content_address(value: object, name: str) -> str:
    if not isinstance(value, str) or _CONTENT_ADDRESS.fullmatch(value) is None:
        raise ValueError(f"{name} must be a sha256 content address")
    return value


def _digest(value: object, name: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _identity(payload: Mapping[str, object]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _strict(value: object, fields: set[str], name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields or any(not isinstance(key, str) for key in value):
        raise MalformedBuildResult(f"{name} has missing or unknown fields")
    return cast(Mapping[str, object], value)


def _bounded_elapsed(value: object, *, timeout: float, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MalformedBuildResult(f"{name} elapsed_seconds must be numeric")
    elapsed = float(value)
    if not math.isfinite(elapsed) or elapsed < 0:
        raise MalformedBuildResult(f"{name} elapsed_seconds must be finite and non-negative")
    if elapsed > timeout:
        raise EnvironmentBuildError(f"{name} exceeded its timeout")
    return elapsed


@dataclass(frozen=True, slots=True)
class EnvironmentBuildIntent:
    intent_id: str
    recipe_id: str
    builder_identity_sha256: str
    build_count: int
    nonce: str

    def __post_init__(self) -> None:
        _content_address(self.intent_id, "intent_id")
        _content_address(self.recipe_id, "recipe_id")
        _digest(self.builder_identity_sha256, "builder_identity_sha256")
        if self.build_count != 2:
            raise ValueError("environment builds require exactly two independent attempts")
        if not isinstance(self.nonce, str) or _NONCE.fullmatch(self.nonce) is None:
            raise ValueError("intent nonce must be bounded lowercase hexadecimal")
        if self.intent_id != _identity(self._identity_payload()):
            raise ValueError("intent_id does not match build intent content")

    def _identity_payload(self) -> dict[str, object]:
        return {
            "recipe_id": self.recipe_id,
            "builder_identity_sha256": self.builder_identity_sha256,
            "build_count": self.build_count,
            "nonce": self.nonce,
        }

    def to_dict(self) -> dict[str, object]:
        return {"intent_id": self.intent_id, **self._identity_payload()}

    @classmethod
    def create(cls, *, recipe_id: str, builder_identity_sha256: str, nonce: str) -> EnvironmentBuildIntent:
        payload = {
            "recipe_id": recipe_id,
            "builder_identity_sha256": builder_identity_sha256,
            "build_count": 2,
            "nonce": nonce,
        }
        return cls(_identity(payload), recipe_id, builder_identity_sha256, 2, nonce)


@dataclass(frozen=True, slots=True)
class QuarantinedDownload:
    quarantine_artifact_id: str
    dependency_sha256: str
    size_bytes: int
    source_chain: tuple[SourceResolution, ...]
    elapsed_seconds: float
    timed_out: bool

    def __post_init__(self) -> None:
        _content_address(self.quarantine_artifact_id, "quarantine_artifact_id")
        _digest(self.dependency_sha256, "dependency_sha256")
        if self.quarantine_artifact_id != "sha256:" + self.dependency_sha256:
            raise ValueError("quarantine artifact id must address the exact downloaded bytes")
        if isinstance(self.size_bytes, bool) or not isinstance(self.size_bytes, int) or self.size_bytes < 1:
            raise ValueError("download size_bytes must be a positive integer")
        if not isinstance(self.source_chain, tuple) or not self.source_chain or any(
            not isinstance(item, SourceResolution) for item in self.source_chain
        ):
            raise TypeError("source_chain must contain validated download hops")
        if any(item.source_sha256 != self.dependency_sha256 for item in self.source_chain):
            raise ValueError("every source hop must bind the downloaded dependency digest")
        if isinstance(self.elapsed_seconds, bool) or not isinstance(self.elapsed_seconds, (int, float)):
            raise TypeError("download elapsed_seconds must be numeric")
        if not math.isfinite(float(self.elapsed_seconds)) or float(self.elapsed_seconds) < 0:
            raise ValueError("download elapsed_seconds must be finite and non-negative")
        object.__setattr__(self, "elapsed_seconds", float(self.elapsed_seconds))
        if not isinstance(self.timed_out, bool):
            raise TypeError("download timed_out must be a bool")

    @classmethod
    def from_mapping(cls, value: object) -> QuarantinedDownload:
        data = _strict(
            value,
            {
                "quarantine_artifact_id",
                "dependency_sha256",
                "size_bytes",
                "source_chain",
                "elapsed_seconds",
                "timed_out",
            },
            "download result",
        )
        chain = data["source_chain"]
        if not isinstance(chain, list):
            raise MalformedBuildResult("download source_chain must be an array")
        parsed: list[SourceResolution] = []
        try:
            for item in chain:
                raw = _strict(item, {"source_sha256", "normalized_url", "addresses"}, "download source hop")
                addresses = raw["addresses"]
                if not isinstance(addresses, list) or any(not isinstance(address, str) for address in addresses):
                    raise MalformedBuildResult("download hop addresses must be an array of strings")
                parsed.append(
                    SourceResolution(
                        cast(str, raw["source_sha256"]),
                        cast(str, raw["normalized_url"]),
                        tuple(addresses),
                    )
                )
            return cls(
                quarantine_artifact_id=cast(str, data["quarantine_artifact_id"]),
                dependency_sha256=cast(str, data["dependency_sha256"]),
                size_bytes=cast(int, data["size_bytes"]),
                source_chain=tuple(parsed),
                elapsed_seconds=cast(float, data["elapsed_seconds"]),
                timed_out=cast(bool, data["timed_out"]),
            )
        except (TypeError, ValueError) as exc:
            if isinstance(exc, MalformedBuildResult):
                raise
            raise MalformedBuildResult("download result is invalid") from exc

    def to_dict(self) -> dict[str, object]:
        return {
            "quarantine_artifact_id": self.quarantine_artifact_id,
            "dependency_sha256": self.dependency_sha256,
            "size_bytes": self.size_bytes,
            "source_chain": [item.to_dict() for item in self.source_chain],
            "elapsed_seconds": self.elapsed_seconds,
            "timed_out": self.timed_out,
        }


@dataclass(frozen=True, slots=True)
class BuildAttempt:
    attempt_id: str
    intent_id: str
    recipe_id: str
    ordinal: int
    dependency_artifact_ids: tuple[str, ...]
    timeout_seconds: float
    network_enabled: bool = False
    secret_names: tuple[str, ...] = ()
    host_mounts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("attempt_id", "intent_id", "recipe_id"):
            _content_address(getattr(self, name), name)
        if self.ordinal not in {1, 2}:
            raise ValueError("build attempt ordinal must be 1 or 2")
        if not isinstance(self.dependency_artifact_ids, tuple):
            raise TypeError("dependency artifact ids must be a tuple")
        for item in self.dependency_artifact_ids:
            _content_address(item, "dependency artifact id")
        if self.dependency_artifact_ids != tuple(sorted(set(self.dependency_artifact_ids))):
            raise ValueError("dependency artifact ids must be unique and canonically sorted")
        if isinstance(self.timeout_seconds, bool) or not isinstance(self.timeout_seconds, (int, float)):
            raise TypeError("attempt timeout_seconds must be numeric")
        if not math.isfinite(float(self.timeout_seconds)) or not 0 < float(self.timeout_seconds) <= 86_400:
            raise ValueError("attempt timeout_seconds is outside the safe range")
        object.__setattr__(self, "timeout_seconds", float(self.timeout_seconds))
        if self.network_enabled is not False or self.secret_names != () or self.host_mounts != ():
            raise ValueError("builder attempts must have no network, secrets, or host mounts")
        if self.attempt_id != _identity(self._identity_payload()):
            raise ValueError("attempt_id does not match build attempt content")

    def _identity_payload(self) -> dict[str, object]:
        return {
            "intent_id": self.intent_id,
            "recipe_id": self.recipe_id,
            "ordinal": self.ordinal,
            "dependency_artifact_ids": list(self.dependency_artifact_ids),
            "timeout_seconds": self.timeout_seconds,
            "network_enabled": self.network_enabled,
            "secret_names": list(self.secret_names),
            "host_mounts": list(self.host_mounts),
        }

    @classmethod
    def create(cls, **values: Any) -> BuildAttempt:
        payload = {
            "intent_id": values["intent_id"],
            "recipe_id": values["recipe_id"],
            "ordinal": values["ordinal"],
            "dependency_artifact_ids": list(values["dependency_artifact_ids"]),
            "timeout_seconds": float(values["timeout_seconds"]),
            "network_enabled": False,
            "secret_names": [],
            "host_mounts": [],
        }
        return cls(attempt_id=_identity(payload), **values)


@dataclass(frozen=True, slots=True)
class StagedBuild:
    staged_artifact_id: str
    attempt_id: str
    image_sha256: str
    output_size_bytes: int
    sbom_sha256: str
    provenance_sha256: str
    isolation_receipt_sha256: str
    elapsed_seconds: float
    timed_out: bool
    exit_code: int
    network_used: bool
    secrets_used: bool
    host_mounts_used: bool

    def __post_init__(self) -> None:
        _content_address(self.staged_artifact_id, "staged_artifact_id")
        _content_address(self.attempt_id, "attempt_id")
        for name in ("image_sha256", "sbom_sha256", "provenance_sha256", "isolation_receipt_sha256"):
            _digest(getattr(self, name), name)
        if self.staged_artifact_id != "sha256:" + self.image_sha256:
            raise ValueError("staged artifact must be addressed by the image digest")
        if isinstance(self.output_size_bytes, bool) or not isinstance(self.output_size_bytes, int) or self.output_size_bytes < 1:
            raise ValueError("staged output_size_bytes must be positive")
        if isinstance(self.elapsed_seconds, bool) or not isinstance(self.elapsed_seconds, (int, float)):
            raise TypeError("staged elapsed_seconds must be numeric")
        if not math.isfinite(float(self.elapsed_seconds)) or float(self.elapsed_seconds) < 0:
            raise ValueError("staged elapsed_seconds must be finite and non-negative")
        object.__setattr__(self, "elapsed_seconds", float(self.elapsed_seconds))
        if not all(isinstance(value, bool) for value in (self.timed_out, self.network_used, self.secrets_used, self.host_mounts_used)):
            raise TypeError("staged verification flags must be bools")
        if isinstance(self.exit_code, bool) or not isinstance(self.exit_code, int):
            raise TypeError("staged exit_code must be an integer")

    @classmethod
    def from_mapping(cls, value: object) -> StagedBuild:
        fields = {
            "staged_artifact_id",
            "attempt_id",
            "image_sha256",
            "output_size_bytes",
            "sbom_sha256",
            "provenance_sha256",
            "isolation_receipt_sha256",
            "elapsed_seconds",
            "timed_out",
            "exit_code",
            "network_used",
            "secrets_used",
            "host_mounts_used",
        }
        data = _strict(value, fields, "staged build")
        try:
            return cls(**cast(Any, dict(data)))
        except (TypeError, ValueError) as exc:
            raise MalformedBuildResult("staged build is invalid") from exc

    def to_dict(self) -> dict[str, object]:
        return {
            "staged_artifact_id": self.staged_artifact_id,
            "attempt_id": self.attempt_id,
            "image_sha256": self.image_sha256,
            "output_size_bytes": self.output_size_bytes,
            "sbom_sha256": self.sbom_sha256,
            "provenance_sha256": self.provenance_sha256,
            "isolation_receipt_sha256": self.isolation_receipt_sha256,
            "elapsed_seconds": self.elapsed_seconds,
            "timed_out": self.timed_out,
            "exit_code": self.exit_code,
            "network_used": self.network_used,
            "secrets_used": self.secrets_used,
            "host_mounts_used": self.host_mounts_used,
        }


@dataclass(frozen=True, slots=True)
class ScanReceipt:
    scan_receipt_id: str
    staged_artifact_id: str
    image_sha256: str
    vulnerability_report_sha256: str
    passed: bool
    elapsed_seconds: float
    timed_out: bool

    def __post_init__(self) -> None:
        _content_address(self.scan_receipt_id, "scan_receipt_id")
        _content_address(self.staged_artifact_id, "staged_artifact_id")
        _digest(self.image_sha256, "image_sha256")
        _digest(self.vulnerability_report_sha256, "vulnerability_report_sha256")
        if not isinstance(self.passed, bool) or not isinstance(self.timed_out, bool):
            raise TypeError("scanner flags must be bools")
        if isinstance(self.elapsed_seconds, bool) or not isinstance(self.elapsed_seconds, (int, float)):
            raise TypeError("scanner elapsed_seconds must be numeric")
        if not math.isfinite(float(self.elapsed_seconds)) or float(self.elapsed_seconds) < 0:
            raise ValueError("scanner elapsed_seconds must be finite and non-negative")
        object.__setattr__(self, "elapsed_seconds", float(self.elapsed_seconds))
        if self.scan_receipt_id != _identity(self._identity_payload()):
            raise ValueError("scan_receipt_id does not match scanner receipt content")

    def _identity_payload(self) -> dict[str, object]:
        return {
            "staged_artifact_id": self.staged_artifact_id,
            "image_sha256": self.image_sha256,
            "vulnerability_report_sha256": self.vulnerability_report_sha256,
            "passed": self.passed,
            "elapsed_seconds": self.elapsed_seconds,
            "timed_out": self.timed_out,
        }

    @classmethod
    def from_mapping(cls, value: object) -> ScanReceipt:
        fields = {
            "scan_receipt_id",
            "staged_artifact_id",
            "image_sha256",
            "vulnerability_report_sha256",
            "passed",
            "elapsed_seconds",
            "timed_out",
        }
        data = _strict(value, fields, "scanner result")
        try:
            return cls(**cast(Any, dict(data)))
        except (TypeError, ValueError) as exc:
            raise MalformedBuildResult("scanner result is invalid") from exc

    @classmethod
    def create(cls, **values: Any) -> ScanReceipt:
        payload = {**values, "elapsed_seconds": float(values["elapsed_seconds"])}
        return cls(scan_receipt_id=_identity(payload), **values)

    def to_dict(self) -> dict[str, object]:
        return {"scan_receipt_id": self.scan_receipt_id, **self._identity_payload()}


@dataclass(frozen=True, slots=True)
class BuildProvenance:
    provenance_id: str
    intent_id: str
    recipe_id: str
    download_evidence_sha256: str
    attempt_ids: tuple[str, str]
    staged_artifact_ids: tuple[str, str]
    builder_provenance_sha256: tuple[str, str]
    scan_receipt_id: str

    def __post_init__(self) -> None:
        for name in ("provenance_id", "intent_id", "recipe_id", "scan_receipt_id"):
            _content_address(getattr(self, name), name)
        _digest(self.download_evidence_sha256, "download_evidence_sha256")
        for values, name, validator in (
            (self.attempt_ids, "attempt_ids", _content_address),
            (self.staged_artifact_ids, "staged_artifact_ids", _content_address),
            (self.builder_provenance_sha256, "builder_provenance_sha256", _digest),
        ):
            if not isinstance(values, tuple) or len(values) != 2:
                raise ValueError(f"{name} must contain exactly two build values")
            for value in values:
                validator(value, name)
        if self.attempt_ids[0] == self.attempt_ids[1]:
            raise ValueError("provenance must identify two independent attempts")
        if self.provenance_id != _identity(self._identity_payload()):
            raise ValueError("provenance_id does not match build provenance content")

    def _identity_payload(self) -> dict[str, object]:
        return {
            "intent_id": self.intent_id,
            "recipe_id": self.recipe_id,
            "download_evidence_sha256": self.download_evidence_sha256,
            "attempt_ids": list(self.attempt_ids),
            "staged_artifact_ids": list(self.staged_artifact_ids),
            "builder_provenance_sha256": list(self.builder_provenance_sha256),
            "scan_receipt_id": self.scan_receipt_id,
        }

    @classmethod
    def create(
        cls,
        *,
        intent: EnvironmentBuildIntent,
        recipe: EnvironmentRecipe,
        downloads: tuple[QuarantinedDownload, ...],
        attempts: tuple[BuildAttempt, BuildAttempt],
        staged: tuple[StagedBuild, StagedBuild],
        scan: ScanReceipt,
    ) -> BuildProvenance:
        download_payload = {"downloads": [item.to_dict() for item in downloads]}
        payload = {
            "intent_id": intent.intent_id,
            "recipe_id": recipe.recipe_id,
            "download_evidence_sha256": hashlib.sha256(
                canonical_json(download_payload).encode("utf-8")
            ).hexdigest(),
            "attempt_ids": [item.attempt_id for item in attempts],
            "staged_artifact_ids": [item.staged_artifact_id for item in staged],
            "builder_provenance_sha256": [item.provenance_sha256 for item in staged],
            "scan_receipt_id": scan.scan_receipt_id,
        }
        return cls(
            provenance_id=_identity(payload),
            intent_id=intent.intent_id,
            recipe_id=recipe.recipe_id,
            download_evidence_sha256=cast(str, payload["download_evidence_sha256"]),
            attempt_ids=(attempts[0].attempt_id, attempts[1].attempt_id),
            staged_artifact_ids=(staged[0].staged_artifact_id, staged[1].staged_artifact_id),
            builder_provenance_sha256=(staged[0].provenance_sha256, staged[1].provenance_sha256),
            scan_receipt_id=scan.scan_receipt_id,
        )

    def to_dict(self) -> dict[str, object]:
        return {"provenance_id": self.provenance_id, **self._identity_payload()}


@dataclass(frozen=True, slots=True)
class PublicationReceipt:
    publication_receipt_id: str
    intent_id: str
    build_receipt_id: str
    provenance_id: str
    staged_artifact_id: str
    output_image: str
    published: bool

    def __post_init__(self) -> None:
        for name in (
            "publication_receipt_id",
            "intent_id",
            "build_receipt_id",
            "provenance_id",
            "staged_artifact_id",
        ):
            _content_address(getattr(self, name), name)
        if not isinstance(self.output_image, str) or _OCI_DIGEST.fullmatch(self.output_image) is None:
            raise ValueError("publication output_image must be digest-pinned")
        if self.published is not True:
            raise ValueError("publication receipt must confirm an atomic publish")
        if self.publication_receipt_id != _identity(self._identity_payload()):
            raise ValueError("publication_receipt_id does not match publication content")

    def _identity_payload(self) -> dict[str, object]:
        return {
            "intent_id": self.intent_id,
            "build_receipt_id": self.build_receipt_id,
            "provenance_id": self.provenance_id,
            "staged_artifact_id": self.staged_artifact_id,
            "output_image": self.output_image,
            "published": self.published,
        }

    @classmethod
    def create(cls, **values: Any) -> PublicationReceipt:
        return cls(publication_receipt_id=_identity(values), **values)

    @classmethod
    def from_mapping(cls, value: object) -> PublicationReceipt:
        fields = {
            "publication_receipt_id",
            "intent_id",
            "build_receipt_id",
            "provenance_id",
            "staged_artifact_id",
            "output_image",
            "published",
        }
        data = _strict(value, fields, "publication receipt")
        try:
            return cls(**cast(Any, dict(data)))
        except (TypeError, ValueError) as exc:
            raise MalformedBuildResult("publication receipt is invalid") from exc

    def to_dict(self) -> dict[str, object]:
        return {"publication_receipt_id": self.publication_receipt_id, **self._identity_payload()}


class DownloadTargetValidator(Protocol):
    def __call__(self, url: str) -> SourceResolution: ...


class DownloadBroker(Protocol):
    def download(
        self,
        dependency: DependencyArtifact,
        *,
        max_bytes: int,
        timeout_seconds: float,
        validate_target: DownloadTargetValidator,
    ) -> object:
        """Fetch into quarantine, calling validate_target before every connection and redirect."""
        ...


class OCIBuilder(Protocol):
    def build(
        self,
        attempt: BuildAttempt,
        recipe: EnvironmentRecipe,
        downloads: tuple[QuarantinedDownload, ...],
    ) -> object: ...


class Scanner(Protocol):
    def scan(self, staged: StagedBuild, *, timeout_seconds: float) -> object: ...


class ArtifactStore(Protocol):
    def record_intent(self, intent: EnvironmentBuildIntent) -> None: ...

    def publish(
        self,
        intent: EnvironmentBuildIntent,
        receipt: BuildReceipt,
        provenance: BuildProvenance,
        downloads: tuple[QuarantinedDownload, ...],
        staged: StagedBuild,
        scan: ScanReceipt,
    ) -> object:
        """Atomically record the receipt and promote the already-verified staged image."""
        ...


class EnvironmentBuilder:
    """Orchestrate quarantined downloads, two isolated builds, scanning and publish."""

    def __init__(
        self,
        *,
        resolver: Resolver,
        download_broker: DownloadBroker,
        oci_builder: OCIBuilder,
        scanner: Scanner,
        artifact_store: ArtifactStore,
        builder_identity_sha256: str,
        output_repository: str,
        policy: BuilderPolicy = BuilderPolicy(),
        max_download_bytes: int = 1024 * 1024 * 1024,
        download_timeout_seconds: float = 300,
        max_build_seconds: float = 86_400,
        scanner_timeout_seconds: float = 600,
        nonce_factory: Callable[[], str] | None = None,
    ) -> None:
        _digest(builder_identity_sha256, "builder_identity_sha256")
        if not isinstance(output_repository, str) or _REPOSITORY.fullmatch(output_repository) is None:
            raise ValueError("output_repository must be a canonical repository name")
        if not isinstance(policy, BuilderPolicy) or not policy.require_reproducible or not policy.require_scanner_passed:
            raise ValueError("runtime policy must require reproducibility and a passing scanner")
        if isinstance(max_download_bytes, bool) or not isinstance(max_download_bytes, int) or max_download_bytes < 1:
            raise ValueError("max_download_bytes must be positive")
        for value, name in (
            (download_timeout_seconds, "download_timeout_seconds"),
            (max_build_seconds, "max_build_seconds"),
            (scanner_timeout_seconds, "scanner_timeout_seconds"),
        ):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < float(value) <= 86_400:
                raise ValueError(f"{name} is outside the safe range")
        self._resolver = resolver
        self._download_broker = download_broker
        self._oci_builder = oci_builder
        self._scanner = scanner
        self._artifact_store = artifact_store
        self._builder_identity_sha256 = builder_identity_sha256
        self._output_repository = output_repository
        self._policy = policy
        self._max_download_bytes = max_download_bytes
        self._download_timeout_seconds = float(download_timeout_seconds)
        self._max_build_seconds = float(max_build_seconds)
        self._scanner_timeout_seconds = float(scanner_timeout_seconds)
        self._nonce_factory = nonce_factory or (lambda: secrets.token_hex(32))

    def build(self, recipe: EnvironmentRecipe) -> BuildReceipt:
        if not isinstance(recipe, EnvironmentRecipe):
            raise TypeError("recipe must be an EnvironmentRecipe")
        try:
            initial_resolutions = validate_environment_recipe(recipe, self._resolver, self._policy)
            intent = EnvironmentBuildIntent.create(
                recipe_id=recipe.recipe_id,
                builder_identity_sha256=self._builder_identity_sha256,
                nonce=self._nonce_factory(),
            )
            self._artifact_store.record_intent(intent)
            downloads = tuple(self._download(dependency) for dependency in recipe.dependencies)
            attempts = self._attempts(intent, recipe, downloads)
            staged = (
                self._run_attempt(attempts[0], recipe, downloads),
                self._run_attempt(attempts[1], recipe, downloads),
            )
            first, second = staged
            if first.image_sha256 != second.image_sha256 or first.output_size_bytes != second.output_size_bytes:
                raise EnvironmentBuildError("independent builds produced different image digests")
            if first.sbom_sha256 != second.sbom_sha256:
                raise EnvironmentBuildError("independent builds produced different SBOM digests")
            scan = self._scan(first)
            provenance = BuildProvenance.create(
                intent=intent,
                recipe=recipe,
                downloads=downloads,
                attempts=attempts,
                staged=staged,
                scan=scan,
            )
            output_image = f"{self._output_repository}@sha256:{first.image_sha256}"
            receipt = BuildReceipt.create(
                recipe_id=recipe.recipe_id,
                builder_identity_sha256=self._builder_identity_sha256,
                output_image=output_image,
                output_size_bytes=first.output_size_bytes,
                sbom_sha256=first.sbom_sha256,
                provenance_sha256=provenance.provenance_id.removeprefix("sha256:"),
                vulnerability_report_sha256=scan.vulnerability_report_sha256,
                sources=initial_resolutions,
                reproducible=True,
                scanner_passed=True,
            )
            validate_build_receipt(recipe, receipt, initial_resolutions, self._policy)
            publication = PublicationReceipt.from_mapping(
                self._artifact_store.publish(intent, receipt, provenance, downloads, first, scan)
            )
            if (
                publication.intent_id != intent.intent_id
                or publication.build_receipt_id != receipt.receipt_id
                or publication.provenance_id != provenance.provenance_id
                or publication.staged_artifact_id != first.staged_artifact_id
                or publication.output_image != receipt.output_image
            ):
                raise MalformedBuildResult("publication receipt does not match the verified build")
            return receipt
        except EnvironmentBuildError:
            raise
        except Exception as exc:
            raise EnvironmentBuildError("environment build failed closed") from exc

    def _download(self, dependency: DependencyArtifact) -> QuarantinedDownload:
        validated_hops: list[SourceResolution] = []

        def validate_target(url: str) -> SourceResolution:
            resolution = validate_public_source_url(url, dependency.sha256, self._resolver, self._policy)
            validated_hops.append(resolution)
            return resolution

        raw = self._download_broker.download(
            dependency,
            max_bytes=self._max_download_bytes,
            timeout_seconds=self._download_timeout_seconds,
            validate_target=validate_target,
        )
        download = QuarantinedDownload.from_mapping(raw)
        if not validated_hops:
            raise MalformedBuildResult("download broker bypassed target validation")
        if download.source_chain != tuple(validated_hops):
            raise MalformedBuildResult("download source chain does not match validated DNS and redirects")
        if download.source_chain[0].normalized_url != dependency.source_url:
            raise MalformedBuildResult("download did not begin at the recipe source URL")
        if download.dependency_sha256 != dependency.sha256:
            raise MalformedBuildResult("download digest does not match the recipe")
        if download.size_bytes > self._max_download_bytes:
            raise MalformedBuildResult("download exceeded its byte limit")
        _bounded_elapsed(download.elapsed_seconds, timeout=self._download_timeout_seconds, name="download")
        if download.timed_out:
            raise EnvironmentBuildError("download broker timed out")
        return download

    def _attempts(
        self,
        intent: EnvironmentBuildIntent,
        recipe: EnvironmentRecipe,
        downloads: tuple[QuarantinedDownload, ...],
    ) -> tuple[BuildAttempt, BuildAttempt]:
        timeout = sum(step.timeout_seconds for step in recipe.build_steps)
        if timeout > self._max_build_seconds:
            raise EnvironmentBuildError("recipe build timeout exceeds the builder policy")
        dependency_ids = tuple(sorted({item.quarantine_artifact_id for item in downloads}))
        def create_attempt(ordinal: int) -> BuildAttempt:
            return BuildAttempt.create(
                intent_id=intent.intent_id,
                recipe_id=recipe.recipe_id,
                ordinal=ordinal,
                dependency_artifact_ids=dependency_ids,
                timeout_seconds=timeout,
                network_enabled=False,
                secret_names=(),
                host_mounts=(),
            )

        return create_attempt(1), create_attempt(2)

    def _run_attempt(
        self,
        attempt: BuildAttempt,
        recipe: EnvironmentRecipe,
        downloads: tuple[QuarantinedDownload, ...],
    ) -> StagedBuild:
        try:
            raw = self._oci_builder.build(attempt, recipe, downloads)
        except Exception as exc:
            raise EnvironmentBuildError("isolated builder crashed") from exc
        staged = StagedBuild.from_mapping(raw)
        if staged.attempt_id != attempt.attempt_id:
            raise MalformedBuildResult("staged build does not bind its attempt")
        _bounded_elapsed(staged.elapsed_seconds, timeout=attempt.timeout_seconds, name="builder")
        if staged.timed_out:
            raise EnvironmentBuildError("isolated builder timed out")
        if staged.exit_code != 0:
            raise EnvironmentBuildError("isolated builder returned a non-zero exit code")
        if staged.network_used or staged.secrets_used or staged.host_mounts_used:
            raise MalformedBuildResult("builder violated network, secret, or host-mount isolation")
        if staged.output_size_bytes > recipe.max_output_bytes:
            raise EnvironmentBuildError("staged image exceeds the recipe output limit")
        return staged

    def _scan(self, staged: StagedBuild) -> ScanReceipt:
        try:
            raw = self._scanner.scan(staged, timeout_seconds=self._scanner_timeout_seconds)
        except Exception as exc:
            raise EnvironmentBuildError("scanner crashed") from exc
        receipt = ScanReceipt.from_mapping(raw)
        if receipt.staged_artifact_id != staged.staged_artifact_id or receipt.image_sha256 != staged.image_sha256:
            raise MalformedBuildResult("scanner receipt does not bind the staged image")
        _bounded_elapsed(receipt.elapsed_seconds, timeout=self._scanner_timeout_seconds, name="scanner")
        if receipt.timed_out:
            raise EnvironmentBuildError("scanner timed out")
        if not receipt.passed:
            raise EnvironmentBuildError("scanner rejected the staged image")
        return receipt
