"""Production boundaries for the AEGIS environment builder."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Any, Mapping

from aegis.artifacts import ContentAddressedArtifactStore
from aegis.environments.models import (
    BuilderPolicy,
    BuildReceipt,
    DependencyArtifact,
    SourceResolution,
)
from aegis.environments.runtime import (
    BuildAttempt,
    BuildProvenance,
    EnvironmentBuilder,
    EnvironmentBuildIntent,
    PublicationReceipt,
    QuarantinedDownload,
    ScanReceipt,
    StagedBuild,
)
from aegis.research.types import ResearchArtifact
from aegis.research.url_security import SystemResolver
from aegis.sandbox.backend import SandboxBackend


class EnvironmentBoundaryError(RuntimeError):
    """Raised when a production environment boundary fails closed."""


@dataclass(slots=True)
class QuarantineCache:
    """In-process content-addressed byte cache shared by download/build."""

    _data: dict[str, bytes] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self._data is None:
            self._data = {}

    def put(self, artifact_id: str, payload: bytes) -> None:
        if not artifact_id.startswith("sha256:") or len(artifact_id) != 71:
            raise EnvironmentBoundaryError("quarantine artifact id is invalid")
        if hashlib.sha256(payload).hexdigest() != artifact_id[7:]:
            raise EnvironmentBoundaryError("quarantine payload digest mismatch")
        self._data[artifact_id] = payload

    def get(self, artifact_id: str) -> bytes:
        try:
            return self._data[artifact_id]
        except KeyError as exc:
            raise EnvironmentBoundaryError("quarantine payload is not cached") from exc


class QuarantineDownloadBroker:
    """Download broker that fetches through the research transport."""

    def __init__(
        self,
        research: Any,
        cache: QuarantineCache,
    ) -> None:
        self._research = research
        self._cache = cache

    def download(
        self,
        dependency: DependencyArtifact,
        *,
        max_bytes: int,
        timeout_seconds: float,
        validate_target: Any,
    ) -> Mapping[str, Any]:
        if not isinstance(dependency, DependencyArtifact):
            raise TypeError("dependency must be a DependencyArtifact")
        if not 0 < max_bytes <= 1024 * 1024 * 1024:
            raise ValueError("max_bytes is outside the safe range")
        started = time.monotonic()
        hops: list[SourceResolution] = [validate_target(dependency.source_url)]
        try:
            artifact: ResearchArtifact = self._research.fetch(dependency.source_url)
        except Exception as exc:
            raise EnvironmentBoundaryError(f"dependency fetch failed: {exc}") from exc
        content = artifact.content
        if len(content) > max_bytes:
            raise EnvironmentBoundaryError("dependency download exceeded max_bytes")
        digest = hashlib.sha256(content).hexdigest()
        if digest != dependency.sha256:
            raise EnvironmentBoundaryError("dependency download digest mismatch")
        chain = artifact.provenance.redirect_chain if artifact.provenance is not None else ()
        for redirect in chain:
            hops.append(validate_target(redirect))
        quarantine_id = f"sha256:{digest}"
        self._cache.put(quarantine_id, content)
        return {
            "quarantine_artifact_id": quarantine_id,
            "dependency_sha256": digest,
            "size_bytes": len(content),
            "source_chain": [item.to_dict() for item in hops],
            "elapsed_seconds": time.monotonic() - started,
            "timed_out": False,
        }


class WslAgentOCIBuilder:
    """OCIBuilder boundary that delegates offline builds to the WSL agent."""

    def __init__(self, sandbox: SandboxBackend, cache: QuarantineCache) -> None:
        self._sandbox = sandbox
        self._cache = cache

    def build(
        self,
        attempt: BuildAttempt,
        recipe: Any,
        downloads: tuple[QuarantinedDownload, ...],
    ) -> Mapping[str, Any]:
        dependencies: dict[str, bytes] = {}
        for index, download in enumerate(downloads):
            dependencies[f"dep-{index}.tar"] = self._cache.get(
                download.quarantine_artifact_id
            )
        raw = self._sandbox.build_image(
            recipe.to_dict(),
            dependencies=dependencies,
            attempt_id=attempt.attempt_id,
            timeout_seconds=attempt.timeout_seconds,
        )
        try:
            StagedBuild.from_mapping(raw)
        except (TypeError, ValueError) as exc:
            raise EnvironmentBoundaryError(f"agent returned an invalid staged build: {exc}") from exc
        return raw


class TrivyScanner:
    """Scanner boundary that runs trivy on the WSL agent."""

    def __init__(self, sandbox: SandboxBackend) -> None:
        self._sandbox = sandbox

    def scan(self, staged: StagedBuild, *, timeout_seconds: float) -> Mapping[str, Any]:
        raw = self._sandbox.scan_image(
            f"sha256:{staged.image_sha256}",
            timeout_seconds=timeout_seconds,
        )
        try:
            receipt = ScanReceipt.create(**raw)
        except (TypeError, ValueError) as exc:
            raise EnvironmentBoundaryError(f"agent returned an invalid scan receipt: {exc}") from exc
        return receipt.to_dict()


class CasEnvironmentArtifactStore:
    """Publish build evidence and the champion environment artifact to CAS."""

    def __init__(self, artifacts: ContentAddressedArtifactStore) -> None:
        self._artifacts = artifacts

    def record_intent(self, intent: EnvironmentBuildIntent) -> None:
        self._artifacts.put_json(
            "environment-build",
            {"kind": "intent", "intent": intent.to_dict()},
        )

    def publish(
        self,
        intent: EnvironmentBuildIntent,
        receipt: BuildReceipt,
        provenance: BuildProvenance,
        downloads: tuple[QuarantinedDownload, ...],
        staged: StagedBuild,
        scan: ScanReceipt,
    ) -> Mapping[str, Any]:
        self._artifacts.put_json(
            "environment-build",
            {
                "kind": "receipt",
                "intent_id": intent.intent_id,
                "receipt": receipt.to_dict(),
            },
        )
        self._artifacts.put_json(
            "environment-build",
            {
                "kind": "provenance",
                "provenance_id": provenance.provenance_id,
                "provenance": provenance.to_dict(),
            },
        )
        self._artifacts.put_json(
            "environment-build",
            {
                "kind": "scan",
                "scan_receipt_id": scan.scan_receipt_id,
                "scan": scan.to_dict(),
            },
        )
        self._artifacts.put_json(
            "environment",
            {
                "output_image": receipt.output_image,
                "recipe_id": receipt.recipe_id,
                "build_receipt_id": receipt.receipt_id,
                "provenance_id": provenance.provenance_id,
            },
        )
        publication = {
            "intent_id": intent.intent_id,
            "build_receipt_id": receipt.receipt_id,
            "provenance_id": provenance.provenance_id,
            "staged_artifact_id": staged.staged_artifact_id,
            "output_image": receipt.output_image,
            "published": True,
        }
        publication_mapping = PublicationReceipt.create(**publication).to_dict()
        self._artifacts.put_json(
            "environment-build",
            {"kind": "publication", "publication": publication_mapping},
        )
        return publication_mapping


def build_wsl_environment_builder(
    *,
    sandbox: SandboxBackend,
    research: Any,
    artifacts: ContentAddressedArtifactStore,
    output_repository: str,
    builder_identity_sha256: str,
    policy: BuilderPolicy | None = None,
) -> EnvironmentBuilder:
    """Assemble a production EnvironmentBuilder over the WSL agent."""
    cache = QuarantineCache()
    download_broker = QuarantineDownloadBroker(research, cache)
    oci_builder = WslAgentOCIBuilder(sandbox, cache)
    scanner = TrivyScanner(sandbox)
    store = CasEnvironmentArtifactStore(artifacts)
    return EnvironmentBuilder(
        resolver=SystemResolver(),
        download_broker=download_broker,
        oci_builder=oci_builder,
        scanner=scanner,
        artifact_store=store,
        builder_identity_sha256=builder_identity_sha256,
        output_repository=output_repository,
        policy=policy or BuilderPolicy(),
    )


__all__ = [
    "CasEnvironmentArtifactStore",
    "EnvironmentBoundaryError",
    "QuarantineCache",
    "QuarantineDownloadBroker",
    "TrivyScanner",
    "WslAgentOCIBuilder",
    "build_wsl_environment_builder",
]
