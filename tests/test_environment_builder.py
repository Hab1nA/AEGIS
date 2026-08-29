from __future__ import annotations

from typing import Callable

import pytest

from aegis.environments import (
    BuildAttempt,
    BuilderNetworkPolicy,
    BuilderPolicy,
    BuildProvenance,
    BuildReceipt,
    BuildStep,
    DependencyArtifact,
    DependencyKind,
    EnvironmentBuilder,
    EnvironmentBuildError,
    EnvironmentBuildIntent,
    EnvironmentRecipe,
    PublicationReceipt,
    QuarantinedDownload,
    ScanReceipt,
    SourceResolution,
    StagedBuild,
)
from aegis.research.url_security import StaticResolver


def dependency() -> DependencyArtifact:
    return DependencyArtifact(
        "demo",
        "1.0.0",
        DependencyKind.PYTHON_WHEEL,
        "https://files.example.org/demo.whl",
        "a" * 64,
    )


def recipe(*, with_dependency: bool = True) -> EnvironmentRecipe:
    dependencies = (dependency(),) if with_dependency else ()
    return EnvironmentRecipe.create(
        parent_image="registry.example/python@sha256:" + "b" * 64,
        network_policy=(
            BuilderNetworkPolicy.BROKERED_PUBLIC if with_dependency else BuilderNetworkPolicy.OFFLINE
        ),
        dependencies=dependencies,
        build_steps=(BuildStep(("python", "-m", "compileall", "src"), timeout_seconds=10),),
        max_output_bytes=1024 * 1024,
    )


class Resolver(StaticResolver):
    def __init__(self) -> None:
        super().__init__(
            {
                "files.example.org": ("93.184.216.34",),
                "cdn.example.org": ("93.184.216.35",),
            }
        )
        self.calls: list[str] = []

    def resolve(self, hostname: str) -> tuple[str, ...]:
        self.calls.append(hostname)
        return super().resolve(hostname)


class Downloader:
    def __init__(self, redirect_url: str | None = None, *, timed_out: bool = False) -> None:
        self.redirect_url = redirect_url
        self.timed_out = timed_out
        self.calls = 0

    def download(
        self,
        item: DependencyArtifact,
        *,
        max_bytes: int,
        timeout_seconds: float,
        validate_target: Callable[[str], SourceResolution],
    ) -> object:
        self.calls += 1
        assert max_bytes > 1024
        assert timeout_seconds > 0
        chain = [validate_target(item.source_url)]
        if self.redirect_url is not None:
            chain.append(validate_target(self.redirect_url))
        return QuarantinedDownload(
            "sha256:" + item.sha256,
            item.sha256,
            1024,
            tuple(chain),
            1,
            self.timed_out,
        ).to_dict()


class Builder:
    def __init__(self, *, second_digest: str | None = None, timed_out: bool = False, crash: bool = False) -> None:
        self.second_digest = second_digest
        self.timed_out = timed_out
        self.crash = crash
        self.attempts: list[BuildAttempt] = []

    def build(
        self,
        attempt: BuildAttempt,
        build_recipe: EnvironmentRecipe,
        downloads: tuple[QuarantinedDownload, ...],
    ) -> object:
        if self.crash:
            raise RuntimeError("builder crashed")
        assert build_recipe.recipe_id == attempt.recipe_id
        assert attempt.network_enabled is False
        assert attempt.secret_names == ()
        assert attempt.host_mounts == ()
        assert all(item.quarantine_artifact_id in attempt.dependency_artifact_ids for item in downloads)
        self.attempts.append(attempt)
        image = self.second_digest if attempt.ordinal == 2 and self.second_digest else "c" * 64
        return StagedBuild(
            staged_artifact_id="sha256:" + image,
            attempt_id=attempt.attempt_id,
            image_sha256=image,
            output_size_bytes=4096,
            sbom_sha256="d" * 64,
            provenance_sha256=("e" if attempt.ordinal == 1 else "f") * 64,
            isolation_receipt_sha256="1" * 64,
            elapsed_seconds=1,
            timed_out=self.timed_out,
            exit_code=0,
            network_used=False,
            secrets_used=False,
            host_mounts_used=False,
        ).to_dict()


class Scanner:
    def __init__(self, *, passed: bool = True, timed_out: bool = False) -> None:
        self.passed = passed
        self.timed_out = timed_out
        self.calls = 0

    def scan(self, staged: StagedBuild, *, timeout_seconds: float) -> object:
        self.calls += 1
        return ScanReceipt.create(
            staged_artifact_id=staged.staged_artifact_id,
            image_sha256=staged.image_sha256,
            vulnerability_report_sha256="2" * 64,
            passed=self.passed,
            elapsed_seconds=min(1, timeout_seconds),
            timed_out=self.timed_out,
        ).to_dict()


class Store:
    def __init__(self) -> None:
        self.intents: list[EnvironmentBuildIntent] = []
        self.publications = 0
        self.provenance: BuildProvenance | None = None
        self.downloads: tuple[QuarantinedDownload, ...] = ()

    def record_intent(self, intent: EnvironmentBuildIntent) -> None:
        self.intents.append(intent)

    def publish(
        self,
        intent: EnvironmentBuildIntent,
        receipt: BuildReceipt,
        provenance: BuildProvenance,
        downloads: tuple[QuarantinedDownload, ...],
        staged: StagedBuild,
        scan: ScanReceipt,
    ) -> object:
        assert self.intents == [intent]
        assert receipt.provenance_sha256 == provenance.provenance_id.removeprefix("sha256:")
        assert scan.scan_receipt_id == provenance.scan_receipt_id
        self.publications += 1
        self.provenance = provenance
        self.downloads = downloads
        return PublicationReceipt.create(
            intent_id=intent.intent_id,
            build_receipt_id=receipt.receipt_id,
            provenance_id=provenance.provenance_id,
            staged_artifact_id=staged.staged_artifact_id,
            output_image=receipt.output_image,
            published=True,
        ).to_dict()


def runtime(
    *,
    resolver: Resolver | None = None,
    downloader: Downloader | None = None,
    builder: Builder | None = None,
    scanner: Scanner | None = None,
    store: Store | None = None,
    policy: BuilderPolicy | None = None,
) -> tuple[EnvironmentBuilder, Resolver, Downloader, Builder, Scanner, Store]:
    resolved = resolver or Resolver()
    downloads = downloader or Downloader()
    builds = builder or Builder()
    scans = scanner or Scanner()
    artifacts = store or Store()
    return (
        EnvironmentBuilder(
            resolver=resolved,
            download_broker=downloads,
            oci_builder=builds,
            scanner=scans,
            artifact_store=artifacts,
            builder_identity_sha256="3" * 64,
            output_repository="registry.example/generated",
            nonce_factory=lambda: "4" * 32,
            policy=policy or BuilderPolicy(),
        ),
        resolved,
        downloads,
        builds,
        scans,
        artifacts,
    )


def test_success_requires_quarantine_two_isolated_builds_scan_and_atomic_publish() -> None:
    environment, resolver, downloader, builder, scanner, store = runtime()
    receipt = environment.build(recipe())

    assert receipt.output_image == "registry.example/generated@sha256:" + "c" * 64
    assert receipt.reproducible is True
    assert receipt.scanner_passed is True
    assert downloader.calls == 1
    assert [item.ordinal for item in builder.attempts] == [1, 2]
    assert scanner.calls == 1
    assert store.publications == 1
    assert store.downloads[0].quarantine_artifact_id == "sha256:" + "a" * 64
    assert store.provenance is not None
    assert resolver.calls.count("files.example.org") == 2


def test_every_public_redirect_is_re_resolved_and_bound_into_provenance() -> None:
    environment, resolver, _, _, _, store = runtime(
        downloader=Downloader("https://cdn.example.org/demo.whl")
    )
    environment.build(recipe())

    assert resolver.calls.count("files.example.org") == 2
    assert resolver.calls.count("cdn.example.org") == 1
    assert [item.normalized_url for item in store.downloads[0].source_chain] == [
        "https://files.example.org/demo.whl",
        "https://cdn.example.org/demo.whl",
    ]


@pytest.mark.parametrize(
    "redirect",
    [
        "https://metadata.google.internal/latest",
        "https://169.254.169.254/latest",
        "https://10.0.0.4/archive",
    ],
)
def test_redirect_to_metadata_or_private_network_fails_before_build_and_publish(redirect: str) -> None:
    environment, _, _, builder, scanner, store = runtime(downloader=Downloader(redirect))
    with pytest.raises(EnvironmentBuildError):
        environment.build(recipe())
    assert builder.attempts == []
    assert scanner.calls == 0
    assert store.publications == 0


def test_non_reproducible_build_publishes_with_evidence_and_strict_policy_fails_closed() -> None:
    # Default policy: a non-reproducible build still publishes, with honest
    # reproducible=False evidence on the receipt.
    environment, _, _, _, scanner, store = runtime(builder=Builder(second_digest="5" * 64))
    receipt = environment.build(recipe())
    assert receipt.reproducible is False
    assert receipt.scanner_passed is True
    assert scanner.calls == 1
    assert store.publications == 1

    # Strict policy: bit-for-bit reproducibility stays enforceable.
    strict, _, _, _, strict_scanner, strict_store = runtime(
        builder=Builder(second_digest="5" * 64),
        policy=BuilderPolicy(require_reproducible=True),
    )
    with pytest.raises(EnvironmentBuildError, match="different image digests"):
        strict.build(recipe())
    assert strict_scanner.calls == 0
    assert strict_store.publications == 0


def test_download_timeout_never_reaches_builder_or_publish() -> None:
    environment, _, _, builder, scanner, store = runtime(downloader=Downloader(timed_out=True))
    with pytest.raises(EnvironmentBuildError, match="download broker timed out"):
        environment.build(recipe())
    assert builder.attempts == []
    assert scanner.calls == 0
    assert store.publications == 0


@pytest.mark.parametrize(
    ("builder", "message"),
    [
        (Builder(timed_out=True), "timed out"),
        (Builder(crash=True), "crashed"),
    ],
)
def test_builder_failures_never_publish(builder: Builder, message: str) -> None:
    environment, _, _, _, _, store = runtime(builder=builder)
    with pytest.raises(EnvironmentBuildError, match=message):
        environment.build(recipe())
    assert store.publications == 0


@pytest.mark.parametrize(
    "scanner",
    [Scanner(passed=False), Scanner(timed_out=True)],
)
def test_scanner_failure_degrades_to_unscanned_receipt(scanner: Scanner) -> None:
    environment, _, _, _, _, store = runtime(scanner=scanner)
    receipt = environment.build(recipe())
    assert receipt.scanner_passed is False
    assert receipt.reproducible is True
    assert store.publications == 1


def test_scanner_failure_strict_policy_fails_closed() -> None:
    environment, _, _, _, _, store = runtime(
        scanner=Scanner(passed=False),
        policy=BuilderPolicy(require_scanner_passed=True),
    )
    with pytest.raises(EnvironmentBuildError, match="rejected"):
        environment.build(recipe())
    assert store.publications == 0


def test_offline_recipe_does_not_call_download_broker() -> None:
    environment, _, downloader, builder, _, store = runtime()
    receipt = environment.build(recipe(with_dependency=False))
    assert downloader.calls == 0
    assert len(builder.attempts) == 2
    assert store.publications == 1
    assert receipt.sources == ()
