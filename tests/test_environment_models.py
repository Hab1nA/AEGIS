from __future__ import annotations

import pytest

from aegis.environments import (
    BuilderNetworkPolicy,
    BuilderPolicy,
    BuildReceipt,
    BuildStep,
    DependencyArtifact,
    DependencyKind,
    EnvironmentRecipe,
    validate_build_receipt,
    validate_environment_recipe,
)
from aegis.research.url_security import StaticResolver


def dependency(url: str = "https://files.example.org/pkg.whl") -> DependencyArtifact:
    return DependencyArtifact("pkg", "1.0.0", DependencyKind.PYTHON_WHEEL, url, "a" * 64)


def recipe(item: DependencyArtifact | None = None) -> EnvironmentRecipe:
    dependencies = () if item is None else (item,)
    network = BuilderNetworkPolicy.OFFLINE if item is None else BuilderNetworkPolicy.BROKERED_PUBLIC
    return EnvironmentRecipe.create(
        parent_image="registry.example/python@sha256:" + "b" * 64,
        network_policy=network,
        dependencies=dependencies,
        build_steps=(BuildStep(("python", "-m", "compileall", "src")),),
        max_output_bytes=1024 * 1024 * 1024,
    )


def receipt(recipe_id: str, sources: tuple[object, ...]) -> BuildReceipt:
    return BuildReceipt.create(
        recipe_id=recipe_id,
        builder_identity_sha256="c" * 64,
        output_image="registry.example/generated@sha256:" + "d" * 64,
        output_size_bytes=1024,
        sbom_sha256="e" * 64,
        provenance_sha256="f" * 64,
        vulnerability_report_sha256="1" * 64,
        sources=sources,
        reproducible=True,
        scanner_passed=True,
    )


def test_public_builder_recipe_and_receipt_bind_exact_sources() -> None:
    created = recipe(dependency())
    resolver = StaticResolver({"files.example.org": ("93.184.216.34",)})
    resolutions = validate_environment_recipe(created, resolver)
    built = receipt(created.recipe_id, resolutions)
    assert validate_build_receipt(created, built, resolutions) is built
    assert created.recipe_id == "sha256:" + created.compute_digest()
    assert built.receipt_id == "sha256:" + built.compute_digest()


@pytest.mark.parametrize(
    ("url", "records", "message"),
    [
        ("https://packages.internal/pkg.whl", {"packages.internal": ("93.184.216.34",)}, "metadata or internal"),
        ("https://metadata.google.internal/pkg.whl", {}, "metadata or internal"),
        ("https://files.example.org/pkg.whl", {"files.example.org": ("10.0.0.4",)}, "non-public"),
        ("https://169.254.169.254/latest", {}, "non-public"),
    ],
)
def test_public_builder_rejects_internal_and_metadata_targets(
    url: str, records: dict[str, tuple[str, ...]], message: str
) -> None:
    created = recipe(dependency(url))
    with pytest.raises(ValueError, match=message):
        validate_environment_recipe(created, StaticResolver(records))


def test_builder_host_allowlist_and_verification_gates_fail_closed() -> None:
    created = recipe(dependency())
    resolver = StaticResolver({"files.example.org": ("93.184.216.34",)})
    with pytest.raises(ValueError, match="allowlisted"):
        validate_environment_recipe(created, resolver, BuilderPolicy(allowed_hosts=frozenset({"other.example"})))
    resolutions = validate_environment_recipe(created, resolver)
    unverified = BuildReceipt.create(
        recipe_id=created.recipe_id,
        builder_identity_sha256="c" * 64,
        output_image="registry.example/generated@sha256:" + "d" * 64,
        output_size_bytes=1024,
        sbom_sha256="e" * 64,
        provenance_sha256="f" * 64,
        vulnerability_report_sha256="1" * 64,
        sources=resolutions,
        reproducible=False,
        scanner_passed=True,
    )
    # Default policy: non-reproducible evidence is accepted as-is.
    validate_build_receipt(created, unverified, resolutions)
    # Strict policy: reproducibility evidence stays enforceable.
    with pytest.raises(ValueError, match="reproducibility"):
        validate_build_receipt(created, unverified, resolutions, BuilderPolicy(require_reproducible=True))
