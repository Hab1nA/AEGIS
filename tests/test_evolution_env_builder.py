from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from aegis.artifacts import ContentAddressedArtifactStore
from aegis.environments.models import (
    BuilderNetworkPolicy,
    BuildStep,
    DependencyArtifact,
    DependencyKind,
    EnvironmentRecipe,
)
from aegis.environments.runtime import (
    BuildAttempt,
    BuildReceipt,
    EnvironmentBuilder,
    QuarantinedDownload,
    ScanReceipt,
    StagedBuild,
)
from aegis.evolution.env_builder import (
    CasEnvironmentArtifactStore,
    QuarantineCache,
    QuarantineDownloadBroker,
    TrivyScanner,
    WslAgentOCIBuilder,
)
from aegis.research.types import Provenance, ResearchArtifact
from aegis.research.url_security import SystemResolver
from aegis.sandbox.fake import FakeSandboxBackend
from tests.test_cycle_ports import FakeResearch


def offline_recipe() -> EnvironmentRecipe:
    return EnvironmentRecipe.create(
        parent_image="localhost/aegis@sha256:" + "a" * 64,
        network_policy=BuilderNetworkPolicy.OFFLINE,
        dependencies=(),
        build_steps=(
            BuildStep(argv=("python", "-c", "print(1)"), cwd=".", timeout_seconds=300),
        ),
        max_output_bytes=1024 * 1024,
    )


class EnvironmentBuilderWiringTests(unittest.TestCase):
    def setUp(self) -> None:
        self._root = tempfile.TemporaryDirectory(prefix="aegis-env-")
        self.root = Path(self._root.name)
        self.artifacts = ContentAddressedArtifactStore(self.root / "artifacts")

    def _fake_staged(self, attempt_id: str, image_sha256: str) -> dict[str, object]:
        return {
            "staged_artifact_id": f"sha256:{image_sha256}",
            "attempt_id": attempt_id,
            "image_sha256": image_sha256,
            "output_size_bytes": 12345,
            "sbom_sha256": "2" * 64,
            "provenance_sha256": "3" * 64,
            "isolation_receipt_sha256": "4" * 64,
            "elapsed_seconds": 1.0,
            "timed_out": False,
            "exit_code": 0,
            "network_used": False,
            "secrets_used": False,
            "host_mounts_used": False,
        }

    def test_full_offline_build_publishes_environment_artifact(self) -> None:
        image_sha256 = "5" * 64
        fake_staged = self._fake_staged

        class Builder:
            def build(
                self,
                attempt: BuildAttempt,
                recipe: EnvironmentRecipe,
                downloads: tuple[QuarantinedDownload, ...],
            ) -> dict[str, object]:
                return fake_staged(attempt.attempt_id, image_sha256)

        class Scanner:
            def scan(
                self, staged: StagedBuild, *, timeout_seconds: float
            ) -> dict[str, object]:
                return ScanReceipt.create(
                    staged_artifact_id=staged.staged_artifact_id,
                    image_sha256=staged.image_sha256,
                    vulnerability_report_sha256="6" * 64,
                    passed=True,
                    elapsed_seconds=1.0,
                    timed_out=False,
                ).to_dict()

        store = CasEnvironmentArtifactStore(self.artifacts)
        builder_obj = EnvironmentBuilder(
            resolver=SystemResolver(),
            download_broker=QuarantineDownloadBroker(FakeResearch(), QuarantineCache()),
            oci_builder=Builder(),
            scanner=Scanner(),
            artifact_store=store,
            builder_identity_sha256="7" * 64,
            output_repository="localhost/aegis-evolution",
        )
        receipt = builder_obj.build(offline_recipe())
        self.assertIsInstance(receipt, BuildReceipt)
        self.assertEqual(receipt.output_image, f"localhost/aegis-evolution@sha256:{image_sha256}")
        self.assertTrue(receipt.reproducible)
        self.assertTrue(receipt.scanner_passed)
        environment_refs = sorted((self.artifacts.root / "environment").iterdir())
        self.assertEqual(len(environment_refs), 1)
        payload = (self.artifacts.root / "environment" / environment_refs[0].name).read_bytes()
        import json

        self.assertEqual(
            json.loads(payload)["output_image"],
            f"localhost/aegis-evolution@sha256:{image_sha256}",
        )

    def test_quarantine_download_broker_verifies_digest_and_hops(self) -> None:
        content = b"dependency-bytes"
        digest = hashlib.sha256(content).hexdigest()

        class Research:
            def fetch(self, url: str, *, validate_as_archive: bool = False) -> ResearchArtifact:
                del validate_as_archive
                return ResearchArtifact(
                    content,
                    Provenance(
                        url,
                        url,
                        "2026-01-01T00:00:00+00:00",
                        digest,
                        len(content),
                        "application/octet-stream",
                        (),
                    ),
                )

        cache = QuarantineCache()
        broker = QuarantineDownloadBroker(Research(), cache)
        dependency = DependencyArtifact(
            "dep",
            "1.0",
            DependencyKind.SOURCE_ARCHIVE,
            "https://example.test/dep.tar.gz",
            digest,
        )

        def validate_target(url: str) -> object:
            from aegis.environments.models import SourceResolution

            return SourceResolution(digest, url, ("93.184.216.34",))

        raw = broker.download(
            dependency,
            max_bytes=1024,
            timeout_seconds=30,
            validate_target=validate_target,
        )
        download = QuarantinedDownload.from_mapping(raw)
        self.assertEqual(download.dependency_sha256, digest)
        self.assertEqual(len(download.source_chain), 1)
        self.assertEqual(cache.get(download.quarantine_artifact_id), content)

        bad = DependencyArtifact(
            "dep",
            "1.0",
            DependencyKind.SOURCE_ARCHIVE,
            "https://example.test/dep.tar.gz",
            "0" * 64,
        )
        with self.assertRaises(Exception):
            broker.download(
                bad, max_bytes=1024, timeout_seconds=30, validate_target=validate_target
            )

    def test_wsl_agent_boundaries_round_trip(self) -> None:
        image_sha256 = "5" * 64
        sandbox = FakeSandboxBackend(
            build_image_handler=lambda recipe, deps, attempt_id, timeout: self._fake_staged(
                attempt_id or "attempt", image_sha256
            ),
            scan_image_handler=lambda image, timeout: {
                "staged_artifact_id": f"sha256:{image_sha256}",
                "image_sha256": image_sha256,
                "vulnerability_report_sha256": "6" * 64,
                "passed": True,
                "elapsed_seconds": 1.0,
                "timed_out": False,
            },
        )
        cache = QuarantineCache()
        oci_builder = WslAgentOCIBuilder(sandbox, cache)
        attempt = BuildAttempt.create(
            intent_id="sha256:" + "0" * 64,
            recipe_id=offline_recipe().recipe_id,
            ordinal=1,
            dependency_artifact_ids=(),
            timeout_seconds=300,
        )
        raw = oci_builder.build(attempt, offline_recipe(), ())
        staged = StagedBuild.from_mapping(raw)
        self.assertEqual(staged.image_sha256, image_sha256)

        scanner = TrivyScanner(sandbox)
        scan_raw = scanner.scan(staged, timeout_seconds=60)
        receipt = ScanReceipt.from_mapping(scan_raw)
        self.assertTrue(receipt.passed)
        self.assertEqual(receipt.image_sha256, image_sha256)


if __name__ == "__main__":
    unittest.main()
