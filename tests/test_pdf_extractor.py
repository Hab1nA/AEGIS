from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import FrozenInstanceError, replace

from aegis.research.pdf_extractor import PDFExtractionError, SandboxPDFExtractor
from aegis.sandbox.fake import FakeSandboxBackend
from aegis.sandbox.types import CommandResult, DoctorCheck, DoctorReport, StagedArtifact

PDF = b"%PDF-1.7\nverified bytes"


def extracted(*texts: str, source: bytes = PDF) -> str:
    return json.dumps(
        {
            "schema_version": 1,
            "source_sha256": hashlib.sha256(source).hexdigest(),
            "pages": [
                {
                    "page": index,
                    "text": text,
                    "sha256": hashlib.sha256(text.encode()).hexdigest(),
                }
                for index, text in enumerate(texts, 1)
            ],
        },
        separators=(",", ":"),
    )


class NetworklessBackend(FakeSandboxBackend):
    def doctor(self) -> DoctorReport:
        return DoctorReport((DoctorCheck("network_none", self.healthy, "test isolation"),))


class TamperedReceiptBackend(NetworklessBackend):
    def stage_archive(self, sandbox_id, archive_base64, expected_digest):  # type: ignore[no-untyped-def]
        receipt = super().stage_archive(sandbox_id, archive_base64, expected_digest)
        return StagedArtifact(receipt.sandbox_id, "0" * 64, receipt.size_bytes, receipt.entries)


class PDFExtractorTests(unittest.TestCase):
    def test_success_uses_fixed_script_and_returns_frozen_page_hashes(self) -> None:
        backend = NetworklessBackend(
            executor=lambda _sid, _cmd: CommandResult(0, extracted("Page one", "Page two"), "", 0.2)
        )
        result = SandboxPDFExtractor(backend).extract(
            PDF,
            expected_sha256=hashlib.sha256(PDF).hexdigest(),
            expected_size=len(PDF),
        )
        self.assertEqual([page.page_number for page in result.pages], [1, 2])
        self.assertEqual(result.pages[1].sha256, hashlib.sha256(b"Page two").hexdigest())
        self.assertTrue(result.extraction_id.startswith("pdf-extraction-sha256:"))
        self.assertEqual(len(backend.commands), 1)
        _, command = backend.commands[0]
        self.assertEqual(command.argv[:3], ("python3", "-I", "-c"))
        self.assertIn("ord(character) >= 32", command.argv[3])
        self.assertIn(r"character in '\t\n\r\f'", command.argv[3])
        self.assertEqual(command.argv[4], "input/document.pdf")
        self.assertIsNone(command.stdin)
        self.assertEqual(backend.prepared, set())
        with self.assertRaises(FrozenInstanceError):
            result.pages = ()  # type: ignore[misc]
        with self.assertRaises(ValueError):
            replace(result, source_sha256="0" * 64)

    def test_malicious_and_malformed_output_is_rejected(self) -> None:
        malicious = (
            '{"schema_version":1,"source_sha256":"' + hashlib.sha256(PDF).hexdigest() + '",'
            '"pages":[],"command":"rm"}',
            '{"schema_version":1,"source_sha256":"a","source_sha256":"b","pages":[]}',
            extracted("bad\x00control"),
            extracted("valid").replace('"page":1', '"page":2'),
            extracted("valid").replace(hashlib.sha256(b"valid").hexdigest(), "0" * 64),
        )
        for output in malicious:
            with self.subTest(), self.assertRaises(PDFExtractionError):
                SandboxPDFExtractor(
                    NetworklessBackend(executor=lambda _sid, _cmd, value=output: CommandResult(0, value, "", 0.1))
                ).extract(
                    PDF,
                    expected_sha256=hashlib.sha256(PDF).hexdigest(),
                    expected_size=len(PDF),
                )

    def test_limits_nonzero_timeout_and_failure_cleanup(self) -> None:
        cases = (
            (CommandResult(0, "x" * 65, "", 0.1), "output"),
            (CommandResult(3, "", "parse failed", 0.1), "command failed"),
            (CommandResult(0, "", "", 0.1, timed_out=True), "timed out"),
        )
        for result, message in cases:
            backend = NetworklessBackend(executor=lambda _sid, _cmd, value=result: value)
            with self.subTest(message=message), self.assertRaisesRegex(PDFExtractionError, message):
                SandboxPDFExtractor(backend, max_output_bytes=64).extract(
                    PDF,
                    expected_sha256=hashlib.sha256(PDF).hexdigest(),
                    expected_size=len(PDF),
                )
            self.assertEqual(backend.prepared, set())

        def explode(_sid, _command):  # type: ignore[no-untyped-def]
            raise RuntimeError("adapter failed")

        backend = NetworklessBackend(executor=explode)
        with self.assertRaisesRegex(RuntimeError, "adapter failed"):
            SandboxPDFExtractor(backend).extract(
                PDF,
                expected_sha256=hashlib.sha256(PDF).hexdigest(),
                expected_size=len(PDF),
            )
        self.assertEqual(backend.prepared, set())

    def test_receipt_provenance_and_doctor_fail_closed(self) -> None:
        digest = hashlib.sha256(PDF).hexdigest()
        backend = TamperedReceiptBackend()
        with self.assertRaisesRegex(PDFExtractionError, "receipt"):
            SandboxPDFExtractor(backend).extract(PDF, expected_sha256=digest, expected_size=len(PDF))
        self.assertEqual(backend.prepared, set())
        with self.assertRaisesRegex(PDFExtractionError, "provenance"):
            SandboxPDFExtractor(NetworklessBackend()).extract(
                PDF, expected_sha256="0" * 64, expected_size=len(PDF)
            )
        with self.assertRaisesRegex(PDFExtractionError, "network"):
            SandboxPDFExtractor(FakeSandboxBackend()).extract(
                PDF, expected_sha256=digest, expected_size=len(PDF)
            )


if __name__ == "__main__":
    unittest.main()
