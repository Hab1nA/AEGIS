"""Sandbox-only extraction of text from provenance-verified PDF bytes."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import math
import re
import tarfile
from dataclasses import dataclass
from threading import Lock
from typing import Any, Mapping, Protocol

from aegis.sandbox.backend import SandboxBackend
from aegis.sandbox.types import CommandResult, CommandSpec, PreparedSandbox, StagedArtifact

MAX_PDF_BYTES = 8 * 1024 * 1024
MAX_PAGES = 256
MAX_PAGE_TEXT_BYTES = 64 * 1024
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_TIMEOUT_SECONDS = 300.0
PYPDF_VERSION = "6.14.2"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_ID_PART = re.compile(r"[a-z0-9](?:[a-z0-9_-]{0,14}[a-z0-9])?\Z")
_INPUT_PATH = "input/document.pdf"

# Trusted control-plane code, passed directly as one argv item.  The PDF never
# contributes Python source, paths, command options, environment, or stdin.
_EXTRACT_SCRIPT = """import hashlib,json,sys
import pypdf
from pypdf import PdfReader
path=sys.argv[1]
max_pages=int(sys.argv[2]);max_page_bytes=int(sys.argv[3]);max_output=int(sys.argv[4])
expected_version=sys.argv[5]
if pypdf.__version__ != expected_version: raise RuntimeError('unexpected pypdf version')
raw=open(path,'rb').read()
reader=PdfReader(path,strict=True)
if reader.is_encrypted: raise RuntimeError('encrypted PDF is unsupported')
if not 1 <= len(reader.pages) <= max_pages: raise RuntimeError('PDF page limit exceeded')
pages=[]
for number,page in enumerate(reader.pages,1):
    text=page.extract_text() or ''
    # PDF text extraction can contain layout/control markers.  Keep only the
    # controls accepted by PDFPage before hashing and serializing the page.
    text=''.join(character for character in text if ord(character) >= 32 or character in '\\t\\n\\r\\f')
    encoded=text.encode('utf-8')
    if len(encoded)>max_page_bytes: raise RuntimeError('PDF page text limit exceeded')
    pages.append({'page':number,'text':text,'sha256':hashlib.sha256(encoded).hexdigest()})
result={'schema_version':1,'source_sha256':hashlib.sha256(raw).hexdigest(),'pages':pages}
output=json.dumps(result,ensure_ascii=False,allow_nan=False,separators=(',',':')).encode('utf-8')
if len(output)>max_output: raise RuntimeError('PDF extraction output limit exceeded')
sys.stdout.buffer.write(output)
"""


class PDFExtractionError(RuntimeError):
    pass


class PDFExtractor(Protocol):
    def extract(
        self,
        content: bytes,
        *,
        expected_sha256: str,
        expected_size: int,
    ) -> PDFExtraction: ...


def _digest(value: object, name: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _duration(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("duration must be numeric")
    result = float(value)
    if not math.isfinite(result) or not 0 <= result <= 3600:
        raise ValueError("duration must be finite and bounded")
    return result


@dataclass(frozen=True, slots=True)
class PDFPage:
    page_number: int
    text: str
    sha256: str

    def __post_init__(self) -> None:
        if isinstance(self.page_number, bool) or not isinstance(self.page_number, int) or not (
            1 <= self.page_number <= MAX_PAGES
        ):
            raise ValueError("page_number is invalid")
        if not isinstance(self.text, str):
            raise TypeError("page text must be a string")
        encoded = self.text.encode("utf-8")
        if len(encoded) > MAX_PAGE_TEXT_BYTES:
            raise ValueError("page text exceeds hard limit")
        if any(ord(character) < 32 and character not in "\t\n\r\f" for character in self.text):
            raise ValueError("page text contains binary control characters")
        _digest(self.sha256, "page sha256")
        if hashlib.sha256(encoded).hexdigest() != self.sha256:
            raise ValueError("page sha256 does not match text")


def _extraction_payload(
    source_sha256: str,
    source_size_bytes: int,
    pages: tuple[PDFPage, ...],
) -> Mapping[str, Any]:
    return {
        "schema_version": 1,
        "extractor": f"pypdf-{PYPDF_VERSION}",
        "source_sha256": source_sha256,
        "source_size_bytes": source_size_bytes,
        "pages": [
            {"page_number": page.page_number, "text": page.text, "sha256": page.sha256}
            for page in pages
        ],
    }


def _extraction_id(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        payload, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return f"pdf-extraction-sha256:{hashlib.sha256(encoded).hexdigest()}"


@dataclass(frozen=True, slots=True)
class PDFExtraction:
    extraction_id: str
    source_sha256: str
    source_size_bytes: int
    pages: tuple[PDFPage, ...]

    @classmethod
    def create(
        cls,
        source_sha256: str,
        source_size_bytes: int,
        pages: tuple[PDFPage, ...],
    ) -> PDFExtraction:
        payload = _extraction_payload(source_sha256, source_size_bytes, pages)
        return cls(_extraction_id(payload), source_sha256, source_size_bytes, pages)

    def __post_init__(self) -> None:
        _digest(self.source_sha256, "source_sha256")
        if (
            isinstance(self.source_size_bytes, bool)
            or not isinstance(self.source_size_bytes, int)
            or not 1 <= self.source_size_bytes <= MAX_PDF_BYTES
        ):
            raise ValueError("source_size_bytes is invalid")
        if not isinstance(self.pages, tuple) or not 1 <= len(self.pages) <= MAX_PAGES:
            raise ValueError("pages must be a non-empty bounded tuple")
        if any(not isinstance(page, PDFPage) for page in self.pages):
            raise TypeError("pages must contain PDFPage values")
        if tuple(page.page_number for page in self.pages) != tuple(range(1, len(self.pages) + 1)):
            raise ValueError("PDF pages must be contiguous and one-based")
        if self.extraction_id != _extraction_id(
            _extraction_payload(self.source_sha256, self.source_size_bytes, self.pages)
        ):
            raise ValueError("extraction_id does not match extracted content")


def _strict_json(value: str) -> Mapping[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in items:
            if key in result:
                raise PDFExtractionError(f"PDF extractor output contains duplicate key: {key}")
            result[key] = item
        return result

    try:
        parsed = json.loads(
            value,
            object_pairs_hook=pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                PDFExtractionError(f"PDF extractor output contains non-finite value: {token}")
            ),
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise PDFExtractionError("PDF extractor output is not strict JSON") from exc
    if not isinstance(parsed, dict):
        raise PDFExtractionError("PDF extractor output must be an object")
    return parsed


def _pdf_archive(content: bytes) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.GNU_FORMAT) as archive:
        info = tarfile.TarInfo(_INPUT_PATH)
        info.size = len(content)
        info.mode = 0o400
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        info.mtime = 0
        archive.addfile(info, io.BytesIO(content))
    return output.getvalue()


class SandboxPDFExtractor:
    def __init__(
        self,
        backend: SandboxBackend,
        *,
        id_namespace: str = "pdf-extract",
        max_pages: int = MAX_PAGES,
        max_page_text_bytes: int = MAX_PAGE_TEXT_BYTES,
        max_output_bytes: int = MAX_OUTPUT_BYTES,
        timeout_seconds: float = 120.0,
    ) -> None:
        if not _ID_PART.fullmatch(id_namespace):
            raise ValueError("id_namespace is invalid")
        for value, name, maximum in (
            (max_pages, "max_pages", MAX_PAGES),
            (max_page_text_bytes, "max_page_text_bytes", MAX_PAGE_TEXT_BYTES),
            (max_output_bytes, "max_output_bytes", MAX_OUTPUT_BYTES),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
                raise ValueError(f"{name} must be an integer in [1, {maximum}]")
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or not (
            0 < timeout_seconds <= MAX_TIMEOUT_SECONDS
        ):
            raise ValueError(f"timeout_seconds must be in (0, {MAX_TIMEOUT_SECONDS}]")
        self.backend = backend
        self.id_namespace = id_namespace
        self.max_pages = max_pages
        self.max_page_text_bytes = max_page_text_bytes
        self.max_output_bytes = max_output_bytes
        self.timeout_seconds = float(timeout_seconds)
        self._counter = 0
        self._counter_lock = Lock()

    def _sandbox_id(self, digest: str) -> str:
        with self._counter_lock:
            self._counter += 1
            counter = self._counter
        return f"{self.id_namespace}-{digest[:12]}-{counter:x}"

    @staticmethod
    def _receipt(receipt: StagedArtifact, sandbox_id: str, digest: str, size: int) -> None:
        if (
            not isinstance(receipt, StagedArtifact)
            or receipt.sandbox_id != sandbox_id
            or receipt.digest != digest
            or receipt.size_bytes != size
            or receipt.entries != 1
        ):
            raise PDFExtractionError("sandbox returned an invalid PDF staging receipt")

    def _parse(self, output: str, source_sha256: str, source_size: int) -> PDFExtraction:
        data = _strict_json(output)
        if set(data) != {"schema_version", "source_sha256", "pages"} or data["schema_version"] != 1:
            raise PDFExtractionError("PDF extractor output has missing or unknown fields")
        if data["source_sha256"] != source_sha256:
            raise PDFExtractionError("PDF extractor source digest disagrees with fetched bytes")
        raw_pages = data["pages"]
        if not isinstance(raw_pages, list) or not 1 <= len(raw_pages) <= self.max_pages:
            raise PDFExtractionError("PDF extractor returned an invalid page count")
        pages: list[PDFPage] = []
        for index, raw in enumerate(raw_pages, 1):
            if not isinstance(raw, Mapping) or set(raw) != {"page", "text", "sha256"}:
                raise PDFExtractionError("PDF extractor page has missing or unknown fields")
            if not isinstance(raw["page"], int) or isinstance(raw["page"], bool) or raw["page"] != index:
                raise PDFExtractionError("PDF extractor pages are not contiguous")
            try:
                page = PDFPage(index, raw["text"], raw["sha256"])
            except (TypeError, ValueError) as exc:
                raise PDFExtractionError("PDF extractor returned an invalid page") from exc
            if len(page.text.encode("utf-8")) > self.max_page_text_bytes:
                raise PDFExtractionError("PDF extractor page exceeds configured text limit")
            pages.append(page)
        page_tuple = tuple(pages)
        return PDFExtraction.create(source_sha256, source_size, page_tuple)

    def extract(
        self,
        content: bytes,
        *,
        expected_sha256: str,
        expected_size: int,
    ) -> PDFExtraction:
        if not isinstance(content, bytes) or not 1 <= len(content) <= MAX_PDF_BYTES:
            raise PDFExtractionError("PDF content must be bounded bytes")
        try:
            expected = _digest(expected_sha256, "expected_sha256")
        except ValueError as exc:
            raise PDFExtractionError("expected PDF digest is invalid") from exc
        if (
            isinstance(expected_size, bool)
            or not isinstance(expected_size, int)
            or expected_size != len(content)
            or hashlib.sha256(content).hexdigest() != expected
        ):
            raise PDFExtractionError("PDF bytes disagree with verified provenance")
        doctor = self.backend.doctor()
        if not doctor.passed or not any(
            check.name == "network_none" and check.passed for check in doctor.checks
        ):
            raise PDFExtractionError("sandbox doctor did not prove network isolation")
        archive = _pdf_archive(content)
        archive_digest = hashlib.sha256(archive).hexdigest()
        sandbox_id = self._sandbox_id(expected)
        prepared = False
        try:
            prepared_receipt = self.backend.prepare(sandbox_id)
            prepared = True
            if not isinstance(prepared_receipt, PreparedSandbox) or prepared_receipt.sandbox_id != sandbox_id:
                raise PDFExtractionError("sandbox returned an invalid prepare receipt")
            receipt = self.backend.stage_archive(
                sandbox_id, base64.b64encode(archive).decode("ascii"), archive_digest
            )
            self._receipt(receipt, sandbox_id, archive_digest, len(archive))
            command = CommandSpec(
                (
                    "python3",
                    "-I",
                    "-c",
                    _EXTRACT_SCRIPT,
                    _INPUT_PATH,
                    str(self.max_pages),
                     str(self.max_page_text_bytes),
                     str(self.max_output_bytes),
                     PYPDF_VERSION,
                 ),
                timeout_seconds=self.timeout_seconds,
            )
            result = self.backend.exec(sandbox_id, command)
            if not isinstance(result, CommandResult):
                raise PDFExtractionError("sandbox returned an invalid PDF command result")
            if (
                isinstance(result.exit_code, bool)
                or not isinstance(result.exit_code, int)
                or not isinstance(result.stdout, str)
                or not isinstance(result.stderr, str)
                or not isinstance(result.timed_out, bool)
            ):
                raise PDFExtractionError("sandbox returned malformed PDF command evidence")
            try:
                _duration(result.duration_seconds)
            except (TypeError, ValueError) as exc:
                raise PDFExtractionError("sandbox returned invalid PDF duration evidence") from exc
            stdout_size = len(result.stdout.encode("utf-8"))
            stderr_size = len(result.stderr.encode("utf-8"))
            if stdout_size + stderr_size > self.max_output_bytes:
                raise PDFExtractionError("PDF extractor output exceeded configured limit")
            if result.timed_out:
                raise PDFExtractionError("PDF extraction timed out")
            if result.exit_code != 0:
                raise PDFExtractionError("PDF extraction command failed")
            return self._parse(result.stdout, expected, expected_size)
        finally:
            if prepared:
                try:
                    self.backend.destroy(sandbox_id)
                except Exception:
                    self.backend.kill(sandbox_id)
