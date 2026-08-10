"""Read-only collection of provenance-backed, citable paper text or PDF pages."""

from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping, Protocol

from .imports import (
    MAX_AUTHORS,
    MAX_IMPORT_BYTES,
    MAX_PROVENANCE_ITEMS,
    ResearchImportArtifact,
    ResearchImportError,
    validate_paper_import,
)
from .pdf_extractor import PDFExtraction, PDFExtractionError, PDFExtractor
from .types import Provenance, ResearchArtifact, SearchHit

_DOI = re.compile(r"doi:(10\.\d{4,9}/[-._;()/:A-Za-z0-9]+)", re.IGNORECASE)
_ARXIV = re.compile(r"arxiv:(\d{4}\.\d{4,5}(?:v[1-9]\d*)?)", re.IGNORECASE)
_PAPER_ID = re.compile(r"[0-9a-fA-F]{40}")
_KNOWN_EXTERNAL_IDS = frozenset(
    {"DOI", "ArXiv", "CorpusId", "MAG", "PubMed", "PubMedCentral", "ACL", "DBLP"}
)
_FIELDS = "title,authors,externalIds,openAccessPdf"
_ATOM = "http://www.w3.org/2005/Atom"
_ARXIV_XML = "http://arxiv.org/schemas/atom"
_OPENSEARCH = "http://a9.com/-/spec/opensearch/1.1/"
_XML_DECLARATION = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)
_ARXIV_ENTRY_ID = re.compile(
    r"https?://(?:export\.)?arxiv\.org/abs/(\d{4}\.\d{4,5}(?:v[1-9]\d*)?)"
)
_ARXIV_FEED_FIELDS = frozenset(
    {
        f"{{{_ATOM}}}id",
        f"{{{_ATOM}}}updated",
        f"{{{_ATOM}}}link",
        f"{{{_ATOM}}}title",
        f"{{{_ATOM}}}entry",
        f"{{{_OPENSEARCH}}}totalResults",
        f"{{{_OPENSEARCH}}}startIndex",
        f"{{{_OPENSEARCH}}}itemsPerPage",
    }
)
_ARXIV_ENTRY_FIELDS = frozenset(
    {
        f"{{{_ATOM}}}id",
        f"{{{_ATOM}}}updated",
        f"{{{_ATOM}}}published",
        f"{{{_ATOM}}}title",
        f"{{{_ATOM}}}summary",
        f"{{{_ATOM}}}author",
        f"{{{_ATOM}}}category",
        f"{{{_ATOM}}}link",
        f"{{{_ARXIV_XML}}}comment",
        f"{{{_ARXIV_XML}}}journal_ref",
        f"{{{_ARXIV_XML}}}doi",
        f"{{{_ARXIV_XML}}}primary_category",
    }
)


class PaperCollectionError(ResearchImportError):
    """Fetched metadata or text did not prove a safe citable paper snapshot."""


class Research(Protocol):
    def search(self, query: str, *, limit: int = 10) -> list[SearchHit]: ...

    def fetch(self, url: str, *, validate_as_archive: bool = False) -> ResearchArtifact: ...


@dataclass(frozen=True, slots=True)
class PaperCollectorLimits:
    max_content_bytes: int = 8 * 1024 * 1024
    max_metadata_bytes: int = 512 * 1024
    max_excerpt_bytes: int = 64 * 1024
    max_excerpts: int = MAX_PROVENANCE_ITEMS

    def __post_init__(self) -> None:
        values = (
            self.max_content_bytes,
            self.max_metadata_bytes,
            self.max_excerpt_bytes,
            self.max_excerpts,
        )
        if any(isinstance(value, bool) or not isinstance(value, int) or value <= 0 for value in values):
            raise ValueError("paper collector limits must be positive integers")
        if self.max_content_bytes > MAX_IMPORT_BYTES or self.max_excerpts > MAX_PROVENANCE_ITEMS:
            raise ValueError("paper collector limits cannot exceed research import hard limits")


@dataclass(frozen=True, slots=True)
class PaperExcerpt:
    locator_type: str
    locator: str
    text: str
    sha256: str


@dataclass(frozen=True, slots=True)
class PaperSnapshot:
    identifier: str
    title: str
    authors: tuple[str, ...]
    content: bytes
    excerpts: tuple[PaperExcerpt, ...]
    metadata_provenance: Provenance
    content_provenance: Provenance
    artifact: ResearchImportArtifact
    execution_granted: bool = False


def _identifier(value: object) -> tuple[str, str]:
    if not isinstance(value, str) or value != value.strip() or len(value) > 256:
        raise PaperCollectionError("identifier must be bounded trimmed text")
    doi = _DOI.fullmatch(value)
    if doi is not None:
        suffix = doi.group(1).lower()
        return f"doi:{suffix}", f"DOI:{suffix}"
    arxiv = _ARXIV.fullmatch(value)
    if arxiv is not None:
        suffix = arxiv.group(1).lower()
        return f"arxiv:{suffix}", f"ARXIV:{suffix}"
    raise PaperCollectionError("identifier must be an exact DOI or versioned/unversioned arXiv id")


def _quote_component(value: str) -> str:
    safe = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    return "".join(chr(byte) if byte in safe else f"%{byte:02X}" for byte in value.encode("utf-8"))


def _https_url(value: object, name: str) -> str:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or len(value) > 2048
        or re.fullmatch(r"https://[A-Za-z0-9.-]+(?::443)?/[!-~]*", value) is None
        or "@" in value.split("/", 3)[2]
        or "#" in value
    ):
        raise PaperCollectionError(f"{name} must be a canonical HTTPS URL without credentials or fragment")
    host = value.split("/", 3)[2].split(":", 1)[0].lower().rstrip(".")
    if (
        host == "localhost"
        or host.endswith((".localhost", ".local", ".internal"))
        or "." not in host
        or host.startswith("127.")
        or host in {"0.0.0.0", "169.254.169.254", "::1"}
    ):
        raise PaperCollectionError(f"{name} must use a qualified public host")
    return value


def _checked_artifact(
    value: object,
    expected_requested_url: str,
    *,
    maximum: int,
    require_json: bool,
) -> ResearchArtifact:
    if not isinstance(value, ResearchArtifact) or not isinstance(value.content, bytes):
        raise PaperCollectionError("research fetch returned an invalid artifact")
    provenance = value.provenance
    if not isinstance(provenance, Provenance):
        raise PaperCollectionError("research fetch omitted provenance")
    digest = hashlib.sha256(value.content).hexdigest()
    if provenance.requested_url != expected_requested_url:
        raise PaperCollectionError(
            "response requested URL provenance is invalid: "
            f"expected {expected_requested_url!r}, observed {provenance.requested_url!r}"
        )
    if provenance.sha256 != digest:
        raise PaperCollectionError("response digest provenance is invalid")
    if provenance.size_bytes != len(value.content):
        raise PaperCollectionError(
            "response size provenance is invalid: "
            f"declared {provenance.size_bytes}, observed {len(value.content)}"
        )
    if not 1 <= len(value.content) <= maximum:
        raise PaperCollectionError(
            "paper response size is outside the configured bound: "
            f"{len(value.content)} bytes, maximum {maximum}"
        )
    _https_url(provenance.final_url, "response final_url")
    if provenance.redirect_chain:
        if provenance.redirect_chain[-1] != provenance.final_url:
            raise PaperCollectionError("response redirect chain does not terminate at final_url")
        for url in provenance.redirect_chain:
            _https_url(url, "response redirect URL")
    elif provenance.final_url != expected_requested_url:
        raise PaperCollectionError("response final_url changed without a redirect chain")
    try:
        retrieved = datetime.fromisoformat(provenance.retrieved_at)
    except (TypeError, ValueError) as exc:
        raise PaperCollectionError("response provenance time is invalid") from exc
    if retrieved.tzinfo is None or retrieved.utcoffset() is None:
        raise PaperCollectionError("response provenance time must be timezone-aware")
    media_type = provenance.media_type.strip().lower()
    if media_type != provenance.media_type:
        raise PaperCollectionError("response media type is not canonical")
    if require_json and media_type not in {"application/json", "application/vnd.api+json"}:
        raise PaperCollectionError("paper metadata response must be JSON")
    return value


def _json(value: bytes) -> Mapping[str, Any]:
    def object_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise PaperCollectionError("metadata contains duplicate JSON keys")
            result[key] = item
        return result

    try:
        parsed = json.loads(
            value.decode("utf-8"),
            object_pairs_hook=object_hook,
            parse_constant=lambda token: (_ for _ in ()).throw(
                PaperCollectionError(f"metadata contains non-finite JSON: {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PaperCollectionError("metadata is not strict UTF-8 JSON") from exc
    if not isinstance(parsed, dict) or set(parsed) != {
        "paperId",
        "title",
        "authors",
        "externalIds",
        "openAccessPdf",
    }:
        raise PaperCollectionError("metadata has missing or unknown fields")
    return parsed


def _metadata(value: Mapping[str, Any], identifier: str) -> tuple[str, tuple[str, ...], str]:
    paper_id = value["paperId"]
    if not isinstance(paper_id, str) or _PAPER_ID.fullmatch(paper_id) is None:
        raise PaperCollectionError("metadata paperId is invalid")
    title = value["title"]
    if (
        not isinstance(title, str)
        or not title.strip()
        or title != title.strip()
        or len(title) > 1000
        or any(ord(char) < 32 for char in title)
    ):
        raise PaperCollectionError("metadata title is invalid")
    authors_raw = value["authors"]
    if not isinstance(authors_raw, list) or not 1 <= len(authors_raw) <= MAX_AUTHORS:
        raise PaperCollectionError("metadata authors must be a non-empty bounded array")
    authors: list[str] = []
    for raw in authors_raw:
        if not isinstance(raw, Mapping) or set(raw) != {"authorId", "name"}:
            raise PaperCollectionError("metadata author has missing or unknown fields")
        name = raw["name"]
        if (
            not isinstance(name, str)
            or not name.strip()
            or name != name.strip()
            or len(name) > 256
            or any(ord(char) < 32 for char in name)
        ):
            raise PaperCollectionError("metadata author name is invalid")
        author_id = raw["authorId"]
        if author_id is not None and (not isinstance(author_id, str) or len(author_id) > 128):
            raise PaperCollectionError("metadata authorId is invalid")
        authors.append(name)
    if len(set(authors)) != len(authors):
        raise PaperCollectionError("metadata authors contain duplicates")
    external = value["externalIds"]
    if not isinstance(external, Mapping) or any(key not in _KNOWN_EXTERNAL_IDS for key in external):
        raise PaperCollectionError("metadata externalIds are invalid")
    if identifier.startswith("doi:"):
        observed = external.get("DOI")
        matches = isinstance(observed, str) and observed.lower() == identifier[4:]
    else:
        observed = external.get("ArXiv")
        matches = isinstance(observed, str) and observed.lower() == identifier[6:]
    if not matches:
        raise PaperCollectionError("metadata identifier drifted from the requested paper")
    access = value["openAccessPdf"]
    if not isinstance(access, Mapping) or set(access) != {"url", "status", "license"}:
        raise PaperCollectionError("metadata openAccessPdf has missing or unknown fields")
    content_url = _https_url(access["url"], "metadata content URL")
    for name in ("status", "license"):
        item = access[name]
        if item is not None and (not isinstance(item, str) or len(item) > 128):
            raise PaperCollectionError(f"metadata openAccessPdf.{name} is invalid")
    return title, tuple(authors), content_url


def _arxiv_urls(identifier: str) -> tuple[str, str]:
    suffix = identifier[6:]
    encoded = _quote_component(suffix)
    return (
        f"https://export.arxiv.org/api/query?id_list={encoded}",
        f"https://export.arxiv.org/pdf/{encoded}",
    )


def _xml_text(element: ET.Element, name: str, *, maximum: int) -> str:
    if element.attrib or len(element) or element.text is None:
        raise PaperCollectionError(f"arXiv metadata {name} is structurally invalid")
    value = " ".join(element.text.split())
    if (
        not value
        or len(value) > maximum
        or any(ord(char) < 32 for char in value)
    ):
        raise PaperCollectionError(f"arXiv metadata {name} is invalid")
    return value


def _single_xml_child(entry: ET.Element, tag: str, name: str, *, maximum: int) -> str:
    values = entry.findall(tag)
    if len(values) != 1:
        raise PaperCollectionError(f"arXiv metadata must contain exactly one {name}")
    return _xml_text(values[0], name, maximum=maximum)


def _arxiv_metadata(value: bytes, identifier: str, media_type: str) -> tuple[str, tuple[str, ...]]:
    if media_type not in {"application/atom+xml", "application/xml", "text/xml"}:
        raise PaperCollectionError("arXiv metadata response must be Atom XML")
    try:
        text = value.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise PaperCollectionError("arXiv metadata is not strict UTF-8 XML") from exc
    if _XML_DECLARATION.search(text):
        raise PaperCollectionError("arXiv metadata must not contain DOCTYPE or ENTITY declarations")
    try:
        feed = ET.fromstring(text)
    except ET.ParseError as exc:
        raise PaperCollectionError("arXiv metadata is not well-formed XML") from exc
    if feed.tag != f"{{{_ATOM}}}feed" or feed.attrib:
        raise PaperCollectionError("arXiv metadata root is invalid")
    if any(child.tag not in _ARXIV_FEED_FIELDS for child in feed):
        raise PaperCollectionError("arXiv metadata feed contains an unknown field")
    entries = feed.findall(f"{{{_ATOM}}}entry")
    if len(entries) != 1:
        raise PaperCollectionError("arXiv metadata must contain exactly one entry")
    totals = feed.findall(f"{{{_OPENSEARCH}}}totalResults")
    if len(totals) > 1 or (totals and _xml_text(totals[0], "totalResults", maximum=16) != "1"):
        raise PaperCollectionError("arXiv metadata totalResults is invalid")

    entry = entries[0]
    if entry.attrib or any(child.tag not in _ARXIV_ENTRY_FIELDS for child in entry):
        raise PaperCollectionError("arXiv metadata entry contains an unknown or attributed field")
    observed_url = _single_xml_child(
        entry, f"{{{_ATOM}}}id", "entry id", maximum=256
    )
    observed = _ARXIV_ENTRY_ID.fullmatch(observed_url)
    if observed is None:
        raise PaperCollectionError("arXiv metadata entry id is invalid")
    requested_suffix = identifier[6:]
    observed_suffix = observed.group(1).lower()
    if "v" in requested_suffix:
        matches = observed_suffix == requested_suffix
    else:
        matches = observed_suffix == requested_suffix or re.fullmatch(
            re.escape(requested_suffix) + r"v[1-9]\d*", observed_suffix
        ) is not None
    if not matches:
        raise PaperCollectionError("arXiv metadata identifier drifted from the requested paper")

    title = _single_xml_child(entry, f"{{{_ATOM}}}title", "title", maximum=1000)
    author_elements = entry.findall(f"{{{_ATOM}}}author")
    if not 1 <= len(author_elements) <= MAX_AUTHORS:
        raise PaperCollectionError("arXiv metadata authors must be non-empty and bounded")
    authors: list[str] = []
    for author in author_elements:
        if author.attrib or any(
            child.tag not in {f"{{{_ATOM}}}name", f"{{{_ARXIV_XML}}}affiliation"}
            for child in author
        ):
            raise PaperCollectionError("arXiv metadata author contains an unknown field")
        authors.append(
            _single_xml_child(author, f"{{{_ATOM}}}name", "author name", maximum=256)
        )
    if len(set(authors)) != len(authors):
        raise PaperCollectionError("arXiv metadata authors contain duplicates")
    return title, tuple(authors)


def _extract(content: bytes, limits: PaperCollectorLimits) -> tuple[str, tuple[PaperExcerpt, ...]]:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PaperCollectionError("paper text is not valid UTF-8") from exc
    if any(ord(char) < 32 and char not in "\t\n\r\f" for char in text):
        raise PaperCollectionError("paper text contains binary control characters")
    excerpts: list[PaperExcerpt] = []
    if "\f" in text:
        parts = text.split("\f")
        locator_type = "page"
        located = ((str(index), part.strip()) for index, part in enumerate(parts, start=1))
    else:
        parts = re.split(r"(?:\r?\n)[ \t]*(?:\r?\n)+", text)
        locator_type = "paragraph"
        located = ((f"p{index}", part.strip()) for index, part in enumerate(parts, start=1))
    for locator, fragment in located:
        if not fragment:
            continue
        encoded = fragment.encode("utf-8")
        if len(encoded) > limits.max_excerpt_bytes:
            raise PaperCollectionError("paper excerpt exceeds the configured bound")
        excerpts.append(
            PaperExcerpt(locator_type, locator, fragment, hashlib.sha256(encoded).hexdigest())
        )
        if len(excerpts) > limits.max_excerpts:
            raise PaperCollectionError("paper has too many citable excerpts")
    if not excerpts:
        raise PaperCollectionError("paper text contains no citable page or paragraph locator")
    return text, tuple(excerpts)


def _pdf_excerpts(
    extraction: PDFExtraction,
    limits: PaperCollectorLimits,
) -> tuple[PaperExcerpt, ...]:
    if not isinstance(extraction, PDFExtraction):
        raise PaperCollectionError("PDF extractor returned an invalid result")
    excerpts: list[PaperExcerpt] = []
    for page in extraction.pages:
        fragment = page.text.strip()
        if not fragment:
            continue
        encoded = fragment.encode("utf-8")
        if len(encoded) > limits.max_excerpt_bytes:
            raise PaperCollectionError("paper excerpt exceeds the configured bound")
        excerpts.append(
            PaperExcerpt("page", str(page.page_number), fragment, hashlib.sha256(encoded).hexdigest())
        )
        if len(excerpts) > limits.max_excerpts:
            raise PaperCollectionError("paper has too many citable excerpts")
    if not excerpts:
        raise PaperCollectionError("PDF contains no citable extracted page text")
    return tuple(excerpts)


class PaperCollector:
    """Collect one exact paper identifier as an immutable citable text snapshot."""

    def __init__(
        self,
        research: Research,
        *,
        limits: PaperCollectorLimits = PaperCollectorLimits(),
        pdf_extractor: PDFExtractor | None = None,
    ) -> None:
        if not hasattr(research, "fetch"):
            raise TypeError("research must provide the ResearchBroker-compatible interface")
        if pdf_extractor is not None and not hasattr(pdf_extractor, "extract"):
            raise TypeError("pdf_extractor must implement PDFExtractor")
        self._research = research
        self._limits = limits
        self._pdf_extractor = pdf_extractor

    def collect(self, identifier: str) -> PaperSnapshot:
        canonical_id, provider_id = _identifier(identifier)
        if canonical_id.startswith("arxiv:"):
            metadata_url, content_url = _arxiv_urls(canonical_id)
        else:
            metadata_url = (
                "https://api.semanticscholar.org/graph/v1/paper/"
                f"{_quote_component(provider_id)}?fields={_FIELDS}"
            )
        metadata_response = _checked_artifact(
            self._research.fetch(metadata_url),
            metadata_url,
            maximum=self._limits.max_metadata_bytes,
            require_json=not canonical_id.startswith("arxiv:"),
        )
        if canonical_id.startswith("arxiv:"):
            title, authors = _arxiv_metadata(
                metadata_response.content,
                canonical_id,
                metadata_response.provenance.media_type,
            )
        else:
            title, authors, content_url = _metadata(_json(metadata_response.content), canonical_id)
        content_response = _checked_artifact(
            self._research.fetch(content_url),
            content_url,
            maximum=self._limits.max_content_bytes,
            require_json=False,
        )
        media_type = content_response.provenance.media_type
        if media_type == "application/pdf":
            if self._pdf_extractor is None:
                raise PaperCollectionError(
                    "PDF extraction is unavailable without an injected verified parser"
                )
            try:
                extraction = self._pdf_extractor.extract(
                    content_response.content,
                    expected_sha256=content_response.provenance.sha256,
                    expected_size=content_response.provenance.size_bytes,
                )
            except PDFExtractionError as exc:
                raise PaperCollectionError("sandbox PDF extraction failed") from exc
            if (
                extraction.source_sha256 != content_response.provenance.sha256
                or extraction.source_size_bytes != content_response.provenance.size_bytes
            ):
                raise PaperCollectionError("PDF extraction result does not bind fetched provenance")
            excerpts = _pdf_excerpts(extraction, self._limits)
        else:
            if content_response.content.startswith(b"%PDF-"):
                raise PaperCollectionError("PDF bytes require canonical application/pdf media type")
            if media_type != "text/plain":
                raise PaperCollectionError("paper content must be UTF-8 text/plain or verified PDF")
            _text, excerpts = _extract(content_response.content, self._limits)
        provenance = [
            {
                "source_url": content_response.provenance.final_url,
                "locator_type": item.locator_type,
                "locator": item.locator,
                "content_sha256": item.sha256,
            }
            for item in excerpts
        ]
        manifest = {
            "schema_version": 1,
            "kind": "paper",
            "source_url": content_response.provenance.final_url,
            "content_sha256": content_response.provenance.sha256,
            "size_bytes": content_response.provenance.size_bytes,
            "metadata": {
                "title": title,
                "authors": list(authors),
                "identifier": canonical_id,
                "provenance": provenance,
            },
        }
        artifact = validate_paper_import(manifest)
        return PaperSnapshot(
            canonical_id,
            title,
            authors,
            content_response.content,
            excerpts,
            metadata_response.provenance,
            content_response.provenance,
            artifact,
        )
