"""Controlled research gateway with provenance and SSRF defenses."""

from .archive import ArchiveLimits, validate_archive
from .broker import ResearchBroker
from .http import (
    LoopbackHTTPFetcher,
    LoopbackProxyTLSTransport,
    PinnedHTTPSFetcher,
    SocketTLSTransport,
    WslLoopbackHTTPFetcher,
)
from .imports import (
    ALLOWED_SKILL_PERMISSIONS,
    GitHubImportMetadata,
    ImportedFile,
    PaperImportMetadata,
    PaperProvenance,
    ResearchImportArtifact,
    ResearchImportError,
    ResearchImportKind,
    SkillDependency,
    SkillImportMetadata,
    validate_github_import,
    validate_paper_import,
    validate_research_import,
    validate_skill_import,
)
from .interfaces import Fetcher, NullFetcher, NullSearchProvider, Resolver, SearchProvider
from .searxng import SearxNGSearchProvider
from .types import FetchResponse, Provenance, ResearchArtifact, SearchHit
from .url_security import (
    StaticResolver,
    SystemResolver,
    UrlPolicy,
    validate_loopback_url_target,
    validate_url,
    validate_url_target,
)

__all__ = [
    "ArchiveLimits",
    "Fetcher",
    "FetchResponse",
    "NullFetcher",
    "NullSearchProvider",
    "LoopbackHTTPFetcher",
    "LoopbackProxyTLSTransport",
    "PinnedHTTPSFetcher",
    "Provenance",
    "ResearchArtifact",
    "ResearchBroker",
    "Resolver",
    "SearchHit",
    "SearchProvider",
    "SearxNGSearchProvider",
    "SocketTLSTransport",
    "WslLoopbackHTTPFetcher",
    "ALLOWED_SKILL_PERMISSIONS",
    "GitHubImportMetadata",
    "ImportedFile",
    "PaperImportMetadata",
    "PaperProvenance",
    "ResearchImportArtifact",
    "ResearchImportError",
    "ResearchImportKind",
    "SkillDependency",
    "SkillImportMetadata",
    "StaticResolver",
    "SystemResolver",
    "UrlPolicy",
    "validate_archive",
    "validate_github_import",
    "validate_loopback_url_target",
    "validate_paper_import",
    "validate_research_import",
    "validate_skill_import",
    "validate_url",
    "validate_url_target",
]
