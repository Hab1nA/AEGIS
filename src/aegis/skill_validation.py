"""Side-effect-free static validation for declarative Skill v1 payloads."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from aegis.models import canonical_json
from aegis.research.imports import (
    ALLOWED_SKILL_PERMISSIONS,
    ResearchImportArtifact,
    ResearchImportKind,
    SkillImportMetadata,
    validate_skill_import,
)

_SHA256 = re.compile(r"[0-9a-f]{64}")
_DANGEROUS_ENTRY = re.compile(
    r"(?im)^\s*[\"']?(?:entrypoint|executable|installer|install_script)[\"']?\s*[:=]"
)


@dataclass(frozen=True, slots=True)
class SkillStaticEvidence:
    artifact_id: str
    content_sha256: str
    checks_sha256: str
    passed: bool
    violations: tuple[str, ...]
    evidence_id: str = ""

    def __post_init__(self) -> None:
        for name in ("artifact_id", "content_sha256", "checks_sha256"):
            value = getattr(self, name)
            if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
                raise ValueError(f"{name} must be a lowercase SHA-256 digest")
        if not isinstance(self.passed, bool):
            raise TypeError("passed must be a bool")
        if (
            not isinstance(self.violations, tuple)
            or any(
                not isinstance(item, str)
                or not item
                or item != item.strip()
                or len(item) > 500
                for item in self.violations
            )
        ):
            raise ValueError("violations must be bounded trimmed strings")
        if self.passed == bool(self.violations):
            raise ValueError("passed must be true exactly when violations is empty")
        expected = self.compute_evidence_id()
        if not self.evidence_id:
            object.__setattr__(self, "evidence_id", expected)
        elif self.evidence_id != expected:
            raise ValueError("evidence_id does not match static evidence")

    def compute_evidence_id(self) -> str:
        return hashlib.sha256(canonical_json(self.to_dict(include_evidence_id=False)).encode()).hexdigest()

    def to_dict(self, *, include_evidence_id: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "artifact_id": self.artifact_id,
            "content_sha256": self.content_sha256,
            "checks_sha256": self.checks_sha256,
            "passed": self.passed,
            "violations": list(self.violations),
        }
        if include_evidence_id:
            result["evidence_id"] = self.evidence_id
        return result


class SkillStaticValidator:
    """Validate opaque Skill v1 content without importing or executing it."""

    _CHECKS = (
        "artifact_identity",
        "content_identity",
        "utf8_text",
        "control_characters",
        "dependencies_empty",
        "allowed_permissions",
        "no_shebang",
        "no_script_entry",
    )

    def validate(self, artifact: object, content: object) -> SkillStaticEvidence:
        violations: list[str] = []
        artifact_id = getattr(artifact, "artifact_id", "0" * 64)
        content_sha256 = hashlib.sha256(content).hexdigest() if isinstance(content, bytes) else "0" * 64
        metadata: SkillImportMetadata | None = None
        if not isinstance(artifact, ResearchImportArtifact) or artifact.kind is not ResearchImportKind.SKILL:
            violations.append("artifact is not a skill import")
        else:
            try:
                rebuilt = validate_skill_import(artifact.to_dict(include_artifact_id=False))
            except (TypeError, ValueError):
                violations.append("artifact manifest is not canonical")
            else:
                if rebuilt != artifact or rebuilt.artifact_id != artifact.artifact_id:
                    violations.append("artifact identity hash mismatch")
            if isinstance(artifact.metadata, SkillImportMetadata):
                metadata = artifact.metadata
            else:
                violations.append("skill metadata has the wrong type")
        if not isinstance(content, bytes) or not content:
            violations.append("content must be non-empty bytes")
            text = None
        else:
            if isinstance(artifact, ResearchImportArtifact) and (
                content_sha256 != artifact.content_sha256 or len(content) != artifact.size_bytes
            ):
                violations.append("content identity hash or size mismatch")
            try:
                text = content.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                text = None
                violations.append("content is not strict UTF-8 text")
        if metadata is not None:
            if metadata.dependencies:
                violations.append("declarative Skill v1 dependencies must be empty")
            if not set(metadata.permissions) <= ALLOWED_SKILL_PERMISSIONS:
                violations.append("declarative Skill v1 permissions exceed the allowlist")
        if text is not None:
            if any(ord(character) < 32 and character not in "\t\n\r" for character in text):
                violations.append("content contains forbidden control characters")
            if text.startswith("#!"):
                violations.append("content must not contain a shebang")
            if _DANGEROUS_ENTRY.search(text):
                violations.append("content declares a dangerous script or executable entry")
        unique = tuple(dict.fromkeys(violations))
        checks_sha256 = hashlib.sha256(
            canonical_json({"checks": list(self._CHECKS)}).encode()
        ).hexdigest()
        return SkillStaticEvidence(
            artifact_id=artifact_id if isinstance(artifact_id, str) and _SHA256.fullmatch(artifact_id) else "0" * 64,
            content_sha256=content_sha256,
            checks_sha256=checks_sha256,
            passed=not unique,
            violations=unique,
        )
