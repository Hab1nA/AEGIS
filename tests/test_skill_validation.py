from __future__ import annotations

import hashlib
from dataclasses import replace

from aegis.research.imports import validate_skill_import
from aegis.skill_validation import SkillStaticValidator


def artifact_for(content: bytes, *, dependencies: list[dict[str, object]] | None = None):
    return validate_skill_import({
        "schema_version": 1,
        "kind": "skill",
        "source_url": "https://skills.example.org/reviewer/1.0.0/manifest.json",
        "content_sha256": hashlib.sha256(content).hexdigest(),
        "size_bytes": len(content),
        "metadata": {
            "name": "reviewer",
            "version": "1.0.0",
            "permissions": ["workspace.read", "sandbox.exec"],
            "dependencies": dependencies or [],
        },
    })


def test_accepts_utf8_declarative_text_with_code_examples() -> None:
    content = "# Review\n```python\nprint('example only')\n```\n".encode()
    evidence = SkillStaticValidator().validate(artifact_for(content), content)
    assert evidence.passed
    assert evidence.violations == ()
    assert evidence.evidence_id == evidence.compute_evidence_id()


def test_rejects_dependencies_controls_shebang_and_entrypoints() -> None:
    dependency = [{"name": "other", "version": "1.0.0", "sha256": "a" * 64}]
    cases = (
        (b"plain", artifact_for(b"plain", dependencies=dependency), "dependencies"),
        (b"text\x00", artifact_for(b"text\x00"), "control"),
        (b"#!/bin/sh\necho no", artifact_for(b"#!/bin/sh\necho no"), "shebang"),
        (b"entrypoint: run.py", artifact_for(b"entrypoint: run.py"), "executable"),
        (b"\xff", artifact_for(b"\xff"), "UTF-8"),
    )
    validator = SkillStaticValidator()
    for content, artifact, expected in cases:
        evidence = validator.validate(artifact, content)
        assert not evidence.passed
        assert expected in " ".join(evidence.violations)


def test_rejects_artifact_and_content_identity_forgery() -> None:
    content = b"safe"
    artifact = artifact_for(content)
    evidence = SkillStaticValidator().validate(replace(artifact, artifact_id="0" * 64), b"changed")
    assert not evidence.passed
    assert "identity" in " ".join(evidence.violations)
