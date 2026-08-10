"""Durable quarantine registry for declarative skill candidates.

The registry stores opaque bytes and immutable manifests.  It deliberately has
no import, exec, extraction, dependency installation, or host-loading path.
Candidates leave the host registry only as deterministic tar archives intended
for ``SandboxBackend.stage_archive``.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import sqlite3
import tarfile
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from threading import RLock
from typing import Any, Mapping, cast

from aegis.models import canonical_json
from aegis.research.imports import (
    ALLOWED_SKILL_PERMISSIONS,
    ResearchImportArtifact,
    ResearchImportKind,
    SkillImportMetadata,
    validate_skill_import,
)
from aegis.sandbox.types import MAX_ARCHIVE_BYTES, validate_staging_archive

_SHA256 = re.compile(r"[0-9a-f]{64}")
_STREAM_GENESIS = "0" * 64


class SkillRegistryError(RuntimeError):
    """Base error for registry policy or integrity failures."""


class SkillRegistryIntegrityError(SkillRegistryError):
    """Raised when durable candidate or event data fails verification."""


class SkillVersionConflictError(SkillRegistryError):
    """Raised when a name/version pair is redefined with different content."""


class SkillCandidateState(StrEnum):
    CANDIDATE = "candidate"
    VALIDATED_PENDING = "validated_pending"
    CHAMPION = "champion"
    SUPERSEDED = "superseded"
    REVOKED = "revoked"


@dataclass(frozen=True, slots=True)
class SkillPromotionEvidence:
    """Hashes of externally verified reports; this class runs no evaluation."""

    artifact_id: str
    safety_verified: bool
    quality_verified: bool
    safety_report_sha256: str
    quality_report_sha256: str

    def __post_init__(self) -> None:
        for name in ("artifact_id", "safety_report_sha256", "quality_report_sha256"):
            value = getattr(self, name)
            if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
                raise ValueError(f"{name} must be a lowercase SHA-256 digest")
        if not isinstance(self.safety_verified, bool) or not isinstance(self.quality_verified, bool):
            raise TypeError("verified evidence flags must be booleans")

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact_id": self.artifact_id,
            "safety_verified": self.safety_verified,
            "quality_verified": self.quality_verified,
            "safety_report_sha256": self.safety_report_sha256,
            "quality_report_sha256": self.quality_report_sha256,
        }


@dataclass(frozen=True, slots=True)
class SkillEvaluationReport:
    report_id: str
    artifact_id: str
    baseline_artifact_id: str | None
    phase: str
    observations_sha256: str
    safety_verified: bool
    quality_verified: bool
    usage_verified: bool
    candidate_tokens: int
    baseline_tokens: int

    def __post_init__(self) -> None:
        for name in ("report_id", "artifact_id", "observations_sha256"):
            value = getattr(self, name)
            if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
                raise ValueError(f"{name} must be a lowercase SHA-256 digest")
        if self.baseline_artifact_id is not None and _SHA256.fullmatch(self.baseline_artifact_id) is None:
            raise ValueError("baseline_artifact_id must be null or a lowercase SHA-256 digest")
        if self.phase not in {"smoke", "full"}:
            raise ValueError("phase must be smoke or full")
        for name in ("safety_verified", "quality_verified", "usage_verified"):
            if not isinstance(getattr(self, name), bool):
                raise TypeError(f"{name} must be a bool")
        for name in ("candidate_tokens", "baseline_tokens"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 10**12:
                raise ValueError(f"{name} must be a bounded non-negative integer")
        if self.report_id != "0" * 64 and self.report_id != self.compute_report_id():
            raise ValueError("report_id does not match evaluation report")

    def compute_report_id(self) -> str:
        payload = self.to_dict()
        del payload["report_id"]
        return hashlib.sha256(canonical_json(payload).encode()).hexdigest()

    @classmethod
    def create(cls, **values: object) -> SkillEvaluationReport:
        provisional = cls(report_id="0" * 64, **values)  # type: ignore[arg-type]
        return cls(report_id=provisional.compute_report_id(), **values)  # type: ignore[arg-type]

    def to_dict(self) -> dict[str, object]:
        return {
            "report_id": self.report_id,
            "artifact_id": self.artifact_id,
            "baseline_artifact_id": self.baseline_artifact_id,
            "phase": self.phase,
            "observations_sha256": self.observations_sha256,
            "safety_verified": self.safety_verified,
            "quality_verified": self.quality_verified,
            "usage_verified": self.usage_verified,
            "candidate_tokens": self.candidate_tokens,
            "baseline_tokens": self.baseline_tokens,
        }


@dataclass(frozen=True, slots=True)
class SkillFunnelReport:
    report_id: str
    artifact_id: str
    baseline_artifact_id: str | None
    baseline_revision: str
    static_evidence_id: str
    smoke_report_id: str
    full_report_id: str
    promotable: bool

    def __post_init__(self) -> None:
        for name in (
            "report_id",
            "artifact_id",
            "static_evidence_id",
            "smoke_report_id",
            "full_report_id",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
                raise ValueError(f"{name} must be a lowercase SHA-256 digest")
        if _SHA256.fullmatch(self.baseline_revision) is None:
            raise ValueError("baseline_revision must be a lowercase SHA-256 digest")
        if self.baseline_artifact_id is not None and _SHA256.fullmatch(self.baseline_artifact_id) is None:
            raise ValueError("baseline_artifact_id must be null or a lowercase SHA-256 digest")
        if not isinstance(self.promotable, bool):
            raise TypeError("promotable must be a bool")
        if self.report_id != "0" * 64 and self.report_id != self.compute_report_id():
            raise ValueError("report_id does not match funnel report")

    def compute_report_id(self) -> str:
        payload = self.to_dict()
        del payload["report_id"]
        return hashlib.sha256(canonical_json(payload).encode()).hexdigest()

    @classmethod
    def create(cls, **values: object) -> SkillFunnelReport:
        provisional = cls(report_id="0" * 64, **values)  # type: ignore[arg-type]
        return cls(report_id=provisional.compute_report_id(), **values)  # type: ignore[arg-type]

    def to_dict(self) -> dict[str, object]:
        return {
            "report_id": self.report_id,
            "artifact_id": self.artifact_id,
            "baseline_artifact_id": self.baseline_artifact_id,
            "baseline_revision": self.baseline_revision,
            "static_evidence_id": self.static_evidence_id,
            "smoke_report_id": self.smoke_report_id,
            "full_report_id": self.full_report_id,
            "promotable": self.promotable,
        }


@dataclass(frozen=True, slots=True)
class SkillCandidate:
    artifact: ResearchImportArtifact
    state: SkillCandidateState
    registered_at: str

    @property
    def name(self) -> str:
        metadata = self.artifact.metadata
        if not isinstance(metadata, SkillImportMetadata):
            raise SkillRegistryIntegrityError("registered artifact is not a skill")
        return metadata.name

    @property
    def version(self) -> str:
        metadata = self.artifact.metadata
        if not isinstance(metadata, SkillImportMetadata):
            raise SkillRegistryIntegrityError("registered artifact is not a skill")
        return metadata.version


@dataclass(frozen=True, slots=True)
class SandboxSkillPackage:
    """Arguments consumable directly by ``SandboxBackend.stage_archive``."""

    archive_base64: str
    expected_digest: str
    size_bytes: int
    entries: int
    artifact_id: str


@dataclass(frozen=True, slots=True)
class _RegistrySnapshot:
    states: Mapping[str, SkillCandidateState]
    champions: Mapping[str, str]
    previously_promoted: frozenset[str]
    champion_revisions: Mapping[str, str]


class SkillRegistry:
    """SQLite-WAL registry with immutable candidates and hash-chained events."""

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS skill_artifacts (
        artifact_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        version TEXT NOT NULL,
        artifact_json TEXT NOT NULL,
        content BLOB NOT NULL,
        registered_at TEXT NOT NULL,
        UNIQUE(name, version)
    );
    CREATE TABLE IF NOT EXISTS skill_events (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL,
        payload TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        event_hash TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS skill_static_evidence (
        evidence_id TEXT PRIMARY KEY,
        artifact_id TEXT NOT NULL UNIQUE,
        evidence_json TEXT NOT NULL,
        passed INTEGER NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS skill_evaluation_reports (
        report_id TEXT PRIMARY KEY,
        artifact_id TEXT NOT NULL,
        phase TEXT NOT NULL,
        report_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(artifact_id, phase)
    );
    CREATE TABLE IF NOT EXISTS skill_funnel_reports (
        report_id TEXT PRIMARY KEY,
        artifact_id TEXT NOT NULL UNIQUE,
        report_json TEXT NOT NULL,
        promotable INTEGER NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS skill_artifacts_no_update
        BEFORE UPDATE ON skill_artifacts BEGIN SELECT RAISE(ABORT, 'skill artifacts are immutable'); END;
    CREATE TRIGGER IF NOT EXISTS skill_artifacts_no_delete
        BEFORE DELETE ON skill_artifacts BEGIN SELECT RAISE(ABORT, 'skill artifacts are immutable'); END;
    CREATE TRIGGER IF NOT EXISTS skill_events_no_update
        BEFORE UPDATE ON skill_events BEGIN SELECT RAISE(ABORT, 'skill events are immutable'); END;
    CREATE TRIGGER IF NOT EXISTS skill_events_no_delete
        BEFORE DELETE ON skill_events BEGIN SELECT RAISE(ABORT, 'skill events are immutable'); END;
    CREATE TRIGGER IF NOT EXISTS skill_static_evidence_no_update
        BEFORE UPDATE ON skill_static_evidence BEGIN SELECT RAISE(ABORT, 'skill static evidence is immutable'); END;
    CREATE TRIGGER IF NOT EXISTS skill_static_evidence_no_delete
        BEFORE DELETE ON skill_static_evidence BEGIN SELECT RAISE(ABORT, 'skill static evidence is immutable'); END;
    CREATE TRIGGER IF NOT EXISTS skill_evaluation_reports_no_update
        BEFORE UPDATE ON skill_evaluation_reports BEGIN SELECT RAISE(ABORT, 'skill evaluation reports are immutable'); END;
    CREATE TRIGGER IF NOT EXISTS skill_evaluation_reports_no_delete
        BEFORE DELETE ON skill_evaluation_reports BEGIN SELECT RAISE(ABORT, 'skill evaluation reports are immutable'); END;
    CREATE TRIGGER IF NOT EXISTS skill_funnel_reports_no_update
        BEFORE UPDATE ON skill_funnel_reports BEGIN SELECT RAISE(ABORT, 'skill funnel reports are immutable'); END;
    CREATE TRIGGER IF NOT EXISTS skill_funnel_reports_no_delete
        BEFORE DELETE ON skill_funnel_reports BEGIN SELECT RAISE(ABORT, 'skill funnel reports are immutable'); END;
    """

    def __init__(
        self,
        db_path: str | Path,
        *,
        permission_ceiling: frozenset[str] = ALLOWED_SKILL_PERMISSIONS,
    ) -> None:
        if not isinstance(permission_ceiling, frozenset) or any(
            not isinstance(item, str) for item in permission_ceiling
        ):
            raise TypeError("permission_ceiling must be a frozenset of strings")
        if not permission_ceiling <= ALLOWED_SKILL_PERMISSIONS:
            raise ValueError("permission_ceiling may only narrow the research import permission set")
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.permission_ceiling = permission_ceiling
        self._lock = RLock()
        self._closed = False
        self._connection = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._connection.execute("PRAGMA busy_timeout=5000")
        self._connection.executescript(self._SCHEMA)
        try:
            self._snapshot()
        except BaseException:
            self._connection.close()
            self._closed = True
            raise

    def __enter__(self) -> SkillRegistry:
        self._ensure_open()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    def _ensure_open(self) -> None:
        if self._closed:
            raise SkillRegistryError("skill registry is closed")

    @staticmethod
    def _validated_artifact(artifact: object, content: object) -> ResearchImportArtifact:
        if not isinstance(artifact, ResearchImportArtifact) or artifact.kind is not ResearchImportKind.SKILL:
            raise SkillRegistryError("only validated skill ResearchImportArtifact values may be registered")
        if not isinstance(content, bytes) or not content:
            raise SkillRegistryError("skill content must be non-empty immutable bytes")
        try:
            expected = validate_skill_import(artifact.to_dict(include_artifact_id=False))
        except (TypeError, ValueError) as exc:
            raise SkillRegistryError("skill artifact failed strict manifest revalidation") from exc
        if expected != artifact or expected.artifact_id != artifact.artifact_id:
            raise SkillRegistryError("skill artifact identity does not match its manifest")
        if hashlib.sha256(content).hexdigest() != artifact.content_sha256 or len(content) != artifact.size_bytes:
            raise SkillRegistryError("skill content does not match artifact hash and size")
        metadata = artifact.metadata
        if not isinstance(metadata, SkillImportMetadata):
            raise SkillRegistryError("skill artifact metadata has the wrong type")
        return artifact

    @staticmethod
    def _event_hash(event_type: str, payload: Mapping[str, Any], previous_hash: str) -> str:
        material = {"event_type": event_type, "payload": payload, "previous_hash": previous_hash}
        return hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()

    def _append_event(self, event_type: str, payload: Mapping[str, Any]) -> None:
        row = self._connection.execute(
            "SELECT event_hash FROM skill_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous_hash = _STREAM_GENESIS if row is None else str(row["event_hash"])
        event_hash = self._event_hash(event_type, payload, previous_hash)
        self._connection.execute(
            "INSERT INTO skill_events(event_type,payload,previous_hash,event_hash,created_at) "
            "VALUES(?,?,?,?,?)",
            (
                event_type,
                canonical_json(payload),
                previous_hash,
                event_hash,
                datetime.now(timezone.utc).isoformat(),
            ),
        )

    def _verified_reports(
        self, known: set[str]
    ) -> tuple[dict[str, object], dict[str, SkillEvaluationReport], dict[str, SkillFunnelReport]]:
        from aegis.skill_validation import SkillStaticEvidence

        static: dict[str, object] = {}
        for row in self._connection.execute(
            "SELECT evidence_id,artifact_id,evidence_json,passed FROM skill_static_evidence ORDER BY rowid"
        ).fetchall():
            try:
                raw = json.loads(row["evidence_json"])
                if not isinstance(raw, dict) or set(raw) != {
                    "evidence_id", "artifact_id", "content_sha256", "checks_sha256", "passed", "violations"
                } or not isinstance(raw["violations"], list):
                    raise ValueError
                evidence = SkillStaticEvidence(
                    evidence_id=raw["evidence_id"], artifact_id=raw["artifact_id"],
                    content_sha256=raw["content_sha256"], checks_sha256=raw["checks_sha256"],
                    passed=raw["passed"], violations=tuple(raw["violations"]),
                )
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise SkillRegistryIntegrityError("durable static evidence is invalid") from exc
            if (
                evidence.artifact_id not in known
                or evidence.evidence_id != row["evidence_id"]
                or evidence.artifact_id != row["artifact_id"]
                or int(evidence.passed) != int(row["passed"])
                or evidence.artifact_id in static
            ):
                raise SkillRegistryIntegrityError("durable static evidence columns disagree")
            static[evidence.artifact_id] = evidence

        evaluations: dict[str, SkillEvaluationReport] = {}
        for row in self._connection.execute(
            "SELECT report_id,artifact_id,phase,report_json FROM skill_evaluation_reports ORDER BY rowid"
        ).fetchall():
            try:
                raw = json.loads(row["report_json"])
                report = SkillEvaluationReport(**raw)
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise SkillRegistryIntegrityError("durable skill evaluation report is invalid") from exc
            if (
                report.artifact_id not in known
                or report.report_id != row["report_id"]
                or report.artifact_id != row["artifact_id"]
                or report.phase != row["phase"]
                or report.report_id in evaluations
            ):
                raise SkillRegistryIntegrityError("durable evaluation report columns disagree")
            evaluations[report.report_id] = report

        funnels: dict[str, SkillFunnelReport] = {}
        for row in self._connection.execute(
            "SELECT report_id,artifact_id,report_json,promotable FROM skill_funnel_reports ORDER BY rowid"
        ).fetchall():
            try:
                raw = json.loads(row["report_json"])
                funnel = SkillFunnelReport(**raw)
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise SkillRegistryIntegrityError("durable skill funnel report is invalid") from exc
            if (
                funnel.artifact_id not in known
                or funnel.report_id != row["report_id"]
                or funnel.artifact_id != row["artifact_id"]
                or int(funnel.promotable) != int(row["promotable"])
                or funnel.report_id in funnels
            ):
                raise SkillRegistryIntegrityError("durable funnel report columns disagree")
            static_item = static.get(funnel.artifact_id)
            smoke = evaluations.get(funnel.smoke_report_id)
            full = evaluations.get(funnel.full_report_id)
            if (
                static_item is None
                or getattr(static_item, "evidence_id") != funnel.static_evidence_id
                or smoke is None
                or full is None
                or smoke.phase != "smoke"
                or full.phase != "full"
                or smoke.artifact_id != funnel.artifact_id
                or full.artifact_id != funnel.artifact_id
                or smoke.baseline_artifact_id != funnel.baseline_artifact_id
                or full.baseline_artifact_id != funnel.baseline_artifact_id
            ):
                raise SkillRegistryIntegrityError("funnel report references inconsistent evidence")
            expected_promotable = bool(
                getattr(static_item, "passed")
                and smoke.safety_verified and smoke.quality_verified and smoke.usage_verified
                and full.safety_verified and full.quality_verified and full.usage_verified
            )
            if funnel.promotable is not expected_promotable:
                raise SkillRegistryIntegrityError("funnel promotable decision disagrees with evidence")
            funnels[funnel.report_id] = funnel
        return static, evaluations, funnels

    def _snapshot(self) -> _RegistrySnapshot:
        self._ensure_open()
        artifact_rows = self._connection.execute(
            "SELECT artifact_id,name,version,artifact_json,content FROM skill_artifacts ORDER BY rowid"
        ).fetchall()
        known: dict[str, tuple[str, str]] = {}
        for row in artifact_rows:
            artifact = self._artifact_from_row(row)
            metadata = artifact.metadata
            if not isinstance(metadata, SkillImportMetadata):
                raise SkillRegistryIntegrityError("durable artifact metadata is not a skill")
            identity = (metadata.name, metadata.version)
            if artifact.artifact_id in known or identity in known.values():
                raise SkillRegistryIntegrityError("duplicate durable skill identity")
            known[artifact.artifact_id] = identity

        static_reports, _, funnel_reports = self._verified_reports(set(known))

        states: dict[str, SkillCandidateState] = {}
        champions: dict[str, str] = {}
        champion_revisions: dict[str, str] = {}
        promoted: set[str] = set()
        validated_events: set[str] = set()
        previous_hash = _STREAM_GENESIS
        rows = self._connection.execute(
            "SELECT sequence,event_type,payload,previous_hash,event_hash FROM skill_events ORDER BY sequence"
        ).fetchall()
        expected_sequence = 1
        for row in rows:
            if int(row["sequence"]) != expected_sequence:
                raise SkillRegistryIntegrityError("skill event sequence is not contiguous")
            expected_sequence += 1
            try:
                payload = json.loads(row["payload"])
            except (TypeError, json.JSONDecodeError) as exc:
                raise SkillRegistryIntegrityError("skill event payload is invalid JSON") from exc
            if not isinstance(payload, dict):
                raise SkillRegistryIntegrityError("skill event payload is not an object")
            event_type = str(row["event_type"])
            if row["previous_hash"] != previous_hash or row["event_hash"] != self._event_hash(
                event_type, payload, previous_hash
            ):
                raise SkillRegistryIntegrityError("skill event hash chain is invalid")
            previous_hash = str(row["event_hash"])
            current_event_hash = previous_hash
            artifact_id = payload.get("artifact_id")
            if not isinstance(artifact_id, str) or artifact_id not in known:
                raise SkillRegistryIntegrityError("skill event references an unknown artifact")
            name, _ = known[artifact_id]
            if event_type == "candidate_registered":
                if set(payload) != {"artifact_id"}:
                    raise SkillRegistryIntegrityError("candidate registration event schema is invalid")
                if artifact_id in states:
                    raise SkillRegistryIntegrityError("skill candidate was registered twice")
                states[artifact_id] = SkillCandidateState.CANDIDATE
            elif event_type == "candidate_static_validated":
                if set(payload) != {"artifact_id", "evidence_id"}:
                    raise SkillRegistryIntegrityError("candidate validation event schema is invalid")
                evidence = static_reports.get(artifact_id)
                if (
                    states.get(artifact_id) is not SkillCandidateState.CANDIDATE
                    or evidence is None
                    or not getattr(evidence, "passed")
                    or payload["evidence_id"] != getattr(evidence, "evidence_id")
                    or artifact_id in validated_events
                ):
                    raise SkillRegistryIntegrityError("candidate validation event disagrees with evidence")
                states[artifact_id] = SkillCandidateState.VALIDATED_PENDING
                validated_events.add(artifact_id)
            elif event_type in {"candidate_promoted", "champion_rolled_back"}:
                expected_fields = (
                    {"artifact_id", "previous_champion_id", "evidence"}
                    if event_type == "candidate_promoted"
                    else {"artifact_id", "previous_champion_id", "reason"}
                )
                if set(payload) != expected_fields:
                    raise SkillRegistryIntegrityError("skill champion event schema is invalid")
                if artifact_id not in states or states[artifact_id] is SkillCandidateState.REVOKED:
                    raise SkillRegistryIntegrityError("invalid skill promotion target")
                if event_type == "candidate_promoted":
                    raw_evidence = payload["evidence"]
                    if not isinstance(raw_evidence, dict):
                        raise SkillRegistryIntegrityError("persisted promotion evidence is invalid")
                    try:
                        evidence = SkillPromotionEvidence(**raw_evidence)
                    except (TypeError, ValueError) as exc:
                        raise SkillRegistryIntegrityError("persisted promotion evidence is invalid") from exc
                    if (
                        evidence.artifact_id != artifact_id
                        or not evidence.safety_verified
                        or not evidence.quality_verified
                    ):
                        raise SkillRegistryIntegrityError("persisted promotion evidence is unverified")
                else:
                    reason = payload["reason"]
                    if (
                        not isinstance(reason, str)
                        or not reason.strip()
                        or reason != reason.strip()
                        or len(reason) > 2_000
                    ):
                        raise SkillRegistryIntegrityError("persisted rollback reason is invalid")
                    if artifact_id not in promoted:
                        raise SkillRegistryIntegrityError(
                            "persisted rollback target was never previously promoted"
                        )
                prior = champions.get(name)
                declared_prior = payload.get("previous_champion_id")
                if declared_prior != prior:
                    raise SkillRegistryIntegrityError("skill event has the wrong prior champion")
                if prior is not None and prior != artifact_id:
                    states[prior] = SkillCandidateState.SUPERSEDED
                states[artifact_id] = SkillCandidateState.CHAMPION
                champions[name] = artifact_id
                champion_revisions[name] = current_event_hash
                promoted.add(artifact_id)
            elif event_type == "candidate_promoted_evaluated":
                if set(payload) != {"artifact_id", "previous_champion_id", "funnel_report_id"}:
                    raise SkillRegistryIntegrityError("evaluated promotion event schema is invalid")
                report = funnel_reports.get(payload["funnel_report_id"])
                prior = champions.get(name)
                if (
                    states.get(artifact_id) is not SkillCandidateState.VALIDATED_PENDING
                    or report is None
                    or report.artifact_id != artifact_id
                    or not report.promotable
                    or report.baseline_artifact_id != prior
                    or report.baseline_revision != champion_revisions.get(name, _STREAM_GENESIS)
                    or payload["previous_champion_id"] != prior
                ):
                    raise SkillRegistryIntegrityError("evaluated promotion event disagrees with evidence")
                if prior is not None and prior != artifact_id:
                    states[prior] = SkillCandidateState.SUPERSEDED
                states[artifact_id] = SkillCandidateState.CHAMPION
                champions[name] = artifact_id
                champion_revisions[name] = current_event_hash
                promoted.add(artifact_id)
            elif event_type == "candidate_revoked":
                if set(payload) != {"artifact_id", "reason"}:
                    raise SkillRegistryIntegrityError("skill revocation event schema is invalid")
                reason = payload["reason"]
                if (
                    not isinstance(reason, str)
                    or not reason.strip()
                    or reason != reason.strip()
                    or len(reason) > 2_000
                ):
                    raise SkillRegistryIntegrityError("persisted revocation reason is invalid")
                if artifact_id not in states or states[artifact_id] is SkillCandidateState.REVOKED:
                    raise SkillRegistryIntegrityError("invalid skill revocation target")
                states[artifact_id] = SkillCandidateState.REVOKED
                if champions.get(name) == artifact_id:
                    del champions[name]
                    champion_revisions[name] = current_event_hash
            else:
                raise SkillRegistryIntegrityError(f"unknown skill event type: {event_type}")
        if set(states) != set(known):
            raise SkillRegistryIntegrityError("durable skill artifact lacks registration event")
        passed_static = {
            artifact_id for artifact_id, evidence in static_reports.items() if getattr(evidence, "passed")
        }
        if passed_static != validated_events:
            raise SkillRegistryIntegrityError("passed static evidence lacks its validation event")
        return _RegistrySnapshot(states, champions, frozenset(promoted), champion_revisions)

    @staticmethod
    def _artifact_from_row(row: sqlite3.Row) -> ResearchImportArtifact:
        try:
            raw = json.loads(row["artifact_json"])
            artifact = validate_skill_import(raw)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise SkillRegistryIntegrityError("durable skill manifest failed validation") from exc
        content = row["content"]
        if not isinstance(content, bytes):
            raise SkillRegistryIntegrityError("durable skill content is not bytes")
        if (
            artifact.artifact_id != row["artifact_id"]
            or hashlib.sha256(content).hexdigest() != artifact.content_sha256
            or len(content) != artifact.size_bytes
        ):
            raise SkillRegistryIntegrityError("durable skill content or identity is corrupted")
        metadata = artifact.metadata
        if (
            not isinstance(metadata, SkillImportMetadata)
            or metadata.name != row["name"]
            or metadata.version != row["version"]
        ):
            raise SkillRegistryIntegrityError("durable skill name/version is corrupted")
        return artifact

    def register_candidate(self, artifact: ResearchImportArtifact, content: bytes) -> SkillCandidate:
        artifact = self._validated_artifact(artifact, content)
        metadata = artifact.metadata
        if not isinstance(metadata, SkillImportMetadata):
            raise SkillRegistryError("skill artifact metadata has the wrong type")
        if not set(metadata.permissions) <= self.permission_ceiling:
            raise SkillRegistryError("skill permissions exceed this registry's narrowed ceiling")
        registered_at = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._ensure_open()
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                existing = self._connection.execute(
                    "SELECT artifact_id,registered_at FROM skill_artifacts WHERE name=? AND version=?",
                    (metadata.name, metadata.version),
                ).fetchone()
                if existing is not None:
                    if existing["artifact_id"] != artifact.artifact_id:
                        raise SkillVersionConflictError(
                            "a skill name/version pair cannot be redefined with different content"
                        )
                    self._connection.execute("COMMIT")
                    snapshot = self._snapshot()
                    return SkillCandidate(
                        artifact, snapshot.states[artifact.artifact_id], str(existing["registered_at"])
                    )
                self._connection.execute(
                    "INSERT INTO skill_artifacts(artifact_id,name,version,artifact_json,content,registered_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (
                        artifact.artifact_id,
                        metadata.name,
                        metadata.version,
                        canonical_json(artifact.to_dict(include_artifact_id=False)),
                        content,
                        registered_at,
                    ),
                )
                self._append_event("candidate_registered", {"artifact_id": artifact.artifact_id})
                self._connection.execute("COMMIT")
            except BaseException:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise
            return SkillCandidate(artifact, SkillCandidateState.CANDIDATE, registered_at)

    def _candidate_row(self, name: str, version: str) -> sqlite3.Row:
        row = self._connection.execute(
            "SELECT artifact_id,name,version,artifact_json,content,registered_at "
            "FROM skill_artifacts WHERE name=? AND version=?",
            (name, version),
        ).fetchone()
        if row is None:
            raise SkillRegistryError("unknown skill candidate")
        return cast(sqlite3.Row, row)

    def candidate(self, name: str, version: str) -> SkillCandidate:
        with self._lock:
            self._ensure_open()
            snapshot = self._snapshot()
            row = self._candidate_row(name, version)
            artifact = self._artifact_from_row(row)
            return SkillCandidate(artifact, snapshot.states[artifact.artifact_id], str(row["registered_at"]))

    def candidates(self, name: str | None = None) -> tuple[SkillCandidate, ...]:
        with self._lock:
            self._ensure_open()
            snapshot = self._snapshot()
            sql = (
                "SELECT artifact_id,name,version,artifact_json,content,registered_at "
                "FROM skill_artifacts"
            )
            parameters: tuple[str, ...] = ()
            if name is not None:
                sql += " WHERE name=?"
                parameters = (name,)
            sql += " ORDER BY name,version,artifact_id"
            result: list[SkillCandidate] = []
            for row in self._connection.execute(sql, parameters).fetchall():
                artifact = self._artifact_from_row(row)
                result.append(
                    SkillCandidate(artifact, snapshot.states[artifact.artifact_id], str(row["registered_at"]))
                )
            return tuple(result)

    def champion(self, name: str) -> SkillCandidate | None:
        with self._lock:
            self._ensure_open()
            snapshot = self._snapshot()
            artifact_id = snapshot.champions.get(name)
            if artifact_id is None:
                return None
            row = self._connection.execute(
                "SELECT artifact_id,name,version,artifact_json,content,registered_at "
                "FROM skill_artifacts WHERE artifact_id=?",
                (artifact_id,),
            ).fetchone()
            if row is None:
                raise SkillRegistryIntegrityError("champion artifact is missing")
            artifact = self._artifact_from_row(row)
            return SkillCandidate(artifact, SkillCandidateState.CHAMPION, str(row["registered_at"]))

    def champion_revision(self, name: str) -> str:
        with self._lock:
            return self._snapshot().champion_revisions.get(name, _STREAM_GENESIS)

    def candidate_by_artifact_id(self, artifact_id: str) -> SkillCandidate:
        with self._lock:
            snapshot = self._snapshot()
            row = self._connection.execute(
                "SELECT artifact_id,name,version,artifact_json,content,registered_at "
                "FROM skill_artifacts WHERE artifact_id=?", (artifact_id,),
            ).fetchone()
            if row is None:
                raise SkillRegistryError("unknown skill artifact")
            artifact = self._artifact_from_row(row)
            return SkillCandidate(artifact, snapshot.states[artifact_id], str(row["registered_at"]))

    def pending_validated(self) -> tuple[SkillCandidate, ...]:
        return tuple(item for item in self.candidates() if item.state is SkillCandidateState.VALIDATED_PENDING)

    def record_static_evidence(self, evidence: object) -> SkillCandidate:
        from aegis.skill_validation import SkillStaticEvidence

        if not isinstance(evidence, SkillStaticEvidence):
            raise SkillRegistryError("static evidence must be trusted SkillStaticEvidence")
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                snapshot = self._snapshot()
                row = self._connection.execute(
                    "SELECT artifact_id,name,version,artifact_json,content,registered_at "
                    "FROM skill_artifacts WHERE artifact_id=?", (evidence.artifact_id,),
                ).fetchone()
                if row is None:
                    raise SkillRegistryError("static evidence targets an unknown artifact")
                artifact = self._artifact_from_row(row)
                if artifact.content_sha256 != evidence.content_sha256:
                    raise SkillRegistryError("static evidence content identity does not match artifact")
                if snapshot.states[artifact.artifact_id] is not SkillCandidateState.CANDIDATE:
                    raise SkillRegistryError("static evidence requires an unvalidated candidate")
                self._connection.execute(
                    "INSERT INTO skill_static_evidence(evidence_id,artifact_id,evidence_json,passed,created_at) "
                    "VALUES(?,?,?,?,?)",
                    (evidence.evidence_id, artifact.artifact_id, canonical_json(evidence.to_dict()),
                     int(evidence.passed), datetime.now(timezone.utc).isoformat()),
                )
                if evidence.passed:
                    self._append_event("candidate_static_validated", {
                        "artifact_id": artifact.artifact_id, "evidence_id": evidence.evidence_id,
                    })
                self._connection.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise SkillRegistryError("static evidence is already recorded") from exc
            except BaseException:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise
            state = SkillCandidateState.VALIDATED_PENDING if evidence.passed else SkillCandidateState.CANDIDATE
            return SkillCandidate(artifact, state, str(row["registered_at"]))

    def record_evaluation_report(self, report: SkillEvaluationReport) -> SkillEvaluationReport:
        if not isinstance(report, SkillEvaluationReport) or report.report_id == "0" * 64:
            raise SkillRegistryError("evaluation report must have a verified content identity")
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                snapshot = self._snapshot()
                if snapshot.states.get(report.artifact_id) is not SkillCandidateState.VALIDATED_PENDING:
                    raise SkillRegistryError("evaluation requires a validated pending candidate")
                if report.baseline_artifact_id is not None and report.baseline_artifact_id not in snapshot.states:
                    raise SkillRegistryError("evaluation baseline is unknown")
                self._connection.execute(
                    "INSERT INTO skill_evaluation_reports(report_id,artifact_id,phase,report_json,created_at) "
                    "VALUES(?,?,?,?,?)", (report.report_id, report.artifact_id, report.phase,
                    canonical_json(report.to_dict()), datetime.now(timezone.utc).isoformat()),
                )
                self._connection.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise SkillRegistryError("evaluation report conflicts with durable evidence") from exc
            except BaseException:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise
        return report

    def record_funnel_report(self, report: SkillFunnelReport) -> SkillFunnelReport:
        if not isinstance(report, SkillFunnelReport) or report.report_id == "0" * 64:
            raise SkillRegistryError("funnel report must have a verified content identity")
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                snapshot = self._snapshot()
                if snapshot.states.get(report.artifact_id) is not SkillCandidateState.VALIDATED_PENDING:
                    raise SkillRegistryError("funnel report requires a validated pending candidate")
                self._connection.execute(
                    "INSERT INTO skill_funnel_reports(report_id,artifact_id,report_json,promotable,created_at) "
                    "VALUES(?,?,?,?,?)", (report.report_id, report.artifact_id,
                    canonical_json(report.to_dict()), int(report.promotable), datetime.now(timezone.utc).isoformat()),
                )
                self._verified_reports(set(snapshot.states))
                self._connection.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise SkillRegistryError("funnel report conflicts with durable evidence") from exc
            except BaseException:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise
        return report

    def promote_evaluated(
        self, *, artifact_id: str, funnel_report_id: str,
        expected_champion_id: str | None, expected_champion_revision: str,
    ) -> SkillCandidate:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                snapshot = self._snapshot()
                row = self._connection.execute(
                    "SELECT artifact_id,name,version,artifact_json,content,registered_at "
                    "FROM skill_artifacts WHERE artifact_id=?", (artifact_id,),
                ).fetchone()
                if row is None:
                    raise SkillRegistryError("unknown skill artifact")
                artifact = self._artifact_from_row(row)
                metadata = cast(SkillImportMetadata, artifact.metadata)
                current = snapshot.champions.get(metadata.name)
                revision = snapshot.champion_revisions.get(metadata.name, _STREAM_GENESIS)
                if current != expected_champion_id or revision != expected_champion_revision:
                    raise SkillRegistryError("champion changed since evaluation was sealed")
                _, _, funnels = self._verified_reports(set(snapshot.states))
                report = funnels.get(funnel_report_id)
                if (
                    report is None or report.artifact_id != artifact_id or not report.promotable
                    or report.baseline_artifact_id != current or report.baseline_revision != revision
                    or snapshot.states.get(artifact_id) is not SkillCandidateState.VALIDATED_PENDING
                ):
                    raise SkillRegistryError("funnel report does not authorize this promotion")
                self._append_event("candidate_promoted_evaluated", {
                    "artifact_id": artifact_id, "previous_champion_id": current,
                    "funnel_report_id": funnel_report_id,
                })
                self._connection.execute("COMMIT")
            except BaseException:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise
            return SkillCandidate(artifact, SkillCandidateState.CHAMPION, str(row["registered_at"]))

    @staticmethod
    def _check_evidence(evidence: object, artifact_id: str) -> SkillPromotionEvidence:
        if not isinstance(evidence, SkillPromotionEvidence):
            raise SkillRegistryError("promotion requires explicit external safety and quality evidence")
        if evidence.artifact_id != artifact_id:
            raise SkillRegistryError("promotion evidence targets a different artifact")
        if not evidence.safety_verified or not evidence.quality_verified:
            raise SkillRegistryError("promotion requires verified safety and quality evidence")
        return evidence

    def promote(self, name: str, version: str, evidence: SkillPromotionEvidence) -> SkillCandidate:
        with self._lock:
            self._ensure_open()
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                snapshot = self._snapshot()
                row = self._candidate_row(name, version)
                artifact = self._artifact_from_row(row)
                self._check_evidence(evidence, artifact.artifact_id)
                state = snapshot.states[artifact.artifact_id]
                if state is SkillCandidateState.REVOKED:
                    raise SkillRegistryError("revoked skill candidates cannot be promoted")
                if state is SkillCandidateState.CHAMPION:
                    raise SkillRegistryError("skill candidate is already champion")
                previous = snapshot.champions.get(name)
                self._append_event(
                    "candidate_promoted",
                    {
                        "artifact_id": artifact.artifact_id,
                        "previous_champion_id": previous,
                        "evidence": evidence.to_dict(),
                    },
                )
                self._connection.execute("COMMIT")
            except BaseException:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise
            return SkillCandidate(artifact, SkillCandidateState.CHAMPION, str(row["registered_at"]))

    def revoke(self, name: str, version: str, reason: str) -> SkillCandidate:
        if not isinstance(reason, str) or not reason.strip() or reason != reason.strip() or len(reason) > 2_000:
            raise SkillRegistryError("revocation reason must be bounded, trimmed text")
        with self._lock:
            self._ensure_open()
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                snapshot = self._snapshot()
                row = self._candidate_row(name, version)
                artifact = self._artifact_from_row(row)
                if snapshot.states[artifact.artifact_id] is SkillCandidateState.REVOKED:
                    raise SkillRegistryError("skill candidate is already revoked")
                self._append_event(
                    "candidate_revoked", {"artifact_id": artifact.artifact_id, "reason": reason}
                )
                self._connection.execute("COMMIT")
            except BaseException:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise
            return SkillCandidate(artifact, SkillCandidateState.REVOKED, str(row["registered_at"]))

    def rollback(self, name: str, version: str, reason: str) -> SkillCandidate:
        if not isinstance(reason, str) or not reason.strip() or reason != reason.strip() or len(reason) > 2_000:
            raise SkillRegistryError("rollback reason must be bounded, trimmed text")
        with self._lock:
            self._ensure_open()
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                snapshot = self._snapshot()
                row = self._candidate_row(name, version)
                artifact = self._artifact_from_row(row)
                if artifact.artifact_id not in snapshot.previously_promoted:
                    raise SkillRegistryError("rollback target must be a previously promoted skill")
                if snapshot.states[artifact.artifact_id] is SkillCandidateState.REVOKED:
                    raise SkillRegistryError("rollback target has been revoked")
                previous = snapshot.champions.get(name)
                if previous == artifact.artifact_id:
                    raise SkillRegistryError("rollback target is already champion")
                self._append_event(
                    "champion_rolled_back",
                    {
                        "artifact_id": artifact.artifact_id,
                        "previous_champion_id": previous,
                        "reason": reason,
                    },
                )
                self._connection.execute("COMMIT")
            except BaseException:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise
            return SkillCandidate(artifact, SkillCandidateState.CHAMPION, str(row["registered_at"]))

    @staticmethod
    def _tar_entry(archive: tarfile.TarFile, name: str, content: bytes) -> None:
        info = tarfile.TarInfo(name)
        info.size = len(content)
        info.mode = 0o444
        info.mtime = 0
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        archive.addfile(info, io.BytesIO(content))

    def sandbox_package(self, name: str, version: str) -> SandboxSkillPackage:
        """Build a deterministic opaque package for sandbox-only inspection/evaluation."""
        with self._lock:
            self._ensure_open()
            snapshot = self._snapshot()
            row = self._candidate_row(name, version)
            artifact = self._artifact_from_row(row)
            if snapshot.states[artifact.artifact_id] is SkillCandidateState.REVOKED:
                raise SkillRegistryError("revoked skill candidates cannot be staged")
            content = row["content"]
            if not isinstance(content, bytes):
                raise SkillRegistryIntegrityError("durable skill content is not bytes")
            metadata = artifact.metadata
            if not isinstance(metadata, SkillImportMetadata):
                raise SkillRegistryIntegrityError("durable artifact metadata is not a skill")
            prefix = f"skills/{metadata.name}/{metadata.version}"
            manifest_bytes = canonical_json(
                {
                    "artifact": artifact.to_dict(),
                    "quarantined": True,
                    "host_execution_allowed": False,
                }
            ).encode("utf-8")
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                self._tar_entry(archive, f"{prefix}/manifest.json", manifest_bytes)
                self._tar_entry(archive, f"{prefix}/payload.bin", content)
            payload = stream.getvalue()
            if len(payload) > MAX_ARCHIVE_BYTES:
                raise SkillRegistryError("skill package exceeds sandbox staging limit")
            digest = hashlib.sha256(payload).hexdigest()
            encoded = base64.b64encode(payload).decode("ascii")
            _, members = validate_staging_archive(encoded, digest)
            return SandboxSkillPackage(encoded, digest, len(payload), len(members), artifact.artifact_id)

    def sandbox_package_by_artifact_id(
        self, artifact_id: str, *, active_path: bool = False
    ) -> SandboxSkillPackage:
        candidate = self.candidate_by_artifact_id(artifact_id)
        if not active_path:
            return self.sandbox_package(candidate.name, candidate.version)
        with self._lock:
            snapshot = self._snapshot()
            if snapshot.states[artifact_id] is SkillCandidateState.REVOKED:
                raise SkillRegistryError("revoked skill candidates cannot be staged")
            row = self._connection.execute(
                "SELECT content FROM skill_artifacts WHERE artifact_id=?", (artifact_id,)
            ).fetchone()
            if row is None or not isinstance(row["content"], bytes):
                raise SkillRegistryIntegrityError("durable skill content is missing")
            content = bytes(row["content"])
            prefix = f".aegis/skills/{candidate.name}/active"
            attestation = canonical_json({
                "artifact_id": artifact_id,
                "content_sha256": candidate.artifact.content_sha256,
                "host_execution_allowed": False,
                "version": candidate.version,
            }).encode()
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                self._tar_entry(archive, f"{prefix}/SKILL.md", content)
                self._tar_entry(archive, f"{prefix}/attestation.json", attestation)
            payload = stream.getvalue()
            if len(payload) > MAX_ARCHIVE_BYTES:
                raise SkillRegistryError("skill package exceeds sandbox staging limit")
            digest = hashlib.sha256(payload).hexdigest()
            encoded = base64.b64encode(payload).decode("ascii")
            _, members = validate_staging_archive(encoded, digest)
            return SandboxSkillPackage(encoded, digest, len(payload), len(members), artifact_id)
