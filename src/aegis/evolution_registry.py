"""Append-only promotion registry for isolated self-modification candidates.

Candidate archives remain opaque immutable blobs.  This module validates tar
metadata but never extracts, imports, executes, or writes candidate files into
the host repository.  Promotion returns only a content-addressed archive for a
later sandbox canary.
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

from aegis.evolution_validation import CommandValidationEvidence, ValidationEvidence
from aegis.evolution_workspace import (
    CandidateFileChange,
    CandidatePatchArtifact,
    ChangeKind,
    FileDigest,
    ValidationCommand,
    WorkspaceSnapshot,
)
from aegis.models import canonical_json
from aegis.sandbox.types import validate_staging_archive

_DIGEST = re.compile(r"[0-9a-f]{64}")
_ARTIFACT_ID = re.compile(r"candidate-sha256:[0-9a-f]{64}")
_REQUEST_ID = re.compile(r"evolution-request-sha256:[0-9a-f]{64}")
_GENESIS = "0" * 64
_MAX_TOKENS = 10**12


class EvolutionRegistryError(RuntimeError):
    pass


class EvolutionRegistryIntegrityError(EvolutionRegistryError):
    pass


class EvolutionCandidateState(StrEnum):
    CANDIDATE = "candidate"
    COLLECTED = "collected"
    VALIDATION_FAILED = "validation_failed"
    CHAMPION = "champion"
    SUPERSEDED = "superseded"
    REVOKED = "revoked"

    @property
    def promotable(self) -> bool:
        return self is EvolutionCandidateState.CANDIDATE

    @property
    def terminal(self) -> bool:
        return self in {
            EvolutionCandidateState.SUPERSEDED,
            EvolutionCandidateState.REVOKED,
            EvolutionCandidateState.VALIDATION_FAILED,
        }


def _digest(value: object, name: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _reason(value: object, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > 2_000
        or any(ord(character) < 32 for character in value)
    ):
        raise EvolutionRegistryError(f"{name} must be bounded trimmed text without controls")
    return value


@dataclass(frozen=True, slots=True)
class EvolutionPromotionEvidence:
    candidate_artifact_id: str
    baseline_archive_sha256: str
    static_checks_passed: bool
    safety_regression_passed: bool
    quality_comparison_passed: bool
    usage_verified: bool
    candidate_tokens: int
    baseline_tokens: int
    static_report_sha256: str
    safety_report_sha256: str
    quality_report_sha256: str
    usage_report_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.candidate_artifact_id, str) or _ARTIFACT_ID.fullmatch(
            self.candidate_artifact_id
        ) is None:
            raise ValueError("candidate_artifact_id is invalid")
        _digest(self.baseline_archive_sha256, "baseline_archive_sha256")
        for name in (
            "static_report_sha256",
            "safety_report_sha256",
            "quality_report_sha256",
            "usage_report_sha256",
        ):
            _digest(getattr(self, name), name)
        for name in (
            "static_checks_passed",
            "safety_regression_passed",
            "quality_comparison_passed",
            "usage_verified",
        ):
            if not isinstance(getattr(self, name), bool):
                raise TypeError(f"{name} must be a bool")
        for name in ("candidate_tokens", "baseline_tokens"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _MAX_TOKENS:
                raise ValueError(f"{name} must be a bounded non-negative integer")

    @property
    def promotable(self) -> bool:
        return (
            self.static_checks_passed
            and self.safety_regression_passed
            and self.quality_comparison_passed
            and self.usage_verified
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "candidate_artifact_id": self.candidate_artifact_id,
            "baseline_archive_sha256": self.baseline_archive_sha256,
            "static_checks_passed": self.static_checks_passed,
            "safety_regression_passed": self.safety_regression_passed,
            "quality_comparison_passed": self.quality_comparison_passed,
            "usage_verified": self.usage_verified,
            "candidate_tokens": self.candidate_tokens,
            "baseline_tokens": self.baseline_tokens,
            "static_report_sha256": self.static_report_sha256,
            "safety_report_sha256": self.safety_report_sha256,
            "quality_report_sha256": self.quality_report_sha256,
            "usage_report_sha256": self.usage_report_sha256,
        }


@dataclass(frozen=True, slots=True)
class EvolutionCandidateRecord:
    artifact_id: str
    baseline_archive_sha256: str
    candidate_archive_sha256: str
    change_count: int
    state: EvolutionCandidateState
    registered_at: str
    parent_champion_id: str | None = None
    baseline_archive_digest: str | None = None


@dataclass(frozen=True, slots=True)
class VersionedCandidateArchive:
    """A sandbox staging payload; not an instruction to modify the host."""

    version: int
    artifact_id: str
    baseline_archive_sha256: str
    archive_base64: str
    expected_digest: str
    size_bytes: int
    entries: int
    promotion_event_hash: str


@dataclass(frozen=True, slots=True)
class _Snapshot:
    states: Mapping[str, EvolutionCandidateState]
    champion_id: str | None
    promoted: frozenset[str]
    promotion_version: int
    champion_event_hash: str | None
    lineages: Mapping[str, tuple[str | None, str | None]]  # artifact_id -> (parent_champion_id, baseline_archive_digest)


def _strict(value: object, keys: set[str], name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise EvolutionRegistryIntegrityError(f"{name} must be an object")
    if set(value) != keys:
        raise EvolutionRegistryIntegrityError(f"{name} has missing or unknown fields")
    return value


def _artifact_from_mapping(value: object, archive: bytes) -> CandidatePatchArtifact:
    data = _strict(
        value,
        {
            "artifact_id",
            "schema_version",
            "baseline_archive_sha256",
            "candidate_archive_sha256",
            "changes",
            "validation_commands",
        },
        "candidate artifact",
    )
    if data["schema_version"] != 1 or isinstance(data["schema_version"], bool):
        raise EvolutionRegistryIntegrityError("candidate schema_version must be 1")
    raw_changes = data["changes"]
    if not isinstance(raw_changes, list):
        raise EvolutionRegistryIntegrityError("candidate changes must be an array")
    changes: list[CandidateFileChange] = []
    for raw in raw_changes:
        item = _strict(
            raw,
            {"path", "kind", "baseline_sha256", "candidate_sha256", "candidate_size_bytes"},
            "candidate change",
        )
        try:
            changes.append(
                CandidateFileChange(
                    path=item["path"],
                    kind=ChangeKind(item["kind"]),
                    baseline_sha256=item["baseline_sha256"],
                    candidate_sha256=item["candidate_sha256"],
                    candidate_size_bytes=item["candidate_size_bytes"],
                )
            )
        except (TypeError, ValueError) as exc:
            raise EvolutionRegistryIntegrityError("candidate change is invalid") from exc
    raw_commands = data["validation_commands"]
    if not isinstance(raw_commands, list):
        raise EvolutionRegistryIntegrityError("validation_commands must be an array")
    commands: list[ValidationCommand] = []
    for raw in raw_commands:
        item = _strict(raw, {"argv", "cwd", "timeout_seconds"}, "validation command")
        argv = item["argv"]
        if not isinstance(argv, list):
            raise EvolutionRegistryIntegrityError("validation argv must be an array")
        try:
            commands.append(ValidationCommand(tuple(argv), item["cwd"], item["timeout_seconds"]))
        except (TypeError, ValueError) as exc:
            raise EvolutionRegistryIntegrityError("validation command is invalid") from exc
    try:
        return CandidatePatchArtifact(
            artifact_id=data["artifact_id"],
            baseline_archive_sha256=data["baseline_archive_sha256"],
            candidate_archive=archive,
            candidate_archive_sha256=data["candidate_archive_sha256"],
            changes=tuple(changes),
            validation_commands=tuple(commands),
        )
    except (TypeError, ValueError) as exc:
        raise EvolutionRegistryIntegrityError("candidate artifact failed integrity validation") from exc


def _validation_from_mapping(value: object) -> ValidationEvidence:
    data = _strict(
        value,
        {
            "evidence_id",
            "schema_version",
            "validation_id",
            "candidate_artifact_id",
            "baseline_archive_sha256",
            "candidate_archive_sha256",
            "pristine_frozen_sha256",
            "post_validation_frozen_sha256",
            "commands",
            "passed",
            "failure_reason",
            "workspace_mutated",
            "total_observed_seconds",
        },
        "validation evidence",
    )
    if data["schema_version"] != 1 or isinstance(data["schema_version"], bool):
        raise EvolutionRegistryIntegrityError("validation evidence schema_version must be 1")
    raw_commands = data["commands"]
    if not isinstance(raw_commands, list):
        raise EvolutionRegistryIntegrityError("validation evidence commands must be an array")
    commands: list[CommandValidationEvidence] = []
    command_keys = {
        "index",
        "command_sha256",
        "result_sha256",
        "exit_code",
        "timed_out",
        "reported_duration_seconds",
        "observed_duration_seconds",
        "stdout_sha256",
        "stderr_sha256",
        "stdout_bytes",
        "stderr_bytes",
        "output_within_limit",
    }
    try:
        for raw in raw_commands:
            item = _strict(raw, command_keys, "validation command evidence")
            commands.append(CommandValidationEvidence(**item))
        return ValidationEvidence(
            evidence_id=data["evidence_id"],
            validation_id=data["validation_id"],
            candidate_artifact_id=data["candidate_artifact_id"],
            baseline_archive_sha256=data["baseline_archive_sha256"],
            candidate_archive_sha256=data["candidate_archive_sha256"],
            pristine_frozen_sha256=data["pristine_frozen_sha256"],
            post_validation_frozen_sha256=data["post_validation_frozen_sha256"],
            commands=tuple(commands),
            passed=data["passed"],
            failure_reason=data["failure_reason"],
            workspace_mutated=data["workspace_mutated"],
            total_observed_seconds=data["total_observed_seconds"],
        )
    except (TypeError, ValueError) as exc:
        raise EvolutionRegistryIntegrityError("validation evidence is invalid") from exc


class EvolutionRegistry:
    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS evolution_artifacts (
        artifact_id TEXT PRIMARY KEY,
        baseline_sha256 TEXT NOT NULL,
        candidate_sha256 TEXT NOT NULL,
        artifact_json TEXT NOT NULL,
        archive BLOB NOT NULL,
        registered_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS evolution_events (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL,
        payload TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        event_hash TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS evolution_request_origins (
        request_id TEXT PRIMARY KEY,
        artifact_id TEXT NOT NULL UNIQUE REFERENCES evolution_artifacts(artifact_id),
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS baseline_archives (
        archive_sha256 TEXT PRIMARY KEY,
        archive BLOB NOT NULL,
        file_count INTEGER NOT NULL,
        total_bytes INTEGER NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS validation_evidence (
        evidence_id TEXT PRIMARY KEY,
        candidate_artifact_id TEXT NOT NULL,
        evidence_json TEXT NOT NULL,
        passed INTEGER NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE UNIQUE INDEX IF NOT EXISTS validation_evidence_candidate
        ON validation_evidence(candidate_artifact_id);
    CREATE TRIGGER IF NOT EXISTS evolution_artifacts_no_update
        BEFORE UPDATE ON evolution_artifacts BEGIN SELECT RAISE(ABORT, 'evolution artifacts are immutable'); END;
    CREATE TRIGGER IF NOT EXISTS evolution_artifacts_no_delete
        BEFORE DELETE ON evolution_artifacts BEGIN SELECT RAISE(ABORT, 'evolution artifacts are immutable'); END;
    CREATE TRIGGER IF NOT EXISTS evolution_events_no_update
        BEFORE UPDATE ON evolution_events BEGIN SELECT RAISE(ABORT, 'evolution events are immutable'); END;
    CREATE TRIGGER IF NOT EXISTS evolution_events_no_delete
        BEFORE DELETE ON evolution_events BEGIN SELECT RAISE(ABORT, 'evolution events are immutable'); END;
    CREATE TRIGGER IF NOT EXISTS evolution_request_origins_no_update
        BEFORE UPDATE ON evolution_request_origins BEGIN SELECT RAISE(ABORT, 'evolution request origins are immutable'); END;
    CREATE TRIGGER IF NOT EXISTS evolution_request_origins_no_delete
        BEFORE DELETE ON evolution_request_origins BEGIN SELECT RAISE(ABORT, 'evolution request origins are immutable'); END;
    CREATE TRIGGER IF NOT EXISTS baseline_archives_no_update
        BEFORE UPDATE ON baseline_archives BEGIN SELECT RAISE(ABORT, 'baseline archives are immutable'); END;
    CREATE TRIGGER IF NOT EXISTS baseline_archives_no_delete
        BEFORE DELETE ON baseline_archives BEGIN SELECT RAISE(ABORT, 'baseline archives are immutable'); END;
    CREATE TRIGGER IF NOT EXISTS validation_evidence_no_update
        BEFORE UPDATE ON validation_evidence BEGIN SELECT RAISE(ABORT, 'validation evidence is immutable'); END;
    CREATE TRIGGER IF NOT EXISTS validation_evidence_no_delete
        BEFORE DELETE ON validation_evidence BEGIN SELECT RAISE(ABORT, 'validation evidence is immutable'); END;
    """

    def __init__(self, db_path: str | Path) -> None:
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._closed = False
        self._connection = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys=ON")
        if self._connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            raise EvolutionRegistryError("SQLite foreign key enforcement is unavailable")
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute("PRAGMA busy_timeout=5000")
        self._connection.executescript(self._SCHEMA)
        try:
            self._snapshot()
        except BaseException:
            self._connection.close()
            self._closed = True
            raise

    def __enter__(self) -> EvolutionRegistry:
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
            raise EvolutionRegistryError("evolution registry is closed")

    @staticmethod
    def _validate_artifact(artifact: object) -> CandidatePatchArtifact:
        if not isinstance(artifact, CandidatePatchArtifact):
            raise EvolutionRegistryError("artifact must be a CandidatePatchArtifact")
        try:
            rebuilt = _artifact_from_mapping(artifact.to_mapping(), artifact.candidate_archive)
            validate_staging_archive(
                base64.b64encode(artifact.candidate_archive).decode("ascii"),
                artifact.candidate_archive_sha256,
            )
        except (TypeError, ValueError, EvolutionRegistryIntegrityError) as exc:
            raise EvolutionRegistryError("candidate artifact failed strict revalidation") from exc
        if rebuilt != artifact:
            raise EvolutionRegistryError("candidate artifact is not canonical")
        return artifact

    @staticmethod
    def _event_hash(event_type: str, payload: Mapping[str, Any], previous_hash: str) -> str:
        return hashlib.sha256(
            canonical_json(
                {"event_type": event_type, "payload": payload, "previous_hash": previous_hash}
            ).encode("utf-8")
        ).hexdigest()

    def _append_event(self, event_type: str, payload: Mapping[str, Any]) -> tuple[int, str]:
        row = self._connection.execute(
            "SELECT event_hash FROM evolution_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous = _GENESIS if row is None else str(row["event_hash"])
        event_hash = self._event_hash(event_type, payload, previous)
        cursor = self._connection.execute(
            "INSERT INTO evolution_events(event_type,payload,previous_hash,event_hash,created_at) "
            "VALUES(?,?,?,?,?)",
            (
                event_type,
                canonical_json(payload),
                previous,
                event_hash,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        if cursor.lastrowid is None:
            raise EvolutionRegistryIntegrityError("evolution event insert returned no sequence")
        return int(cursor.lastrowid), event_hash

    def _artifact_from_row(self, row: sqlite3.Row) -> CandidatePatchArtifact:
        archive = row["archive"]
        if not isinstance(archive, bytes):
            raise EvolutionRegistryIntegrityError("durable candidate archive is not bytes")
        try:
            artifact = _artifact_from_mapping(json.loads(row["artifact_json"]), archive)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise EvolutionRegistryIntegrityError("durable candidate artifact is invalid") from exc
        if (
            artifact.artifact_id != row["artifact_id"]
            or artifact.baseline_archive_sha256 != row["baseline_sha256"]
            or artifact.candidate_archive_sha256 != row["candidate_sha256"]
        ):
            raise EvolutionRegistryIntegrityError("durable candidate columns disagree with artifact")
        return artifact

    @staticmethod
    def _validate_baseline(snapshot: object, artifact: CandidatePatchArtifact) -> WorkspaceSnapshot:
        if not isinstance(snapshot, WorkspaceSnapshot):
            raise EvolutionRegistryError("baseline must be a WorkspaceSnapshot")
        if snapshot.archive_sha256 != artifact.baseline_archive_sha256:
            raise EvolutionRegistryError("baseline archive does not bind the candidate")
        encoded = base64.b64encode(snapshot.archive).decode("ascii")
        try:
            _, members = validate_staging_archive(encoded, snapshot.archive_sha256)
            files: list[FileDigest] = []
            with tarfile.open(fileobj=io.BytesIO(snapshot.archive), mode="r:*") as archive:
                for member in members:
                    if member.isdir():
                        continue
                    source = archive.extractfile(member)
                    if source is None:
                        raise EvolutionRegistryIntegrityError("baseline archive file cannot be read")
                    content = source.read()
                    files.append(
                        FileDigest(member.name, hashlib.sha256(content).hexdigest(), len(content))
                    )
        except (tarfile.TarError, TypeError, ValueError) as exc:
            raise EvolutionRegistryError("baseline archive failed strict validation") from exc
        if tuple(sorted(files, key=lambda item: item.path)) != snapshot.files:
            raise EvolutionRegistryError("baseline file manifest does not match archive")
        return snapshot

    def _store_baseline(self, snapshot: WorkspaceSnapshot, created_at: str) -> None:
        row = self._connection.execute(
            "SELECT archive,file_count,total_bytes FROM baseline_archives WHERE archive_sha256=?",
            (snapshot.archive_sha256,),
        ).fetchone()
        expanded_bytes = sum(item.size_bytes for item in snapshot.files)
        if row is not None:
            if (
                row["archive"] != snapshot.archive
                or int(row["file_count"]) != len(snapshot.files)
                or int(row["total_bytes"]) != expanded_bytes
            ):
                raise EvolutionRegistryIntegrityError("baseline archive identity was redefined")
            return
        self._connection.execute(
            "INSERT INTO baseline_archives(archive_sha256,archive,file_count,total_bytes,created_at) "
            "VALUES(?,?,?,?,?)",
            (
                snapshot.archive_sha256,
                snapshot.archive,
                len(snapshot.files),
                expanded_bytes,
                created_at,
            ),
        )

    def _baseline_by_digest(self, digest: str) -> WorkspaceSnapshot:
        row = self._connection.execute(
            "SELECT archive,file_count,total_bytes FROM baseline_archives WHERE archive_sha256=?",
            (digest,),
        ).fetchone()
        if row is None or not isinstance(row["archive"], bytes):
            raise EvolutionRegistryError("unknown durable baseline archive")
        archive_bytes = bytes(row["archive"])
        if hashlib.sha256(archive_bytes).hexdigest() != digest:
            raise EvolutionRegistryIntegrityError("durable baseline archive digest is invalid")
        try:
            _, members = validate_staging_archive(base64.b64encode(archive_bytes).decode("ascii"), digest)
            files: list[FileDigest] = []
            with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:*") as archive:
                for member in members:
                    if member.isdir():
                        continue
                    source = archive.extractfile(member)
                    if source is None:
                        raise EvolutionRegistryIntegrityError("durable baseline file cannot be read")
                    content = source.read()
                    files.append(
                        FileDigest(member.name, hashlib.sha256(content).hexdigest(), len(content))
                    )
        except (tarfile.TarError, TypeError, ValueError) as exc:
            raise EvolutionRegistryIntegrityError("durable baseline archive is invalid") from exc
        manifest = tuple(sorted(files, key=lambda item: item.path))
        if (
            int(row["file_count"]) != len(manifest)
            or int(row["total_bytes"]) != sum(item.size_bytes for item in manifest)
        ):
            raise EvolutionRegistryIntegrityError("durable baseline metadata is invalid")
        return WorkspaceSnapshot(archive_bytes, digest, manifest)

    def _snapshot(self) -> _Snapshot:
        self._ensure_open()
        known: set[str] = set()
        artifact_baselines: dict[str, str] = {}
        for row in self._connection.execute(
            "SELECT artifact_id,baseline_sha256,candidate_sha256,artifact_json,archive "
            "FROM evolution_artifacts ORDER BY rowid"
        ).fetchall():
            artifact = self._artifact_from_row(row)
            if artifact.artifact_id in known:
                raise EvolutionRegistryIntegrityError("duplicate durable candidate artifact")
            known.add(artifact.artifact_id)
            artifact_baselines[artifact.artifact_id] = artifact.baseline_archive_sha256
        origin_requests: set[str] = set()
        origin_artifacts: set[str] = set()
        for row in self._connection.execute(
            "SELECT request_id,artifact_id FROM evolution_request_origins ORDER BY rowid"
        ).fetchall():
            request_id = row["request_id"]
            artifact_id = row["artifact_id"]
            if (
                not isinstance(request_id, str)
                or _REQUEST_ID.fullmatch(request_id) is None
                or not isinstance(artifact_id, str)
                or artifact_id not in known
                or request_id in origin_requests
                or artifact_id in origin_artifacts
            ):
                raise EvolutionRegistryIntegrityError("durable evolution request origin is invalid")
            origin_requests.add(request_id)
            origin_artifacts.add(artifact_id)
        validations: dict[str, ValidationEvidence] = {}
        for row in self._connection.execute(
            "SELECT evidence_id,candidate_artifact_id,evidence_json,passed "
            "FROM validation_evidence ORDER BY rowid"
        ).fetchall():
            try:
                evidence = _validation_from_mapping(json.loads(row["evidence_json"]))
            except (TypeError, json.JSONDecodeError) as exc:
                raise EvolutionRegistryIntegrityError("durable validation evidence is invalid") from exc
            if (
                evidence.evidence_id != row["evidence_id"]
                or evidence.candidate_artifact_id != row["candidate_artifact_id"]
                or int(evidence.passed) != int(row["passed"])
                or evidence.candidate_artifact_id in validations
            ):
                raise EvolutionRegistryIntegrityError("durable validation columns disagree with evidence")
            validations[evidence.candidate_artifact_id] = evidence
        states: dict[str, EvolutionCandidateState] = {}
        champion: str | None = None
        promoted: set[str] = set()
        version = 0
        champion_event_hash: str | None = None
        lineages: dict[str, tuple[str | None, str | None]] = {}
        validation_events: set[str] = set()
        event_origins: dict[str, str] = {}
        previous = _GENESIS
        rows = self._connection.execute(
            "SELECT sequence,event_type,payload,previous_hash,event_hash FROM evolution_events ORDER BY sequence"
        ).fetchall()
        for expected_sequence, row in enumerate(rows, 1):
            if int(row["sequence"]) != expected_sequence:
                raise EvolutionRegistryIntegrityError("evolution event sequence is not contiguous")
            try:
                payload = json.loads(row["payload"])
            except (TypeError, json.JSONDecodeError) as exc:
                raise EvolutionRegistryIntegrityError("evolution event payload is invalid") from exc
            if not isinstance(payload, dict):
                raise EvolutionRegistryIntegrityError("evolution event payload is not an object")
            event_type = str(row["event_type"])
            event_hash = str(row["event_hash"])
            if row["previous_hash"] != previous or event_hash != self._event_hash(
                event_type, payload, previous
            ):
                raise EvolutionRegistryIntegrityError("evolution event hash chain is invalid")
            previous = event_hash
            artifact_id = payload.get("artifact_id")
            if not isinstance(artifact_id, str) or artifact_id not in known:
                raise EvolutionRegistryIntegrityError("evolution event references an unknown artifact")
            if event_type == "request_origin_bound":
                request_id = payload.get("request_id")
                if (
                    set(payload) != {"artifact_id", "request_id"}
                    or not isinstance(request_id, str)
                    or _REQUEST_ID.fullmatch(request_id) is None
                    or request_id in event_origins
                    or artifact_id in event_origins.values()
                ):
                    raise EvolutionRegistryIntegrityError("invalid evolution request origin event")
                event_origins[request_id] = artifact_id
            elif event_type == "candidate_registered":
                if set(payload) != {"artifact_id"} or artifact_id in states:
                    raise EvolutionRegistryIntegrityError("invalid candidate registration event")
                states[artifact_id] = EvolutionCandidateState.CANDIDATE
                lineages[artifact_id] = (champion, artifact_baselines[artifact_id])
            elif event_type == "candidate_collected":
                if (
                    set(payload)
                    != {"artifact_id", "parent_champion_id", "baseline_archive_sha256"}
                    or artifact_id in states
                    or payload["parent_champion_id"] != champion
                    or payload["baseline_archive_sha256"] != artifact_baselines[artifact_id]
                ):
                    raise EvolutionRegistryIntegrityError("invalid candidate collection event")
                self._baseline_by_digest(artifact_baselines[artifact_id])
                states[artifact_id] = EvolutionCandidateState.COLLECTED
                lineages[artifact_id] = (champion, artifact_baselines[artifact_id])
            elif event_type == "candidate_validated":
                if (
                    set(payload) != {"artifact_id", "evidence_id", "passed"}
                    or states.get(artifact_id) is not EvolutionCandidateState.COLLECTED
                    or artifact_id not in validations
                ):
                    raise EvolutionRegistryIntegrityError("invalid candidate validation event")
                evidence = validations[artifact_id]
                if payload["evidence_id"] != evidence.evidence_id or payload["passed"] is not evidence.passed:
                    raise EvolutionRegistryIntegrityError("validation event disagrees with evidence")
                states[artifact_id] = (
                    EvolutionCandidateState.CANDIDATE
                    if evidence.passed
                    else EvolutionCandidateState.VALIDATION_FAILED
                )
                validation_events.add(artifact_id)
            elif event_type in {"candidate_promoted", "champion_rolled_back"}:
                expected = (
                    {"artifact_id", "previous_champion_id", "promotion_version", "evidence"}
                    if event_type == "candidate_promoted"
                    else {"artifact_id", "previous_champion_id", "promotion_version", "reason"}
                )
                if set(payload) != expected or artifact_id not in states:
                    raise EvolutionRegistryIntegrityError("invalid evolution promotion event")
                if payload["previous_champion_id"] != champion:
                    raise EvolutionRegistryIntegrityError("evolution event has wrong previous champion")
                if payload["promotion_version"] != version + 1:
                    raise EvolutionRegistryIntegrityError("evolution promotion version is not contiguous")
                if states[artifact_id] is EvolutionCandidateState.REVOKED:
                    raise EvolutionRegistryIntegrityError("revoked candidate was promoted")
                if event_type == "candidate_promoted":
                    raw_evidence = payload["evidence"]
                    if not isinstance(raw_evidence, dict):
                        raise EvolutionRegistryIntegrityError("persisted evolution evidence is invalid")
                    try:
                        promotion_evidence = EvolutionPromotionEvidence(**raw_evidence)
                    except (TypeError, ValueError) as exc:
                        raise EvolutionRegistryIntegrityError("persisted evolution evidence is invalid") from exc
                    artifact = self._row_artifact_by_id(artifact_id)
                    if (
                        promotion_evidence.candidate_artifact_id != artifact_id
                        or promotion_evidence.baseline_archive_sha256
                        != artifact.baseline_archive_sha256
                        or not promotion_evidence.promotable
                    ):
                        raise EvolutionRegistryIntegrityError("persisted evolution evidence is not promotable")
                else:
                    if artifact_id not in promoted:
                        raise EvolutionRegistryIntegrityError("rollback target was never champion")
                    _reason(payload["reason"], "persisted rollback reason")
                if champion is not None and champion != artifact_id:
                    states[champion] = EvolutionCandidateState.SUPERSEDED
                states[artifact_id] = EvolutionCandidateState.CHAMPION
                champion = artifact_id
                promoted.add(artifact_id)
                version += 1
                champion_event_hash = event_hash
            elif event_type == "candidate_superseded":
                if set(payload) != {"artifact_id", "reason"} or states.get(
                    artifact_id
                ) is not EvolutionCandidateState.CANDIDATE:
                    raise EvolutionRegistryIntegrityError("invalid candidate supersession event")
                _reason(payload["reason"], "persisted supersession reason")
                states[artifact_id] = EvolutionCandidateState.SUPERSEDED
            elif event_type == "candidate_revoked":
                if set(payload) != {"artifact_id", "reason"} or artifact_id not in states:
                    raise EvolutionRegistryIntegrityError("invalid candidate revocation event")
                if states[artifact_id] is EvolutionCandidateState.REVOKED:
                    raise EvolutionRegistryIntegrityError("candidate was revoked twice")
                _reason(payload["reason"], "persisted revocation reason")
                states[artifact_id] = EvolutionCandidateState.REVOKED
                if champion == artifact_id:
                    champion = None
                    champion_event_hash = None
            else:
                raise EvolutionRegistryIntegrityError(f"unknown evolution event type: {event_type}")
        if set(states) != known:
            raise EvolutionRegistryIntegrityError("durable candidate lacks registration event")
        if set(validations) != validation_events:
            raise EvolutionRegistryIntegrityError("durable validation evidence lacks matching event")
        table_origins = {
            str(row["request_id"]): str(row["artifact_id"])
            for row in self._connection.execute(
                "SELECT request_id,artifact_id FROM evolution_request_origins"
            ).fetchall()
        }
        if table_origins != event_origins:
            raise EvolutionRegistryIntegrityError("evolution request origins disagree with event history")
        return _Snapshot(states, champion, frozenset(promoted), version, champion_event_hash, lineages)

    def _row_artifact_by_id(self, artifact_id: str) -> CandidatePatchArtifact:
        row = self._connection.execute(
            "SELECT artifact_id,baseline_sha256,candidate_sha256,artifact_json,archive "
            "FROM evolution_artifacts WHERE artifact_id=?",
            (artifact_id,),
        ).fetchone()
        if row is None:
            raise EvolutionRegistryError("unknown evolution candidate")
        return self._artifact_from_row(cast(sqlite3.Row, row))

    @staticmethod
    def _record(
        artifact: CandidatePatchArtifact,
        state: EvolutionCandidateState,
        registered_at: str,
        *,
        parent_champion_id: str | None = None,
        baseline_archive_digest: str | None = None,
    ) -> EvolutionCandidateRecord:
        return EvolutionCandidateRecord(
            artifact.artifact_id,
            artifact.baseline_archive_sha256,
            artifact.candidate_archive_sha256,
            len(artifact.changes),
            state,
            registered_at,
            parent_champion_id=parent_champion_id,
            baseline_archive_digest=baseline_archive_digest,
        )

    def register_candidate(self, artifact: CandidatePatchArtifact) -> EvolutionCandidateRecord:
        artifact = self._validate_artifact(artifact)
        registered_at = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._ensure_open()
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    "SELECT artifact_id,registered_at FROM evolution_artifacts WHERE artifact_id=?",
                    (artifact.artifact_id,),
                ).fetchone()
                if row is not None:
                    stored = self._row_artifact_by_id(artifact.artifact_id)
                    if stored != artifact:
                        raise EvolutionRegistryIntegrityError("artifact identity was redefined")
                    self._connection.execute("COMMIT")
                    snapshot = self._snapshot()
                    return self._record(
                        artifact, snapshot.states[artifact.artifact_id], str(row["registered_at"])
                    )
                self._connection.execute(
                    "INSERT INTO evolution_artifacts(artifact_id,baseline_sha256,candidate_sha256,"
                    "artifact_json,archive,registered_at) VALUES(?,?,?,?,?,?)",
                    (
                        artifact.artifact_id,
                        artifact.baseline_archive_sha256,
                        artifact.candidate_archive_sha256,
                        canonical_json(artifact.to_mapping()),
                        artifact.candidate_archive,
                        registered_at,
                    ),
                )
                self._append_event("candidate_registered", {"artifact_id": artifact.artifact_id})
                self._connection.execute("COMMIT")
            except BaseException:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise
            return self._record(artifact, EvolutionCandidateState.CANDIDATE, registered_at)

    def register_collected(
        self,
        artifact: CandidatePatchArtifact,
        baseline: WorkspaceSnapshot,
        *,
        parent_champion_id: str | None = None,
        request_id: str | None = None,
    ) -> EvolutionCandidateRecord:
        """Durably record an isolated candidate before validation begins."""
        artifact = self._validate_artifact(artifact)
        baseline = self._validate_baseline(baseline, artifact)
        if request_id is not None and _REQUEST_ID.fullmatch(request_id) is None:
            raise EvolutionRegistryError("evolution request_id is invalid")
        registered_at = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._ensure_open()
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                snapshot = self._snapshot()
                if parent_champion_id != snapshot.champion_id:
                    raise EvolutionRegistryError("candidate parent is not the active champion")
                if request_id is not None:
                    request_origin = self._connection.execute(
                        "SELECT artifact_id FROM evolution_request_origins WHERE request_id=?",
                        (request_id,),
                    ).fetchone()
                    if request_origin is not None and request_origin["artifact_id"] != artifact.artifact_id:
                        raise EvolutionRegistryError("evolution request was already bound to another artifact")
                    artifact_origin = self._connection.execute(
                        "SELECT request_id FROM evolution_request_origins WHERE artifact_id=?",
                        (artifact.artifact_id,),
                    ).fetchone()
                    if artifact_origin is not None and artifact_origin["request_id"] != request_id:
                        raise EvolutionRegistryError("evolution artifact was already bound to another request")
                row = self._connection.execute(
                    "SELECT registered_at FROM evolution_artifacts WHERE artifact_id=?",
                    (artifact.artifact_id,),
                ).fetchone()
                if row is not None:
                    stored = self._row_artifact_by_id(artifact.artifact_id)
                    if stored != artifact:
                        raise EvolutionRegistryIntegrityError("artifact identity was redefined")
                    lineage = snapshot.lineages.get(artifact.artifact_id)
                    if lineage != (parent_champion_id, baseline.archive_sha256):
                        raise EvolutionRegistryError("candidate collection lineage was redefined")
                    if request_id is not None and request_origin is None:
                        self._connection.execute(
                            "INSERT INTO evolution_request_origins(request_id,artifact_id,created_at) "
                            "VALUES(?,?,?)",
                            (request_id, artifact.artifact_id, registered_at),
                        )
                        self._append_event(
                            "request_origin_bound",
                            {"artifact_id": artifact.artifact_id, "request_id": request_id},
                        )
                    self._connection.execute("COMMIT")
                    return self.candidate(artifact.artifact_id)
                self._store_baseline(baseline, registered_at)
                self._connection.execute(
                    "INSERT INTO evolution_artifacts(artifact_id,baseline_sha256,candidate_sha256,"
                    "artifact_json,archive,registered_at) VALUES(?,?,?,?,?,?)",
                    (
                        artifact.artifact_id,
                        artifact.baseline_archive_sha256,
                        artifact.candidate_archive_sha256,
                        canonical_json(artifact.to_mapping()),
                        artifact.candidate_archive,
                        registered_at,
                    ),
                )
                self._append_event(
                    "candidate_collected",
                    {
                        "artifact_id": artifact.artifact_id,
                        "parent_champion_id": parent_champion_id,
                        "baseline_archive_sha256": baseline.archive_sha256,
                    },
                )
                if request_id is not None:
                    self._connection.execute(
                        "INSERT INTO evolution_request_origins(request_id,artifact_id,created_at) "
                        "VALUES(?,?,?)",
                        (request_id, artifact.artifact_id, registered_at),
                    )
                    self._append_event(
                        "request_origin_bound",
                        {"artifact_id": artifact.artifact_id, "request_id": request_id},
                    )
                self._connection.execute("COMMIT")
            except BaseException:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise
            return self._record(
                artifact,
                EvolutionCandidateState.COLLECTED,
                registered_at,
                parent_champion_id=parent_champion_id,
                baseline_archive_digest=baseline.archive_sha256,
            )

    def record_validation(
        self,
        artifact_id: str,
        evidence: ValidationEvidence,
    ) -> EvolutionCandidateRecord:
        if not isinstance(evidence, ValidationEvidence):
            raise EvolutionRegistryError("validation evidence must be ValidationEvidence")
        with self._lock:
            self._ensure_open()
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                snapshot = self._snapshot()
                artifact = self._row_artifact_by_id(artifact_id)
                if (
                    evidence.candidate_artifact_id != artifact.artifact_id
                    or evidence.baseline_archive_sha256 != artifact.baseline_archive_sha256
                    or evidence.candidate_archive_sha256 != artifact.candidate_archive_sha256
                ):
                    raise EvolutionRegistryError("validation evidence does not bind candidate archives")
                existing = self._connection.execute(
                    "SELECT evidence_json FROM validation_evidence WHERE candidate_artifact_id=?",
                    (artifact_id,),
                ).fetchone()
                if existing is not None:
                    try:
                        stored = _validation_from_mapping(json.loads(existing["evidence_json"]))
                    except (TypeError, json.JSONDecodeError) as exc:
                        raise EvolutionRegistryIntegrityError("durable validation evidence is invalid") from exc
                    if stored != evidence:
                        raise EvolutionRegistryError("validation evidence was already recorded differently")
                    self._connection.execute("COMMIT")
                    return self.candidate(artifact_id)
                if snapshot.states.get(artifact_id) is not EvolutionCandidateState.COLLECTED:
                    raise EvolutionRegistryError("only a collected candidate may be validated")
                created_at = datetime.now(timezone.utc).isoformat()
                self._connection.execute(
                    "INSERT INTO validation_evidence(evidence_id,candidate_artifact_id,evidence_json,passed,created_at) "
                    "VALUES(?,?,?,?,?)",
                    (
                        evidence.evidence_id,
                        artifact_id,
                        canonical_json(evidence.to_mapping()),
                        int(evidence.passed),
                        created_at,
                    ),
                )
                self._append_event(
                    "candidate_validated",
                    {
                        "artifact_id": artifact_id,
                        "evidence_id": evidence.evidence_id,
                        "passed": evidence.passed,
                    },
                )
                self._connection.execute("COMMIT")
            except BaseException:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise
            return self.candidate(artifact_id)

    def candidate(self, artifact_id: str) -> EvolutionCandidateRecord:
        with self._lock:
            snapshot = self._snapshot()
            artifact = self._row_artifact_by_id(artifact_id)
            row = self._connection.execute(
                "SELECT registered_at FROM evolution_artifacts WHERE artifact_id=?", (artifact_id,)
            ).fetchone()
            parent, baseline = snapshot.lineages[artifact_id]
            return self._record(
                artifact,
                snapshot.states[artifact_id],
                str(row["registered_at"]),
                parent_champion_id=parent,
                baseline_archive_digest=baseline,
            )

    def candidate_artifact(self, artifact_id: str) -> CandidatePatchArtifact:
        with self._lock:
            self._snapshot()
            return self._row_artifact_by_id(artifact_id)

    def candidate_for_request(self, request_id: str) -> CandidatePatchArtifact | None:
        if not isinstance(request_id, str) or _REQUEST_ID.fullmatch(request_id) is None:
            raise EvolutionRegistryError("evolution request_id is invalid")
        with self._lock:
            self._snapshot()
            row = self._connection.execute(
                "SELECT artifact_id FROM evolution_request_origins WHERE request_id=?",
                (request_id,),
            ).fetchone()
            if row is None:
                return None
            return self._row_artifact_by_id(str(row["artifact_id"]))

    def pending_candidates(self) -> tuple[EvolutionCandidateRecord, ...]:
        with self._lock:
            snapshot = self._snapshot()
            rows = self._connection.execute(
                "SELECT artifact_id FROM evolution_artifacts ORDER BY registered_at,artifact_id"
            ).fetchall()
            return tuple(
                self.candidate(str(row["artifact_id"]))
                for row in rows
                if snapshot.states[str(row["artifact_id"])] is EvolutionCandidateState.CANDIDATE
            )

    def validation(self, artifact_id: str) -> ValidationEvidence:
        with self._lock:
            self._snapshot()
            row = self._connection.execute(
                "SELECT evidence_json FROM validation_evidence WHERE candidate_artifact_id=?",
                (artifact_id,),
            ).fetchone()
            if row is None:
                raise EvolutionRegistryError("candidate has no durable validation evidence")
            try:
                return _validation_from_mapping(json.loads(row["evidence_json"]))
            except (TypeError, json.JSONDecodeError) as exc:
                raise EvolutionRegistryIntegrityError("durable validation evidence is invalid") from exc

    def baseline_snapshot(self, artifact_id: str) -> WorkspaceSnapshot:
        with self._lock:
            snapshot = self._snapshot()
            baseline = snapshot.lineages.get(artifact_id, (None, None))[1]
            if baseline is None:
                raise EvolutionRegistryError("candidate has no durable baseline archive")
            return self._baseline_by_digest(baseline)

    def champion(self) -> EvolutionCandidateRecord | None:
        with self._lock:
            snapshot = self._snapshot()
            if snapshot.champion_id is None:
                return None
            return self.candidate(snapshot.champion_id)

    def _archive(
        self,
        artifact: CandidatePatchArtifact,
        version: int,
        event_hash: str,
    ) -> VersionedCandidateArchive:
        encoded = base64.b64encode(artifact.candidate_archive).decode("ascii")
        _, members = validate_staging_archive(encoded, artifact.candidate_archive_sha256)
        return VersionedCandidateArchive(
            version,
            artifact.artifact_id,
            artifact.baseline_archive_sha256,
            encoded,
            artifact.candidate_archive_sha256,
            len(artifact.candidate_archive),
            len(members),
            event_hash,
        )

    def promote(
        self, artifact_id: str, evidence: EvolutionPromotionEvidence
    ) -> VersionedCandidateArchive:
        return self._promote(artifact_id, evidence)

    def promote_if_current(
        self,
        artifact_id: str,
        evidence: EvolutionPromotionEvidence,
        *,
        expected_champion_id: str | None,
        expected_promotion_version: int,
    ) -> VersionedCandidateArchive:
        if (
            isinstance(expected_promotion_version, bool)
            or not isinstance(expected_promotion_version, int)
            or expected_promotion_version < 0
        ):
            raise EvolutionRegistryError("expected_promotion_version must be non-negative")
        return self._promote(
            artifact_id,
            evidence,
            expected_champion_id=expected_champion_id,
            expected_promotion_version=expected_promotion_version,
            enforce_cas=True,
        )

    def _promote(
        self,
        artifact_id: str,
        evidence: EvolutionPromotionEvidence,
        *,
        expected_champion_id: str | None = None,
        expected_promotion_version: int = 0,
        enforce_cas: bool = False,
    ) -> VersionedCandidateArchive:
        with self._lock:
            self._ensure_open()
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                snapshot = self._snapshot()
                artifact = self._row_artifact_by_id(artifact_id)
                if enforce_cas and (
                    snapshot.champion_id != expected_champion_id
                    or snapshot.promotion_version != expected_promotion_version
                ):
                    raise EvolutionRegistryError("active champion changed before candidate promotion")
                if not isinstance(evidence, EvolutionPromotionEvidence):
                    raise EvolutionRegistryError("promotion requires EvolutionPromotionEvidence")
                if (
                    evidence.candidate_artifact_id != artifact.artifact_id
                    or evidence.baseline_archive_sha256 != artifact.baseline_archive_sha256
                ):
                    raise EvolutionRegistryError("promotion evidence does not bind candidate and baseline")
                if not evidence.safety_regression_passed:
                    raise EvolutionRegistryError("any safety regression failure forbids promotion")
                if not evidence.promotable:
                    raise EvolutionRegistryError("promotion evidence is incomplete or failed")
                if snapshot.states[artifact_id] is not EvolutionCandidateState.CANDIDATE:
                    raise EvolutionRegistryError("only a pending candidate may be promoted")
                version = snapshot.promotion_version + 1
                _, event_hash = self._append_event(
                    "candidate_promoted",
                    {
                        "artifact_id": artifact_id,
                        "previous_champion_id": snapshot.champion_id,
                        "promotion_version": version,
                        "evidence": evidence.to_dict(),
                    },
                )
                self._connection.execute("COMMIT")
            except BaseException:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise
            return self._archive(artifact, version, event_hash)

    def supersede(self, artifact_id: str, reason: str) -> EvolutionCandidateRecord:
        rationale = _reason(reason, "supersession reason")
        return self._terminal_event(artifact_id, "candidate_superseded", rationale)

    def revoke(self, artifact_id: str, reason: str) -> EvolutionCandidateRecord:
        rationale = _reason(reason, "revocation reason")
        return self._terminal_event(artifact_id, "candidate_revoked", rationale)

    def _terminal_event(
        self, artifact_id: str, event_type: str, reason: str
    ) -> EvolutionCandidateRecord:
        with self._lock:
            self._ensure_open()
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                snapshot = self._snapshot()
                artifact = self._row_artifact_by_id(artifact_id)
                state = snapshot.states[artifact_id]
                if event_type == "candidate_superseded" and state is not EvolutionCandidateState.CANDIDATE:
                    raise EvolutionRegistryError("only a pending candidate may be explicitly superseded")
                if event_type == "candidate_revoked" and state is EvolutionCandidateState.REVOKED:
                    raise EvolutionRegistryError("candidate is already revoked")
                self._append_event(event_type, {"artifact_id": artifact_id, "reason": reason})
                self._connection.execute("COMMIT")
            except BaseException:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise
            target_state = (
                EvolutionCandidateState.SUPERSEDED
                if event_type == "candidate_superseded"
                else EvolutionCandidateState.REVOKED
            )
            row = self._connection.execute(
                "SELECT registered_at FROM evolution_artifacts WHERE artifact_id=?", (artifact_id,)
            ).fetchone()
            return self._record(artifact, target_state, str(row["registered_at"]))

    def rollback(self, artifact_id: str, reason: str) -> VersionedCandidateArchive:
        rationale = _reason(reason, "rollback reason")
        with self._lock:
            self._ensure_open()
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                snapshot = self._snapshot()
                artifact = self._row_artifact_by_id(artifact_id)
                if artifact_id not in snapshot.promoted:
                    raise EvolutionRegistryError("rollback target was never champion")
                if snapshot.states[artifact_id] is EvolutionCandidateState.REVOKED:
                    raise EvolutionRegistryError("revoked candidate cannot be restored")
                if snapshot.champion_id == artifact_id:
                    raise EvolutionRegistryError("rollback target is already champion")
                version = snapshot.promotion_version + 1
                _, event_hash = self._append_event(
                    "champion_rolled_back",
                    {
                        "artifact_id": artifact_id,
                        "previous_champion_id": snapshot.champion_id,
                        "promotion_version": version,
                        "reason": rationale,
                    },
                )
                self._connection.execute("COMMIT")
            except BaseException:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise
            return self._archive(artifact, version, event_hash)

    def champion_archive(self) -> VersionedCandidateArchive | None:
        with self._lock:
            snapshot = self._snapshot()
            if snapshot.champion_id is None or snapshot.champion_event_hash is None:
                return None
            artifact = self._row_artifact_by_id(snapshot.champion_id)
            return self._archive(artifact, snapshot.promotion_version, snapshot.champion_event_hash)
