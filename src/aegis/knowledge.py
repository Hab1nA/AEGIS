"""Immutable, cross-round knowledge artifacts backed by SQLite.

Knowledge is deliberately advisory data.  This store persists provenance and
evaluation evidence, but does not execute, install, or trust stored material.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock, local
from typing import Any, Callable, Iterable, Mapping, TypeVar
from urllib.parse import urlsplit

from aegis.models import Role

MAX_SOURCE_URL_BYTES = 2_048
MAX_SUMMARY_BYTES = 16_384
MAX_EVIDENCE_BYTES = 8_192
MAX_QUERY_BYTES = 512
MAX_TAGS = 32
MAX_TAG_BYTES = 64
MAX_RESULTS = 100
MAX_RESEARCH_DESCRIPTOR_BYTES = 512 * 1024
MAX_RESEARCH_BLOB_BYTES = 8 * 1024 * 1024
MAX_RESEARCH_BLOBS = 128
MAX_RESEARCH_LOCATOR_BYTES = 4_096

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MEDIA_TYPE = re.compile(
    r"[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}\Z"
)


class KnowledgeStoreError(RuntimeError):
    """Base error raised by the knowledge store."""


class KnowledgeStoreClosedError(KnowledgeStoreError):
    """Raised when an operation is attempted on a closed store."""


class KnowledgeConflictError(KnowledgeStoreError):
    """Raised when a content hash is reused with different metadata."""


class ResearchSnapshotConflictError(KnowledgeStoreError):
    """Raised when an immutable research snapshot identity is redefined."""


_T = TypeVar("_T")


def _bounded_text(value: object, name: str, limit: int, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    if value != value.strip():
        raise ValueError(f"{name} must not contain surrounding whitespace")
    if not value and not allow_empty:
        raise ValueError(f"{name} must be non-empty")
    if "\x00" in value:
        raise ValueError(f"{name} must not contain NUL")
    if len(value.encode("utf-8")) > limit:
        raise ValueError(f"{name} exceeds {limit} UTF-8 bytes")
    return value


def _source_url(value: object) -> str:
    url = _bounded_text(value, "source_url", MAX_SOURCE_URL_BYTES)
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError("source_url must be an HTTPS URL without credentials or fragment")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("source_url contains an invalid port") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("source_url contains an invalid port")
    return url


def _content_sha256(value: object) -> str:
    digest = _bounded_text(value, "sha256", 64)
    if not _SHA256.fullmatch(digest):
        raise ValueError("sha256 must be 64 lowercase hexadecimal characters")
    return digest


def _media_type_value(value: object) -> str:
    media_type = _bounded_text(value, "media_type", 255)
    if not _MEDIA_TYPE.fullmatch(media_type):
        raise ValueError("media_type must be a lowercase type/subtype without parameters")
    return media_type


def _tags(values: Iterable[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise TypeError("tags must be an iterable of strings")
    items = tuple(values)
    if len(items) > MAX_TAGS:
        raise ValueError(f"tags must contain at most {MAX_TAGS} items")
    normalized: list[str] = []
    for value in items:
        tag = _bounded_text(value, "tag", MAX_TAG_BYTES)
        if tag != tag.lower():
            raise ValueError("tags must be lowercase")
        normalized.append(tag)
    if len(set(normalized)) != len(normalized):
        raise ValueError("tags must be unique")
    return tuple(sorted(normalized))


def _roles(values: Iterable[Role | str]) -> tuple[Role, ...]:
    if isinstance(values, (str, bytes)):
        raise TypeError("applicable_roles must be an iterable")
    roles: list[Role] = []
    for value in values:
        try:
            role = value if isinstance(value, Role) else Role(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid applicable role: {value!r}") from exc
        roles.append(role)
    if not roles:
        raise ValueError("applicable_roles must not be empty")
    if len(set(roles)) != len(roles):
        raise ValueError("applicable_roles must be unique")
    return tuple(sorted(roles, key=lambda item: item.value))


@dataclass(frozen=True, slots=True)
class KnowledgeArtifact:
    """A provenance-preserving and immutable unit of learned knowledge."""

    artifact_id: str
    source_url: str
    sha256: str
    media_type: str
    summary: str
    tags: tuple[str, ...]
    applicable_roles: tuple[Role, ...]
    experiment_result: str | None
    failure_reason: str | None
    created_at: datetime

    def __post_init__(self) -> None:
        digest = _content_sha256(self.sha256)
        if self.artifact_id != f"sha256:{digest}":
            raise ValueError("artifact_id must be derived from sha256")
        _source_url(self.source_url)
        _media_type_value(self.media_type)
        _bounded_text(self.summary, "summary", MAX_SUMMARY_BYTES)
        if self.tags != _tags(self.tags):
            raise ValueError("tags must be in canonical order")
        if self.applicable_roles != _roles(self.applicable_roles):
            raise ValueError("applicable_roles must be in canonical order")
        if self.experiment_result is not None:
            _bounded_text(self.experiment_result, "experiment_result", MAX_EVIDENCE_BYTES)
        if self.failure_reason is not None:
            _bounded_text(self.failure_reason, "failure_reason", MAX_EVIDENCE_BYTES)
        if self.experiment_result is not None and self.failure_reason is not None:
            raise ValueError("experiment_result and failure_reason are mutually exclusive")
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError("created_at must be timezone-aware")
        object.__setattr__(self, "created_at", self.created_at.astimezone(timezone.utc))


@dataclass(frozen=True, slots=True)
class ResearchBlob:
    """One bounded, inert byte range belonging to a research snapshot."""

    locator: str
    sha256: str
    media_type: str
    content: bytes

    def __post_init__(self) -> None:
        _bounded_text(self.locator, "locator", MAX_RESEARCH_LOCATOR_BYTES)
        _content_sha256(self.sha256)
        _media_type_value(self.media_type)
        if not isinstance(self.content, bytes):
            raise TypeError("research blob content must be bytes")
        if not 1 <= len(self.content) <= MAX_RESEARCH_BLOB_BYTES:
            raise ValueError("research blob content is outside the size limit")
        if hashlib.sha256(self.content).hexdigest() != self.sha256:
            raise ValueError("research blob sha256 does not match content")


@dataclass(frozen=True, slots=True)
class ResearchSnapshot:
    """Immutable, provenance-preserving GitHub, paper, or skill research data."""

    artifact_id: str
    kind: str
    content_sha256: str
    source_url: str
    descriptor: Mapping[str, Any]
    blobs: tuple[ResearchBlob, ...]
    created_at: datetime

    def __post_init__(self) -> None:
        artifact_id = _bounded_text(self.artifact_id, "artifact_id", 128)
        bare_digest = artifact_id[7:] if artifact_id.startswith("sha256:") else artifact_id
        if not _SHA256.fullmatch(bare_digest):
            raise ValueError("artifact_id must be a bare or sha256-prefixed digest identity")
        if self.kind not in {"github", "paper", "skill"}:
            raise ValueError("research kind must be github, paper, or skill")
        _content_sha256(self.content_sha256)
        _source_url(self.source_url)
        descriptor_json = _strict_json_object(self.descriptor, "descriptor")
        if len(descriptor_json.encode("utf-8")) > MAX_RESEARCH_DESCRIPTOR_BYTES:
            raise ValueError("research descriptor exceeds the size limit")
        if not 1 <= len(self.blobs) <= MAX_RESEARCH_BLOBS:
            raise ValueError("research snapshot must contain a bounded non-empty blob set")
        if len({blob.locator for blob in self.blobs}) != len(self.blobs):
            raise ValueError("research blob locators must be unique")
        if tuple(sorted(self.blobs, key=lambda item: item.locator)) != self.blobs:
            raise ValueError("research blobs must be in canonical locator order")
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError("created_at must be timezone-aware")
        object.__setattr__(self, "descriptor", json.loads(descriptor_json))
        object.__setattr__(self, "created_at", self.created_at.astimezone(timezone.utc))


def _strict_json_object(value: object, name: str) -> str:
    if not isinstance(value, Mapping):
        raise TypeError(f"{name} must be a JSON object")
    try:
        encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        decoded = json.loads(encoded)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must contain strict finite JSON") from exc
    if not isinstance(decoded, dict):
        raise TypeError(f"{name} must be a JSON object")
    return encoded


class KnowledgeStore:
    """Durable artifact repository shared by rounds and roles."""

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS knowledge_artifacts (
        artifact_id TEXT PRIMARY KEY,
        source_url TEXT NOT NULL,
        sha256 TEXT NOT NULL UNIQUE,
        media_type TEXT NOT NULL,
        summary TEXT NOT NULL,
        tags_json TEXT NOT NULL,
        roles_json TEXT NOT NULL,
        search_text TEXT NOT NULL,
        experiment_result TEXT,
        failure_reason TEXT,
        created_at TEXT NOT NULL,
        CHECK(length(sha256) = 64),
        CHECK(NOT (experiment_result IS NOT NULL AND failure_reason IS NOT NULL))
    );
    CREATE TABLE IF NOT EXISTS knowledge_artifact_roles (
        artifact_id TEXT NOT NULL REFERENCES knowledge_artifacts(artifact_id),
        role TEXT NOT NULL,
        PRIMARY KEY(artifact_id, role)
    );
    CREATE INDEX IF NOT EXISTS idx_knowledge_roles_role
        ON knowledge_artifact_roles(role, artifact_id);
    CREATE TABLE IF NOT EXISTS research_snapshots (
        artifact_id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        content_sha256 TEXT NOT NULL,
        source_url TEXT NOT NULL,
        descriptor_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        CHECK(kind IN ('github', 'paper', 'skill')),
        CHECK(length(content_sha256) = 64)
    );
    CREATE INDEX IF NOT EXISTS idx_research_snapshots_content_sha256
        ON research_snapshots(content_sha256, artifact_id);
    CREATE TABLE IF NOT EXISTS research_snapshot_blobs (
        artifact_id TEXT NOT NULL REFERENCES research_snapshots(artifact_id),
        locator TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        media_type TEXT NOT NULL,
        content BLOB NOT NULL,
        PRIMARY KEY(artifact_id, locator),
        CHECK(length(sha256) = 64)
    );
    CREATE TRIGGER IF NOT EXISTS knowledge_artifacts_no_update
    BEFORE UPDATE ON knowledge_artifacts BEGIN
        SELECT RAISE(ABORT, 'knowledge artifacts are immutable');
    END;
    CREATE TRIGGER IF NOT EXISTS knowledge_artifacts_no_delete
    BEFORE DELETE ON knowledge_artifacts BEGIN
        SELECT RAISE(ABORT, 'knowledge artifacts are immutable');
    END;
    CREATE TRIGGER IF NOT EXISTS knowledge_roles_no_update
    BEFORE UPDATE ON knowledge_artifact_roles BEGIN
        SELECT RAISE(ABORT, 'knowledge artifacts are immutable');
    END;
    CREATE TRIGGER IF NOT EXISTS knowledge_roles_no_delete
    BEFORE DELETE ON knowledge_artifact_roles BEGIN
        SELECT RAISE(ABORT, 'knowledge artifacts are immutable');
    END;
    CREATE TRIGGER IF NOT EXISTS research_snapshots_no_update
    BEFORE UPDATE ON research_snapshots BEGIN
        SELECT RAISE(ABORT, 'research snapshots are immutable');
    END;
    CREATE TRIGGER IF NOT EXISTS research_snapshots_no_delete
    BEFORE DELETE ON research_snapshots BEGIN
        SELECT RAISE(ABORT, 'research snapshots are immutable');
    END;
    CREATE TRIGGER IF NOT EXISTS research_snapshot_blobs_no_update
    BEFORE UPDATE ON research_snapshot_blobs BEGIN
        SELECT RAISE(ABORT, 'research snapshots are immutable');
    END;
    CREATE TRIGGER IF NOT EXISTS research_snapshot_blobs_no_delete
    BEFORE DELETE ON research_snapshot_blobs BEGIN
        SELECT RAISE(ABORT, 'research snapshots are immutable');
    END;
    """

    def __init__(
        self,
        db_path: str | Path,
        *,
        busy_retries: int = 8,
        retry_delay: float = 0.005,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if isinstance(busy_retries, bool) or not isinstance(busy_retries, int) or busy_retries < 0:
            raise ValueError("busy_retries must be a non-negative integer")
        if isinstance(retry_delay, bool) or not isinstance(retry_delay, (int, float)) or retry_delay < 0:
            raise ValueError("retry_delay must be non-negative")
        self._path = Path(db_path)
        self._busy_retries = busy_retries
        self._retry_delay = float(retry_delay)
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._local = local()
        self._connections: set[sqlite3.Connection] = set()
        self._connections_lock = Lock()
        self._closed = False
        self._initialize()

    @property
    def path(self) -> Path:
        return self._path

    def _connect(self) -> sqlite3.Connection:
        if self._closed:
            raise KnowledgeStoreClosedError("knowledge store is closed")
        connection = sqlite3.connect(
            self._path,
            timeout=0.05,
            isolation_level=None,
            check_same_thread=False,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=50")
        with self._connections_lock:
            if self._closed:
                connection.close()
                raise KnowledgeStoreClosedError("knowledge store is closed")
            self._connections.add(connection)
        return connection

    def _connection(self) -> sqlite3.Connection:
        if self._closed:
            raise KnowledgeStoreClosedError("knowledge store is closed")
        connection = getattr(self._local, "connection", None)
        if connection is None:
            connection = self._connect()
            self._local.connection = connection
        return connection

    def _initialize(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._connection().executescript(self._SCHEMA)

    def _with_retry(self, operation: Callable[[], _T]) -> _T:
        for attempt in range(self._busy_retries + 1):
            try:
                return operation()
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc).lower() and "busy" not in str(exc).lower():
                    raise KnowledgeStoreError("knowledge store operation failed") from exc
                if attempt == self._busy_retries:
                    raise KnowledgeStoreError("knowledge store remained busy") from exc
                time.sleep(self._retry_delay * (2**attempt))
        raise AssertionError("unreachable")

    def add(
        self,
        *,
        source_url: str,
        sha256: str,
        media_type: str,
        summary: str,
        tags: Iterable[str],
        applicable_roles: Iterable[Role | str],
        experiment_result: str | None = None,
        failure_reason: str | None = None,
        created_at: datetime | None = None,
    ) -> KnowledgeArtifact:
        """Add an artifact; an exactly repeated hash is idempotent."""
        validated_url = _source_url(source_url)
        validated_sha = _content_sha256(sha256)
        validated_media_type = _media_type_value(media_type)
        validated_summary = _bounded_text(summary, "summary", MAX_SUMMARY_BYTES)
        validated_tags = _tags(tags)
        validated_roles = _roles(applicable_roles)
        validated_result = (
            None
            if experiment_result is None
            else _bounded_text(experiment_result, "experiment_result", MAX_EVIDENCE_BYTES)
        )
        validated_failure = (
            None
            if failure_reason is None
            else _bounded_text(failure_reason, "failure_reason", MAX_EVIDENCE_BYTES)
        )
        if validated_result is not None and validated_failure is not None:
            raise ValueError("experiment_result and failure_reason are mutually exclusive")
        timestamp = self._clock() if created_at is None else created_at
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("created_at must be timezone-aware")
        timestamp = timestamp.astimezone(timezone.utc)
        artifact_id = f"sha256:{validated_sha}"
        tags_json = json.dumps(validated_tags, ensure_ascii=False, separators=(",", ":"))
        roles_json = json.dumps(
            tuple(role.value for role in validated_roles), ensure_ascii=False, separators=(",", ":")
        )
        search_text = "\n".join(
            part
            for part in (
                validated_url,
                validated_media_type,
                validated_summary,
                " ".join(validated_tags),
                validated_result,
                validated_failure,
            )
            if part is not None
        )
        artifact = KnowledgeArtifact(
            artifact_id,
            validated_url,
            validated_sha,
            validated_media_type,
            validated_summary,
            validated_tags,
            validated_roles,
            validated_result,
            validated_failure,
            timestamp,
        )

        def operation() -> KnowledgeArtifact:
            connection = self._connection()
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM knowledge_artifacts WHERE sha256 = ?", (validated_sha,)
                ).fetchone()
                if row is not None:
                    existing = self._to_artifact(row)
                    connection.execute("COMMIT")
                    if not self._same_metadata(existing, artifact):
                        raise KnowledgeConflictError(
                            "sha256 already belongs to an immutable artifact with different metadata"
                        )
                    return existing
                connection.execute(
                    "INSERT INTO knowledge_artifacts "
                    "(artifact_id, source_url, sha256, media_type, summary, tags_json, roles_json, "
                    "search_text, experiment_result, failure_reason, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        artifact_id,
                        validated_url,
                        validated_sha,
                        validated_media_type,
                        validated_summary,
                        tags_json,
                        roles_json,
                        search_text,
                        validated_result,
                        validated_failure,
                        timestamp.isoformat(),
                    ),
                )
                connection.executemany(
                    "INSERT INTO knowledge_artifact_roles(artifact_id, role) VALUES (?, ?)",
                    ((artifact_id, role.value) for role in validated_roles),
                )
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
            return artifact

        return self._with_retry(operation)

    def archive_research(
        self,
        *,
        artifact_id: str,
        kind: str,
        content_sha256: str,
        source_url: str,
        descriptor: Mapping[str, Any],
        blobs: Iterable[ResearchBlob],
        created_at: datetime | None = None,
    ) -> ResearchSnapshot:
        """Persist an inert research snapshot; exact repeats are idempotent."""
        timestamp = self._clock() if created_at is None else created_at
        canonical_blobs = tuple(sorted(tuple(blobs), key=lambda item: item.locator))
        snapshot = ResearchSnapshot(
            artifact_id,
            kind,
            content_sha256,
            source_url,
            descriptor,
            canonical_blobs,
            timestamp,
        )
        descriptor_json = _strict_json_object(snapshot.descriptor, "descriptor")

        def operation() -> ResearchSnapshot:
            connection = self._connection()
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM research_snapshots WHERE artifact_id = ?",
                    (snapshot.artifact_id,),
                ).fetchone()
                if row is not None:
                    existing = self._research_snapshot_from_row(connection, row)
                    connection.execute("COMMIT")
                    if not self._same_research_snapshot(existing, snapshot):
                        raise ResearchSnapshotConflictError(
                            "research artifact_id already belongs to different immutable data"
                        )
                    return existing
                connection.execute(
                    "INSERT INTO research_snapshots "
                    "(artifact_id,kind,content_sha256,source_url,descriptor_json,created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        snapshot.artifact_id,
                        snapshot.kind,
                        snapshot.content_sha256,
                        snapshot.source_url,
                        descriptor_json,
                        snapshot.created_at.isoformat(),
                    ),
                )
                connection.executemany(
                    "INSERT INTO research_snapshot_blobs "
                    "(artifact_id,locator,sha256,media_type,content) VALUES (?, ?, ?, ?, ?)",
                    (
                        (
                            snapshot.artifact_id,
                            blob.locator,
                            blob.sha256,
                            blob.media_type,
                            sqlite3.Binary(blob.content),
                        )
                        for blob in snapshot.blobs
                    ),
                )
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
            return snapshot

        return self._with_retry(operation)

    @staticmethod
    def _same_research_snapshot(left: ResearchSnapshot, right: ResearchSnapshot) -> bool:
        return (
            left.artifact_id,
            left.kind,
            left.content_sha256,
            left.source_url,
            left.descriptor,
            left.blobs,
        ) == (
            right.artifact_id,
            right.kind,
            right.content_sha256,
            right.source_url,
            right.descriptor,
            right.blobs,
        )

    @staticmethod
    def _research_snapshot_from_row(
        connection: sqlite3.Connection, row: sqlite3.Row
    ) -> ResearchSnapshot:
        blob_rows = connection.execute(
            "SELECT locator,sha256,media_type,content FROM research_snapshot_blobs "
            "WHERE artifact_id=? ORDER BY locator",
            (row["artifact_id"],),
        ).fetchall()
        try:
            descriptor = json.loads(row["descriptor_json"])
            created_at = datetime.fromisoformat(row["created_at"])
            blobs = tuple(
                ResearchBlob(
                    item["locator"], item["sha256"], item["media_type"], bytes(item["content"])
                )
                for item in blob_rows
            )
            return ResearchSnapshot(
                row["artifact_id"],
                row["kind"],
                row["content_sha256"],
                row["source_url"],
                descriptor,
                blobs,
                created_at,
            )
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise KnowledgeStoreError("stored research snapshot is invalid") from exc

    def research_get(self, artifact_id: str) -> ResearchSnapshot | None:
        validated_id = _bounded_text(artifact_id, "artifact_id", 128)
        connection = self._connection()
        row = connection.execute(
            "SELECT * FROM research_snapshots WHERE artifact_id=?", (validated_id,)
        ).fetchone()
        return None if row is None else self._research_snapshot_from_row(connection, row)

    def research_by_hash(self, sha256: str, *, limit: int = 20) -> tuple[ResearchSnapshot, ...]:
        """Recall exact immutable snapshots by their collector-verified content hash."""
        digest = _content_sha256(sha256)
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 20:
            raise ValueError("research recall limit must be an integer from 1 to 20")
        connection = self._connection()
        rows = connection.execute(
            "SELECT * FROM research_snapshots WHERE content_sha256=? "
            "ORDER BY created_at DESC, artifact_id ASC LIMIT ?",
            (digest, limit),
        ).fetchall()
        return tuple(self._research_snapshot_from_row(connection, row) for row in rows)

    @staticmethod
    def _same_metadata(left: KnowledgeArtifact, right: KnowledgeArtifact) -> bool:
        """Compare immutable content metadata while ignoring ingestion time."""
        return (
            left.artifact_id,
            left.source_url,
            left.sha256,
            left.media_type,
            left.summary,
            left.tags,
            left.applicable_roles,
            left.experiment_result,
            left.failure_reason,
        ) == (
            right.artifact_id,
            right.source_url,
            right.sha256,
            right.media_type,
            right.summary,
            right.tags,
            right.applicable_roles,
            right.experiment_result,
            right.failure_reason,
        )

    @staticmethod
    def _to_artifact(row: sqlite3.Row) -> KnowledgeArtifact:
        tags = json.loads(row["tags_json"])
        roles = json.loads(row["roles_json"])
        if not isinstance(tags, list) or not all(isinstance(item, str) for item in tags):
            raise KnowledgeStoreError("stored tags are invalid")
        if not isinstance(roles, list) or not all(isinstance(item, str) for item in roles):
            raise KnowledgeStoreError("stored roles are invalid")
        try:
            parsed_roles = tuple(Role(item) for item in roles)
            created_at = datetime.fromisoformat(row["created_at"])
        except (TypeError, ValueError) as exc:
            raise KnowledgeStoreError("stored artifact is invalid") from exc
        try:
            return KnowledgeArtifact(
                row["artifact_id"],
                row["source_url"],
                row["sha256"],
                row["media_type"],
                row["summary"],
                tuple(tags),
                parsed_roles,
                row["experiment_result"],
                row["failure_reason"],
                created_at,
            )
        except (TypeError, ValueError) as exc:
            raise KnowledgeStoreError("stored artifact violates the knowledge schema") from exc

    def get(self, artifact_id: str) -> KnowledgeArtifact | None:
        validated_id = _bounded_text(artifact_id, "artifact_id", 71)
        row = self._connection().execute(
            "SELECT * FROM knowledge_artifacts WHERE artifact_id = ?", (validated_id,)
        ).fetchone()
        return None if row is None else self._to_artifact(row)

    def query(
        self,
        text: str = "",
        *,
        role: Role | str | None = None,
        limit: int = 20,
    ) -> tuple[KnowledgeArtifact, ...]:
        """Search case-insensitively across provenance, summary, tags, and evidence."""
        validated_text = _bounded_text(text, "text", MAX_QUERY_BYTES, allow_empty=True)
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_RESULTS:
            raise ValueError(f"limit must be an integer from 1 to {MAX_RESULTS}")
        validated_role: Role | None = None
        if role is not None:
            try:
                validated_role = role if isinstance(role, Role) else Role(role)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"invalid role: {role!r}") from exc
        sql = "SELECT DISTINCT a.* FROM knowledge_artifacts AS a"
        parameters: list[object] = []
        conditions: list[str] = []
        if validated_role is not None:
            sql += " JOIN knowledge_artifact_roles AS r ON r.artifact_id = a.artifact_id"
            conditions.append("r.role = ?")
            parameters.append(validated_role.value)
        terms = validated_text.casefold().split()
        for term in terms:
            escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            conditions.append("lower(a.search_text) LIKE ? ESCAPE '\\'")
            parameters.append(f"%{escaped}%")
        if conditions:
            sql += " WHERE " + " AND ".join(conditions)
        sql += " ORDER BY a.created_at DESC, a.artifact_id ASC LIMIT ?"
        parameters.append(limit)
        rows = self._connection().execute(sql, parameters).fetchall()
        return tuple(self._to_artifact(row) for row in rows)

    def close(self) -> None:
        with self._connections_lock:
            if self._closed:
                return
            self._closed = True
            connections = tuple(self._connections)
            self._connections.clear()
        for connection in connections:
            connection.close()
        self._local.connection = None

    def __enter__(self) -> KnowledgeStore:
        if self._closed:
            raise KnowledgeStoreClosedError("knowledge store is closed")
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def sha256_bytes(content: bytes) -> str:
    """Return the canonical digest used for artifact identity."""
    if not isinstance(content, bytes):
        raise TypeError("content must be bytes")
    return hashlib.sha256(content).hexdigest()
