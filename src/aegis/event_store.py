"""Append-only SQLite WAL event store with concurrent-writer retries."""

from __future__ import annotations

import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock, local
from typing import Any, Callable, Mapping

from aegis.models import AuditEvent, canonical_json


class EventStoreError(RuntimeError):
    pass


class EventStoreClosedError(EventStoreError):
    pass


class EventStoreSequenceConflict(EventStoreError):
    """Raised when another writer changed a campaign after its expected checkpoint."""


class EventStore:
    """Durable event stream; mutation is intentionally limited to append."""

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        campaign_id TEXT NOT NULL,
        sequence INTEGER NOT NULL CHECK(sequence > 0),
        event_type TEXT NOT NULL,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(campaign_id, sequence)
    );
    CREATE INDEX IF NOT EXISTS idx_events_campaign_sequence
        ON events(campaign_id, sequence);
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
        if retry_delay < 0:
            raise ValueError("retry_delay must be non-negative")
        self._path = Path(db_path)
        self._busy_retries = busy_retries
        self._retry_delay = retry_delay
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
            raise EventStoreClosedError("event store is closed")
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
                raise EventStoreClosedError("event store is closed")
            self._connections.add(connection)
        return connection

    def _connection(self) -> sqlite3.Connection:
        if self._closed:
            raise EventStoreClosedError("event store is closed")
        connection = getattr(self._local, "connection", None)
        if connection is None:
            connection = self._connect()
            self._local.connection = connection
        return connection

    def _initialize(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        connection = self._connection()
        connection.executescript(self._SCHEMA)

    def _with_retry(self, operation: Callable[[], AuditEvent]) -> AuditEvent:
        for attempt in range(self._busy_retries + 1):
            try:
                return operation()
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc).lower() and "busy" not in str(exc).lower():
                    raise EventStoreError("event store operation failed") from exc
                if attempt == self._busy_retries:
                    raise EventStoreError("event store remained busy") from exc
                time.sleep(self._retry_delay * (2**attempt))
        raise AssertionError("unreachable")

    def append(
        self,
        campaign_id: str,
        event_type: str,
        payload: Mapping[str, Any],
        *,
        created_at: datetime | None = None,
    ) -> AuditEvent:
        if not isinstance(campaign_id, str) or not campaign_id.strip():
            raise ValueError("campaign_id must be a non-empty string")
        if not isinstance(event_type, str) or not event_type.strip():
            raise ValueError("event_type must be a non-empty string")
        if not isinstance(payload, Mapping):
            raise TypeError("payload must be a mapping")
        try:
            encoded = canonical_json(payload)
        except (TypeError, ValueError) as exc:
            raise EventStoreError("payload must be strict JSON") from exc
        timestamp = self._clock() if created_at is None else created_at
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("created_at must be timezone-aware")
        timestamp = timestamp.astimezone(timezone.utc)

        def operation() -> AuditEvent:
            connection = self._connection()
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT COALESCE(MAX(sequence), 0) + 1 FROM events WHERE campaign_id = ?",
                    (campaign_id,),
                ).fetchone()
                sequence = int(row[0])
                connection.execute(
                    "INSERT INTO events(campaign_id, sequence, event_type, payload, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (campaign_id, sequence, event_type, encoded, timestamp.isoformat()),
                )
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
            return AuditEvent(campaign_id, sequence, event_type, payload, timestamp)

        return self._with_retry(operation)

    def append_if_sequence(
        self,
        campaign_id: str,
        expected_sequence: int,
        event_type: str,
        payload: Mapping[str, Any],
        *,
        created_at: datetime | None = None,
    ) -> AuditEvent:
        """Append only if the campaign stream still ends at ``expected_sequence``."""
        if isinstance(expected_sequence, bool) or not isinstance(expected_sequence, int) or expected_sequence < 0:
            raise ValueError("expected_sequence must be a non-negative integer")
        if not isinstance(campaign_id, str) or not campaign_id.strip():
            raise ValueError("campaign_id must be a non-empty string")
        if not isinstance(event_type, str) or not event_type.strip():
            raise ValueError("event_type must be a non-empty string")
        if not isinstance(payload, Mapping):
            raise TypeError("payload must be a mapping")
        try:
            encoded = canonical_json(payload)
        except (TypeError, ValueError) as exc:
            raise EventStoreError("payload must be strict JSON") from exc
        timestamp = self._clock() if created_at is None else created_at
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("created_at must be timezone-aware")
        timestamp = timestamp.astimezone(timezone.utc)

        def operation() -> AuditEvent:
            connection = self._connection()
            try:
                connection.execute("BEGIN IMMEDIATE")
                current = int(
                    connection.execute(
                        "SELECT COALESCE(MAX(sequence), 0) FROM events WHERE campaign_id = ?",
                        (campaign_id,),
                    ).fetchone()[0]
                )
                if current != expected_sequence:
                    raise EventStoreSequenceConflict(
                        f"campaign sequence changed from {expected_sequence} to {current}"
                    )
                sequence = current + 1
                connection.execute(
                    "INSERT INTO events(campaign_id, sequence, event_type, payload, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (campaign_id, sequence, event_type, encoded, timestamp.isoformat()),
                )
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
            return AuditEvent(campaign_id, sequence, event_type, payload, timestamp)

        return self._with_retry(operation)

    @staticmethod
    def _to_event(row: sqlite3.Row) -> AuditEvent:
        payload = json.loads(row["payload"])
        return AuditEvent(
            row["campaign_id"],
            int(row["sequence"]),
            row["event_type"],
            payload,
            datetime.fromisoformat(row["created_at"]),
        )

    def read(
        self,
        campaign_id: str,
        *,
        after_sequence: int = 0,
        limit: int | None = None,
    ) -> tuple[AuditEvent, ...]:
        if not isinstance(after_sequence, int) or isinstance(after_sequence, bool) or after_sequence < 0:
            raise ValueError("after_sequence must be a non-negative integer")
        if limit is not None and (isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0):
            raise ValueError("limit must be a positive integer or None")
        sql = (
            "SELECT campaign_id, sequence, event_type, payload, created_at FROM events "
            "WHERE campaign_id = ? AND sequence > ? ORDER BY sequence"
        )
        parameters: list[Any] = [campaign_id, after_sequence]
        if limit is not None:
            sql += " LIMIT ?"
            parameters.append(limit)
        rows = self._connection().execute(sql, parameters).fetchall()
        return tuple(self._to_event(row) for row in rows)

    def max_sequence(self, campaign_id: str) -> int:
        row = (
            self._connection()
            .execute(
                "SELECT COALESCE(MAX(sequence), 0) FROM events WHERE campaign_id = ?",
                (campaign_id,),
            )
            .fetchone()
        )
        return int(row[0])

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

    def __enter__(self) -> EventStore:
        if self._closed:
            raise EventStoreClosedError("event store is closed")
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
