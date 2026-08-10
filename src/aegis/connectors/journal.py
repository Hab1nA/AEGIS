"""Append-only, replay-safe journal for connector intents and receipts."""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Mapping

from aegis.plugins.runtime import ExternalEffectReceipt, ExternalIntent


class ConnectorJournalError(RuntimeError):
    pass


def _serialize(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


class SqliteConnectorJournal:
    """Persistent intent-first journal; replay is idempotent and fail-closed."""

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS connector_intents (
        intent_id TEXT PRIMARY KEY,
        request_id TEXT NOT NULL UNIQUE,
        intent TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS connector_receipts (
        receipt_id TEXT PRIMARY KEY,
        request_id TEXT NOT NULL UNIQUE,
        intent_id TEXT NOT NULL,
        receipt TEXT NOT NULL
    );
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.executescript(self._SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> SqliteConnectorJournal:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def record_intent(self, intent: ExternalIntent) -> None:
        if not isinstance(intent, ExternalIntent):
            raise TypeError("intent must be an ExternalIntent")
        with self._lock:
            row = self._connection.execute(
                "SELECT intent FROM connector_intents WHERE request_id=?", (intent.request_id,)
            ).fetchone()
            if row is not None:
                expected = _serialize(intent.to_dict())
                if str(row["intent"]) != expected:
                    raise ConnectorJournalError(
                        "connector intent replay conflicts with the existing request journal"
                    )
                return
            self._connection.execute(
                "INSERT INTO connector_intents(intent_id,request_id,intent) VALUES(?,?,?)",
                (intent.intent_id, intent.request_id, _serialize(intent.to_dict())),
            )

    def record_receipt(self, receipt: ExternalEffectReceipt) -> None:
        if not isinstance(receipt, ExternalEffectReceipt):
            raise TypeError("receipt must be an ExternalEffectReceipt")
        with self._lock:
            intent = self._connection.execute(
                "SELECT intent_id FROM connector_intents WHERE request_id=?", (receipt.request_id,)
            ).fetchone()
            if intent is None:
                raise ConnectorJournalError("connector receipt references an unknown intent")
            if str(intent["intent_id"]) != receipt.intent_id:
                raise ConnectorJournalError("connector receipt does not match its intent")
            existing = self._connection.execute(
                "SELECT receipt FROM connector_receipts WHERE request_id=?", (receipt.request_id,)
            ).fetchone()
            if existing is not None:
                expected = _serialize(receipt.to_dict())
                if str(existing["receipt"]) != expected:
                    raise ConnectorJournalError(
                        "connector receipt replay conflicts with the existing request journal"
                    )
                return
            self._connection.execute(
                "INSERT INTO connector_receipts(receipt_id,request_id,intent_id,receipt) VALUES(?,?,?,?)",
                (
                    receipt.external_receipt_id,
                    receipt.request_id,
                    receipt.intent_id,
                    _serialize(receipt.to_dict()),
                ),
            )

    def intents(self) -> tuple[Mapping[str, Any], ...]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT intent_id,request_id,intent FROM connector_intents ORDER BY rowid"
            ).fetchall()
            return tuple(dict(row) for row in rows)

    def receipts(self) -> tuple[Mapping[str, Any], ...]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT receipt_id,request_id,intent_id,receipt FROM connector_receipts ORDER BY rowid"
            ).fetchall()
            return tuple(dict(row) for row in rows)
