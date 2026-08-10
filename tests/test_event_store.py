from __future__ import annotations

import sqlite3
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from aegis.event_store import EventStore, EventStoreClosedError, EventStoreError, EventStoreSequenceConflict


class EventStoreTests(unittest.TestCase):
    def test_append_read_is_typed_canonical_and_campaign_scoped(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "events.db"
            moment = datetime(2026, 8, 5, tzinfo=timezone.utc)
            with EventStore(path) as store:
                first = store.append("c1", "started", {"z": 1, "a": [2]}, created_at=moment)
                other = store.append("c2", "started", {})
                second = store.append("c1", "advanced", {"state": "preparing"})
                self.assertEqual((first.sequence, other.sequence, second.sequence), (1, 1, 2))
                self.assertEqual(store.read("c1"), (first, second))
                self.assertEqual(store.read("c1", after_sequence=1), (second,))
                connection = sqlite3.connect(path)
                encoded = connection.execute(
                    "SELECT payload FROM events WHERE campaign_id='c1' AND sequence=1"
                ).fetchone()[0]
                connection.close()
                self.assertEqual(encoded, '{"a":[2],"z":1}')
            with self.assertRaises(EventStoreClosedError):
                store.read("c1")

    def test_reopen_resumes_sequence_and_wal_mode(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "events.db"
            store = EventStore(path)
            store.append("c", "one", {})
            store.close()
            reopened = EventStore(path)
            self.assertEqual(reopened.append("c", "two", {}).sequence, 2)
            connection = sqlite3.connect(path)
            try:
                mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
            finally:
                connection.close()
            self.assertEqual(mode.lower(), "wal")
            reopened.close()

    def test_multiple_instances_append_gap_free_sequences(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "events.db"
            stores = [EventStore(path, busy_retries=12, retry_delay=0.001) for _ in range(4)]

            def append(index: int) -> int:
                return stores[index % len(stores)].append("shared", "tick", {"i": index}).sequence

            with ThreadPoolExecutor(max_workers=12) as pool:
                sequences = list(pool.map(append, range(80)))
            self.assertEqual(sorted(sequences), list(range(1, 81)))
            self.assertEqual(stores[0].max_sequence("shared"), 80)
            for store in stores:
                store.close()

    def test_append_if_sequence_rejects_a_stale_writer(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "events.db"
            with EventStore(path) as first, EventStore(path) as second:
                first.append("campaign", "created", {})
                with self.assertRaises(EventStoreSequenceConflict):
                    second.append_if_sequence("campaign", 0, "state_changed", {"state": "preparing"})
                self.assertEqual(first.max_sequence("campaign"), 1)

    def test_invalid_payload_and_paging_are_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            store = EventStore(Path(directory) / "events.db")
            with self.assertRaises(EventStoreError):
                store.append("c", "bad", {"value": float("nan")})
            with self.assertRaises(ValueError):
                store.read("c", limit=0)
            store.close()


if __name__ == "__main__":
    unittest.main()
