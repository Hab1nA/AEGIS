"""SQLite-backed, hash-chained registry for dynamic task artifacts."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping, cast

from aegis.taskpacks.validation import TaskPackValidation

from .models import (
    CohortMember,
    CohortTier,
    DynamicTaskArtifact,
    DynamicTaskCohort,
    DynamicTaskOrigin,
    DynamicTaskRecord,
    DynamicTaskStatus,
    TaskValidationEvidence,
    canonical_json,
)

_GENESIS = "0" * 64


class DynamicTaskRegistryError(RuntimeError):
    pass


class DynamicTaskIntegrityError(DynamicTaskRegistryError):
    pass


class DynamicTaskConflictError(DynamicTaskRegistryError):
    pass


class DynamicTaskEligibilityError(DynamicTaskRegistryError):
    pass


class DynamicTaskRegistry:
    """Durable task bank with immutable artifacts and per-record CAS revisions."""

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS dynamic_task_artifacts (
        artifact_id TEXT PRIMARY KEY,
        descriptor TEXT NOT NULL,
        archive BLOB NOT NULL
    );
    CREATE TABLE IF NOT EXISTS dynamic_task_events (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL,
        payload TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        event_hash TEXT NOT NULL UNIQUE,
        created_at REAL NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS dynamic_task_artifacts_no_update
    BEFORE UPDATE ON dynamic_task_artifacts BEGIN SELECT RAISE(ABORT, 'dynamic task artifacts are immutable'); END;
    CREATE TRIGGER IF NOT EXISTS dynamic_task_artifacts_no_delete
    BEFORE DELETE ON dynamic_task_artifacts BEGIN SELECT RAISE(ABORT, 'dynamic task artifacts are immutable'); END;
    CREATE TRIGGER IF NOT EXISTS dynamic_task_events_no_update
    BEFORE UPDATE ON dynamic_task_events BEGIN SELECT RAISE(ABORT, 'dynamic task events are immutable'); END;
    CREATE TRIGGER IF NOT EXISTS dynamic_task_events_no_delete
    BEFORE DELETE ON dynamic_task_events BEGIN SELECT RAISE(ABORT, 'dynamic task events are immutable'); END;
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._connection.executescript(self._SCHEMA)
        self._replay()

    def __enter__(self) -> DynamicTaskRegistry:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    @staticmethod
    def _event_hash(event_type: str, payload: Mapping[str, Any], previous_hash: str) -> str:
        material = canonical_json(
            {"event_type": event_type, "payload": payload, "previous_hash": previous_hash}
        ).encode("ascii")
        return hashlib.sha256(material).hexdigest()

    def _append_event(self, event_type: str, payload: Mapping[str, Any]) -> str:
        row = self._connection.execute(
            "SELECT event_hash FROM dynamic_task_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous = _GENESIS if row is None else str(row["event_hash"])
        event_hash = self._event_hash(event_type, payload, previous)
        self._connection.execute(
            "INSERT INTO dynamic_task_events(event_type,payload,previous_hash,event_hash,created_at) "
            "VALUES(?,?,?,?,?)",
            (event_type, canonical_json(payload), previous, event_hash, time.time()),
        )
        return event_hash

    def _artifacts(self) -> dict[str, DynamicTaskArtifact]:
        artifacts: dict[str, DynamicTaskArtifact] = {}
        rows = self._connection.execute(
            "SELECT artifact_id,descriptor,archive FROM dynamic_task_artifacts ORDER BY artifact_id"
        )
        for row in rows:
            try:
                raw = json.loads(str(row["descriptor"]))
                if not isinstance(raw, dict):
                    raise ValueError("descriptor is not an object")
                artifact = DynamicTaskArtifact.from_mapping(raw)
                archive = bytes(row["archive"])
                if (
                    artifact.artifact_id != row["artifact_id"]
                    or hashlib.sha256(archive).hexdigest() != artifact.archive_sha256
                    or len(archive) != artifact.size_bytes
                ):
                    raise ValueError("artifact bytes do not match descriptor")
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise DynamicTaskIntegrityError("dynamic task artifact integrity check failed") from exc
            artifacts[artifact.artifact_id] = artifact
        return artifacts

    def _replay(self) -> dict[str, DynamicTaskRecord]:
        artifacts = self._artifacts()
        records: dict[str, DynamicTaskRecord] = {}
        previous = _GENESIS
        rows = self._connection.execute(
            "SELECT sequence,event_type,payload,previous_hash,event_hash "
            "FROM dynamic_task_events ORDER BY sequence"
        )
        for row in rows:
            try:
                payload = json.loads(str(row["payload"]))
                if not isinstance(payload, dict):
                    raise ValueError("event payload is not an object")
                event_type = str(row["event_type"])
                event_hash = str(row["event_hash"])
                if row["previous_hash"] != previous or event_hash != self._event_hash(
                    event_type, payload, previous
                ):
                    raise ValueError("event hash chain mismatch")
                previous = event_hash
                artifact_id = payload.get("artifact_id")
                if not isinstance(artifact_id, str):
                    raise ValueError("event artifact_id is missing")
                if event_type == "task_registered":
                    if artifact_id in records or artifact_id not in artifacts:
                        raise ValueError("task registration is duplicated or missing bytes")
                    required = {
                        "artifact_id",
                        "origin",
                        "creator_generation",
                        "source_spec_id",
                        "source_evidence_ids",
                        "eligible_generation",
                        "status",
                        "validation",
                    }
                    if set(payload) != required or not isinstance(payload["validation"], dict):
                        raise ValueError("task registration payload is malformed")
                    registered = DynamicTaskRecord(
                        artifacts[artifact_id],
                        DynamicTaskOrigin(payload["origin"]),
                        payload["creator_generation"],
                        payload["source_spec_id"],
                        tuple(payload["source_evidence_ids"]),
                        payload["eligible_generation"],
                        DynamicTaskStatus(payload["status"]),
                        TaskValidationEvidence.from_mapping(payload["validation"]),
                        event_hash,
                    )
                    expected_status = (
                        DynamicTaskStatus.REJECTED
                        if not registered.validation.valid
                        else (
                            DynamicTaskStatus.FIXED_ANCHOR
                            if registered.origin is DynamicTaskOrigin.FIXED_ANCHOR
                            else DynamicTaskStatus.QUARANTINED
                        )
                    )
                    if registered.status is not expected_status:
                        raise ValueError("task registration starts from an invalid state")
                    records[artifact_id] = registered
                    continue
                record = records.get(artifact_id)
                if record is None:
                    raise ValueError("task transition precedes registration")
                if event_type == "holdout_recorded":
                    if set(payload) != {"artifact_id", "evaluated_generation", "accepted", "evidence_id"}:
                        raise ValueError("holdout payload is malformed")
                    if record.status is not DynamicTaskStatus.QUARANTINED:
                        raise ValueError("holdout transition starts from an invalid state")
                    evaluated = payload["evaluated_generation"]
                    if (
                        isinstance(evaluated, bool)
                        or not isinstance(evaluated, int)
                        or evaluated < record.eligible_generation
                    ):
                        raise ValueError("holdout generation violates the delay")
                    if not isinstance(payload["accepted"], bool):
                        raise ValueError("holdout accepted flag is not a bool")
                    if (
                        not isinstance(payload["evidence_id"], str)
                        or not payload["evidence_id"]
                        or len(payload["evidence_id"]) > 256
                    ):
                        raise ValueError("holdout evidence_id is invalid")
                    status = (
                        DynamicTaskStatus.HOLDOUT_PASSED
                        if payload["accepted"] is True
                        else DynamicTaskStatus.REJECTED
                    )
                    records[artifact_id] = replace(record, status=status, revision=event_hash)
                elif event_type == "task_promoted_hof":
                    if set(payload) != {"artifact_id"} or record.status is not DynamicTaskStatus.HOLDOUT_PASSED:
                        raise ValueError("hall-of-fame transition starts from an invalid state")
                    records[artifact_id] = replace(
                        record, status=DynamicTaskStatus.HALL_OF_FAME, revision=event_hash
                    )
                elif event_type == "task_retired":
                    if set(payload) != {"artifact_id", "reason"} or record.status is not DynamicTaskStatus.HALL_OF_FAME:
                        raise ValueError("retirement transition starts from an invalid state")
                    records[artifact_id] = replace(
                        record, status=DynamicTaskStatus.RETIRED, revision=event_hash
                    )
                else:
                    raise ValueError("unknown dynamic task event")
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise DynamicTaskIntegrityError(
                    f"dynamic task event replay failed at sequence {row['sequence']}"
                ) from exc
        if set(artifacts) != set(records):
            raise DynamicTaskIntegrityError("dynamic task artifact has no registration event")
        return records

    def register(
        self,
        artifact: DynamicTaskArtifact,
        archive: bytes,
        report: TaskPackValidation,
        *,
        creator_generation: int,
        source_spec_id: str,
        source_evidence_ids: tuple[str, ...],
        holdout_delay: int,
        origin: DynamicTaskOrigin,
    ) -> DynamicTaskRecord:
        if hashlib.sha256(archive).hexdigest() != artifact.archive_sha256 or len(archive) != artifact.size_bytes:
            raise ValueError("artifact archive does not match its descriptor")
        if (
            isinstance(creator_generation, bool)
            or not isinstance(creator_generation, int)
            or creator_generation < 1
        ):
            raise ValueError("creator_generation must be positive")
        if isinstance(holdout_delay, bool) or not isinstance(holdout_delay, int) or holdout_delay < 1:
            raise ValueError("holdout_delay must be at least one generation")
        if not isinstance(origin, DynamicTaskOrigin):
            raise TypeError("origin must be a DynamicTaskOrigin")
        validation = TaskValidationEvidence.from_report(artifact.artifact_id, report)
        if not report.valid:
            status = DynamicTaskStatus.REJECTED
        elif origin is DynamicTaskOrigin.FIXED_ANCHOR:
            status = DynamicTaskStatus.FIXED_ANCHOR
        else:
            status = DynamicTaskStatus.QUARANTINED
        payload = {
            "artifact_id": artifact.artifact_id,
            "origin": origin.value,
            "creator_generation": creator_generation,
            "source_spec_id": source_spec_id,
            "source_evidence_ids": list(source_evidence_ids),
            "eligible_generation": creator_generation + holdout_delay,
            "status": status.value,
            "validation": validation.to_mapping(),
        }
        provisional = DynamicTaskRecord(
            artifact,
            origin,
            creator_generation,
            source_spec_id,
            source_evidence_ids,
            creator_generation + holdout_delay,
            status,
            validation,
            _GENESIS,
        )
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                records = self._replay()
                existing = records.get(artifact.artifact_id)
                if existing is not None:
                    if existing.origin is not origin:
                        raise DynamicTaskConflictError(
                            "a content-addressed task cannot be reclassified between anchor and dynamic origins"
                        )
                    self._connection.execute("COMMIT")
                    return existing
                self._connection.execute(
                    "INSERT INTO dynamic_task_artifacts(artifact_id,descriptor,archive) VALUES(?,?,?)",
                    (artifact.artifact_id, canonical_json(artifact.to_mapping()), archive),
                )
                revision = self._append_event("task_registered", payload)
                self._connection.execute("COMMIT")
            except BaseException:
                self._connection.execute("ROLLBACK")
                raise
        return replace(provisional, revision=revision)

    def record(self, artifact_id: str) -> DynamicTaskRecord:
        with self._lock:
            try:
                return self._replay()[artifact_id]
            except KeyError as exc:
                raise DynamicTaskRegistryError("unknown dynamic task artifact") from exc

    def records(self) -> tuple[DynamicTaskRecord, ...]:
        with self._lock:
            records = self._replay()
            return tuple(records[key] for key in sorted(records))

    def record_holdout(
        self,
        artifact_id: str,
        *,
        evaluated_generation: int,
        accepted: bool,
        evidence_id: str,
        expected_revision: str,
    ) -> DynamicTaskRecord:
        if not isinstance(accepted, bool):
            raise TypeError("accepted must be a bool")
        if not isinstance(evidence_id, str) or not evidence_id or len(evidence_id) > 256:
            raise ValueError("evidence_id must be bounded non-empty text")
        payload = {
            "artifact_id": artifact_id,
            "evaluated_generation": evaluated_generation,
            "accepted": accepted,
            "evidence_id": evidence_id,
        }
        return self._transition(
            artifact_id,
            expected_revision,
            "holdout_recorded",
            payload,
            required_status=DynamicTaskStatus.QUARANTINED,
            evaluated_generation=evaluated_generation,
        )

    def promote_hall_of_fame(
        self, artifact_id: str, *, expected_revision: str
    ) -> DynamicTaskRecord:
        return self._transition(
            artifact_id,
            expected_revision,
            "task_promoted_hof",
            {"artifact_id": artifact_id},
            required_status=DynamicTaskStatus.HOLDOUT_PASSED,
        )

    def retire(
        self, artifact_id: str, reason: str, *, expected_revision: str
    ) -> DynamicTaskRecord:
        if not isinstance(reason, str) or not reason or reason.strip() != reason or len(reason) > 512:
            raise ValueError("retirement reason must be bounded non-empty text")
        return self._transition(
            artifact_id,
            expected_revision,
            "task_retired",
            {"artifact_id": artifact_id, "reason": reason},
            required_status=DynamicTaskStatus.HALL_OF_FAME,
        )

    def _transition(
        self,
        artifact_id: str,
        expected_revision: str,
        event_type: str,
        payload: Mapping[str, Any],
        *,
        required_status: DynamicTaskStatus,
        evaluated_generation: int | None = None,
    ) -> DynamicTaskRecord:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                records = self._replay()
                record = records.get(artifact_id)
                if record is None:
                    raise DynamicTaskRegistryError("unknown dynamic task artifact")
                if record.revision != expected_revision:
                    raise DynamicTaskConflictError("dynamic task revision changed")
                if record.origin is not DynamicTaskOrigin.DYNAMIC or record.status is not required_status:
                    raise DynamicTaskEligibilityError("dynamic task is not eligible for this transition")
                if evaluated_generation is not None:
                    if (
                        isinstance(evaluated_generation, bool)
                        or not isinstance(evaluated_generation, int)
                        or evaluated_generation < record.eligible_generation
                    ):
                        raise DynamicTaskEligibilityError(
                            "same-generation or premature holdout evidence cannot prove a task"
                        )
                self._append_event(event_type, payload)
                updated = self._replay()[artifact_id]
                self._connection.execute("COMMIT")
                return updated
            except BaseException:
                self._connection.execute("ROLLBACK")
                raise

    def _anchor_members(
        self, target_generation: int, *, known: set[str]
    ) -> list[CohortMember]:
        with self._lock:
            records = self._replay().values()

        def _shuffle(anchor: CohortMember) -> bytes:
            return hashlib.sha256(
                f"dynamic cohort v1\0{target_generation}\0{anchor.artifact_id}".encode("ascii")
            ).digest()

        return sorted(
            (
                CohortMember(
                    record.artifact.artifact_id,
                    CohortTier.HALL_OF_FAME,
                    record.creator_generation,
                    record.revision,
                )
                for record in records
                if (
                    record.origin is DynamicTaskOrigin.FIXED_ANCHOR
                    and record.status is DynamicTaskStatus.FIXED_ANCHOR
                    and record.creator_generation < target_generation
                    and record.artifact.artifact_id not in known
                )
            ),
            key=_shuffle,
        )

    def select_dynamic_cohort(
        self, target_generation: int, *, limit: int | None = None
    ) -> DynamicTaskCohort:
        if isinstance(target_generation, bool) or not isinstance(target_generation, int) or target_generation < 1:
            raise ValueError("target_generation must be positive")
        if limit is not None and (isinstance(limit, bool) or not isinstance(limit, int) or limit < 1):
            raise ValueError("limit must be a positive integer or None")
        with self._lock:
            records = self._replay().values()

        def _shuffle(member: CohortMember) -> bytes:
            return hashlib.sha256(
                f"dynamic cohort v1\0{target_generation}\0{member.artifact_id}".encode("ascii")
            ).digest()

        dynamic_members: list[CohortMember] = []
        # Dynamic tasks are the long-term curriculum source.  Fresh holdout
        # tasks are the newest Judge-authored curriculum: schedule them first
        # so a forged task is adopted by the very next cycle instead of losing
        # a hash lottery against veteran regression tasks.
        for record in records:
            if (
                record.origin is not DynamicTaskOrigin.DYNAMIC
                or record.creator_generation >= target_generation
            ):
                continue
            if record.status is DynamicTaskStatus.HALL_OF_FAME:
                tier = CohortTier.HALL_OF_FAME
            elif (
                record.status is DynamicTaskStatus.QUARANTINED
                and record.eligible_generation <= target_generation
            ):
                tier = CohortTier.FRESH_HOLDOUT
            else:
                continue
            dynamic_members.append(
                CohortMember(
                    record.artifact.artifact_id,
                    tier,
                    record.creator_generation,
                    record.revision,
                )
            )
        fresh = sorted(
            (member for member in dynamic_members if member.tier is CohortTier.FRESH_HOLDOUT),
            key=_shuffle,
        )
        regression = sorted(
            (member for member in dynamic_members if member.tier is not CohortTier.FRESH_HOLDOUT),
            key=_shuffle,
        )
        members = fresh + regression
        # Anchors retire gradually: they only backfill the slots the dynamic
        # bank cannot fill yet, instead of vanishing the moment one dynamic
        # task exists (which would collapse the cohort to a single task).
        if limit is None:
            if not members:
                members = self._anchor_members(target_generation, known=set())
        else:
            members = members[:limit]
            if len(members) < limit:
                members = members + self._anchor_members(
                    target_generation,
                    known={member.artifact_id for member in members},
                )[: limit - len(members)]
        selected = tuple(members)
        return DynamicTaskCohort.create(target_generation, selected)

    def archive(self, artifact_id: str) -> bytes:
        with self._lock:
            row = self._connection.execute(
                "SELECT archive FROM dynamic_task_artifacts WHERE artifact_id=?", (artifact_id,)
            ).fetchone()
            if row is None:
                raise DynamicTaskRegistryError("unknown dynamic task artifact")
            payload = bytes(cast(sqlite3.Row, row)["archive"])
            artifact = self.record(artifact_id).artifact
            if hashlib.sha256(payload).hexdigest() != artifact.archive_sha256:
                raise DynamicTaskIntegrityError("dynamic task archive integrity check failed")
            return payload
