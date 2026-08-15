"""OpenEvolve-style quality-diversity population archive.

MAP-Elites keeps one champion per behavior cell.  A behavior descriptor is a
canonical tuple derived from the candidate (surface, changed harness roots,
targeted failure mode, proposal objective) so that the system keeps exploring
distinct regions of harness space instead of converging on one file or one
failure mode.  The archive is append-only over the EventStore and replays into
an in-memory bounded grid; a new candidate only replaces an existing cell
member when its fitness is strictly better.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from aegis.event_store import EventStore
from aegis.models import AuditEvent, thaw_json

from .surfaces import EvolutionSurface

POPULATION_REGISTERED = "evolution_population_registered_v1"

_KNOWN_EVENTS = frozenset({POPULATION_REGISTERED})
_CONTENT_ID = re.compile(r"evolution-candidate-sha256:[0-9a-f]{64}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")

DEFAULT_MAX_CELLS = 256


class PopulationArchiveError(RuntimeError):
    """A persistence or integrity failure in the population archive."""


def population_stream_id(campaign_id: str) -> str:
    if not isinstance(campaign_id, str) or not campaign_id or campaign_id != campaign_id.strip():
        raise PopulationArchiveError("campaign_id must be non-empty trimmed text")
    return f"{campaign_id}:evolution:population:v2"


def _normalize_cell(cell: Sequence[Any]) -> tuple[str, ...]:
    """Make every cell element a hashable string (nested lists/tuples from
    replay cannot be dict keys)."""
    normalized: list[str] = []
    for item in cell:
        if isinstance(item, str):
            normalized.append(item)
        else:
            normalized.append(
                json.dumps(item, sort_keys=True, separators=(",", ":"))
            )
    return tuple(normalized)


def behavior_descriptor(
    *,
    surface: EvolutionSurface,
    changed_roots: tuple[str, ...] = (),
    failure_mode: str | None = None,
    objective: str = "",
) -> tuple[str, ...]:
    """Canonical MAP-Elites cell key for one candidate."""
    roots_key = "|".join(tuple(sorted(set(changed_roots)))[:3])
    failure_digest = (
        hashlib.sha256(failure_mode.encode("utf-8")).hexdigest()[:12]
        if failure_mode
        else ""
    )
    objective_digest = (
        hashlib.sha256(objective.encode("utf-8")).hexdigest()[:8]
        if objective
        else ""
    )
    return (surface.value, roots_key, failure_digest, objective_digest)


def harness_changed_roots(changes: Mapping[str, Any]) -> tuple[str, ...]:
    """Derive the top-level harness roots touched by a harness-code patch."""
    roots: set[str] = set()
    for item in changes.get("changes", ()):
        if not isinstance(item, Mapping) or not isinstance(item.get("path"), str):
            continue
        parts = item["path"].split("/")
        if len(parts) >= 3 and parts[0] == "src" and parts[1] == "aegis":
            roots.add(parts[2])
        else:
            roots.add(parts[0])
    return tuple(sorted(roots))


def behavior_roots(
    content: Mapping[str, Any],
    *,
    surface: EvolutionSurface,
) -> tuple[str, ...]:
    """Behavior roots per surface: for harness code, the touched harness
    modules; for workflows, the leading stage; otherwise a surface marker."""
    if surface is EvolutionSurface.HARNESS_CODE:
        return harness_changed_roots(content)
    if surface is EvolutionSurface.WORKFLOW:
        plan = content.get("stage_plan")
        if isinstance(plan, (list, tuple)) and plan and isinstance(plan[0], str):
            return (f"workflow:{plan[0][:64]}",)
        return ("workflow",)
    return (surface.value,)


@dataclass(frozen=True, slots=True)
class PopulationEntry:
    cell: tuple[str, ...]
    candidate_id: str
    fitness: float
    evidence_id: str
    sequence: int
    descriptor: tuple[str, ...]

    def __post_init__(self) -> None:
        if _CONTENT_ID.fullmatch(self.candidate_id) is None:
            raise PopulationArchiveError("population candidate_id is invalid")
        if isinstance(self.fitness, bool) or not isinstance(self.fitness, (int, float)):
            raise PopulationArchiveError("population fitness must be numeric")
        if not 0.0 <= float(self.fitness) <= 1.0:
            raise PopulationArchiveError("population fitness must be in [0, 1]")
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int) or self.sequence < 0:
            raise PopulationArchiveError("population sequence must be non-negative")
        if not self.cell:
            raise PopulationArchiveError("population cell must not be empty")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "cell": list(self.cell),
            "candidate_id": self.candidate_id,
            "fitness": self.fitness,
            "evidence_id": self.evidence_id,
            "sequence": self.sequence,
            "descriptor": list(self.descriptor),
        }


@dataclass(frozen=True, slots=True)
class PopulationProjection:
    campaign_id: str
    stream_id: str
    sequence: int = 0
    cells: Mapping[tuple[str, ...], PopulationEntry] = field(default_factory=dict)
    entries: tuple[PopulationEntry, ...] = ()

    def __post_init__(self) -> None:
        if self.stream_id != population_stream_id(self.campaign_id):
            raise PopulationArchiveError("population stream id does not match the campaign")
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int) or self.sequence < 0:
            raise PopulationArchiveError("population sequence must be non-negative")
        object.__setattr__(self, "cells", MappingProxyType(dict(self.cells)))


class PopulationArchive:
    """Bounded MAP-Elites archive persisted on the campaign event stream."""

    def __init__(
        self,
        store: EventStore,
        campaign_id: str,
        *,
        max_cells: int = DEFAULT_MAX_CELLS,
    ) -> None:
        if not isinstance(store, EventStore):
            raise TypeError("store must be an EventStore")
        if isinstance(max_cells, bool) or not isinstance(max_cells, int):
            raise PopulationArchiveError("max_cells must be an integer")
        if max_cells < 1:
            raise PopulationArchiveError("max_cells must be positive")
        self._store = store
        self._campaign_id = str(campaign_id)
        self._stream_id = population_stream_id(self._campaign_id)
        self._max_cells = max_cells
        self._projection = PopulationProjection(self._campaign_id, self._stream_id)
        self.refresh()

    def set_max_cells(self, max_cells: int) -> None:
        if isinstance(max_cells, bool) or not isinstance(max_cells, int) or max_cells < 1:
            raise PopulationArchiveError("max_cells must be a positive integer")
        self._max_cells = max_cells
        self.refresh()
        if len(self._projection.cells) > max_cells:
            retained = sorted(
                self._projection.cells.items(), key=lambda item: item[1].sequence, reverse=True
            )[:max_cells]
            self._projection = PopulationProjection(
                self._campaign_id, self._stream_id, self._projection.sequence,
                dict(retained), self._projection.entries,
            )

    def refresh(self) -> None:
        events = self._store.read(self._stream_id, after_sequence=0)
        projection = PopulationProjection(self._campaign_id, self._stream_id)
        for event in events:
            projection = self._apply_event(projection, event)
        self._projection = projection

    def register(
        self,
        *,
        candidate_id: str,
        cell: tuple[str, ...],
        fitness: float,
        evidence_id: str,
        descriptor: tuple[str, ...],
    ) -> PopulationEntry:
        cell = _normalize_cell(cell)
        descriptor = _normalize_cell(descriptor)
        current = self._projection.cells.get(cell)
        if current is not None and fitness <= current.fitness:
            return current
        payload = {
            "schema_version": 2,
            "cell": list(cell),
            "candidate_id": candidate_id,
            "fitness": fitness,
            "evidence_id": evidence_id,
            "descriptor": list(descriptor),
        }
        event = self._store.append_if_sequence(
            self._stream_id,
            self._projection.sequence,
            POPULATION_REGISTERED,
            payload,
        )
        updated = self._apply_event(self._projection, event)
        if len(updated.cells) > self._max_cells:
            # Keep the archive bounded: drop the oldest non-champion cell.
            overflow = sorted(
                (
                    (entry.sequence, cell_key)
                    for cell_key, entry in updated.cells.items()
                )
            )
            while len(updated.cells) > self._max_cells and overflow:
                _, oldest = overflow.pop(0)
                cells = dict(updated.cells)
                cells.pop(oldest, None)
                updated = PopulationProjection(
                    self._campaign_id,
                    self._stream_id,
                    updated.sequence,
                    cells,
                    updated.entries,
                )
            self._projection = updated
        else:
            self._projection = updated
        return self._projection.cells[cell]

    def cells(self) -> Mapping[tuple[str, ...], PopulationEntry]:
        return self._projection.cells

    def diversity_report(self) -> Mapping[str, Any]:
        cells = self._projection.cells
        surfaces: dict[str, int] = {}
        roots: dict[str, int] = {}
        for entry in cells.values():
            surface = entry.descriptor[0] if entry.descriptor else "unknown"
            surfaces[surface] = surfaces.get(surface, 0) + 1
            if len(entry.descriptor) > 1:
                for root in (
                    entry.descriptor[1].split("|") if entry.descriptor[1] else ()
                ):
                    roots[root] = roots.get(root, 0) + 1
        return {
            "cell_count": len(cells),
            "max_cells": self._max_cells,
            "surfaces": surfaces,
            "harness_roots": roots,
            "entry_count": len(self._projection.entries),
        }

    def _apply_event(
        self, projection: PopulationProjection, event: AuditEvent
    ) -> PopulationProjection:
        if event.campaign_id != projection.stream_id:
            raise PopulationArchiveError("population event belongs to another stream")
        if event.sequence != projection.sequence + 1:
            raise PopulationArchiveError("population event sequence is not contiguous")
        if event.event_type not in _KNOWN_EVENTS:
            return PopulationProjection(
                projection.campaign_id,
                projection.stream_id,
                event.sequence,
                projection.cells,
                projection.entries,
            )
        payload = thaw_json(event.payload)
        if not isinstance(payload, Mapping):
            raise PopulationArchiveError("population event payload must be an object")
        cell = _normalize_cell(payload["cell"])
        descriptor = _normalize_cell(payload.get("descriptor", cell))
        entry = PopulationEntry(
            cell=cell,
            candidate_id=payload["candidate_id"],
            fitness=float(payload["fitness"]),
            evidence_id=payload["evidence_id"],
            sequence=event.sequence,
            descriptor=descriptor,
        )
        cells = dict(projection.cells)
        current = cells.get(cell)
        if current is None or entry.fitness > current.fitness:
            cells[cell] = entry
        return PopulationProjection(
            projection.campaign_id,
            projection.stream_id,
            event.sequence,
            cells,
            projection.entries + (entry,),
        )


__all__ = [
    "DEFAULT_MAX_CELLS",
    "PopulationArchive",
    "PopulationArchiveError",
    "PopulationEntry",
    "behavior_descriptor",
    "behavior_roots",
    "harness_changed_roots",
    "population_stream_id",
]
