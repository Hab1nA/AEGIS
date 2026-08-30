"""Trusted genesis seeding for the dynamic-only v2 task bank.

The v2 design intentionally forbids a fixed task-pack curriculum.  A dynamic
campaign therefore needs a small number of repository-owned anchor tasks that
are content-addressed and mutation-validated through the exact same
``TaskForge`` boundary as Judge-forged tasks, then registered as
``FIXED_ANCHOR``.  Anchors are only ever returned by the cohort provider as a
cold-start fallback while no eligible dynamic task exists yet.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from aegis.taskpacks.builtin import load_builtin_python_taskpacks
from aegis.taskpacks.manifest import TaskPack
from aegis.taskpacks.validation import TaskPackRunner

from .forge import TaskForge
from .models import DynamicTaskOrigin, DynamicTaskRecord
from .registry import DynamicTaskRegistry

_SOURCE_SPEC_PREFIX = "builtin-anchor-v1:"


class GenesisSeeder:
    """Idempotently register built-in anchors when the task bank is empty."""

    def __init__(
        self,
        registry: DynamicTaskRegistry,
        forge: TaskForge,
        *,
        builtin_root: Path | None = None,
    ) -> None:
        self.registry = registry
        self.forge = forge
        self.builtin_root = builtin_root

    def seed(
        self,
        runner: TaskPackRunner,
        *,
        creator_generation: int = 1,
    ) -> tuple[DynamicTaskRecord, ...]:
        known = {record.artifact.task_id for record in self.registry.records()}
        packs = [
            pack
            for pack in load_builtin_python_taskpacks(self.builtin_root)
            if pack.manifest.task_id not in known
        ]
        if not packs:
            return ()
        records: list[DynamicTaskRecord] = []
        for pack in sorted(packs, key=lambda item: (item.manifest.task_id, item.manifest.version)):
            records.append(
                self.forge.forge(
                    pack,
                    runner,
                    creator_generation=creator_generation,
                    source_spec_id=self._source_spec_id(pack),
                    source_evidence_ids=(),
                    holdout_delay=1,
                    origin=DynamicTaskOrigin.FIXED_ANCHOR,
                )
            )
        return tuple(records)

    @classmethod
    def _source_spec_id(cls, pack: TaskPack) -> str:
        identity = (
            f"{pack.manifest.task_id}:{pack.manifest.version}:{pack.manifest.content_hash}"
        ).encode("utf-8")
        return _SOURCE_SPEC_PREFIX + hashlib.sha256(identity).hexdigest()
