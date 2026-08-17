"""Declarative Judge task specifications and the control-plane TaskPackBuilder.

The Judge declares task content as plain text/JSON task specs; the control
plane owns canonical layout, manifest and content hash, task-id preflight,
file whitelisting, validation dry-run and atomic registration.  Model-written
workspace files no longer participate in task authoring.
"""

from __future__ import annotations

import json
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from aegis.dynamic_tasks.forge import artifact_from_pack, canonical_taskpack_archive
from aegis.dynamic_tasks.models import DynamicTaskOrigin, DynamicTaskRecord
from aegis.dynamic_tasks.registry import DynamicTaskRegistry
from aegis.taskpacks.builtin import load_builtin_python_taskpacks
from aegis.taskpacks.manifest import TaskPack, compute_tree_hash
from aegis.taskpacks.validation import TaskPackRunner, validate_taskpack

TASK_SPEC_MAX_TOTAL_BYTES = 256 * 1024
TASK_SPEC_MAX_PROMPT_BYTES = 32 * 1024
TASK_SPEC_MAX_SOURCE_BYTES = 64 * 1024
TASK_SPEC_MAX_CASES = 100
TASK_SPEC_MAX_MUTANTS = 8
_TASK_ID_RE = re.compile(r"^[a-z][a-z0-9-]{1,127}$")
_MUTANT_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


class TaskSpecError(ValueError):
    """A declared task specification is invalid or conflicts with the bank."""


def _bounded_text(data: Mapping[str, Any], key: str, limit: int, *, empty_ok: bool = False) -> str:
    value = data[key]
    if not isinstance(value, str):
        raise TaskSpecError(f"{key} must be a string")
    if not empty_ok and not value.strip():
        raise TaskSpecError(f"{key} must not be empty")
    if len(value.encode("utf-8")) > limit:
        raise TaskSpecError(f"{key} exceeds {limit} bytes")
    return value


def _python_source(value: object, task_id: str, label: str) -> str:
    if not isinstance(value, str):
        raise TaskSpecError(f"{label} must be a string")
    if len(value.encode("utf-8")) > TASK_SPEC_MAX_SOURCE_BYTES:
        raise TaskSpecError(f"{label} exceeds {TASK_SPEC_MAX_SOURCE_BYTES} bytes")
    try:
        compile(value, f"<task-spec:{task_id}:{label}>", "exec")
    except SyntaxError as exc:
        raise TaskSpecError(f"{label} is not valid Python: {exc}") from exc
    return value


def _cases_file(value: object, key: str) -> Mapping[str, Any]:
    """Validate a sealed-suite cases.json file object ({version, cases})."""
    if not isinstance(value, Mapping):
        raise TaskSpecError(f"{key} must be a JSON object with version and cases")
    if set(value) != {"version", "cases"} or value["version"] != 1:
        raise TaskSpecError(f"{key} must have the shape {{version: 1, cases: [...]}}")
    cases = value["cases"]
    if not isinstance(cases, list) or not 1 <= len(cases) <= TASK_SPEC_MAX_CASES:
        raise TaskSpecError(f"{key} must contain 1..{TASK_SPEC_MAX_CASES} cases")
    for case in cases:
        if not isinstance(case, Mapping) or set(case) != {"name", "steps"}:
            raise TaskSpecError(f"{key} cases must contain exactly name and steps")
        name = case["name"]
        steps = case["steps"]
        if not isinstance(name, str) or not name or len(name) > 128:
            raise TaskSpecError(f"{key} case name is invalid")
        if (
            not isinstance(steps, list)
            or not 1 <= len(steps) <= 128
            or not all(isinstance(step, Mapping) for step in steps)
        ):
            raise TaskSpecError(f"{key} case steps are invalid")
    try:
        json.dumps(value, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise TaskSpecError(f"{key} must be strict finite JSON: {exc}") from exc
    return dict(value)


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True, slots=True)
class TaskMutantSpec:
    name: str
    solution: str


@dataclass(frozen=True, slots=True)
class TaskSpec:
    task_id: str
    prompt: str
    public_cases: Mapping[str, Any]
    public_test: str
    hidden_cases: Mapping[str, Any]
    reference_solution: str
    defect_solution: str
    mutants: tuple[TaskMutantSpec, ...]

    _FIELDS = frozenset(
        {
            "task_id",
            "prompt",
            "public_cases",
            "public_test",
            "hidden_cases",
            "reference_solution",
            "defect_solution",
            "mutants",
        }
    )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "prompt": self.prompt,
            "public_cases": dict(self.public_cases),
            "public_test": self.public_test,
            "hidden_cases": dict(self.hidden_cases),
            "reference_solution": self.reference_solution,
            "defect_solution": self.defect_solution,
            "mutants": [{"name": item.name, "solution": item.solution} for item in self.mutants],
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "TaskSpec":
        if not isinstance(data, Mapping):
            raise TaskSpecError("task spec must be a JSON object")
        if set(data) != cls._FIELDS:
            missing = sorted(cls._FIELDS - set(data))
            unknown = sorted(set(data) - cls._FIELDS)
            raise TaskSpecError(f"task spec fields invalid: missing={missing} unknown={unknown}")
        task_id = data["task_id"]
        if not isinstance(task_id, str) or not _TASK_ID_RE.fullmatch(task_id):
            raise TaskSpecError("task_id must match ^[a-z][a-z0-9-]{1,127}$")
        prompt = _bounded_text(data, "prompt", TASK_SPEC_MAX_PROMPT_BYTES)
        public_test = _python_source(data["public_test"], task_id, "public_test")
        reference = _python_source(data["reference_solution"], task_id, "reference_solution")
        defect = _python_source(data["defect_solution"], task_id, "defect_solution")
        public_cases = _cases_file(data["public_cases"], "public_cases")
        hidden_cases = _cases_file(data["hidden_cases"], "hidden_cases")
        mutants_raw = data["mutants"]
        if not isinstance(mutants_raw, list) or not 1 <= len(mutants_raw) <= TASK_SPEC_MAX_MUTANTS:
            raise TaskSpecError(f"mutants must contain 1..{TASK_SPEC_MAX_MUTANTS} entries")
        mutants: list[TaskMutantSpec] = []
        for raw in mutants_raw:
            if not isinstance(raw, Mapping) or set(raw) != {"name", "solution"}:
                raise TaskSpecError("mutant entries must contain exactly name and solution")
            name = raw["name"]
            if not isinstance(name, str) or not _MUTANT_NAME_RE.fullmatch(name):
                raise TaskSpecError("mutant name must match ^[a-z][a-z0-9_]{0,63}$")
            solution = _python_source(raw["solution"], task_id, f"mutant:{name}")
            mutants.append(TaskMutantSpec(name, solution))
        if len({item.name for item in mutants}) != len(mutants):
            raise TaskSpecError("mutant names must be unique")
        spec = cls(
            task_id,
            prompt,
            public_cases,
            public_test,
            hidden_cases,
            reference,
            defect,
            tuple(mutants),
        )
        encoded = json.dumps(spec.to_mapping(), ensure_ascii=False, allow_nan=False).encode("utf-8")
        if len(encoded) > TASK_SPEC_MAX_TOTAL_BYTES:
            raise TaskSpecError(f"task spec exceeds {TASK_SPEC_MAX_TOTAL_BYTES} bytes")
        return spec


class TaskPackBuilder:
    """Materialize declarative Judge specs into validated, banked task packs."""

    def __init__(self, registry: DynamicTaskRegistry, runner: TaskPackRunner) -> None:
        self.registry = registry
        self.runner = runner

    def reserved_task_ids(self) -> frozenset[str]:
        """Every task id that a new spec must not reuse."""
        reserved = {pack.manifest.task_id for pack in load_builtin_python_taskpacks()}
        reserved.update(record.artifact.task_id for record in self.registry.records())
        return frozenset(reserved)

    def preflight_task_id(self, task_id: str) -> None:
        if task_id in self.reserved_task_ids():
            raise TaskSpecError(
                f"task_id {task_id!r} is already used by a built-in anchor or the dynamic task "
                "bank; declare a different slug"
            )

    def materialize(self, spec: TaskSpec, root: Path) -> TaskPack:
        """Write the canonical pack layout under root and verify integrity."""
        pack_root = root / "drafts" / spec.task_id
        public = pack_root / "public"
        hidden = pack_root / "hidden"
        reference = pack_root / "reference"
        defect = pack_root / "defect"
        for directory in (pack_root, public, hidden, reference, defect, pack_root / "mutants"):
            directory.mkdir(parents=True, exist_ok=False)
        mutant_dirs: list[str] = []
        for mutant in spec.mutants:
            mdir = pack_root / "mutants" / mutant.name
            mdir.mkdir(parents=False, exist_ok=False)
            (mdir / "solution.py").write_text(mutant.solution, encoding="utf-8")
            mutant_dirs.append(f"mutants/{mutant.name}")
        (pack_root / "prompt.md").write_text(spec.prompt, encoding="utf-8")
        (public / "cases.json").write_text(_canonical_json(spec.public_cases), encoding="utf-8")
        (public / "test_solution.py").write_text(spec.public_test, encoding="utf-8")
        (hidden / "cases.json").write_text(_canonical_json(spec.hidden_cases), encoding="utf-8")
        (reference / "solution.py").write_text(spec.reference_solution, encoding="utf-8")
        (defect / "solution.py").write_text(spec.defect_solution, encoding="utf-8")
        digest = compute_tree_hash(pack_root, exclude=frozenset({"manifest.json"}))
        manifest = {
            "task_id": spec.task_id,
            "version": 1,
            "language": "python",
            "public_dir": "public",
            "hidden_dir": "hidden",
            "reference_dir": "reference",
            "defect_dir": "defect",
            "mutant_dirs": mutant_dirs,
            "content_hash": digest,
        }
        (pack_root / "manifest.json").write_text(_canonical_json(manifest), encoding="utf-8")
        return TaskPack.load(pack_root)

    def dry_run(self, spec: TaskSpec) -> tuple[bool, tuple[str, ...]]:
        """Preflight and validate a spec without registering it."""
        self.preflight_task_id(spec.task_id)
        with tempfile.TemporaryDirectory(prefix="aegis-task-spec-dryrun-") as directory:
            root = Path(directory).resolve(strict=True)
            pack = self.materialize(spec, root)
            report = validate_taskpack(pack, self.runner)
            return report.valid, report.reasons

    def commit(
        self,
        spec: TaskSpec,
        *,
        creator_generation: int,
        source_spec_id: str,
        source_evidence_ids: Sequence[str],
        holdout_delay: int,
    ) -> DynamicTaskRecord:
        """Validate and atomically register a spec as a dynamic task."""
        self.preflight_task_id(spec.task_id)
        with tempfile.TemporaryDirectory(prefix="aegis-task-spec-commit-") as directory:
            root = Path(directory).resolve(strict=True)
            pack = self.materialize(spec, root)
            report = validate_taskpack(pack, self.runner)
            archive = canonical_taskpack_archive(pack)
            artifact = artifact_from_pack(pack, archive)
            return self.registry.register(
                artifact,
                archive,
                report,
                creator_generation=creator_generation,
                source_spec_id=source_spec_id,
                source_evidence_ids=tuple(sorted(source_evidence_ids)),
                holdout_delay=holdout_delay,
                origin=DynamicTaskOrigin.DYNAMIC,
            )
