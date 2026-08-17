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
_CLAUSE_ID_RE = re.compile(r"^[A-Z][A-Z0-9._-]{0,63}$")


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


def _cases_file(
    value: object, key: str, *, require_clause_ids: bool = False
) -> Mapping[str, Any]:
    """Validate a sealed-suite cases.json file object ({version, cases})."""
    if not isinstance(value, Mapping):
        raise TaskSpecError(f"{key} must be a JSON object with version and cases")
    if set(value) != {"version", "cases"} or value["version"] != 1:
        raise TaskSpecError(f"{key} must have the shape {{version: 1, cases: [...]}}")
    cases = value["cases"]
    if not isinstance(cases, list) or not 1 <= len(cases) <= TASK_SPEC_MAX_CASES:
        raise TaskSpecError(f"{key} must contain 1..{TASK_SPEC_MAX_CASES} cases")
    for case in cases:
        if not isinstance(case, Mapping) or set(case) != {"name", "steps", "clause_ids"}:
            raise TaskSpecError(f"{key} cases must contain exactly name, steps and clause_ids")
        name = case["name"]
        steps = case["steps"]
        clause_ids = case["clause_ids"]
        if not isinstance(name, str) or not name or len(name) > 128:
            raise TaskSpecError(f"{key} case name is invalid")
        if (
            not isinstance(steps, list)
            or not 1 <= len(steps) <= 128
            or not all(isinstance(step, Mapping) for step in steps)
        ):
            raise TaskSpecError(f"{key} case steps are invalid")
        if (
            not isinstance(clause_ids, list)
            or not clause_ids
            or not all(isinstance(item, str) and _CLAUSE_ID_RE.fullmatch(item) for item in clause_ids)
        ):
            raise TaskSpecError(f"{key} case clause_ids must be a non-empty list of clause ids")
    try:
        json.dumps(value, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise TaskSpecError(f"{key} must be strict finite JSON: {exc}") from exc
    return dict(value)


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))




def _clause_list(value: object, name: str, declared: set[str]) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or len(value) > 8:
        raise TaskSpecError(f"{name} must be a non-empty list of at most 8 clause ids")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or _CLAUSE_ID_RE.fullmatch(item) is None:
            raise TaskSpecError(f"{name} contains an invalid clause id")
        if item not in declared:
            raise TaskSpecError(f"{name} references an undeclared clause {item!r}")
        if item not in result:
            result.append(item)
    return tuple(result)


def _validate_case_clauses(
    cases_file: Mapping[str, Any], declared: set[str], label: str
) -> None:
    for case in cases_file.get("cases", []):
        if not isinstance(case, Mapping):
            continue
        for clause_id in case.get("clause_ids", []):
            if not isinstance(clause_id, str) or clause_id not in declared:
                raise TaskSpecError(f"{label} case references an undeclared clause {clause_id!r}")

@dataclass(frozen=True, slots=True)
class TaskClauseSpec:
    """One declared public contract clause a task must honor.

    Hidden cases, the defect implementation and every mutant must trace to at
    least one declared clause so the sealed evaluator proves compliance with a
    public contract instead of grading an undeclared expectation.
    """

    clause_id: str
    statement: str
    input_partition: str = ""
    expected_outcome: str = ""
    security_relevant: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.clause_id, str) or _CLAUSE_ID_RE.fullmatch(self.clause_id) is None:
            raise TaskSpecError("clause_id must match ^[A-Z][A-Z0-9._-]{0,63}$")
        if not isinstance(self.statement, str) or not self.statement.strip():
            raise TaskSpecError("clause statement must be non-empty")
        if len(self.statement.encode("utf-8")) > 512:
            raise TaskSpecError("clause statement exceeds 512 bytes")
        for name in ("input_partition", "expected_outcome"):
            value = getattr(self, name)
            if not isinstance(value, str):
                raise TaskSpecError(f"clause {name} must be a string")
            if len(value.encode("utf-8")) > 256:
                raise TaskSpecError(f"clause {name} exceeds 256 bytes")
        if not isinstance(self.security_relevant, bool):
            raise TaskSpecError("clause security_relevant must be a boolean")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "clause_id": self.clause_id,
            "statement": self.statement,
            "input_partition": self.input_partition,
            "expected_outcome": self.expected_outcome,
            "security_relevant": self.security_relevant,
        }

    @classmethod
    def from_mapping(cls, value: object) -> "TaskClauseSpec":
        if not isinstance(value, Mapping) or set(value) != {
            "clause_id",
            "statement",
            "input_partition",
            "expected_outcome",
            "security_relevant",
        }:
            raise TaskSpecError("clause entries must contain exactly clause_id, statement, input_partition, expected_outcome, security_relevant")
        return cls(
            str(value["clause_id"]),
            str(value["statement"]),
            str(value["input_partition"]),
            str(value["expected_outcome"]),
            bool(value["security_relevant"]),
        )


@dataclass(frozen=True, slots=True)
class TaskMutantSpec:
    name: str
    solution: str
    clause_ids: tuple[str, ...] = ()


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
    clauses: tuple[TaskClauseSpec, ...] = ()
    defect_clause_ids: tuple[str, ...] = ()

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
            "clauses",
            "defect_clause_ids",
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
            "mutants": [
                {
                    "name": item.name,
                    "solution": item.solution,
                    "clause_ids": list(item.clause_ids),
                }
                for item in self.mutants
            ],
            "clauses": [item.to_mapping() for item in self.clauses],
            "defect_clause_ids": list(self.defect_clause_ids),
        }

    def clause_summary(self) -> dict[str, Any]:
        return {
            "clause_ids": [item.clause_id for item in self.clauses],
            "obligations": {
                item.clause_id: (
                    "security" if item.security_relevant else "behavioral"
                )
                for item in self.clauses
            },
            "coverage": {
                "public_cases": sum(
                    1
                    for case in self.public_cases.get("cases", [])
                    if isinstance(case, Mapping) and case.get("clause_ids")
                ),
                "hidden_cases": sum(
                    1
                    for case in self.hidden_cases.get("cases", [])
                    if isinstance(case, Mapping) and case.get("clause_ids")
                ),
                "defect": bool(self.defect_clause_ids),
                "mutants": len(self.mutants),
            },
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
        public_cases = _cases_file(data["public_cases"], "public_cases", require_clause_ids=True)
        hidden_cases = _cases_file(data["hidden_cases"], "hidden_cases", require_clause_ids=True)
        clauses_raw = data["clauses"]
        if not isinstance(clauses_raw, list) or not 1 <= len(clauses_raw) <= 16:
            raise TaskSpecError("clauses must contain 1..16 entries")
        clauses = tuple(TaskClauseSpec.from_mapping(item) for item in clauses_raw)
        if len({item.clause_id for item in clauses}) != len(clauses):
            raise TaskSpecError("clause ids must be unique")
        declared = {item.clause_id for item in clauses}
        defect_clause_ids = _clause_list(data["defect_clause_ids"], "defect_clause_ids", declared)
        if not defect_clause_ids:
            raise TaskSpecError("defect_clause_ids must trace the defect to at least one clause")
        _validate_case_clauses(public_cases, declared, "public_cases")
        _validate_case_clauses(hidden_cases, declared, "hidden_cases")
        hidden_covered: set[str] = set()
        for case in hidden_cases.get("cases", []):
            if isinstance(case, Mapping):
                hidden_covered.update(
                    str(item) for item in case.get("clause_ids", []) if isinstance(item, str)
                )
        for clause in clauses:
            if clause.security_relevant and clause.clause_id not in hidden_covered:
                raise TaskSpecError(
                    f"security-relevant clause {clause.clause_id} must have at least one hidden case"
                )
        mutants_raw = data["mutants"]
        if not isinstance(mutants_raw, list) or not 1 <= len(mutants_raw) <= TASK_SPEC_MAX_MUTANTS:
            raise TaskSpecError(f"mutants must contain 1..{TASK_SPEC_MAX_MUTANTS} entries")
        mutants: list[TaskMutantSpec] = []
        for raw in mutants_raw:
            if not isinstance(raw, Mapping) or set(raw) != {"name", "solution", "clause_ids"}:
                raise TaskSpecError("mutant entries must contain exactly name, solution and clause_ids")
            name = raw["name"]
            if not isinstance(name, str) or not _MUTANT_NAME_RE.fullmatch(name):
                raise TaskSpecError("mutant name must match ^[a-z][a-z0-9_]{0,63}$")
            solution = _python_source(raw["solution"], task_id, f"mutant:{name}")
            mutant_clauses = _clause_list(raw["clause_ids"], f"mutant:{name}:clause_ids", declared)
            if not mutant_clauses:
                raise TaskSpecError(f"mutant {name} must trace to at least one clause")
            mutants.append(TaskMutantSpec(name, solution, mutant_clauses))
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
            clauses,
            defect_clause_ids,
        )
        encoded = json.dumps(spec.to_mapping(), ensure_ascii=False, allow_nan=False).encode("utf-8")
        if len(encoded) > TASK_SPEC_MAX_TOTAL_BYTES:
            raise TaskSpecError(f"task spec exceeds {TASK_SPEC_MAX_TOTAL_BYTES} bytes")
        return spec



def _strip_case_clause_ids(cases_file: Mapping[str, Any]) -> Mapping[str, Any]:
    """Sealed evaluator cases stay {name, steps}; clause traceability is
    control-plane metadata on the TaskSpec and contract.json, never part of the
    executable suite."""
    cases = []
    for case in cases_file.get("cases", []):
        if not isinstance(case, Mapping):
            cases.append(case)
            continue
        clean = {key: value for key, value in case.items() if key != "clause_ids"}
        cases.append(clean)
    return {"version": cases_file.get("version", 1), "cases": cases}

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
        (public / "cases.json").write_text(
            _canonical_json(_strip_case_clause_ids(spec.public_cases)), encoding="utf-8"
        )
        (public / "test_solution.py").write_text(spec.public_test, encoding="utf-8")
        (hidden / "cases.json").write_text(
            _canonical_json(_strip_case_clause_ids(spec.hidden_cases)), encoding="utf-8"
        )
        (reference / "solution.py").write_text(spec.reference_solution, encoding="utf-8")
        (defect / "solution.py").write_text(spec.defect_solution, encoding="utf-8")
        contract = {
            "schema_version": 1,
            "clauses": [item.to_mapping() for item in spec.clauses],
            "defect_clause_ids": list(spec.defect_clause_ids),
            "coverage": spec.clause_summary(),
        }
        (pack_root / "contract.json").write_text(_canonical_json(contract), encoding="utf-8")
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
