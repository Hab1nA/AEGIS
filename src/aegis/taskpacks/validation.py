"""Runner-neutral validation of reference, defect and anti-hacking mutants."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .manifest import TaskPack


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    passed: bool
    tests_run: int
    exit_code: int
    timed_out: bool = False
    output_digest: str = ""
    failure_summary: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.tests_run < 0:
            raise ValueError("tests_run cannot be negative")


class TaskPackRunner(Protocol):
    """Implemented by the sandbox layer; never executes task code in control plane."""

    def run(self, pack: TaskPack, implementation_dir: str, suite: str) -> ExecutionResult: ...


@dataclass(frozen=True, slots=True)
class TaskPackValidation:
    valid: bool
    reasons: tuple[str, ...]
    reference_public: ExecutionResult
    reference_hidden: ExecutionResult
    defect_public: ExecutionResult
    defect_hidden: ExecutionResult
    mutant_hidden: tuple[ExecutionResult, ...]


def _failure_detail(result: ExecutionResult, label: str) -> str:
    """Render bounded per-case failure names into a validation reason."""
    if not result.failure_summary:
        return ""
    return f" [{label}: {'; '.join(result.failure_summary[:5])}]"


def validate_taskpack(pack: TaskPack, runner: TaskPackRunner) -> TaskPackValidation:
    """Require a solvable reference and hidden tests that kill defect/mutants."""
    reference_public = runner.run(pack, pack.manifest.reference_dir, "public")
    reference_hidden = runner.run(pack, pack.manifest.reference_dir, "hidden")
    defect_public = runner.run(pack, pack.manifest.defect_dir, "public")
    defect_hidden = runner.run(pack, pack.manifest.defect_dir, "hidden")
    mutant_hidden = tuple(runner.run(pack, mutant, "hidden") for mutant in pack.manifest.mutant_dirs)
    reasons: list[str] = []
    if not reference_public.passed or not reference_hidden.passed:
        detail = _failure_detail(
            reference_public if not reference_public.passed else reference_hidden,
            "reference public" if not reference_public.passed else "reference hidden",
        )
        reasons.append(
            "reference implementation does not pass all suites" + detail
        )
    if reference_public.tests_run == 0 or reference_hidden.tests_run == 0:
        reasons.append("public and hidden suites must each execute at least one test")
    if defect_public.passed and defect_hidden.passed:
        reasons.append("defect implementation is not detected")
    surviving = [name for name, result in zip(pack.manifest.mutant_dirs, mutant_hidden) if result.passed]
    if surviving:
        reasons.append(f"hidden suite does not kill mutants: {', '.join(surviving)}")
    if not pack.manifest.mutant_dirs:
        reasons.append("at least one anti-hacking mutant is required")
    return TaskPackValidation(
        not reasons,
        tuple(reasons),
        reference_public,
        reference_hidden,
        defect_public,
        defect_hidden,
        mutant_hidden,
    )
