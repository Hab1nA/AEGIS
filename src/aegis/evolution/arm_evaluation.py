"""Deterministic public-suite quality evaluation for paired evolution arms."""

from __future__ import annotations

import base64
import hashlib
import io
import tarfile
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from aegis.dynamic_tasks import DynamicTaskRegistry
from aegis.sandbox import SandboxBackend
from aegis.sandbox.types import SealedEvaluationResult
from aegis.taskpacks.manifest import TaskPack
from aegis.taskpacks.runtime import _sealed_cases_archive

MAX_WORKSPACE_BYTES = 32 * 1024 * 1024
MAX_TASK_OVERLAY_BYTES = 8 * 1024 * 1024
MAX_TASK_OVERLAY_FILES = 64
_OVERLAY_ALLOWED_SUFFIXES = frozenset(
    {".py", ".txt", ".json", ".toml", ".yaml", ".yml", ".md"}
)
_EXCLUDED_NAMES = frozenset(
    {"__pycache__", ".pytest_cache", ".git", ".aegis", "cases.json"}
)


class ArmEvaluationError(RuntimeError):
    """Raised when an arm cannot be staged or evaluated safely."""


@dataclass(frozen=True, slots=True)
class TaskArmResult:
    task_id: str
    artifact_id: str
    passed: int
    total: int
    timed_out: bool
    safety_violations: tuple[str, ...]
    changed_paths: tuple[str, ...]

    @property
    def passed_task(self) -> bool:
        return (
            self.total > 0
            and self.passed == self.total
            and not self.timed_out
            and not self.safety_violations
        )


@dataclass(frozen=True, slots=True)
class ArmEvaluation:
    workspace_digest: str
    quality: float
    passed_tasks: int
    total_tasks: int
    task_results: tuple[TaskArmResult, ...]
    safety_violations: tuple[str, ...]

    @property
    def integrity_passed(self) -> bool:
        return not self.safety_violations and all(
            item.total > 0 for item in self.task_results
        )


class _TaskPackContext:
    """Keep every cohort task pack extracted for the duration of one arm."""

    def __init__(self, registry: DynamicTaskRegistry, tasks: Sequence[Mapping[str, Any]]) -> None:
        self._root = tempfile.TemporaryDirectory(prefix="aegis-arm-task-")
        self._packs: dict[str, TaskPack] = {}
        for task in tasks:
            artifact_id = task["artifact_id"]
            archive = registry.archive(artifact_id)
            directory = Path(self._root.name) / ("task-" + artifact_id.rsplit(":", 1)[1])
            directory.mkdir(parents=True, exist_ok=False)
            with tempfile.TemporaryFile() as stream:
                stream.write(archive)
                stream.seek(0)
                with tarfile.open(fileobj=stream, mode="r:*") as handle:
                    handle.extractall(directory, filter="data")
            pack = TaskPack.load(directory)
            pack.verify_layout()
            pack.verify_integrity()
            self._packs[artifact_id] = pack

    def pack(self, artifact_id: str) -> TaskPack:
        try:
            return self._packs[artifact_id]
        except KeyError as exc:
            raise ArmEvaluationError(f"task archive is not loaded: {artifact_id}") from exc

    def close(self) -> None:
        self._root.cleanup()


def _tar_bytes(entries: Mapping[str, bytes]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name in sorted(entries):
            info = tarfile.TarInfo(name)
            payload = entries[name]
            info.size = len(payload)
            info.mode = 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(payload))
    return output.getvalue()


def _read_tree(directory: Path, prefix: PurePosixPath) -> dict[str, bytes]:
    entries: dict[str, bytes] = {}
    for path in sorted(directory.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(directory).as_posix()
        if any(part in _EXCLUDED_NAMES for part in PurePosixPath(relative).parts):
            continue
        entries[str(prefix / relative)] = path.read_bytes()
    return entries


def build_cohort_workspace(
    registry: DynamicTaskRegistry, tasks: Sequence[Mapping[str, Any]]
) -> bytes:
    """Build the bounded workspace handed to the Warrior for one whole cohort.

    Each task lives under ``tasks/<task_id>/`` with its defect baseline,
    ``TASK.md`` prompt, and public tests under ``tests/public``.  ``cases.json``
    is never exposed to the model.
    """
    context = _TaskPackContext(registry, tasks)
    try:
        entries: dict[str, bytes] = {}
        for task in tasks:
            artifact_id = task["artifact_id"]
            task_id = task["task_id"]
            pack = context.pack(artifact_id)
            prefix = PurePosixPath("tasks") / task_id
            entries.update(_read_tree(pack.path(pack.manifest.defect_dir), prefix))
            public_entries = _read_tree(pack.public_path, prefix / "tests" / "public")
            public_entries = {
                name: payload
                for name, payload in public_entries.items()
                if not name.endswith("/cases.json")
            }
            entries.update(public_entries)
            prompt = (pack.root / "prompt.md").read_text(encoding="utf-8").strip()
            if not prompt:
                raise ArmEvaluationError(f"task prompt is empty: {task_id}")
            entries[str(prefix / "TASK.md")] = prompt.encode("utf-8")
            if sum(len(payload) for payload in entries.values()) > MAX_WORKSPACE_BYTES:
                raise ArmEvaluationError("cohort workspace exceeds the byte limit")
        return _tar_bytes(entries)
    finally:
        context.close()


def stage_cohort_workspace(
    sandbox: SandboxBackend, sandbox_id: str, workspace: bytes
) -> str:
    if len(workspace) > MAX_WORKSPACE_BYTES:
        raise ArmEvaluationError("cohort workspace exceeds the byte limit")
    digest = hashlib.sha256(workspace).hexdigest()
    receipt = sandbox.stage_archive(
        sandbox_id, base64.b64encode(workspace).decode("ascii"), digest
    )
    if receipt.digest != digest or receipt.size_bytes != len(workspace):
        raise ArmEvaluationError("cohort workspace staging receipt failed verification")
    return digest


def freeze_workspace_bytes(
    sandbox: SandboxBackend, sandbox_id: str, *, max_bytes: int = MAX_WORKSPACE_BYTES
) -> tuple[str, bytes]:
    frozen = sandbox.freeze(sandbox_id)
    with tempfile.TemporaryDirectory(prefix="aegis-arm-freeze-") as directory:
        destination = Path(directory) / "workspace.tar"
        exported = sandbox.export(sandbox_id, destination)
        payload = destination.read_bytes()
    if frozen.digest != exported.digest or hashlib.sha256(payload).hexdigest() != frozen.digest:
        raise ArmEvaluationError("workspace freeze digest mismatch")
    if len(payload) > max_bytes:
        raise ArmEvaluationError("frozen workspace exceeds the byte limit")
    return frozen.digest, payload


def _overlay_workspace_task_files(
    workspace_bytes: bytes, task_id: str
) -> tuple[dict[str, bytes], tuple[str, ...]]:
    """Extract the model's files for one task from the frozen workspace."""
    prefix = PurePosixPath("tasks") / task_id
    entries: dict[str, bytes] = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(workspace_bytes), mode="r:*") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not path.parts:
                raise ArmEvaluationError(f"workspace contains an unsafe path: {member.name}")
            try:
                relative = path.relative_to(prefix)
            except ValueError:
                continue
            parts = relative.parts
            if not parts or any(part in _EXCLUDED_NAMES for part in parts):
                continue
            if relative.as_posix().startswith("tests/"):
                # Public tests are baseline-owned and never overlaid; the model
                # simply receives them staged in its workspace.
                continue
            if relative.suffix not in _OVERLAY_ALLOWED_SUFFIXES:
                # Extra files outside the overlay ABI are ignored; they never
                # replace baseline content and are not a safety violation.
                continue
            source = archive.extractfile(member)
            if source is None:
                raise ArmEvaluationError("workspace file cannot be read")
            payload = source.read()
            total += len(payload)
            if total > MAX_TASK_OVERLAY_BYTES or len(entries) >= MAX_TASK_OVERLAY_FILES:
                raise ArmEvaluationError("task overlay exceeds its byte or file limit")
            entries[relative.as_posix()] = payload
    return entries, ()


def _baseline_entries(pack: TaskPack) -> dict[str, bytes]:
    entries = _read_tree(pack.path(pack.manifest.defect_dir), PurePosixPath("."))
    public_entries = _read_tree(pack.public_path, PurePosixPath("tests/public"))
    entries.update(
        {
            name: payload
            for name, payload in public_entries.items()
            if not name.endswith("/cases.json")
        }
    )
    prompt = (pack.root / "prompt.md").read_text(encoding="utf-8").strip()
    entries["TASK.md"] = prompt.encode("utf-8")
    return entries


def _tar_file_hashes(payload: bytes) -> dict[str, str]:
    result: dict[str, str] = {}
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            source = archive.extractfile(member)
            if source is None:
                raise ArmEvaluationError("archive file cannot be read")
            result[member.name] = hashlib.sha256(source.read()).hexdigest()
    return result


def _evaluate_one_task(
    sandbox: SandboxBackend,
    *,
    pack: TaskPack,
    task_id: str,
    workspace_bytes: bytes,
    timeout_seconds: float,
    namespace: str,
) -> TaskArmResult:
    overlay, _skipped = _overlay_workspace_task_files(workspace_bytes, task_id)
    safety: list[str] = []
    changed_paths: tuple[str, ...] = ()
    passed = total = 0
    timed_out = False
    judge_id = f"judge-{namespace}-" + hashlib.sha256(task_id.encode("utf-8")).hexdigest()[:20]
    try:
        sandbox.prepare(judge_id)
        entries = _baseline_entries(pack)
        entries.update(overlay)
        staged = _tar_bytes(entries)
        staged_digest = hashlib.sha256(staged).hexdigest()
        receipt = sandbox.stage_archive(
            judge_id, base64.b64encode(staged).decode("ascii"), staged_digest
        )
        if receipt.digest != staged_digest or receipt.size_bytes != len(staged):
            raise ArmEvaluationError("judge staging receipt failed verification")
        sealed_archive = _sealed_cases_archive(pack.public_path)
        sealed_digest = hashlib.sha256(sealed_archive).hexdigest()
        result: SealedEvaluationResult = sandbox.evaluate_sealed(
            judge_id,
            base64.b64encode(sealed_archive).decode("ascii"),
            sealed_digest,
            timeout_seconds,
        )
        passed, total = result.passed, result.total
        timed_out = result.timed_out
        safety.extend(f"public: {item}" for item in result.safety_violations)
        if timed_out:
            safety.append("public test execution timed out")
        frozen = sandbox.freeze(judge_id)
        with tempfile.TemporaryDirectory(prefix="aegis-arm-post-") as directory:
            destination = Path(directory) / "post.tar"
            sandbox.export(judge_id, destination)
            post = destination.read_bytes()
        if frozen.size_bytes <= 0:
            safety.append("judge export was unexpectedly empty")
        baseline_hashes = _tar_file_hashes(staged)
        observed_hashes = _tar_file_hashes(post)
        changed_paths = tuple(
            sorted(
                path
                for path in baseline_hashes.keys() | observed_hashes.keys()
                if baseline_hashes.get(path) != observed_hashes.get(path)
            )
        )
        if changed_paths:
            safety.append("staged submission or tests changed during evaluation")
    finally:
        sandbox.destroy(judge_id)
    return TaskArmResult(
        task_id=task_id,
        artifact_id="",
        passed=passed,
        total=total,
        timed_out=timed_out,
        safety_violations=tuple(safety),
        changed_paths=changed_paths,
    )


def evaluate_frozen_workspace(
    registry: DynamicTaskRegistry,
    sandbox: SandboxBackend,
    workspace_bytes: bytes,
    workspace_digest: str,
    tasks: Sequence[Mapping[str, Any]],
    *,
    timeout_seconds: float = 120.0,
    namespace: str = "arm",
) -> ArmEvaluation:
    """Deterministically score one arm on the sealed public suites."""
    if not 0 < timeout_seconds <= 3600:
        raise ArmEvaluationError("timeout_seconds must be in (0, 3600]")
    if hashlib.sha256(workspace_bytes).hexdigest() != workspace_digest:
        raise ArmEvaluationError("workspace digest does not match its bytes")
    if len(workspace_bytes) > MAX_WORKSPACE_BYTES:
        raise ArmEvaluationError("workspace exceeds the byte limit")
    context = _TaskPackContext(registry, tasks)
    try:
        results: list[TaskArmResult] = []
        for task in tasks:
            pack = context.pack(task["artifact_id"])
            results.append(
                _evaluate_one_task(
                    sandbox,
                    pack=pack,
                    task_id=task["task_id"],
                    workspace_bytes=workspace_bytes,
                    timeout_seconds=timeout_seconds,
                    namespace=namespace,
                )
            )
    finally:
        context.close()
    passed_tasks = sum(1 for item in results if item.passed_task)
    total_tasks = len(results)
    safety: list[str] = []
    for item in results:
        safety.extend(item.safety_violations)
    quality = passed_tasks / total_tasks if total_tasks else 0.0
    return ArmEvaluation(
        workspace_digest=workspace_digest,
        quality=round(quality, 12),
        passed_tasks=passed_tasks,
        total_tasks=total_tasks,
        task_results=tuple(results),
        safety_violations=tuple(dict.fromkeys(safety)),
    )


__all__ = [
    "ArmEvaluation",
    "ArmEvaluationError",
    "MAX_WORKSPACE_BYTES",
    "TaskArmResult",
    "build_cohort_workspace",
    "evaluate_frozen_workspace",
    "freeze_workspace_bytes",
    "stage_cohort_workspace",
]
