"""Sandbox-only runtime for integrity-checked Python task packs."""

from __future__ import annotations

import base64
import hashlib
import io
import tarfile
import tempfile
from dataclasses import asdict
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from aegis.evaluation import PairedObservation, PromotionPolicy, decide_promotion
from aegis.evaluation.scoring import EvaluationEvidence, TamperEvidence, score_quality
from aegis.sandbox import SandboxBackend
from aegis.sandbox.sealed import load_sealed_cases

from .manifest import TaskPack
from .validation import TaskPackValidation


class PythonTaskProvider:
    """Prepare warrior inputs and evaluate frozen outputs without host execution.

    A provider accepts only task packs accompanied by a successful validation
    report.  Hidden tests, references, and mutants never enter the warrior
    archive or the public task mapping.
    """

    def __init__(
        self,
        packs: Sequence[tuple[TaskPack, TaskPackValidation]],
        sandbox: SandboxBackend,
        *,
        promotion_policy: PromotionPolicy | None = None,
    ) -> None:
        if not packs:
            raise ValueError("at least one validated task pack is required")
        self.sandbox = sandbox
        self.policy = promotion_policy or PromotionPolicy()
        self._packs: dict[str, tuple[TaskPack, TaskPackValidation]] = {}
        self._order: list[str] = []
        for pack, report in packs:
            pack.verify_layout()
            pack.verify_integrity()
            _sealed_cases_archive(pack.public_path)
            _sealed_cases_archive(pack.hidden_path)
            if not report.valid:
                raise ValueError(f"task pack is not validated: {pack.manifest.task_id}")
            key = self._pack_key(pack)
            if key in self._packs:
                raise ValueError(f"duplicate task pack: {key}")
            self._packs[key] = (pack, report)
            self._order.append(key)
        self._warrior_sandboxes: dict[tuple[str, int], str] = {}
        self._observations: dict[tuple[str, int], PairedObservation] = {}
        self._judge_counter = 0

    def bind_sandbox_backend(self, backend: SandboxBackend) -> None:
        """Bind the controller-owned backend used for all future task actions."""
        if not isinstance(backend, SandboxBackend):
            raise TypeError("backend does not implement the sandbox contract")
        self.sandbox = backend

    def task_for_round(self, round_number: int) -> Mapping[str, Any]:
        if round_number < 1:
            raise ValueError("round_number must be positive")
        index = (round_number - 1) % len(self._order)
        seed = (round_number - 1) // len(self._order)
        pack, _ = self._packs[self._order[index]]
        prompt = (pack.root / "prompt.md").read_text(encoding="utf-8").strip()
        if not prompt:
            raise ValueError(f"task prompt is empty: {pack.manifest.task_id}")
        return {
            "task_id": pack.manifest.task_id,
            "task_version": pack.manifest.version,
            "language": "python",
            "seed": seed,
            "content_hash": pack.manifest.content_hash,
            "description": prompt,
            "public_test_command": ["python", "-m", "pytest", "-q", "tests/public"],
        }

    def promotion_task_ids(self) -> tuple[str, ...]:
        """Return the sealed, integrity-checked task identities in stable order."""
        return tuple(self._order)

    def task_for_promotion(self, task_key: str, seed: int) -> Mapping[str, Any]:
        """Resolve one exact task/seed pair without exposing hidden material."""
        if task_key not in self._packs:
            raise ValueError("unknown promotion task")
        if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
            raise ValueError("promotion seed must be a non-negative integer")
        pack, _ = self._packs[task_key]
        return {
            "task_id": pack.manifest.task_id,
            "task_version": pack.manifest.version,
            "language": "python",
            "seed": seed,
            "content_hash": pack.manifest.content_hash,
            "description": "Repair the supplied implementation while preserving documented behavior and passing the available tests.",
            "public_test_command": ["python", "-m", "pytest", "-q", "tests/public"],
        }

    def isolated(self) -> "PythonTaskProvider":
        """Create an evaluator with no workspace or observation state."""
        return PythonTaskProvider(tuple(self._packs.values()), self.sandbox, promotion_policy=self.policy)

    def prepare_warrior_workspace(self, task: Mapping[str, Any], sandbox_id: str) -> str:
        pack, _ = self._resolve_task(task)
        key = (self._pack_key(pack), self._task_seed(task))
        if key in self._warrior_sandboxes:
            raise RuntimeError("warrior workspace is already prepared for this task/seed")
        archive = _archive_from_directories(
            (
                (pack.path(pack.manifest.defect_dir), PurePosixPath(".")),
                (pack.public_path, PurePosixPath("tests/public")),
            ),
            extra_files=((pack.root / "prompt.md", PurePosixPath("TASK.md")),),
            excluded_relative_names=frozenset({"cases.json"}),
        )
        digest = hashlib.sha256(archive).hexdigest()
        receipt = self.sandbox.stage_archive(sandbox_id, base64.b64encode(archive).decode("ascii"), digest)
        if receipt.digest != digest or receipt.size_bytes != len(archive):
            raise RuntimeError("warrior staging receipt failed verification")
        self._warrior_sandboxes[key] = sandbox_id
        return digest

    def attach_warrior_workspace(self, task: Mapping[str, Any], sandbox_id: str) -> None:
        """Restore controller ownership without restaging a durable workspace.

        The task identity and current pack hash are revalidated before the
        mapping is accepted.  Existence and artifact integrity remain enforced
        by the sandbox export/freeze receipt during evaluation.
        """
        pack, _ = self._resolve_task(task)
        if (
            not isinstance(sandbox_id, str)
            or not sandbox_id
            or any(not (character.isalnum() or character in "-_") for character in sandbox_id)
        ):
            raise ValueError("sandbox id is invalid")
        key = (self._pack_key(pack), self._task_seed(task))
        existing = self._warrior_sandboxes.get(key)
        if existing is not None and existing != sandbox_id:
            raise RuntimeError("task/seed is already attached to another warrior workspace")
        self._warrior_sandboxes[key] = sandbox_id

    def evaluate(
        self,
        task: Mapping[str, Any],
        artifact_digest: str,
        judge_output: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        del judge_output  # AI opinion never determines the locked quality score.
        pack, validation = self._resolve_task(task)
        key = (self._pack_key(pack), self._task_seed(task))
        warrior_id = self._warrior_sandboxes.get(key)
        if warrior_id is None:
            raise RuntimeError("warrior workspace was not prepared by this provider")
        self._judge_counter += 1
        judge_id = f"judge-{hashlib.sha256(f'{key}-{self._judge_counter}'.encode()).hexdigest()[:20]}"
        safety: list[str] = []
        changed_paths: tuple[str, ...] = ()
        public_passed = public_total = hidden_passed = hidden_total = 0
        public_timed_out = hidden_timed_out = False
        try:
            self.sandbox.prepare(judge_id)
            with tempfile.TemporaryDirectory() as directory:
                frozen_path = Path(directory) / "warrior.tar"
                exported = self.sandbox.export(warrior_id, frozen_path)
                frozen_bytes = frozen_path.read_bytes()
                if (
                    exported.digest != artifact_digest
                    or hashlib.sha256(frozen_bytes).hexdigest() != artifact_digest
                ):
                    safety.append("frozen warrior artifact hash mismatch")
                receipt = self.sandbox.stage_archive(
                    judge_id,
                    base64.b64encode(frozen_bytes).decode("ascii"),
                    artifact_digest,
                )
                if receipt.digest != artifact_digest:
                    safety.append("judge import hash mismatch")
                public_archive = _sealed_cases_archive(pack.public_path)
                public_digest = hashlib.sha256(public_archive).hexdigest()
                hidden_archive = _sealed_cases_archive(pack.hidden_path)
                hidden_digest = hashlib.sha256(hidden_archive).hexdigest()
                baseline = _tar_file_hashes(frozen_bytes)
                public_sealed = self.sandbox.evaluate_sealed(
                    judge_id,
                    base64.b64encode(public_archive).decode("ascii"),
                    public_digest,
                    120,
                )
                hidden_sealed = self.sandbox.evaluate_sealed(
                    judge_id,
                    base64.b64encode(hidden_archive).decode("ascii"),
                    hidden_digest,
                    120,
                )
                public_passed, public_total = public_sealed.passed, public_sealed.total
                hidden_passed, hidden_total = hidden_sealed.passed, hidden_sealed.total
                public_timed_out, hidden_timed_out = public_sealed.timed_out, hidden_sealed.timed_out
                if public_timed_out:
                    safety.append("public test execution timed out")
                if hidden_timed_out:
                    safety.append("hidden test execution timed out")
                safety.extend(f"public: {item}" for item in public_sealed.safety_violations)
                safety.extend(f"hidden: {item}" for item in hidden_sealed.safety_violations)
                post = self.sandbox.freeze(judge_id)
                post_path = Path(directory) / "judge.tar"
                self.sandbox.export(judge_id, post_path)
                observed = _tar_file_hashes(post_path.read_bytes())
                # Compare the complete namespace, not only the baseline keys.  A
                # submission that drops a new conftest.py/sitecustomize.py (or
                # any other file) into the evaluator is tampering just as surely
                # as one that edits or removes a staged file.
                changed_paths = tuple(
                    sorted(
                        path
                        for path in baseline.keys() | observed.keys()
                        if baseline.get(path) != observed.get(path)
                    )
                )
                if changed_paths:
                    safety.append("staged submission or tests changed during evaluation")
                if post.size_bytes <= 0:
                    safety.append("judge export was unexpectedly empty")
        finally:
            self.sandbox.destroy(judge_id)

        if public_total == 0 or hidden_total == 0:
            safety.append("test runner did not report a non-empty public and hidden suite")
            quality = None
        else:
            evidence = EvaluationEvidence(
                public_passed,
                public_total,
                hidden_passed,
                hidden_total,
                len(validation.mutant_hidden),
                len(validation.mutant_hidden),
                not public_timed_out and not hidden_timed_out,
                tuple(safety),
                TamperEvidence(artifact_digest, artifact_digest, changed_paths),
            )
            quality = score_quality(evidence)
        return {
            "score": quality.score if quality is not None else 0.0,
            "accepted": quality.accepted if quality is not None else False,
            "task_id": pack.manifest.task_id,
            "seed": self._task_seed(task),
            "public_passed": public_passed,
            "public_total": public_total,
            "hidden_passed": hidden_passed,
            "hidden_total": hidden_total,
            "safety_violations": list(safety),
            "changed_paths": list(changed_paths),
            "artifact_digest": artifact_digest,
        }

    def add_paired_observation(self, observation: PairedObservation) -> None:
        key = (observation.task_id, observation.seed)
        if key in self._observations:
            raise ValueError("duplicate paired task/seed observation")
        self._observations[key] = observation

    def promote(
        self,
        task: Mapping[str, Any],
        quality: Mapping[str, Any],
        prosecutor_output: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        del task, quality, prosecutor_output
        required = self.policy.required_tasks * self.policy.seeds_per_task
        if len(self._observations) != required:
            return {
                "promoted": False,
                "pending": True,
                "reason": f"pending paired evaluation: {len(self._observations)}/{required} observations",
                "pairs": len(self._observations),
                "required_pairs": required,
            }
        decision = decide_promotion(self._observations.values(), self.policy)
        return {**asdict(decision), "pending": False, "required_pairs": required}

    @staticmethod
    def _pack_key(pack: TaskPack) -> str:
        return f"{pack.manifest.task_id}@{pack.manifest.version}"

    @staticmethod
    def _task_seed(task: Mapping[str, Any]) -> int:
        seed = task.get("seed")
        if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
            raise ValueError("task seed is invalid")
        return seed

    def _resolve_task(self, task: Mapping[str, Any]) -> tuple[TaskPack, TaskPackValidation]:
        task_id = task.get("task_id")
        version = task.get("task_version")
        content_hash = task.get("content_hash")
        if not isinstance(task_id, str) or isinstance(version, bool) or not isinstance(version, int):
            raise ValueError("task identity is invalid")
        entry = self._packs.get(f"{task_id}@{version}")
        if entry is None or entry[0].manifest.content_hash != content_hash:
            raise ValueError("task identity or content hash does not match a validated pack")
        entry[0].verify_integrity()
        return entry


def _archive_from_directories(
    sources: Sequence[tuple[Path, PurePosixPath]],
    *,
    extra_files: Sequence[tuple[Path, PurePosixPath]] = (),
    excluded_relative_names: frozenset[str] = frozenset(),
) -> bytes:
    archive_files: dict[str, Path] = {}
    for source_root, prefix in sources:
        for path in sorted(source_root.rglob("*"), key=lambda item: item.as_posix()):
            if path.is_symlink():
                raise ValueError("task pack staging source contains a symlink")
            if path.is_dir():
                continue
            if not path.is_file():
                raise ValueError("task pack staging source contains an unsupported file")
            relative = PurePosixPath(path.relative_to(source_root).as_posix())
            if relative.as_posix() in excluded_relative_names:
                continue
            target = relative if prefix == PurePosixPath(".") else prefix / relative
            name = target.as_posix()
            if name in archive_files:
                raise ValueError(f"task pack staging paths collide: {name}")
            archive_files[name] = path
    for path, target in extra_files:
        if path.is_symlink() or not path.is_file():
            raise ValueError("task pack staging file is missing or unsafe")
        name = target.as_posix()
        if target.is_absolute() or any(part in {"", ".", ".."} for part in target.parts):
            raise ValueError("task pack staging target is unsafe")
        if name in archive_files:
            raise ValueError(f"task pack staging paths collide: {name}")
        archive_files[name] = path
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, path in sorted(archive_files.items()):
            data = path.read_bytes()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))
    return output.getvalue()


def _sealed_cases_archive(directory: Path) -> bytes:
    cases = directory / "cases.json"
    if not cases.is_file() or cases.is_symlink():
        raise ValueError(f"sealed suite is missing cases.json: {directory}")
    other = [
        path
        for path in directory.iterdir()
        if path.name != "cases.json"
        and not (
            directory.name == "public"
            and path.is_file()
            and path.name.startswith("test_")
            and path.suffix == ".py"
        )
    ]
    if other:
        raise ValueError(f"sealed suite directory contains unsupported files: {directory}")
    archive = _archive_from_directories((), extra_files=((cases, PurePosixPath("cases.json")),))
    load_sealed_cases(archive)
    return archive


def _tar_file_hashes(payload: bytes) -> dict[str, str]:
    result: dict[str, str] = {}
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            source = archive.extractfile(member)
            if source is None:
                raise ValueError("archive file cannot be read")
            result[member.name] = hashlib.sha256(source.read()).hexdigest()
    return result
