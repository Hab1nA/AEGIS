"""Sandbox-backed execution adapter for preflight task-pack validation."""

from __future__ import annotations

import base64
import hashlib
from pathlib import PurePosixPath

from aegis.sandbox import SandboxBackend

from .manifest import TaskPack
from .runtime import _archive_from_directories, _sealed_cases_archive
from .validation import ExecutionResult


class SandboxTaskPackRunner:
    """Run every implementation/suite pair in a fresh offline sandbox."""

    def __init__(
        self,
        sandbox: SandboxBackend,
        *,
        timeout_seconds: float = 120.0,
        id_namespace: str = "",
    ) -> None:
        if not 0 < timeout_seconds <= 3600:
            raise ValueError("timeout_seconds must be in (0, 3600]")
        self.sandbox = sandbox
        self.timeout_seconds = timeout_seconds
        self.id_namespace = id_namespace
        self._sequence = 0

    @staticmethod
    def _bounded_namespace(namespace: str) -> str:
        # Sandbox IDs are capped at 64 characters. Keep short campaign IDs
        # readable and deterministically compress longer derived namespaces.
        if len(namespace) <= 34:
            return namespace
        digest = hashlib.sha256(namespace.encode("utf-8")).hexdigest()[:12]
        return f"{namespace[:21]}-{digest}"

    def run(self, pack: TaskPack, implementation_dir: str, suite: str) -> ExecutionResult:
        if suite not in {"public", "hidden"}:
            raise ValueError("suite must be public or hidden")
        allowed_implementations = {
            pack.manifest.reference_dir,
            pack.manifest.defect_dir,
            *pack.manifest.mutant_dirs,
        }
        if implementation_dir not in allowed_implementations:
            raise ValueError("implementation directory is not declared by the task pack")
        pack.verify_layout()
        pack.verify_integrity()
        doctor = self.sandbox.doctor()
        if not doctor.passed:
            raise RuntimeError(
                "sandbox doctor failed before task-pack validation: " + ", ".join(doctor.failed_names())
            )
        self._sequence += 1
        identity = (
            f"{self.id_namespace}:{pack.manifest.task_id}:{implementation_dir}:{suite}:{self._sequence}"
        )
        bounded_namespace = self._bounded_namespace(self.id_namespace)
        namespace = f"{bounded_namespace}-" if bounded_namespace else ""
        sandbox_id = f"validate-{namespace}" + hashlib.sha256(identity.encode()).hexdigest()[:20]
        prepared = False
        try:
            self.sandbox.prepare(sandbox_id)
            prepared = True
            suite_path = pack.public_path if suite == "public" else pack.hidden_path
            archive = _archive_from_directories(((pack.path(implementation_dir), PurePosixPath(".")),))
            digest = hashlib.sha256(archive).hexdigest()
            receipt = self.sandbox.stage_archive(
                sandbox_id,
                base64.b64encode(archive).decode("ascii"),
                digest,
            )
            if receipt.digest != digest or receipt.size_bytes != len(archive):
                raise RuntimeError("task-pack validation staging receipt failed verification")
            sealed_archive = _sealed_cases_archive(suite_path)
            sealed_digest = hashlib.sha256(sealed_archive).hexdigest()
            sealed = self.sandbox.evaluate_sealed(
                sandbox_id,
                base64.b64encode(sealed_archive).decode("ascii"),
                sealed_digest,
                self.timeout_seconds,
            )
            output_digest = hashlib.sha256(
                repr(
                    (
                        sealed.passed,
                        sealed.total,
                        sealed.failures,
                        sealed.timed_out,
                        sealed.safety_violations,
                    )
                ).encode("utf-8")
            ).hexdigest()
            return ExecutionResult(
                passed=(
                    not sealed.timed_out and not sealed.safety_violations and sealed.passed == sealed.total
                ),
                tests_run=sealed.total,
                exit_code=0 if sealed.passed == sealed.total and not sealed.safety_violations else 1,
                timed_out=sealed.timed_out,
                output_digest=output_digest,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            raise RuntimeError(
                f"task-pack sandbox run failed for {pack.manifest.task_id} "
                f"implementation={implementation_dir} suite={suite} sandbox_id={sandbox_id}: {exc}"
            ) from exc
        finally:
            if prepared:
                self.sandbox.destroy(sandbox_id)
