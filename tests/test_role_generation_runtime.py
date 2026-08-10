from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile
from collections.abc import Callable
from typing import Any

import pytest

from aegis.models import Role
from aegis.plugins import EffectClass
from aegis.roles import (
    DEFAULT_ROLE_OBJECTIVES,
    BrokerRolePolicy,
    GenerationBundle,
    RoleGeneration,
    RoleGenerationProtocolError,
    RoleGenerationRuntime,
    RoleGenerationRuntimeError,
    SandboxArtifactPackage,
)
from aegis.sandbox import CommandResult, CommandSpec, FakeSandboxBackend, StagedArtifact
from aegis.sandbox.owned import OwnedSandboxBackend


def role_generation(role: Role, offset: int, plugins: tuple[str, ...] = ()) -> RoleGeneration:
    markers = "123456789abcdef"
    return RoleGeneration(
        role=role,
        model_profile_sha256=markers[offset] * 64,
        workflow_artifact_id="sha256:" + markers[offset + 1] * 64,
        subject_artifact_id="sha256:" + markers[offset + 2] * 64,
        runtime_image=f"registry.example/{role.value}@sha256:{markers[offset + 3] * 64}",
        plugin_artifact_ids=plugins,
        budget_policy_sha256=markers[offset + 4] * 64,
    )


def bundle() -> GenerationBundle:
    return GenerationBundle.create(
        parent_generation_id=None,
        controller_abi=1,
        source_commit="a" * 40,
        roles=(
            role_generation(Role.WARRIOR, 0, ("sha256:" + "7" * 64,)),
            role_generation(Role.JUDGE, 5),
            role_generation(Role.PROSECUTOR, 9),
        ),
        evidence_manifest_sha256="f" * 64,
    )


def archive(path: str, content: bytes) -> tuple[str, str]:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as tar:
        info = tarfile.TarInfo(path)
        info.size = len(content)
        info.mtime = 0
        info.uid = info.gid = 0
        tar.addfile(info, io.BytesIO(content))
    payload = output.getvalue()
    return base64.b64encode(payload).decode("ascii"), hashlib.sha256(payload).hexdigest()


class Artifacts:
    def __init__(self) -> None:
        self.loaded: list[tuple[str, str]] = []

    def load(self, artifact_id: str, kind: str) -> SandboxArtifactPackage:
        self.loaded.append((artifact_id, kind))
        encoded, digest = archive(f"{kind}/{artifact_id[-8:]}.json", artifact_id.encode("ascii"))
        return SandboxArtifactPackage(
            artifact_id=artifact_id,
            kind=kind,
            archive_base64=encoded,
            archive_sha256=digest,
            module_sha256=artifact_id.removeprefix("sha256:"),
        )


class Factory:
    def __init__(
        self,
        *,
        mutate: Callable[[dict[str, Any]], None] | None = None,
        result: CommandResult | None = None,
        backend_type: type[FakeSandboxBackend] = FakeSandboxBackend,
    ) -> None:
        self.mutate = mutate
        self.fixed_result = result
        self.backend_type = backend_type
        self.images: list[str] = []
        self.backends: list[FakeSandboxBackend] = []
        self.events: list[tuple[str, dict[str, Any]]] = []

    def create(self, runtime_image: str) -> OwnedSandboxBackend:
        self.images.append(runtime_image)

        def execute(sandbox_id: str, command: CommandSpec) -> CommandResult:
            if self.fixed_result is not None:
                return self.fixed_result
            assert command.stdin is not None
            request = json.loads(command.stdin)
            plugins = request["plugin_artifact_ids"]
            payload: dict[str, Any] = {
                "abi_version": 1,
                "request_id": request["request_id"],
                "status": "ok",
                "result": {"accepted": True},
                "attestation": {
                    "sandbox_id": sandbox_id,
                    "generation_id": request["generation_id"],
                    "role": request["role"],
                    "runtime_image": request["runtime_image"],
                    "model_profile_sha256": request["model_profile_sha256"],
                    "budget_policy_sha256": request["budget_policy_sha256"],
                    "subject_module_sha256": request["subject_artifact_id"].removeprefix("sha256:"),
                    "workflow_module_sha256": request["workflow_artifact_id"].removeprefix("sha256:"),
                    "plugin_module_sha256": [item.removeprefix("sha256:") for item in plugins],
                    "artifact_ids": [
                        request["subject_artifact_id"],
                        request["workflow_artifact_id"],
                        *plugins,
                    ],
                    "broker_policy_sha256": request["broker_policy_sha256"],
                    "direct_plugin_execution": False,
                },
            }
            if self.mutate is not None:
                self.mutate(payload)
            return CommandResult(0, json.dumps(payload, separators=(",", ":")), "", 0.25)

        backend = self.backend_type(executor=execute)
        self.backends.append(backend)
        return OwnedSandboxBackend(backend, lambda kind, payload: self.events.append((kind, payload)))


def policy(generation: GenerationBundle, role: Role) -> BrokerRolePolicy:
    selected = next(item for item in generation.roles if item.role is role)
    effects = (
        tuple(EffectClass)
        if role is Role.WARRIOR
        else (EffectClass.PURE, EffectClass.WORKSPACE_READ)
    )
    return BrokerRolePolicy.create(
        generation_id=generation.generation_id,
        role=role,
        plugin_artifact_ids=selected.plugin_artifact_ids,
        allowed_effects=effects,
    )


def runtime(factory: Factory, artifacts: Artifacts | None = None) -> RoleGenerationRuntime:
    return RoleGenerationRuntime(
        sandbox_factory=factory,
        artifact_store=artifacts or Artifacts(),
        nonce_factory=lambda: "abc123abc123abc1",
    )


def test_generation_is_loaded_and_executed_only_through_fresh_owned_sandbox() -> None:
    generation = bundle()
    artifacts = Artifacts()
    factory = Factory()
    receipt = runtime(factory, artifacts).execute(
        generation,
        Role.WARRIOR,
        {"task_id": "task-1"},
        policy(generation, Role.WARRIOR),
    )

    selected = generation.roles[0]
    assert factory.images == [selected.runtime_image]
    assert artifacts.loaded == [
        (selected.subject_artifact_id, "subject"),
        (selected.workflow_artifact_id, "workflow"),
        (selected.plugin_artifact_ids[0], "plugin"),
    ]
    backend = factory.backends[0]
    assert backend.prepared == set()
    assert len(backend.commands) == 1
    _, command = backend.commands[0]
    assert command.argv == ("/opt/aegis/bin/role-generation-runner", "--json-abi", "1")
    assert command.cwd == "."
    assert command.stdin is not None
    request = json.loads(command.stdin)
    assert request["objective"] == DEFAULT_ROLE_OBJECTIVES[Role.WARRIOR]
    assert request["context"] == {"task_id": "task-1"}
    assert backend.workspace_access_history[0][1][0].path == "output"
    assert [kind for kind, _ in factory.events] == [
        "sandbox_prepare_intent",
        "sandbox_prepared",
        "sandbox_destroyed",
    ]
    assert receipt.runtime_image == selected.runtime_image
    assert receipt.subject_module_sha256 == selected.subject_artifact_id.removeprefix("sha256:")
    assert receipt.plugin_module_sha256 == (selected.plugin_artifact_ids[0].removeprefix("sha256:"),)
    assert receipt.artifact_ids == (
        selected.subject_artifact_id,
        selected.workflow_artifact_id,
        *selected.plugin_artifact_ids,
    )
    assert len(receipt.artifact_archive_sha256) == 3
    assert receipt.receipt_id.startswith("sha256:")


def test_judge_and_prosecutor_broker_policy_cannot_grant_write_or_external_effects() -> None:
    generation = bundle()
    selected = generation.roles[1]
    with pytest.raises(ValueError, match="read-only"):
        BrokerRolePolicy.create(
            generation_id=generation.generation_id,
            role=Role.JUDGE,
            plugin_artifact_ids=selected.plugin_artifact_ids,
            allowed_effects=(EffectClass.PURE, EffectClass.WORKSPACE_WRITE),
        )
    with pytest.raises(ValueError, match="read-only"):
        BrokerRolePolicy.create(
            generation_id=generation.generation_id,
            role=Role.PROSECUTOR,
            plugin_artifact_ids=(),
            allowed_effects=(EffectClass.EXTERNAL,),
        )


def test_judge_sandbox_has_no_writable_workspace_rules() -> None:
    generation = bundle()
    factory = Factory()
    runtime(factory).execute(generation, Role.JUDGE, {"evidence": ()}, policy(generation, Role.JUDGE))
    assert factory.backends[0].workspace_access_history[0][1] == ()


@pytest.mark.parametrize(
    "mutation",
    [
        lambda payload: payload["attestation"].__setitem__("runtime_image", "registry/x@sha256:" + "0" * 64),
        lambda payload: payload["attestation"].__setitem__("subject_module_sha256", "0" * 64),
        lambda payload: payload["attestation"].__setitem__("direct_plugin_execution", True),
        lambda payload: payload.__setitem__("unknown", True),
    ],
)
def test_image_module_policy_or_protocol_tampering_fails_closed_and_destroys(
    mutation: Callable[[dict[str, Any]], None],
) -> None:
    generation = bundle()
    factory = Factory(mutate=mutation)
    with pytest.raises(RoleGenerationProtocolError):
        runtime(factory).execute(
            generation,
            Role.WARRIOR,
            {"task": 1},
            policy(generation, Role.WARRIOR),
        )
    assert factory.backends[0].prepared == set()
    assert factory.events[-1][0] == "sandbox_destroyed"


def test_timeout_kills_owned_sandbox_and_returns_no_receipt() -> None:
    generation = bundle()
    factory = Factory(result=CommandResult(124, "", "timed out", 1, timed_out=True))
    with pytest.raises(RoleGenerationRuntimeError, match="timed out"):
        runtime(factory).execute(
            generation,
            Role.WARRIOR,
            {},
            policy(generation, Role.WARRIOR),
            timeout_seconds=1,
        )
    sandbox_id = "role-warrior-abc123abc123abc1"
    assert sandbox_id in factory.backends[0].killed
    assert factory.events[-1] == ("sandbox_killed", {"sandbox_id": sandbox_id})


def test_reported_duration_beyond_deadline_is_rejected_even_without_timeout_flag() -> None:
    generation = bundle()
    factory = Factory(result=CommandResult(0, "{}", "", 2, timed_out=False))
    with pytest.raises(RoleGenerationRuntimeError, match="timeout"):
        runtime(factory).execute(
            generation,
            Role.WARRIOR,
            {},
            policy(generation, Role.WARRIOR),
            timeout_seconds=1,
        )
    assert factory.events[-1][0] == "sandbox_destroyed"


def test_destroy_failure_suppresses_otherwise_valid_receipt() -> None:
    class FailedDestroy(FakeSandboxBackend):
        def destroy(self, sandbox_id: str) -> None:
            raise RuntimeError("destroy failed")

    generation = bundle()
    factory = Factory(backend_type=FailedDestroy)
    with pytest.raises(RoleGenerationRuntimeError, match="destruction failed"):
        runtime(factory).execute(
            generation,
            Role.WARRIOR,
            {},
            policy(generation, Role.WARRIOR),
        )
    assert factory.events[-1][0] == "sandbox_cleanup_failed"


def test_staging_receipt_mismatch_fails_before_exec_and_still_destroys() -> None:
    class BadStage(FakeSandboxBackend):
        def stage_archive(self, sandbox_id: str, archive_base64: str, expected_digest: str) -> StagedArtifact:
            staged = super().stage_archive(sandbox_id, archive_base64, expected_digest)
            return StagedArtifact(staged.sandbox_id, "0" * 64, staged.size_bytes, staged.entries)

    generation = bundle()
    factory = Factory(backend_type=BadStage)
    with pytest.raises(RoleGenerationProtocolError, match="staged artifact"):
        runtime(factory).execute(
            generation,
            Role.WARRIOR,
            {},
            policy(generation, Role.WARRIOR),
        )
    assert factory.backends[0].commands == []
    assert factory.events[-1][0] == "sandbox_destroyed"
