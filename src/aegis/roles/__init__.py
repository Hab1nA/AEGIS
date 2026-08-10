"""Content-addressed role generation bundles."""

from .generation import GenerationBundle, RoleGeneration
from .registry import (
    ROLE_ACTIVE_SET_COMMITTED_V2,
    ROLE_ACTIVE_SET_ROLLED_BACK_V2,
    ROLE_CANDIDATE_COLLECTED_V2,
    ROLE_CANDIDATE_QUALIFIED_V2,
    ROLE_CANDIDATE_VALIDATED_V2,
    RoleCandidateRecord,
    RoleCandidateState,
    RoleRegistry,
    RoleRegistryError,
    RoleRegistryProjection,
    role_registry_stream_id,
)
from .runtime import (
    DEFAULT_ROLE_OBJECTIVES,
    BrokerRolePolicy,
    GenerationArtifactStore,
    OwnedSandboxFactory,
    RoleExecutionReceipt,
    RoleExecutionRequest,
    RoleGenerationProtocolError,
    RoleGenerationRuntime,
    RoleGenerationRuntimeError,
    SandboxArtifactPackage,
)

__all__ = [
    "BrokerRolePolicy",
    "DEFAULT_ROLE_OBJECTIVES",
    "GenerationArtifactStore",
    "GenerationBundle",
    "OwnedSandboxFactory",
    "ROLE_ACTIVE_SET_COMMITTED_V2",
    "ROLE_ACTIVE_SET_ROLLED_BACK_V2",
    "ROLE_CANDIDATE_COLLECTED_V2",
    "ROLE_CANDIDATE_QUALIFIED_V2",
    "ROLE_CANDIDATE_VALIDATED_V2",
    "RoleCandidateRecord",
    "RoleCandidateState",
    "RoleGeneration",
    "RoleExecutionReceipt",
    "RoleExecutionRequest",
    "RoleGenerationProtocolError",
    "RoleGenerationRuntime",
    "RoleGenerationRuntimeError",
    "RoleRegistry",
    "RoleRegistryError",
    "RoleRegistryProjection",
    "SandboxArtifactPackage",
    "role_registry_stream_id",
]
