"""Versioned curriculum-domain foundations for the AEGIS v2 control plane."""

from .models import (
    MANDATORY_PROTECTED_CONTROLS,
    ActiveRoleSet,
    Constitution,
    CurriculumSnapshot,
    ObjectiveVersion,
    RoleVersionIdentity,
)
from .planner import (
    CapabilityGap,
    CurriculumHypothesis,
    CurriculumPlan,
    CurriculumPlanner,
    CurriculumPlanningError,
    TaskCapabilityProfile,
)
from .registry import (
    CONSTITUTION_RECORDED_V2,
    CURRICULUM_SNAPSHOT_RECORDED_V2,
    CYCLE_STATE_CHANGED_V2,
    OBJECTIVE_ACTIVATED_V2,
    OBJECTIVE_PROBATION_STARTED_V2,
    OBJECTIVE_PROVISIONAL_V2,
    OBJECTIVE_ROLLED_BACK_V2,
    CurriculumRegistry,
    CurriculumRegistryError,
    CycleProjection,
    ObjectiveStatus,
)
from .state_machine import (
    CycleState,
    CycleStateMachine,
    InvalidCycleTransitionError,
    available_cycle_actions,
    cycle_transition,
)

__all__ = [
    "MANDATORY_PROTECTED_CONTROLS",
    "ActiveRoleSet",
    "Constitution",
    "CapabilityGap",
    "CONSTITUTION_RECORDED_V2",
    "CURRICULUM_SNAPSHOT_RECORDED_V2",
    "CurriculumSnapshot",
    "CurriculumHypothesis",
    "CurriculumPlan",
    "CurriculumPlanner",
    "CurriculumPlanningError",
    "CurriculumRegistry",
    "CurriculumRegistryError",
    "CYCLE_STATE_CHANGED_V2",
    "CycleProjection",
    "CycleState",
    "CycleStateMachine",
    "InvalidCycleTransitionError",
    "ObjectiveVersion",
    "ObjectiveStatus",
    "OBJECTIVE_ACTIVATED_V2",
    "OBJECTIVE_PROBATION_STARTED_V2",
    "OBJECTIVE_PROVISIONAL_V2",
    "OBJECTIVE_ROLLED_BACK_V2",
    "RoleVersionIdentity",
    "TaskCapabilityProfile",
    "available_cycle_actions",
    "cycle_transition",
]
