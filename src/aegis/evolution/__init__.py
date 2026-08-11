"""Self-evolution surfaces, registries, and runtime binding for AEGIS v2."""

from .control_core import (
    DEFAULT_CONTROL_CORE_POLICY,
    ControlCorePolicy,
    ControlCorePolicyError,
)
from .surfaces import (
    EVOLUTION_PROTOCOL_SCHEMA,
    EvolutionProposal,
    EvolutionSurface,
    validate_evolution_proposal,
    validate_surface_content,
)

__all__ = [
    "EVOLUTION_PROTOCOL_SCHEMA",
    "DEFAULT_CONTROL_CORE_POLICY",
    "ControlCorePolicy",
    "ControlCorePolicyError",
    "EvolutionProposal",
    "EvolutionSurface",
    "validate_evolution_proposal",
    "validate_surface_content",
]
