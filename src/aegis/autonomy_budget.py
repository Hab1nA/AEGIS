"""Structural budget contract for the dedicated autonomous-evolution smoke."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

AUTONOMY_ROLE_SHARES: Mapping[str, float] = {
    "warrior": 0.55,
    "judge": 0.225,
    "prosecutor": 0.225,
}
AUTONOMY_ATTEMPTS_PER_CALL = 3
AUTONOMY_MIN_AGENT_STEPS = 20
AUTONOMY_MIN_OUTPUT_TOKENS = 4_096

# v2 dynamic design: one cycle performs warrior solve, judge review/forge,
# prosecutor audit/deliberate, and three role reflections (8 model calls).
V2_CALLS_PER_CYCLE = 8
V2_CYCLES = 2
V2_ROLE_CALLS: Mapping[str, int] = {
    "warrior": 1 * V2_CYCLES,
    "judge": 3 * V2_CYCLES,
    "prosecutor": 3 * V2_CYCLES,
}
V2_MIN_REQUESTS = V2_CALLS_PER_CYCLE * V2_CYCLES * AUTONOMY_ATTEMPTS_PER_CALL
V2_PROMPT_RESERVE_BYTES = 32_768
V2_RECOMMENDED_TOTAL_TOKENS = 16_000_000


@dataclass(frozen=True, slots=True)
class AutonomyBudgetCheck:
    passed: bool
    minimum_requests: int
    global_tokens_required: int
    role_tokens_required: Mapping[str, int]
    failures: tuple[str, ...]


def autonomy_v2_budget_check(
    *,
    total_tokens: int,
    max_requests: int,
    role_shares: Mapping[str, float],
    max_output_tokens: Mapping[str, int],
) -> AutonomyBudgetCheck:
    """Prove capacity for two dynamic v2 cycles (8 model calls each) with relay retries."""
    if set(role_shares) != set(AUTONOMY_ROLE_SHARES) or set(max_output_tokens) != set(
        AUTONOMY_ROLE_SHARES
    ):
        raise ValueError("autonomy v2 budget roles must be warrior, judge, and prosecutor")
    role_required = {
        role: calls
        * AUTONOMY_ATTEMPTS_PER_CALL
        * (V2_PROMPT_RESERVE_BYTES + max_output_tokens[role])
        for role, calls in V2_ROLE_CALLS.items()
    }
    global_required = sum(role_required.values())
    failures: list[str] = []
    for role, output_tokens in max_output_tokens.items():
        if output_tokens < AUTONOMY_MIN_OUTPUT_TOKENS:
            failures.append(
                f"{role} max_output_tokens {output_tokens} < {AUTONOMY_MIN_OUTPUT_TOKENS}"
            )
    if max_requests < V2_MIN_REQUESTS:
        failures.append(f"requests {max_requests} < {V2_MIN_REQUESTS}")
    if total_tokens < global_required:
        failures.append(f"global token dimension {total_tokens} < {global_required}")
    for role, required in role_required.items():
        available = int(total_tokens * role_shares[role])
        if available < required:
            failures.append(f"{role} token dimension {available} < {required}")
    return AutonomyBudgetCheck(
        not failures,
        V2_MIN_REQUESTS,
        global_required,
        role_required,
        tuple(failures),
    )
