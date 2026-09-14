"""Candidate-side entrypoint used by the trusted WSL supervisor.

Harness candidates may evolve :func:`run_cycle`, but cannot choose which
module or command the supervisor executes.  The default implementation runs
the standard full v2 cycle through :mod:`aegis.wsl_cycle_runtime`; evolved
candidates may replace the cycle flow itself — the frozen-path byte
comparison against the pinned source ref, the supervisor protocol, and the
credential sidecar remain outside that authority.
"""

from __future__ import annotations

from typing import Any, Mapping


def run_cycle(request_payload: Mapping[str, Any]) -> Mapping[str, Any]:
    """Run the active harness cycle and return bounded JSON evidence."""
    from aegis.wsl_cycle_runtime import execute_standard_cycle

    return execute_standard_cycle(request_payload)
