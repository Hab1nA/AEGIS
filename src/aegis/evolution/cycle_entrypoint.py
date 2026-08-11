"""Fixed candidate-side entrypoint used by the trusted WSL supervisor.

Harness candidates may evolve :func:`run_cycle`, but cannot choose which
module or command the supervisor executes.  The default implementation is a
minimal deterministic heartbeat-compatible cycle hook.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

from aegis.models import canonical_json


def run_cycle(request_payload: Mapping[str, Any]) -> Mapping[str, Any]:
    """Run the active harness cycle hook and return bounded JSON evidence."""

    return {
        "accepted": True,
        "request_sha256": hashlib.sha256(
            canonical_json(request_payload).encode("utf-8")
        ).hexdigest(),
    }
