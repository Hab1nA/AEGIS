"""Default sandbox entry point for deriving bounded role workflow advice."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Mapping, Sequence

ROLES = frozenset({"warrior", "judge", "prosecutor"})
MAX_CONTEXT_BYTES = 64 * 1024


def build_workflow(role: str, context: Mapping[str, Any]) -> Mapping[str, object]:
    """Return conservative defaults; evolved candidates may improve this pure contract."""
    if role not in ROLES:
        raise ValueError("role is invalid")
    if not isinstance(context, Mapping):
        raise TypeError("context must be an object")
    role_focus = {
        "warrior": "Implement the smallest robust change and verify the relevant behavior.",
        "judge": "Attack boundaries, state transitions, and assumptions with bounded tests.",
        "prosecutor": "Audit evidence, attribution, safety, and verified token efficiency.",
    }[role]
    return {
        "stage_plan": ["Inspect", "Search prior evidence", "Act", "Verify", "Submit"],
        "research_query_templates": [
            "{language} {failure_mode} current engineering practice",
            "{library} official documentation {api}",
        ],
        "tool_selection_rules": [
            "Search cross-round knowledge before repeating external research.",
            "Prefer primary sources and exact immutable versions.",
            role_focus,
        ],
        "stop_conditions": [
            "Stop when the objective is met and the relevant verification passes.",
            "Stop and report evidence when a safety or budget boundary blocks progress.",
        ],
        "verification_checklist": [
            "Check the smallest relevant test first.",
            "Run the broader regression suite when the change can affect shared behavior.",
            "Confirm no permission, budget, sandbox, scoring, or hidden-test boundary changed.",
        ],
        "skill_references": ["registry:promoted-champions-only"],
        "max_steps": 20,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=sorted(ROLES), required=True)
    args = parser.parse_args(argv)
    raw = sys.stdin.buffer.read(MAX_CONTEXT_BYTES + 1)
    if len(raw) > MAX_CONTEXT_BYTES:
        raise ValueError("context exceeds the input limit")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("context must be a JSON object")
    sys.stdout.write(
        json.dumps(build_workflow(args.role, value), ensure_ascii=False, allow_nan=False, sort_keys=True)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

