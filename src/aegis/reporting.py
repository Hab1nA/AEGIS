"""Auditable JSON and Markdown campaign reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aegis.event_store import EventStore
from aegis.models import thaw_json


def replay_events(store: EventStore, campaign_id: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    after = 0
    while True:
        batch = store.read(campaign_id, after_sequence=after, limit=1000)
        if not batch:
            return result
        result.extend(
            {
                "sequence": item.sequence,
                "event_type": item.event_type,
                "payload": thaw_json(item.payload),
                "created_at": item.created_at.isoformat(),
            }
            for item in batch
        )
        after = batch[-1].sequence


def build_report(store: EventStore, campaign_id: str) -> dict[str, Any]:
    events = replay_events(store, campaign_id)
    state = "unknown"
    tokens = requests = rounds = 0
    qualities: list[dict[str, Any]] = []
    promotions: list[dict[str, Any]] = []
    usage: dict[str, Any] = {
        "input_tokens": 0,
        "output_tokens": 0,
        "cached_tokens": 0,
        "reasoning_tokens": 0,
        "verified": True,
        "by_role": {},
    }
    for event in events:
        payload = event["payload"]
        if event["event_type"] == "campaign_created" and state == "unknown":
            state = "created"
        elif event["event_type"] == "state_changed":
            state = payload["state"]
        elif event["event_type"] == "usage_committed":
            input_tokens = int(payload.get("input_tokens", 0))
            output_tokens = int(payload.get("output_tokens", payload.get("tokens", 0)))
            tokens += input_tokens + output_tokens
            requests += 1
            role = str(payload.get("role", "unknown"))
            row = usage["by_role"].setdefault(
                role,
                {
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "cached_tokens": 0,
                    "reasoning_tokens": 0,
                    "requests": 0,
                    "verified": True,
                },
            )
            for field, value in (
                ("input_tokens", input_tokens),
                ("output_tokens", output_tokens),
                ("cached_tokens", int(payload.get("cached_tokens", 0))),
                ("reasoning_tokens", int(payload.get("reasoning_tokens", 0))),
            ):
                usage[field] += value
                row[field] += value
            row["requests"] += 1
            row["verified"] = row["verified"] and bool(payload.get("verified", False))
            usage["verified"] = usage["verified"] and bool(payload.get("verified", False))
        elif event["event_type"] == "round_completed":
            rounds += 1
        elif event["event_type"] == "quality_locked":
            qualities.append(payload)
        elif event["event_type"] == "promotion_decided":
            promotions.append(payload)
    return {
        "campaign_id": campaign_id,
        "state": state,
        "rounds_completed": rounds,
        "tokens_used": tokens,
        "requests_used": requests,
        "qualities": qualities,
        "usage": usage,
        "promotions": promotions,
        "event_count": len(events),
        "events": events,
    }


def report_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# AEGIS campaign `{report['campaign_id']}`",
        "",
        f"- State: **{report['state']}**",
        f"- Rounds completed: {report['rounds_completed']}",
        f"- Tokens used: {report['tokens_used']}",
        f"- Requests: {report['requests_used']}",
        "",
        "## Quality and promotion",
        "",
    ]
    if not report["qualities"]:
        lines.append("No quality decisions were locked.")
    for item in report["qualities"]:
        lines.append(f"- Round {item['round']}: score `{item['quality'].get('score')}`")
    for item in report["promotions"]:
        decision = item["decision"]
        lines.append(
            f"- Round {item['round']} promotion: `{decision.get('promoted')}` — {decision.get('reason', '')}"
        )
    lines.extend(["", "## Audit trail", "", "| Seq | Event | Timestamp |", "|---:|---|---|"])
    lines.extend(
        f"| {event['sequence']} | {event['event_type']} | {event['created_at']} |"
        for event in report["events"]
    )
    return "\n".join(lines) + "\n"


def write_report(
    store: EventStore, campaign_id: str, destination: str | Path, *, format: str = "json"
) -> Path:
    target = Path(destination)
    target.parent.mkdir(parents=True, exist_ok=True)
    report = build_report(store, campaign_id)
    if format == "json":
        text = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    elif format == "markdown":
        text = report_markdown(report)
    else:
        raise ValueError("format must be json or markdown")
    target.write_text(text, encoding="utf-8")
    return target
