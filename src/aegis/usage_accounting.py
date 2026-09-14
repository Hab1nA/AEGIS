"""Frozen token-usage accounting.

This module is deliberately **outside** every harness-code evolvable root
(see ``aegis.evolution.surfaces.HARNESS_ALLOWED_ROOTS``): the figures that
feed budget enforcement, fitness attribution, and the Prosecutor's usage
audit are part of the score function, and an agent must not be able to edit
the code that produces them.  The model transport (``gateway.client``, an
editable surface) hands the raw relay payload here; this module is the only
place that constructs a verified :class:`TokenUsage`, and it stamps any
internally inconsistent figure with an anomaly instead of silently trusting
it.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import TYPE_CHECKING, Mapping

if TYPE_CHECKING:
    from aegis.gateway.types import GatewayRequest


class UsageAccountingError(RuntimeError):
    """Raised when a relay usage payload is malformed beyond recovery."""


@dataclass(frozen=True, slots=True)
class TokenUsage:
    input_tokens: int
    output_tokens: int
    cached_tokens: int = 0
    reasoning_tokens: int = 0
    verified: bool = True
    anomalies: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if min(self.input_tokens, self.output_tokens, self.cached_tokens, self.reasoning_tokens) < 0:
            raise ValueError("token counts cannot be negative")

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


def extract_usage(
    data: Mapping[str, object], request: "GatewayRequest", text: str
) -> TokenUsage:
    """Map a relay response payload to a :class:`TokenUsage`.

    The mapping itself is moved verbatim from the transport client so the
    accounting semantics cannot drift with an edited transport.  Figures that
    are internally impossible (output beyond the request's reserved output
    budget, reasoning exceeding the reported output) keep their numbers but
    are flagged ``verified=False`` plus an anomaly tag, so downstream budget
    enforcement and the Prosecutor audit see the tampering instead of a
    plausible-looking total.
    """
    usage = data.get("usage")
    if isinstance(usage, Mapping):
        input_tokens = usage.get("input_tokens")
        output_tokens = usage.get("output_tokens")
        if isinstance(input_tokens, int) and isinstance(output_tokens, int):
            cached = 0
            reasoning = 0
            details = usage.get("input_tokens_details")
            if isinstance(details, Mapping) and isinstance(details.get("cached_tokens"), int):
                cached = int(details["cached_tokens"])
            out_details = usage.get("output_tokens_details")
            if isinstance(out_details, Mapping) and isinstance(out_details.get("reasoning_tokens"), int):
                reasoning = int(out_details["reasoning_tokens"])
            return _finalize(request, TokenUsage(input_tokens, output_tokens, cached, reasoning, True), text)
        # Some compatibility relays answer the Responses endpoint with
        # chat-completions-shaped usage (prompt/completion tokens).
        prompt_tokens = usage.get("prompt_tokens")
        completion_tokens = usage.get("completion_tokens")
        if isinstance(prompt_tokens, int) and isinstance(completion_tokens, int):
            cached = 0
            details = usage.get("prompt_tokens_details")
            if isinstance(details, Mapping) and isinstance(details.get("cached_tokens"), int):
                cached = int(details["cached_tokens"])
            reasoning = usage.get("reasoning_tokens")
            if not isinstance(reasoning, int):
                reasoning = 0
            return _finalize(request, TokenUsage(prompt_tokens, completion_tokens, cached, reasoning, True), text)
    # Conservative, explicitly unverified approximation for relays omitting usage.
    input_chars = sum(len(m.content) for m in request.messages)
    return TokenUsage(math.ceil(input_chars / 3), math.ceil(len(text) / 3), verified=False)


def _finalize(request: "GatewayRequest", usage: TokenUsage, text: str) -> TokenUsage:
    anomalies: list[str] = []
    verified = True
    if usage.output_tokens > request.max_output_tokens:
        anomalies.append("output_tokens_exceed_reserved_budget")
        verified = False
    if usage.reasoning_tokens > usage.output_tokens:
        anomalies.append("reasoning_tokens_exceed_output_tokens")
        verified = False
    if usage.cached_tokens > usage.input_tokens:
        anomalies.append("cached_tokens_exceed_input_tokens")
        verified = False
    if usage.output_tokens == 0 and usage.input_tokens > 0 and text.strip():
        # A non-empty completion with zero billed output tokens is a free-output
        # claim: plausible only if the relay genuinely produced nothing, which
        # the non-empty text excludes.  Zero is a *possible* number, so it
        # slips past the impossibility checks above — flag it explicitly.
        anomalies.append("zero_output_tokens_with_nonempty_text")
        verified = False
    if not anomalies:
        return usage
    return TokenUsage(
        usage.input_tokens,
        usage.output_tokens,
        usage.cached_tokens,
        usage.reasoning_tokens,
        verified,
        tuple(anomalies),
    )
