"""Strict, immutable control-plane value objects.

This module deliberately contains no imports from AEGIS subpackages.  A few
subsystems have similarly named implementation-specific result types; keeping
the domain types dependency-free prevents import cycles and accidental type
coupling.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Mapping

JsonScalar = str | int | float | bool | None
JsonValue = JsonScalar | tuple["JsonValue", ...] | Mapping[str, "JsonValue"]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _required_text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    if value != value.strip():
        raise ValueError(f"{name} must not contain surrounding whitespace")
    return value


def _non_negative_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


def _non_negative_number(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be numeric")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise ValueError(f"{name} must be finite and non-negative")
    return result


def _aware_datetime(value: object, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")
    return value


def freeze_json(value: Any, *, path: str = "payload") -> JsonValue:
    """Validate a JSON value and recursively make containers immutable."""
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{path} contains a non-finite number")
        return value
    if isinstance(value, (list, tuple)):
        return tuple(freeze_json(item, path=f"{path}[]") for item in value)
    if isinstance(value, Mapping):
        frozen: dict[str, JsonValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"{path} contains a non-string object key")
            frozen[key] = freeze_json(item, path=f"{path}.{key}")
        return MappingProxyType(frozen)
    raise TypeError(f"{path} contains non-JSON value {type(value).__name__}")


def thaw_json(value: JsonValue) -> Any:
    """Convert an immutable JSON value back to standard JSON containers."""
    if isinstance(value, Mapping):
        return {key: thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [thaw_json(item) for item in value]
    return value


def canonical_json(value: Mapping[str, Any]) -> str:
    frozen = freeze_json(value)
    return json.dumps(
        thaw_json(frozen),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


class Role(StrEnum):
    WARRIOR = "warrior"
    JUDGE = "judge"
    PROSECUTOR = "prosecutor"


@dataclass(frozen=True, slots=True)
class AuditEvent:
    campaign_id: str
    sequence: int
    event_type: str
    payload: Mapping[str, JsonValue]
    created_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        _required_text(self.campaign_id, "campaign_id")
        if _non_negative_int(self.sequence, "sequence") == 0:
            raise ValueError("sequence must be positive")
        _required_text(self.event_type, "event_type")
        if not isinstance(self.payload, Mapping):
            raise TypeError("payload must be a mapping")
        object.__setattr__(self, "payload", freeze_json(self.payload))
        _aware_datetime(self.created_at, "created_at")


@dataclass(frozen=True, slots=True)
class PromotionDecision:
    proposal_id: str
    promoted: bool
    reason: str
    quality_delta: float
    token_change: float

    def __post_init__(self) -> None:
        _required_text(self.proposal_id, "proposal_id")
        if not isinstance(self.promoted, bool):
            raise TypeError("promoted must be a bool")
        _required_text(self.reason, "reason")
        for name in ("quality_delta", "token_change"):
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
            ):
                raise ValueError(f"{name} must be a finite number")
            object.__setattr__(self, name, float(value))
