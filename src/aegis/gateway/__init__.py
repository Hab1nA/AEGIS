"""OpenAI-compatible native Responses model gateway and role protocols.

The relay currently targets `agnes-2.5-flash` at
`https://apihub.agnes-ai.com/v1/responses` (Responses protocol, Bearer auth,
`reasoning_effort: "max"` enables thinking with a full 65,536-token budget).
The same gateway contract works against any OpenAI/DeepSeek-compatible
Responses endpoint; only base_url and credentials are project-configured.
"""

from .client import GatewayConfig, ModelGateway, RetryPolicy
from .protocols import Role, RoleOutput, RolePolicy, build_role_request, parse_role_output
from .transport import HTTPResponse, HTTPTransport, StdlibHTTPTransport
from .types import (
    CancelToken,
    GatewayAttempt,
    GatewayAttemptObserver,
    GatewayAttemptResult,
    GatewayCancelled,
    GatewayError,
    GatewayHTTPError,
    GatewayRequest,
    GatewayResponse,
    Message,
    TokenUsage,
)

__all__ = [
    "CancelToken",
    "GatewayConfig",
    "GatewayCancelled",
    "GatewayAttempt",
    "GatewayAttemptObserver",
    "GatewayAttemptResult",
    "GatewayError",
    "GatewayHTTPError",
    "GatewayRequest",
    "GatewayResponse",
    "HTTPResponse",
    "HTTPTransport",
    "Message",
    "ModelGateway",
    "RetryPolicy",
    "Role",
    "RoleOutput",
    "RolePolicy",
    "StdlibHTTPTransport",
    "TokenUsage",
    "build_role_request",
    "parse_role_output",
]
