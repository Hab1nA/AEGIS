"""DeepSeek native Responses model gateway and role protocols."""

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
