"""Control-plane MCP bridge.

The sandbox stays offline; MCP servers run on the control plane (or on the
host) and are exposed to the Warrior through ``aegis.mcp_call``.  The bridge
speaks the MCP JSON-RPC 2.0 subset over HTTPS (or loopback HTTP for local
tooling): ``tools/list`` for discovery and ``tools/call`` for invocation.
Every endpoint is validated (HTTPS or loopback only, no credentials) and every
tool call result is size-bounded before it reaches the agent.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Mapping, Sequence
from urllib.parse import urlsplit

from aegis.models import canonical_json

if TYPE_CHECKING:
    from .evolution import McpBinding, McpCandidate

_NAME = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")


class McpBridgeError(RuntimeError):
    """A policy, connectivity, or protocol failure in the MCP bridge."""


@dataclass(frozen=True, slots=True)
class McpServerManifest:
    manifest_id: str
    name: str
    endpoint: str
    tool_names: tuple[str, ...]
    version: str
    rationale: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or _NAME.fullmatch(self.name) is None:
            raise McpBridgeError("MCP server name must match [a-z][a-z0-9-]{0,63}")
        if not isinstance(self.version, str) or not self.version or len(self.version) > 64:
            raise McpBridgeError("MCP server version must be bounded non-empty text")
        if not isinstance(self.rationale, str) or not self.rationale or len(self.rationale) > 2000:
            raise McpBridgeError("MCP server rationale must be bounded non-empty text")
        parsed = urlsplit(self.endpoint)
        host = parsed.hostname
        if parsed.scheme == "https" and host is not None and parsed.query == "" and parsed.fragment == "":
            pass
        elif parsed.scheme == "http" and host in {"127.0.0.1", "localhost", "::1"}:
            if parsed.query or parsed.fragment:
                raise McpBridgeError("loopback MCP endpoints must not carry query or fragment")
        else:
            raise McpBridgeError("MCP endpoint must be HTTPS or a loopback HTTP URL")
        if parsed.username is not None or parsed.password is not None:
            raise McpBridgeError("MCP endpoint must not carry credentials")
        if not self.tool_names or len(self.tool_names) > 64 or len(set(self.tool_names)) != len(self.tool_names):
            raise McpBridgeError("MCP tool_names must be a unique non-empty list")
        if any(not isinstance(item, str) or not item or len(item) > 128 for item in self.tool_names):
            raise McpBridgeError("MCP tool names must be bounded non-empty text")
        expected = "mcp-server-sha256:" + hashlib.sha256(
            canonical_json(self.to_mapping(include_id=False)).encode("utf-8")
        ).hexdigest()
        if self.manifest_id != expected:
            raise McpBridgeError("MCP manifest content id mismatch")

    @classmethod
    def create(
        cls,
        *,
        name: str,
        endpoint: str,
        tool_names: Sequence[str],
        version: str,
        rationale: str,
    ) -> McpServerManifest:
        payload = {
            "name": name,
            "endpoint": endpoint,
            "tool_names": tuple(tool_names),
            "version": version,
            "rationale": rationale,
        }
        return cls(
            "mcp-server-sha256:"
            + hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest(),
            name,
            endpoint,
            tuple(tool_names),
            version,
            rationale,
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> McpServerManifest:
        expected = {"manifest_id", "name", "endpoint", "tool_names", "version", "rationale"}
        if set(value) != expected:
            raise McpBridgeError("MCP manifest has missing or unknown fields")
        return cls(
            value["manifest_id"],
            value["name"],
            value["endpoint"],
            tuple(value["tool_names"]),
            value["version"],
            value["rationale"],
        )

    def to_mapping(self, *, include_id: bool = True) -> dict[str, Any]:
        payload = {
            "name": self.name,
            "endpoint": self.endpoint,
            "tool_names": list(self.tool_names),
            "version": self.version,
            "rationale": self.rationale,
        }
        return {"manifest_id": self.manifest_id, **payload} if include_id else payload


@dataclass(frozen=True, slots=True)
class McpToolCatalogEntry:
    name: str
    input_schema: Mapping[str, Any]
    description: str

    @property
    def schema_sha256(self) -> str:
        return hashlib.sha256(
            canonical_json(self.input_schema).encode("utf-8")
        ).hexdigest()

    def to_mapping(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "input_schema": dict(self.input_schema),
            "description": self.description,
            "schema_sha256": self.schema_sha256,
        }


@dataclass(frozen=True, slots=True)
class McpCallReceipt:
    binding_id: str
    server_name: str
    tool_name: str
    arguments_sha256: str
    result_sha256: str
    receipt_id: str

    @classmethod
    def create(
        cls,
        *,
        binding_id: str,
        server_name: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        result: Mapping[str, Any],
    ) -> "McpCallReceipt":
        arguments_sha256 = hashlib.sha256(
            canonical_json(arguments).encode("utf-8")
        ).hexdigest()
        result_sha256 = hashlib.sha256(
            canonical_json(result).encode("utf-8")
        ).hexdigest()
        payload = {
            "binding_id": binding_id,
            "server_name": server_name,
            "tool_name": tool_name,
            "arguments_sha256": arguments_sha256,
            "result_sha256": result_sha256,
        }
        receipt_id = "mcp-call-sha256:" + hashlib.sha256(
            canonical_json(payload).encode("utf-8")
        ).hexdigest()
        return cls(
            binding_id,
            server_name,
            tool_name,
            arguments_sha256,
            result_sha256,
            receipt_id,
        )

    def to_mapping(self) -> dict[str, str]:
        return {
            "binding_id": self.binding_id,
            "server_name": self.server_name,
            "tool_name": self.tool_name,
            "arguments_sha256": self.arguments_sha256,
            "result_sha256": self.result_sha256,
            "receipt_id": self.receipt_id,
        }


class McpClient:
    """Minimal MCP JSON-RPC 2.0 client over HTTPS or loopback HTTP."""

    def __init__(self, endpoint: str, *, timeout_seconds: float = 15.0) -> None:
        manifest_probe = McpServerManifest.create(
            name="probe",
            endpoint=endpoint,
            tool_names=("probe",),
            version="0",
            rationale="client probe",
        )
        del manifest_probe
        self._endpoint = endpoint
        parsed = urlsplit(endpoint)
        self._host = parsed.hostname or ""
        self._port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self._loopback_transport = parsed.scheme == "http"
        self._pinned_ips = self._resolve_and_validate_endpoint()
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
            raise McpBridgeError("MCP timeout must be numeric")
        if not 1 <= float(timeout_seconds) <= 300:
            raise McpBridgeError("MCP timeout must be in [1, 300]")
        self._timeout = float(timeout_seconds)

    def _resolve_and_validate_endpoint(self) -> tuple[str, ...]:
        try:
            rows = socket.getaddrinfo(
                self._host, self._port, type=socket.SOCK_STREAM
            )
        except OSError as exc:
            raise McpBridgeError(f"MCP endpoint DNS resolution failed: {exc}") from exc
        addresses = tuple(sorted({str(item[4][0]) for item in rows}))
        if not addresses:
            raise McpBridgeError("MCP endpoint resolved to no address")
        parsed = tuple(ipaddress.ip_address(item) for item in addresses)
        if self._loopback_transport:
            if any(not item.is_loopback for item in parsed):
                raise McpBridgeError("loopback MCP endpoint resolved outside loopback")
        elif any(
            item.is_private
            or item.is_loopback
            or item.is_link_local
            or item.is_multicast
            or item.is_reserved
            or item.is_unspecified
            for item in parsed
        ):
            raise McpBridgeError("HTTPS MCP endpoint resolved to a non-public address")
        return addresses

    def _verify_dns_pin(self) -> None:
        if self._resolve_and_validate_endpoint() != self._pinned_ips:
            raise McpBridgeError("MCP endpoint DNS binding changed after validation")

    def list_tools(self) -> tuple[str, ...]:
        return tuple(item.name for item in self.list_tool_catalog())

    def list_tool_catalog(self) -> tuple[McpToolCatalogEntry, ...]:
        response = self._rpc("tools/list", {})
        tools = response.get("result", {})
        if not isinstance(tools, Mapping):
            raise McpBridgeError("MCP tools/list returned a malformed result")
        names = tuple(tools.get("tools", ()))
        parsed: list[McpToolCatalogEntry] = []
        for item in names:
            if not isinstance(item, Mapping) or not isinstance(item.get("name"), str):
                raise McpBridgeError("MCP tools/list returned a malformed tool")
            schema = item.get("inputSchema", {"type": "object"})
            description = item.get("description", "undocumented MCP tool")
            if not isinstance(schema, Mapping) or not isinstance(description, str):
                raise McpBridgeError("MCP tools/list returned a malformed tool schema")
            parsed.append(McpToolCatalogEntry(item["name"], dict(schema), description[:1000]))
        by_name = {item.name: item for item in parsed}
        if len(by_name) != len(parsed):
            raise McpBridgeError("MCP tools/list returned duplicate tool names")
        return tuple(by_name[name] for name in sorted(by_name))

    def call_tool(self, name: str, arguments: Mapping[str, Any]) -> Mapping[str, Any]:
        response = self._rpc("tools/call", {"name": name, "arguments": dict(arguments)})
        result = response.get("result", {})
        if not isinstance(result, Mapping):
            raise McpBridgeError("MCP tools/call returned a malformed result")
        return result

    def _rpc(self, method: str, params: Mapping[str, Any]) -> Mapping[str, Any]:
        self._verify_dns_pin()
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": dict(params),
            "id": hashlib.sha256(
                canonical_json({"method": method, "params": params}).encode("utf-8")
            ).hexdigest()[:16],
        }
        body = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
        request = urllib.request.Request(
            self._endpoint,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            opener = urllib.request.build_opener(_NoRedirectHandler())
            with opener.open(request, timeout=self._timeout) as response:
                raw = response.read(2 * 1024 * 1024)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise McpBridgeError(f"MCP request failed: {exc}") from exc
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise McpBridgeError("MCP response is not JSON") from exc
        if not isinstance(decoded, Mapping) or decoded.get("jsonrpc") != "2.0":
            raise McpBridgeError("MCP response is not a JSON-RPC 2.0 envelope")
        if "error" in decoded:
            error = decoded["error"]
            raise McpBridgeError(f"MCP {method} error: {error!r}")
        return decoded


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        del req, fp, code, msg, headers, newurl
        raise McpBridgeError("MCP endpoint redirects are forbidden")


class McpBridge:
    """Registry of validated, live-checked MCP servers exposed to the runtime."""

    def __init__(self) -> None:
        self._servers: dict[str, tuple[McpServerManifest, McpClient, McpBinding | None]] = {}
        self._receipts: list[McpCallReceipt] = []

    def deploy(self, manifest: McpServerManifest) -> Mapping[str, Any]:
        if manifest.name in self._servers:
            raise McpBridgeError(f"MCP server {manifest.name!r} is already deployed")
        client = McpClient(manifest.endpoint)
        available = client.list_tools()
        missing = sorted(set(manifest.tool_names) - set(available))
        if missing:
            raise McpBridgeError(
                f"MCP server {manifest.name!r} does not expose tools: {missing}"
            )
        self._servers[manifest.name] = (manifest, client, None)
        return {
            "manifest_id": manifest.manifest_id,
            "name": manifest.name,
            "endpoint": manifest.endpoint,
            "tools_available": list(available),
        }

    def deploy_candidate(self, candidate: "McpCandidate") -> Mapping[str, Any]:
        """Validate a candidate's exact catalog and bind it to this bridge only."""
        from .evolution import McpCandidate

        if not isinstance(candidate, McpCandidate):
            raise TypeError("candidate must be an McpCandidate")
        if candidate.manifest.name in self._servers:
            raise McpBridgeError(
                f"MCP server {candidate.manifest.name!r} is already deployed"
            )
        client = McpClient(candidate.manifest.endpoint)
        catalog = client.list_tool_catalog()
        actual = {item.name: item for item in catalog}
        declared = {item.tool_name: item for item in candidate.binding.authorizations}
        if set(actual) != set(declared):
            raise McpBridgeError("MCP catalog names do not match the immutable binding")
        drifted = sorted(
            name
            for name, grant in declared.items()
            if actual[name].schema_sha256 != grant.schema_sha256
        )
        if drifted:
            raise McpBridgeError(f"MCP tool schemas drifted for: {drifted}")
        self._servers[candidate.manifest.name] = (
            candidate.manifest,
            client,
            candidate.binding,
        )
        return {
            "manifest_id": candidate.manifest.manifest_id,
            "candidate_id": candidate.candidate_id,
            "binding_id": candidate.binding.binding_id,
            "name": candidate.manifest.name,
            "catalog": [item.to_mapping() for item in catalog],
        }

    def with_candidate(self, candidate: "McpCandidate") -> "McpBridge":
        overlay = McpBridge()
        overlay._servers = dict(self._servers)
        overlay._servers.pop(candidate.manifest.name, None)
        overlay.deploy_candidate(candidate)
        return overlay

    def activate_candidate(self, candidate: "McpCandidate") -> Mapping[str, Any]:
        """Install or replace one already-qualified binding in the live bridge."""
        previous = self._servers.pop(candidate.manifest.name, None)
        try:
            return self.deploy_candidate(candidate)
        except Exception:
            if previous is not None:
                self._servers[candidate.manifest.name] = previous
            raise

    def call(
        self, name: str, tool: str, arguments: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        entry = self._servers.get(name)
        if entry is None:
            raise McpBridgeError(f"MCP server {name!r} is not deployed")
        manifest, client, binding = entry
        if tool not in manifest.tool_names:
            raise McpBridgeError(
                f"MCP tool {tool!r} is not in the declared grant of server {name!r}"
            )
        result = client.call_tool(tool, arguments)
        encoded = json.dumps(result, ensure_ascii=False, sort_keys=True).encode("utf-8")
        if len(encoded) > 256 * 1024:
            raise McpBridgeError("MCP tool result exceeds the size bound")
        if binding is not None:
            self._receipts.append(
                McpCallReceipt.create(
                    binding_id=binding.binding_id,
                    server_name=name,
                    tool_name=tool,
                    arguments=arguments,
                    result=result,
                )
            )
        return result

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._servers))

    def receipts(self) -> tuple[McpCallReceipt, ...]:
        return tuple(self._receipts)

    def candidate_was_used(self, binding_id: str) -> bool:
        return any(item.binding_id == binding_id for item in self._receipts)


__all__ = [
    "McpBridge",
    "McpBridgeError",
    "McpCallReceipt",
    "McpClient",
    "McpServerManifest",
    "McpToolCatalogEntry",
]
