"""URL and address validation for the controlled fetch boundary."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import cast
from urllib.parse import urlsplit, urlunsplit

from .interfaces import Resolver


@dataclass(frozen=True, slots=True)
class UrlPolicy:
    allowed_schemes: frozenset[str] = frozenset({"https"})
    allowed_ports: frozenset[int] = frozenset({443})


class SystemResolver:
    def resolve(self, hostname: str) -> tuple[str, ...]:
        return tuple(sorted({cast(str, item[4][0]) for item in socket.getaddrinfo(hostname, None)}))


class StaticResolver:
    """Explicit resolver useful for deterministic tests and pinned deployments."""

    def __init__(self, records: dict[str, tuple[str, ...]]) -> None:
        self.records = {name.rstrip(".").lower(): addresses for name, addresses in records.items()}

    def resolve(self, hostname: str) -> tuple[str, ...]:
        try:
            return self.records[hostname.rstrip(".").lower()]
        except KeyError as exc:
            raise OSError(f"host not found: {hostname}") from exc


def _is_public(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    # is_global rejects private, loopback, link-local, multicast, unspecified,
    # documentation and reserved ranges. Explicit checks document our intent.
    return bool(
        address.is_global
        and not address.is_private
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_multicast
        and not address.is_reserved
        and not address.is_unspecified
    )


def validate_url_target(
    url: str, resolver: Resolver, policy: UrlPolicy = UrlPolicy()
) -> tuple[str, tuple[str, ...]]:
    if not isinstance(url, str) or len(url) > 2048 or any(ord(char) < 32 for char in url):
        raise ValueError("invalid URL text")
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    if scheme not in policy.allowed_schemes:
        raise ValueError("URL scheme is not allowed")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URL credentials are not allowed")
    if not parsed.hostname:
        raise ValueError("URL must include a hostname")
    addresses: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid URL port") from exc
    default_port = 443 if scheme == "https" else 80
    if (port or default_port) not in policy.allowed_ports:
        raise ValueError("URL port is not allowed")
    hostname = parsed.hostname.rstrip(".").lower()
    try:
        literal = ipaddress.ip_address(hostname)
        addresses = (literal,)
    except ValueError:
        if hostname == "localhost" or hostname.endswith(".localhost"):
            raise ValueError("local hostnames are not allowed")
        resolved = resolver.resolve(hostname)
        if not resolved:
            raise ValueError("hostname resolved to no addresses")
        try:
            addresses = tuple(ipaddress.ip_address(item) for item in resolved)
        except ValueError as exc:
            raise ValueError("resolver returned an invalid IP address") from exc
    if not all(_is_public(address) for address in addresses):
        raise ValueError("URL resolves to a non-public address")
    if parsed.fragment:
        raise ValueError("URL fragments are not accepted at the fetch boundary")
    host_text = f"[{hostname}]" if ":" in hostname else hostname
    netloc = host_text if port is None else f"{host_text}:{port}"
    normalized = urlunsplit((scheme, netloc, parsed.path or "/", parsed.query, ""))
    return normalized, tuple(str(address) for address in addresses)


def validate_url(url: str, resolver: Resolver, policy: UrlPolicy = UrlPolicy()) -> str:
    return validate_url_target(url, resolver, policy)[0]


# ── Narrow loopback exception for local SearxNG ─────────────────────────

LOOPBACK_ADDRESSES: frozenset[str] = frozenset({"127.0.0.1", "::1"})
LOOPBACK_PORT = 8888


def validate_loopback_url_target(url: str) -> tuple[str, tuple[str, ...]]:
    """Validate a URL for the narrow SearxNG loopback exception.

    Accepts **only** HTTP scheme, literal loopback IPs (``127.0.0.1`` or
    ``::1``), and port 8888.  Rejects hostnames (including ``localhost``),
    private/LAN addresses, credentials, fragments, and every other port.
    """
    if not isinstance(url, str) or len(url) > 2048 or any(ord(char) < 32 for char in url):
        raise ValueError("invalid URL text")
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    if scheme != "http":
        raise ValueError("loopback URL must use HTTP scheme")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URL credentials are not allowed")
    hostname_raw = parsed.hostname
    if not hostname_raw:
        raise ValueError("URL must include a hostname")
    hostname = hostname_raw.rstrip(".").lower()
    # Only literal loopback IPs — no hostnames, no DNS resolution.
    if hostname not in LOOPBACK_ADDRESSES:
        raise ValueError("loopback URL must use 127.0.0.1 or [::1]")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid URL port") from exc
    if (port or 80) != LOOPBACK_PORT:
        raise ValueError("loopback URL must use port 8888")
    if parsed.fragment:
        raise ValueError("URL fragments are not accepted at the fetch boundary")
    host_text = f"[{hostname}]" if ":" in hostname else hostname
    netloc = host_text if port is None else f"{host_text}:{port}"
    normalized = urlunsplit(("http", netloc, parsed.path or "/", parsed.query, ""))
    return normalized, (hostname,)
