#!/usr/bin/python3
"""Start the pinned SearxNG container through the Windows host proxy."""

import ipaddress
import os
import socket
import subprocess
from pathlib import Path

route = subprocess.run(
    ["/usr/sbin/ip", "-4", "route", "show", "default"],
    check=True,
    capture_output=True,
    text=True,
).stdout.split()
if "via" not in route:
    raise SystemExit("default IPv4 gateway is unavailable")
gateway = route[route.index("via") + 1]
address = ipaddress.ip_address(gateway)
if address.version != 4 or not address.is_private:
    raise SystemExit("refusing non-private Windows proxy gateway")
with socket.create_connection((gateway, 7897), timeout=3):
    pass

proxy = f"http://{gateway}:7897"
source = Path("/etc/aegis-search/settings.yml").read_text(encoding="utf-8")
if source.count("__PROXY__") != 1:
    raise SystemExit("search settings must contain exactly one proxy placeholder")
runtime_root = Path("/home/aegis/.cache/aegis-search")
runtime_root.mkdir(mode=0o700, parents=True, exist_ok=True)
runtime_root.chmod(0o700)
runtime_settings = runtime_root / "settings.yml"
runtime_settings.write_text(source.replace("__PROXY__", proxy), encoding="utf-8")
runtime_settings.chmod(0o600)

image = "docker.io/searxng/searxng@sha256:f4c8e59de166ed71f6380c0847c312ca51f0d41996e31d0559163b6b09ecde52"
argv = [
    "/usr/bin/podman",
    "run",
    "--name",
    "aegis-search",
    "--replace",
    "--network",
    "host",
    "--env",
    "SEARXNG_BIND_ADDRESS=127.0.0.1",
    "--env",
    "SEARXNG_PORT=8888",
    "--env",
    "GRANIAN_HOST=127.0.0.1",
    "--env",
    "GRANIAN_PORT=8888",
    "--env",
    "FORCE_OWNERSHIP=false",
    "--cap-drop",
    "all",
    "--security-opt",
    "no-new-privileges",
    "--memory",
    "512m",
    "--cpus",
    "1",
    "--pids-limit",
    "128",
    "--read-only",
    "--tmpfs",
    "/tmp:rw,noexec,nosuid,nodev,size=64m",
    "--tmpfs",
    "/var/cache/searxng:rw,noexec,nosuid,nodev,size=64m",
    "--volume",
    "/home/aegis/.cache/aegis-search/settings.yml:/etc/searxng/settings.yml:ro",
    image,
]
os.execv(argv[0], argv)
