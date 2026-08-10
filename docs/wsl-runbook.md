# Dedicated WSL runbook

1. Create a new distribution used only for AEGIS. Do not reuse a development distribution.
2. Render the bootstrap plan with an OCI image pinned by SHA-256. Review it before using `--apply` with an absolute, empty staging root.
3. Copy the staged files into the dedicated distribution as root. `--apply` does not install packages, create users, enable systemd units, mount filesystems, or change the live distribution.
4. Create the unprivileged `aegis` user without sudo; install Python 3.12+, `curl`, and rootless Podman; configure subordinate UID/GID ranges; build `deploy/wsl/Containerfile.aegis`, then configure the resulting immutable digest (never a mutable tag). The verified initial image is `localhost/aegis-python@sha256:4ca421c781f3b9047629b8e1cefa6e892e96fc13d279aacaa85b8fa3a3ec3381`.
5. Enable `aegis-sandbox-prepare.service`, terminate the distribution, and restart it. The root-owned helper creates a 64 MiB backing file, formats it once as ext4, mounts it with `loop,nosuid,nodev`, checks `/proc/self/mountinfo` and `statvfs`, then atomically writes the quota marker.
6. Run `aegis doctor`. Any missing marker, ordinary directory, oversized filesystem, Windows mount, interop, secret, network policy, or container-runtime check must block execution.
7. Confirm no Windows drives appear, `cmd.exe` cannot run, no relay key exists inside WSL, and the task container has no network.

## Local research service

The initial deployment uses the pinned SearxNG image
`docker.io/searxng/searxng@sha256:f4c8e59de166ed71f6380c0847c312ca51f0d41996e31d0559163b6b09ecde52`.
Install `deploy/wsl/aegis-search-settings.yml` as `/etc/aegis-search/settings.yml`, generate and replace
`__GENERATE__` with a high-entropy secret, install `aegis-search-run.py` as
`/usr/local/libexec/aegis-search-run`, and install/enable `aegis-search.service` as a system unit. The service
runs rootless as `aegis` with host networking but makes SearxNG itself bind only WSL loopback
`127.0.0.1:8888`; it also has a read-only root filesystem, dropped capabilities, `no-new-privileges`, and
CPU, memory, and PID limits. Host networking is limited to this pinned research sidecar and is never used by
task containers.

The launcher deliberately discovers the current WSL private gateway instead of persisting an address. It
requires the Windows host proxy on port 7897; if that proxy is unavailable the unit fails closed and retries.
Set these Windows user environment variables before starting AEGIS:

```powershell
[Environment]::SetEnvironmentVariable("AEGIS_SEARCH_BASE_URL", "http://127.0.0.1:8888", "User")
[Environment]::SetEnvironmentVariable("AEGIS_ALLOW_INSECURE_SEARCH_LOOPBACK", "true", "User")
```

Restart WSL and exercise one JSON query through AEGIS before creating the first campaign. The Windows
research transport awakens the distribution and retries briefly while `aegis-search.service` starts, so a
separate keepalive process is not required. Do not put relay credentials or API keys in the distribution or
the search settings file.

Do not manually create the quota marker. Delete a failed staging root and render again; `apply_plan` intentionally refuses to overwrite existing files.
