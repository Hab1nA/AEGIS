"""Generate and validate a dedicated AEGIS WSL sandbox installation plan.

The default CLI mode is a dry run.  ``--apply`` writes files only beneath the
explicit ``--root`` staging/target directory; importing this module has no side
effects and the module never invokes ``wsl.exe`` or a package manager.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Mapping

NETWORK_MARKER = "enforced=podman-network-none-v1\n"
QUOTA_MARKER = "enforced=workspace-size-limit-v1\n"
WORKSPACE_BYTES = 67_108_864


@dataclass(frozen=True, slots=True)
class BootstrapSpec:
    image: str
    sandbox_user: str = "aegis"
    workspace_root: str = "/var/lib/aegis-sandbox/workspaces"
    memory: str = "1g"
    cpus: str = "1.0"
    pids_limit: int = 256
    tmpfs_size: str = "256m"
    max_workspace_bytes: int = WORKSPACE_BYTES

    def validate(self) -> None:
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", self.sandbox_user):
            raise ValueError("invalid sandbox user")
        root = PurePosixPath(self.workspace_root)
        if not root.is_absolute() or root == PurePosixPath("/") or ".." in root.parts:
            raise ValueError("workspace_root must be a safe non-root absolute path")
        if not re.search(r"@sha256:[0-9a-f]{64}$", self.image):
            raise ValueError("image must be pinned by sha256 digest")
        if not 1 <= self.pids_limit <= 4096:
            raise ValueError("invalid pids limit")
        if self.max_workspace_bytes != WORKSPACE_BYTES:
            raise ValueError(f"max_workspace_bytes must be exactly {WORKSPACE_BYTES}")
        for value in (self.memory, self.cpus, self.tmpfs_size):
            if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?[A-Za-z]*", value):
                raise ValueError("invalid resource limit")


def render_files(spec: BootstrapSpec) -> dict[str, str]:
    """Return absolute POSIX target paths and their complete desired contents."""
    spec.validate()
    agent_config = {
        "workspace_root": spec.workspace_root,
        "image": spec.image,
        "network_policy_marker": "/etc/aegis-sandbox/network-none.policy",
        "quota_policy_marker": "/etc/aegis-sandbox/workspace-quota.policy",
        "podman": "podman",
        "memory": spec.memory,
        "cpus": spec.cpus,
        "pids_limit": spec.pids_limit,
        "tmpfs_size": spec.tmpfs_size,
        "max_workspace_bytes": spec.max_workspace_bytes,
    }
    return {
        "/etc/wsl.conf": (
            "[boot]\n"
            "systemd=true\n\n"
            "[automount]\n"
            "enabled=false\n\n"
            "[interop]\n"
            "enabled=false\n"
            "appendWindowsPath=false\n\n"
            "[user]\n"
            f"default={spec.sandbox_user}\n"
        ),
        "/etc/containers/containers.conf": (
            "[containers]\n"
            'netns = "private"\n'
            "no_hosts = true\n"
            f"pids_limit = {spec.pids_limit}\n"
            "default_capabilities = []\n\n"
            "[engine]\n"
            'cgroup_manager = "systemd"\n'
            'events_logger = "file"\n'
        ),
        "/etc/aegis-sandbox/agent.json": json.dumps(agent_config, indent=2, sort_keys=True) + "\n",
        "/etc/aegis-sandbox/network-none.policy": NETWORK_MARKER,
        "/etc/systemd/system/aegis-sandbox-prepare.service": (
            "[Unit]\nDescription=Mount the bounded AEGIS ext4 workspace\n"
            "After=local-fs.target\nBefore=aegis-sandbox-agent.service\n\n[Service]\nType=oneshot\n"
            "ExecStart=/usr/local/libexec/aegis-workspace-setup\n"
            "RemainAfterExit=yes\n\n[Install]\nWantedBy=multi-user.target\n"
        ),
        "/usr/local/libexec/aegis-workspace-setup": (
            "#!/usr/bin/python3\n"
            "import os, pathlib, pwd, grp, subprocess\n"
            f"ROOT=pathlib.Path({spec.workspace_root!r})\n"
            "IMAGE=pathlib.Path('/var/lib/aegis-sandbox/workspace.ext4')\n"
            "MARKER=pathlib.Path('/etc/aegis-sandbox/workspace-quota.policy')\n"
            f"SIZE={spec.max_workspace_bytes}\nUSER={spec.sandbox_user!r}\n"
            "def run(*argv): subprocess.run(argv, check=True)\n"
            "MARKER.unlink(missing_ok=True)\n"
            "IMAGE.parent.mkdir(mode=0o711, parents=True, exist_ok=True)\n"
            "os.chown(IMAGE.parent, 0, 0); os.chmod(IMAGE.parent, 0o711)\n"
            "if IMAGE.exists():\n"
            "    if not IMAGE.is_file() or IMAGE.stat().st_size != SIZE: raise SystemExit('invalid workspace backing image')\n"
            "else:\n"
            "    fd=os.open(IMAGE, os.O_CREAT|os.O_EXCL|os.O_WRONLY, 0o600)\n"
            "    try: os.ftruncate(fd, SIZE)\n"
            "    finally: os.close(fd)\n"
            "    run('/usr/sbin/mkfs.ext4', '-q', '-F', str(IMAGE))\n"
            "ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)\n"
            "if not os.path.ismount(ROOT): run('/usr/bin/mount', '-t', 'ext4', '-o', 'loop,nosuid,nodev', str(IMAGE), str(ROOT))\n"
            "mounts=pathlib.Path('/proc/self/mountinfo').read_text().splitlines()\n"
            "row=next((line for line in mounts if line.split()[4] == str(ROOT)), None)\n"
            "if row is None or ' - ext4 /dev/loop' not in row: raise SystemExit('workspace is not a loopback ext4 mount')\n"
            "stats=os.statvfs(ROOT); capacity=stats.f_blocks*stats.f_frsize\n"
            "if capacity <= 0 or capacity > SIZE: raise SystemExit('workspace capacity is not bounded')\n"
            "uid=pwd.getpwnam(USER).pw_uid; gid=grp.getgrnam(USER).gr_gid\n"
            "os.chown(ROOT, uid, gid); os.chmod(ROOT, 0o700)\n"
            "tmp=MARKER.with_suffix('.tmp'); tmp.write_text('enforced=workspace-size-limit-v1\\n')\n"
            "os.chmod(tmp, 0o644); os.replace(tmp, MARKER)\n"
        ),
        "/usr/local/bin/aegis-sandbox-agent": (
            "#!/usr/bin/python3\nfrom aegis.sandbox.agent import main\nraise SystemExit(main())\n"
        ),
    }


def validate_rendered(files: Mapping[str, str], spec: BootstrapSpec) -> None:
    """Fail if a generated plan omits a required security invariant."""
    spec.validate()
    expected_paths = set(render_files(spec))
    if set(files) != expected_paths:
        raise ValueError("bootstrap plan has missing or unknown files")
    wsl = files["/etc/wsl.conf"]
    for setting in ("enabled=false", "appendWindowsPath=false", "systemd=true"):
        if setting not in wsl:
            raise ValueError(f"wsl.conf lacks {setting}")
    containers = files["/etc/containers/containers.conf"]
    for setting in ('netns = "private"', "default_capabilities = []", 'cgroup_manager = "systemd"'):
        if setting not in containers:
            raise ValueError(f"containers.conf lacks {setting}")
    if files["/etc/aegis-sandbox/network-none.policy"] != NETWORK_MARKER:
        raise ValueError("invalid network policy marker")
    agent = json.loads(files["/etc/aegis-sandbox/agent.json"])
    if agent["image"] != spec.image or agent["workspace_root"] != spec.workspace_root:
        raise ValueError("agent config does not match bootstrap spec")
    if agent.get("max_workspace_bytes") != WORKSPACE_BYTES:
        raise ValueError("agent config lacks the fixed workspace byte limit")
    service = files["/etc/systemd/system/aegis-sandbox-prepare.service"]
    if "ExecStart=/usr/local/libexec/aegis-workspace-setup" not in service:
        raise ValueError("prepare service does not invoke the workspace setup helper")
    helper = files["/usr/local/libexec/aegis-workspace-setup"]
    for invariant in (
        "mkfs.ext4",
        "loop,nosuid,nodev",
        "/proc/self/mountinfo",
        "os.statvfs",
        "workspace is not a loopback ext4 mount",
    ):
        if invariant not in helper:
            raise ValueError(f"workspace setup helper lacks {invariant}")
    if "os.chown(IMAGE.parent, 0, 0); os.chmod(IMAGE.parent, 0o711)" not in helper:
        raise ValueError("workspace setup helper must grant aegis traverse on sandbox root (0o711)")
    if "os.chmod(tmp, 0o644); os.replace(tmp, MARKER)" not in helper:
        raise ValueError("workspace setup helper must make quota marker world-readable (0o644)")
    if "/etc/aegis-sandbox/workspace-quota.policy" in files:
        raise ValueError("quota marker must be created only after runtime mount verification")


def installation_plan(spec: BootstrapSpec) -> dict[str, object]:
    files = render_files(spec)
    validate_rendered(files, spec)
    return {
        "mode": "dry-run",
        "files": [
            {
                "path": path,
                "mode": "0755" if path.startswith(("/usr/local/bin/", "/usr/local/libexec/")) else "0644",
                "content": content,
            }
            for path, content in files.items()
        ],
        "operator_commands": [
            f"Create the dedicated {spec.sandbox_user} user; do not grant sudo or Windows interop access",
            "Install Python 3.12+ and rootless Podman in the dedicated distribution",
            f"Configure subordinate UID/GID ranges for {spec.sandbox_user}",
            f"Import the pinned OCI image {spec.image} as {spec.sandbox_user}",
            "Place the aegis Python package in the distribution's system Python environment",
            "Enable aegis-sandbox-prepare.service, terminate the distribution, then restart it",
            "The prepare service provisions and verifies a dedicated 64 MiB loopback ext4 filesystem, then atomically publishes the quota marker",
            "Run aegis.sandbox.agent doctor and require every check to pass",
        ],
    }


def apply_plan(spec: BootstrapSpec, root: Path) -> list[Path]:
    """Materialize the plan below an explicit staging root without running commands."""
    if not root.is_absolute() or root == Path(root.anchor):
        raise ValueError("--root must be a non-root absolute path")
    files = render_files(spec)
    validate_rendered(files, spec)
    written: list[Path] = []
    for posix_target, content in files.items():
        relative = PurePosixPath(posix_target).relative_to("/")
        target = root.joinpath(*relative.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            raise FileExistsError(f"refusing to overwrite {target}")
        target.write_text(content, encoding="utf-8", newline="\n")
        if posix_target.startswith(("/usr/local/bin/", "/usr/local/libexec/")):
            target.chmod(0o755)
        written.append(target)
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate an AEGIS WSL sandbox bootstrap plan")
    parser.add_argument("--image", required=True, help="OCI image reference pinned with @sha256")
    parser.add_argument("--apply", action="store_true", help="write the plan beneath --root")
    parser.add_argument("--root", type=Path, help="absolute staging/target root; required with --apply")
    args = parser.parse_args(argv)
    spec = BootstrapSpec(image=args.image)
    if args.apply:
        if args.root is None:
            parser.error("--apply requires --root")
        written = apply_plan(spec, args.root.resolve())
        print(json.dumps({"mode": "applied", "files": [str(path) for path in written]}, indent=2))
    else:
        print(json.dumps(installation_plan(spec), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
