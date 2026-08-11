"""Stable Linux-side doctor for WSL harness/supervisor deployment."""

from __future__ import annotations

import importlib
import re
import stat
import sys
from pathlib import Path
from typing import Any

from aegis.models import canonical_json

from .source import SOURCE_MIRROR_PATH

_posix_os: Any = importlib.import_module("os")
_posix_pwd: Any = importlib.import_module("pwd")
_posix_grp: Any = importlib.import_module("grp")

CAMPAIGNS_ROOT = Path("/var/lib/aegis/campaigns")
MAX_CAMPAIGN_VOLUME_BYTES = 8 * 1024 * 1024 * 1024
SOURCE_MIRROR = Path(SOURCE_MIRROR_PATH)
FIXED_AGENTS = (
    Path("/usr/local/bin/aegis-harness-agent"),
    Path("/usr/local/bin/aegis-supervisor-agent"),
    Path("/usr/local/bin/aegis-evolution-doctor"),
)


def doctor() -> list[dict[str, Any]]:
    checks: dict[str, tuple[bool, str]] = {}
    invalid_agents: list[str] = []
    for path in FIXED_AGENTS:
        try:
            metadata = path.lstat()
        except OSError:
            invalid_agents.append(str(path))
            continue
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or path.is_symlink()
            or metadata.st_uid != 0
            or mode & 0o022
            or not mode & 0o100
        ):
            invalid_agents.append(str(path))
    checks["fixed_agents"] = (
        not invalid_agents,
        "fixed root-owned agents are non-writable"
        if not invalid_agents
        else "invalid fixed agents: " + ",".join(invalid_agents),
    )

    mirror_ok = False
    mirror_detail = f"missing source mirror at {SOURCE_MIRROR_PATH}"
    try:
        if SOURCE_MIRROR.is_dir() and not SOURCE_MIRROR.is_symlink():
            if (SOURCE_MIRROR / "HEAD").is_file():
                mirror_ok = True
                mirror_detail = f"source mirror exists at {SOURCE_MIRROR_PATH}"
                try:
                    mirror_uid = SOURCE_MIRROR.stat().st_uid
                    aegis_uid = _posix_pwd.getpwnam("aegis").pw_uid
                    aegis_gid = _posix_grp.getgrnam("aegis").gr_gid
                    owned = mirror_uid == aegis_uid
                    group_readable = (SOURCE_MIRROR.stat().st_mode & 0o040) != 0 and aegis_gid == SOURCE_MIRROR.stat().st_gid
                    if not (owned or group_readable):
                        mirror_ok = False
                        mirror_detail = (
                            "source mirror is not readable by the aegis agent user"
                        )
                except KeyError:
                    mirror_ok = False
                    mirror_detail = "aegis agent user is not defined"
    except OSError as exc:
        mirror_detail = f"cannot inspect source mirror: {exc}"
    checks["source_mirror"] = (mirror_ok, mirror_detail)

    mount = _campaign_mount()
    if mount is None:
        checks["campaign_volume_ext4"] = (False, "campaign root is not a dedicated mount")
        checks["campaign_volume_bounded"] = (False, "campaign volume capacity is unverifiable")
    else:
        filesystem, source, options = mount
        ext4 = filesystem == "ext4" and not source.lower().startswith(("drvfs", "9p"))
        hardened = {"nosuid", "nodev"} <= options
        checks["campaign_volume_ext4"] = (
            ext4 and hardened,
            f"filesystem={filesystem}, source={source}, options={','.join(sorted(options))}",
        )
        try:
            stats = _posix_os.statvfs(CAMPAIGNS_ROOT)
            capacity = stats.f_blocks * stats.f_frsize
        except OSError as exc:
            capacity = 0
            detail = f"cannot inspect campaign volume capacity: {exc}"
        else:
            detail = f"capacity_bytes={capacity}, maximum={MAX_CAMPAIGN_VOLUME_BYTES}"
        checks["campaign_volume_bounded"] = (
            0 < capacity <= MAX_CAMPAIGN_VOLUME_BYTES,
            detail,
        )

    try:
        mounts = Path("/proc/self/mountinfo").read_text(encoding="utf-8", errors="replace")
        bad_mounts = [
            line
            for line in mounts.splitlines()
            if " drvfs " in line
            or " - 9p " in line and re.search(r"\s/mnt/[a-z](?:/|\s)", line)
            or re.search(r"\s/mnt/[a-z](?:/|\s)", line)
        ]
    except OSError as exc:
        checks["windows_mounts_disabled"] = (False, f"cannot inspect mounts: {exc}")
    else:
        checks["windows_mounts_disabled"] = (
            not bad_mounts,
            "no DrvFS or Windows drive mounts detected"
            if not bad_mounts
            else "Windows/DrvFS mount detected",
        )

    interop = Path("/proc/sys/fs/binfmt_misc/WSLInterop")
    try:
        interop_text = interop.read_text(encoding="ascii", errors="replace") if interop.exists() else ""
    except OSError as exc:
        checks["interop_disabled"] = (False, f"cannot inspect WSL interop: {exc}")
    else:
        enabled = interop.exists() and "enabled" in interop_text.lower()
        checks["interop_disabled"] = (
            not enabled,
            "WSL interop is disabled" if not enabled else "WSL interop is enabled",
        )

    order = (
        "fixed_agents",
        "source_mirror",
        "campaign_volume_ext4",
        "campaign_volume_bounded",
        "windows_mounts_disabled",
        "interop_disabled",
    )
    return [
        {"name": name, "passed": checks[name][0], "detail": checks[name][1]}
        for name in order
    ]


def _campaign_mount() -> tuple[str, str, set[str]] | None:
    try:
        lines = Path("/proc/self/mountinfo").read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
    except OSError:
        return None
    target = str(CAMPAIGNS_ROOT)
    for line in lines:
        left, separator, right = line.partition(" - ")
        if not separator:
            continue
        fields = left.split()
        trailing = right.split()
        if len(fields) < 6 or len(trailing) < 3 or fields[4] != target:
            continue
        options = set(fields[5].split(",")) | set(trailing[2].split(","))
        return trailing[0], trailing[1], options
    return None


def main() -> int:
    if len(sys.argv) != 1 or sys.stdin.read(1):
        print(canonical_json({"ok": False, "message": "doctor accepts no arguments or input"}))
        return 2
    print(canonical_json({"ok": True, "checks": doctor()}))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
