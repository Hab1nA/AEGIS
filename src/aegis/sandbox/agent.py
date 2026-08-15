"""WSL-side sandbox agent.

The process accepts exactly one JSON object on stdin and emits exactly one JSON
object on stdout.  It is intentionally stateless between invocations; lifecycle
state is represented by directories and marker files below ``workspace_root``.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import selectors
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Protocol

from aegis.models import canonical_json

from .sealed import (
    MAX_WORKER_OUTPUT_BYTES,
    WORKER_SOURCE,
    check_worker_result,
    load_sealed_cases,
    worker_scenario,
)

PROTOCOL_VERSION = 1
OPERATIONS = frozenset(
    {
        "doctor",
        "scanner_probe",
        "prepare",
        "build_image",
        "scan_image",
        "stage_archive",
        "configure_workspace_access",
        "exec",
        "evaluate_sealed",
        "freeze",
        "export",
        "destroy",
        "kill",
    }
)
REQUIRED_CHECKS = (
    "windows_mounts_disabled",
    "interop_disabled",
    "rootless_oci",
    "cgroup_v2_controllers",
    "network_none",
    "disk_quota_marker",
    "secret_absence",
)
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
ALLOWED_ENV = frozenset({"CI", "LANG", "LC_ALL", "NO_COLOR", "PYTHONHASHSEED", "TZ", "TERM"})
PODMAN_HOST_ENV = frozenset(
    {"PATH", "HOME", "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "DBUS_SESSION_BUS_ADDRESS"}
)
SENSITIVE_ENV = re.compile(
    r"(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH|OPENAI|ANTHROPIC|AWS|AZURE|GITHUB|SSH)", re.I
)
NETWORK_MARKER = "enforced=podman-network-none-v1"
QUOTA_MARKER = "enforced=workspace-size-limit-v1"
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_EXPANDED_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 4096
MAX_PROCESS_OUTPUT_BYTES = 1024 * 1024
MAX_WRITABLE_PATHS = 64
ACCESS_POLICY_FILE = "workspace-access.json"
SCANNER_BINARY = "trivy"
_IMAGE_REFERENCE = re.compile(r"(?:@sha256:|^sha256:)[0-9a-f]{64}$")


def _image_digest(value: str) -> str:
    """Extract the sha256 digest from a pinned image reference."""
    if _IMAGE_REFERENCE.search(value) is None:
        raise RuntimeError("sandbox image must be pinned by sha256 digest")
    if "@sha256:" in value:
        return value.rsplit("@sha256:", 1)[1]
    return value.removeprefix("sha256:")


class Runner(Protocol):
    def __call__(
        self,
        argv: list[str],
        *,
        input: str | None = None,
        timeout: float | None = None,
        env: Mapping[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]: ...


def run_process(
    argv: list[str],
    *,
    input: str | None = None,
    timeout: float | None = None,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run without shell while placing a hard bound on captured host memory."""
    process = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=False,
        shell=False,
    )
    if input is not None and process.stdin is not None:
        process.stdin.write(input.encode("utf-8"))
        process.stdin.close()
    selector = selectors.DefaultSelector()
    assert process.stdout is not None and process.stderr is not None
    for stream, label in ((process.stdout, "stdout"), (process.stderr, "stderr")):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, label)
    chunks: dict[str, list[bytes]] = {"stdout": [], "stderr": []}
    captured = 0
    started = time.monotonic()
    exceeded = False
    try:
        while selector.get_map():
            remaining = None if timeout is None else timeout - (time.monotonic() - started)
            if remaining is not None and remaining <= 0:
                assert timeout is not None
                process.kill()
                process.wait(timeout=5)
                raise subprocess.TimeoutExpired(
                    argv,
                    float(timeout),
                    output=b"".join(chunks["stdout"]),
                    stderr=b"".join(chunks["stderr"]),
                )
            for key, _ in selector.select(remaining):
                block = os.read(key.fd, 8192)
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                captured += len(block)
                if captured > MAX_PROCESS_OUTPUT_BYTES:
                    exceeded = True
                    process.kill()
                    break
                chunks[key.data].append(block)
            if exceeded:
                break
        process.wait(timeout=5)
    finally:
        selector.close()
    stdout = b"".join(chunks["stdout"]).decode("utf-8", errors="replace")
    stderr = b"".join(chunks["stderr"]).decode("utf-8", errors="replace")
    if exceeded:
        stderr += "\nprocess output exceeded hard limit"
    return subprocess.CompletedProcess(argv, 125 if exceeded else process.returncode, stdout, stderr)


def current_euid() -> int:
    """Return the effective uid; the WSL runtime always provides ``geteuid``."""
    getter = getattr(os, "geteuid", None)
    return int(getter()) if getter is not None else 0


@dataclass(frozen=True, slots=True)
class AgentConfig:
    workspace_root: Path
    image: str
    network_policy_marker: Path
    quota_policy_marker: Path
    max_workspace_bytes: int = 64 * 1024 * 1024
    podman: str = "podman"
    memory: str = "1g"
    cpus: str = "1.0"
    pids_limit: int = 256
    tmpfs_size: str = "256m"

    @classmethod
    def load(cls, path: Path = Path("/etc/aegis-sandbox/agent.json")) -> "AgentConfig":
        raw = _read_json_file(path)
        expected = {
            "workspace_root",
            "image",
            "network_policy_marker",
            "quota_policy_marker",
            "max_workspace_bytes",
            "podman",
            "memory",
            "cpus",
            "pids_limit",
            "tmpfs_size",
        }
        if set(raw) != expected:
            raise ValueError("agent config has missing or unknown fields")
        config = cls(
            workspace_root=Path(_required_string(raw, "workspace_root")),
            image=_required_string(raw, "image"),
            network_policy_marker=Path(_required_string(raw, "network_policy_marker")),
            quota_policy_marker=Path(_required_string(raw, "quota_policy_marker")),
            max_workspace_bytes=_required_int(raw, "max_workspace_bytes"),
            podman=_required_string(raw, "podman"),
            memory=_required_string(raw, "memory"),
            cpus=_required_string(raw, "cpus"),
            pids_limit=_required_int(raw, "pids_limit"),
            tmpfs_size=_required_string(raw, "tmpfs_size"),
        )
        config.validate()
        return config

    def validate(self) -> None:
        if not self.workspace_root.is_absolute() or self.workspace_root == Path("/"):
            raise ValueError("workspace_root must be a non-root absolute path")
        if not self.network_policy_marker.is_absolute() or not self.quota_policy_marker.is_absolute():
            raise ValueError("policy markers must use absolute paths")
        if "@sha256:" not in self.image or not re.search(r"@sha256:[0-9a-f]{64}$", self.image):
            raise ValueError("sandbox image must be pinned by sha256 digest")
        if not 1 <= self.pids_limit <= 4096:
            raise ValueError("pids_limit is outside the safe range")
        if not 1024 * 1024 <= self.max_workspace_bytes <= 1024 * 1024 * 1024:
            raise ValueError("max_workspace_bytes is outside the safe range")
        for value, label in ((self.memory, "memory"), (self.cpus, "cpus"), (self.tmpfs_size, "tmpfs_size")):
            if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?[a-zA-Z]*", value):
                raise ValueError(f"invalid {label}")


class SandboxAgent:
    def __init__(
        self,
        config: AgentConfig,
        *,
        runner: Runner = run_process,
        environ: Mapping[str, str] | None = None,
        uid_getter: Any = current_euid,
        mounts_path: Path = Path("/proc/mounts"),
        interop_path: Path = Path("/proc/sys/fs/binfmt_misc/WSLInterop"),
        controllers_path: Path = Path("/sys/fs/cgroup/cgroup.controllers"),
        quota_checker: Any | None = None,
    ) -> None:
        config.validate()
        self.config = config
        self.runner = runner
        self.environ = dict(os.environ if environ is None else environ)
        self.uid_getter = uid_getter
        self.mounts_path = mounts_path
        self.interop_path = interop_path
        self.controllers_path = controllers_path
        self.quota_checker = quota_checker or _verify_workspace_quota

    def handle(self, request: object) -> dict[str, Any]:
        data = _object(request, "request")
        operation = data.get("operation")
        if operation not in OPERATIONS:
            raise ValueError("unsupported operation")
        sandbox_operations = {
            "prepare",
            "stage_archive",
            "configure_workspace_access",
            "exec",
            "evaluate_sealed",
            "freeze",
            "export",
            "destroy",
            "kill",
        }
        required = (
            {"version", "operation"}
            if operation not in sandbox_operations
            else {"version", "operation", "sandbox_id"}
        )
        extra = (
            {"command"}
            if operation == "exec"
            else (
                {"archive_base64", "expected_sha256", "timeout_seconds"}
                if operation == "evaluate_sealed"
                else (
                    {"archive_base64", "expected_sha256"}
                    if operation == "stage_archive"
                    else (
                        {"writable_paths"}
                        if operation == "configure_workspace_access"
                        else (
                            {"image"}
                            if operation == "prepare"
                            else (
                                {"recipe", "dependencies", "attempt_id", "timeout_seconds"}
                                if operation == "build_image"
                                else (
                                    {"image", "timeout_seconds"}
                                    if operation == "scan_image"
                                    else set()
                                )
                            )
                        )
                    )
                )
            )
        )
        optional: set[str] = set()
        if operation == "prepare":
            optional.add("image")
        if not (required <= set(data) and set(data) <= (required | extra | optional)):
            raise ValueError("request has missing or unknown fields")
        if not optional and set(data) != (required | extra):
            raise ValueError("request has missing or unknown fields")
        if data.get("version") != PROTOCOL_VERSION:
            raise ValueError("unsupported protocol version")
        if operation == "doctor":
            return {"ok": True, "checks": self.doctor()}
        if operation == "scanner_probe":
            available, detail = self._scanner_available()
            return {"ok": True, "available": available, "detail": detail}
        if operation == "build_image":
            return {
                "ok": True,
                "staged": self.build_image(
                    data["recipe"],
                    data.get("dependencies", {}),
                    data["attempt_id"],
                    data["timeout_seconds"],
                ),
            }
        if operation == "scan_image":
            return {
                "ok": True,
                "scan": self.scan_image(data["image"], data["timeout_seconds"]),
            }
        sandbox_id = _sandbox_id(data.get("sandbox_id"))
        if operation == "destroy":
            self.destroy(sandbox_id)
            return {"ok": True}
        if operation == "kill":
            self.kill(sandbox_id)
            return {"ok": True}
        self._require_healthy()
        if operation == "prepare":
            self.prepare(sandbox_id, image=data.get("image"))
            return {"ok": True}
        if operation == "exec":
            return {"ok": True, "result": self.execute(sandbox_id, data["command"])}
        if operation == "stage_archive":
            digest, size, entries = self.stage_archive(
                sandbox_id, data["archive_base64"], data["expected_sha256"]
            )
            return {"ok": True, "staged": {"sha256": digest, "size_bytes": size, "entries": entries}}
        if operation == "configure_workspace_access":
            self.configure_workspace_access(sandbox_id, data["writable_paths"])
            return {"ok": True}
        if operation == "evaluate_sealed":
            return {
                "ok": True,
                "sealed_evaluation": self.evaluate_sealed(
                    sandbox_id,
                    data["archive_base64"],
                    data["expected_sha256"],
                    data["timeout_seconds"],
                ),
            }
        archive = self.freeze(sandbox_id)
        result: dict[str, Any] = {
            "ok": True,
            "artifact": {"sha256": hashlib.sha256(archive).hexdigest(), "size_bytes": len(archive)},
        }
        if operation == "export":
            result["archive_base64"] = base64.b64encode(archive).decode("ascii")
        return result

    def doctor(self) -> list[dict[str, Any]]:
        checks: dict[str, tuple[bool, str]] = {}
        try:
            mounts = self.mounts_path.read_text(encoding="utf-8", errors="replace")
            bad = [
                line
                for line in mounts.splitlines()
                if " drvfs " in line or re.search(r"\s/mnt/[a-z](?:/|\s)", line)
            ]
            checks["windows_mounts_disabled"] = (
                not bad,
                "no Windows mounts detected" if not bad else "Windows/DrvFS mount detected",
            )
        except OSError as exc:
            checks["windows_mounts_disabled"] = (False, f"cannot inspect mounts: {exc}")
        try:
            interop = (
                self.interop_path.read_text(encoding="utf-8", errors="replace")
                if self.interop_path.exists()
                else "disabled"
            )
            enabled = self.interop_path.exists() and "enabled" in interop.lower()
            checks["interop_disabled"] = (
                not enabled,
                "WSL interop disabled" if not enabled else "WSL interop is enabled",
            )
        except OSError as exc:
            checks["interop_disabled"] = (False, f"cannot inspect WSL interop: {exc}")
        checks["rootless_oci"] = self._check_rootless_oci()
        try:
            controllers = set(self.controllers_path.read_text(encoding="ascii").split())
            missing = {"cpu", "memory", "pids"} - controllers
            checks["cgroup_v2_controllers"] = (
                not missing,
                "cpu, memory and pids available"
                if not missing
                else f"missing controllers: {','.join(sorted(missing))}",
            )
        except OSError as exc:
            checks["cgroup_v2_controllers"] = (False, f"cannot inspect cgroup v2: {exc}")
        checks["network_none"] = _marker_check(self.config.network_policy_marker, NETWORK_MARKER)
        marker_ok, marker_detail = _marker_check(self.config.quota_policy_marker, QUOTA_MARKER)
        quota_ok, quota_detail = self.quota_checker(
            self.config.workspace_root, self.config.max_workspace_bytes
        )
        checks["disk_quota_marker"] = (
            marker_ok and quota_ok,
            f"{marker_detail}; {quota_detail}",
        )
        sensitive = sorted(name for name in self.environ if SENSITIVE_ENV.search(name))
        checks["secret_absence"] = (
            not sensitive,
            "no sensitive environment names"
            if not sensitive
            else f"sensitive variables present: {','.join(sensitive)}",
        )
        scanner_ok, scanner_detail = self._scanner_available()
        checks["scanner_available"] = (scanner_ok, scanner_detail)
        return [
            {"name": name, "passed": checks[name][0], "detail": checks[name][1]} for name in REQUIRED_CHECKS
        ]

    def prepare(self, sandbox_id: str, image: object = None) -> None:
        root = self._sandbox_path(sandbox_id)
        if root.exists():
            if (root / "prepared").is_file():
                # Idempotent re-entry: a prior prepare completed but its
                # transport response may have been lost before the caller saw it.
                return
            raise RuntimeError("sandbox already exists but is not prepared")
        root.mkdir(mode=0o700, parents=True)
        if image is not None:
            if not isinstance(image, str):
                raise RuntimeError("sandbox image must be pinned by sha256 digest")
            digest = _image_digest(image)
            candidate = image
            exists = self.runner(
                [self.config.podman, "image", "exists", candidate],
                input=None,
                timeout=30,
                env=self._podman_env(),
            )
            if exists.returncode != 0 and "@sha256:" in candidate:
                # A locally built image may only be resolvable by its image id
                # even though the manifest carries a repository@digest
                # reference.  Fall back to the digest-only form before failing.
                candidate = f"sha256:{digest}"
                exists = self.runner(
                    [self.config.podman, "image", "exists", candidate],
                    input=None,
                    timeout=30,
                    env=self._podman_env(),
                )
            if exists.returncode != 0:
                raise RuntimeError("requested sandbox image is unavailable in the distribution")
            (root / "image").write_text(candidate + "\n", encoding="ascii")
        (root / "workspace").mkdir(mode=0o700)
        (root / "prepared").write_text("1\n", encoding="ascii")

    def _sandbox_image(self, sandbox_id: str) -> str:
        marker = self._sandbox_path(sandbox_id) / "image"
        if marker.is_file():
            image = marker.read_text(encoding="ascii").strip()
            if _IMAGE_REFERENCE.search(image) is None:
                raise RuntimeError("sandbox image marker is invalid")
            return image
        return self.config.image

    def _scanner_available(self) -> tuple[bool, str]:
        try:
            result = self.runner(
                [SCANNER_BINARY, "--version"],
                input=None,
                timeout=15,
                env=self._podman_env(),
            )
        except Exception as exc:
            return False, f"scanner probe failed: {exc}"
        if result.returncode == 0:
            return True, result.stdout.strip()[:200] or "scanner available"
        return False, (result.stderr.strip()[:200] or "scanner binary unavailable")

    def _podman_runtime_dir(self) -> str:
        return f"/run/user/{int(self.uid_getter())}"

    def _ensure_podman_socket(self) -> None:
        """Start the rootless podman API socket when the WSL instance has no
        live user session for it yet.  Trivy resolves images through this
        socket, and a fresh WSL instance starts with the socket inactive."""
        runtime_dir = self._podman_runtime_dir()
        socket_path = Path(runtime_dir) / "podman" / "podman.sock"
        if socket_path.exists():
            return
        env = dict(self.environ)
        env["XDG_RUNTIME_DIR"] = runtime_dir
        result = self.runner(
            ["systemctl", "--user", "start", "podman.socket"],
            input=None,
            timeout=30,
            env=env,
        )
        if result.returncode != 0:
            raise RuntimeError(
                "cannot start the podman API socket for image scanning: "
                + (result.stderr or result.stdout or "")[:500]
            )
        for _ in range(40):
            if socket_path.exists():
                return
            time.sleep(0.5)
        raise RuntimeError("podman API socket did not become ready")

    def build_image(
        self,
        recipe: object,
        dependencies: object,
        attempt_id: str,
        timeout_seconds: object,
    ) -> dict[str, Any]:
        if not isinstance(recipe, Mapping) or not isinstance(dependencies, Mapping):
            raise ValueError("build_image requires a recipe object and dependencies object")
        if not isinstance(attempt_id, str) or not attempt_id:
            raise ValueError("build_image requires a non-empty attempt_id")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not 0 < float(timeout_seconds) <= 86_400
        ):
            raise ValueError("build_image timeout is outside the safe range")
        recipe_id = recipe.get("recipe_id")
        parent_image = recipe.get("parent_image")
        build_steps = recipe.get("build_steps")
        if not isinstance(recipe_id, str) or not recipe_id.startswith("sha256:"):
            raise ValueError("recipe_id must be a content address")
        if not isinstance(parent_image, str) or re.search(r"@sha256:[0-9a-f]{64}$", parent_image) is None:
            raise ValueError("parent_image must be pinned by sha256 digest")
        if not isinstance(build_steps, list) or not build_steps or len(build_steps) > 32:
            raise ValueError("build_steps must be a bounded non-empty list")
        dependency_hashes: dict[str, str] = {}
        started = time.monotonic()
        context = Path(tempfile.mkdtemp(dir=self.config.workspace_root, prefix="aegis-build-"))
        timed_out = False
        exit_code = 0
        try:
            for name, payload in sorted(dependencies.items()):
                if not isinstance(name, str) or not name or "\x00" in name:
                    raise ValueError("dependency name is invalid")
                relative = PurePosixPath(name)
                if relative.is_absolute() or ".." in relative.parts:
                    raise ValueError("dependency name is not a safe relative path")
                if not isinstance(payload, bytes) or not payload:
                    raise ValueError("dependency payload must be non-empty bytes")
                target = context.joinpath(*relative.parts)
                if target.is_symlink() or not str(target).startswith(str(context)):
                    raise ValueError("dependency target escapes the build context")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(payload)
                dependency_hashes[name] = hashlib.sha256(payload).hexdigest()
            lines = [f"FROM {parent_image}"]
            for name in sorted(dependency_hashes):
                lines.append(f"COPY {name} /opt/aegis-deps/{name}")
            for step in build_steps:
                if not isinstance(step, Mapping):
                    raise ValueError("build step must be an object")
                argv = step.get("argv")
                cwd = step.get("cwd", ".")
                if (
                    not isinstance(argv, list)
                    or not argv
                    or len(argv) > 32
                    or not all(isinstance(item, str) and item and "\x00" not in item for item in argv)
                ):
                    raise ValueError("build step argv is invalid")
                if not isinstance(cwd, str) or cwd.startswith("/") or ".." in PurePosixPath(cwd).parts:
                    raise ValueError("build step cwd is invalid")
                if cwd != ".":
                    lines.append(f"WORKDIR /{cwd}")
                lines.append(f"RUN {json.dumps(argv)}")
            containerfile = context / "Containerfile"
            containerfile.write_text("\n".join(lines) + "\n", encoding="ascii")
            iidfile = context / "image.id"
            result = self.runner(
                [
                    self.config.podman,
                    "build",
                    "--network",
                    "none",
                    "--iidfile",
                    str(iidfile),
                    "-f",
                    str(containerfile),
                    str(context),
                ],
                input=None,
                timeout=float(timeout_seconds),
                env=self._podman_env(),
            )
            exit_code = result.returncode
            if exit_code == 124:
                timed_out = True
            if exit_code != 0 and not timed_out:
                raise RuntimeError("podman build failed: " + (result.stderr or "")[-2000:])
            if timed_out or not iidfile.is_file():
                raise RuntimeError("podman build timed out")
            image_id = iidfile.read_text(encoding="ascii").strip()
            if re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None:
                raise RuntimeError("build produced an invalid image id")
            image_sha256 = image_id.split(":")[1]
            inspect = self.runner(
                [self.config.podman, "image", "inspect", "--format", "{{.Size}}", image_id],
                input=None,
                timeout=30,
                env=self._podman_env(),
            )
            size = int(inspect.stdout.strip()) if inspect.returncode == 0 and inspect.stdout.strip().isdigit() else 0
            if size <= 0:
                raise RuntimeError("build produced an empty image")
            sbom_payload = {
                "recipe_id": recipe_id,
                "dependency_hashes": dependency_hashes,
                "image_sha256": image_sha256,
            }
            sbom_sha256 = hashlib.sha256(canonical_json(sbom_payload).encode("utf-8")).hexdigest()
            provenance_payload = {
                "attempt_id": attempt_id,
                "recipe_id": recipe_id,
                "image_sha256": image_sha256,
                "elapsed_seconds": time.monotonic() - started,
            }
            provenance_sha256 = hashlib.sha256(
                canonical_json(provenance_payload).encode("utf-8")
            ).hexdigest()
            isolation_sha256 = hashlib.sha256(
                "network=none;secrets=none;host_mounts=none".encode("utf-8")
            ).hexdigest()
            return {
                "staged_artifact_id": f"sha256:{image_sha256}",
                "attempt_id": attempt_id,
                "image_sha256": image_sha256,
                "output_size_bytes": size,
                "sbom_sha256": sbom_sha256,
                "provenance_sha256": provenance_sha256,
                "isolation_receipt_sha256": isolation_sha256,
                "elapsed_seconds": time.monotonic() - started,
                "timed_out": timed_out,
                "exit_code": exit_code,
                "network_used": False,
                "secrets_used": False,
                "host_mounts_used": False,
            }
        finally:
            shutil.rmtree(context, ignore_errors=True)

    def scan_image(self, image: object, timeout_seconds: object) -> dict[str, Any]:
        if not isinstance(image, str):
            raise ValueError("scan_image requires a digest-pinned image")
        image_digest = _image_digest(image)
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not 0 < float(timeout_seconds) <= 3600
        ):
            raise ValueError("scan_image timeout is outside the safe range")
        available, detail = self._scanner_available()
        if not available:
            raise RuntimeError("image scanner is unavailable: " + detail)
        self._ensure_podman_socket()
        started = time.monotonic()
        timed_out = False
        try:
            result = self.runner(
                [
                    SCANNER_BINARY,
                    "image",
                    "--scanners",
                    "vuln",
                    "--no-progress",
                    "--exit-code",
                    "1",
                    "--ignore-unfixed",
                    "--skip-db-update",
                    "--skip-java-db-update",
                    "--skip-version-check",
                    f"sha256:{image_digest}",
                ],
                input=None,
                timeout=float(timeout_seconds),
                env=self._podman_env(),
            )
        except subprocess.TimeoutExpired:
            timed_out = True
            raise RuntimeError("image scan timed out") from None
        report_bytes = (result.stdout or "").encode("utf-8") + (result.stderr or "").encode("utf-8")
        return {
            "staged_artifact_id": f"sha256:{image_digest}",
            "image_sha256": image_digest,
            "vulnerability_report_sha256": hashlib.sha256(report_bytes).hexdigest(),
            "passed": result.returncode == 0,
            "elapsed_seconds": time.monotonic() - started,
            "timed_out": timed_out,
        }

    def execute(self, sandbox_id: str, command: object) -> dict[str, Any]:
        root = self._active_root(sandbox_id)
        spec = _parse_command(command)
        argv, child_env = self.build_podman_command(sandbox_id, root / "workspace", spec)
        started = time.monotonic()
        try:
            proc = self.runner(argv, input=spec[3], timeout=spec[4], env=child_env)
            timed_out = False
            exit_code = proc.returncode
            stdout, stderr = proc.stdout, proc.stderr
            if exit_code == 125 and "output exceeded hard limit" in stderr:
                self._kill_container(sandbox_id)
        except subprocess.TimeoutExpired as exc:
            self._kill_container(sandbox_id)
            timed_out = True
            exit_code = 124
            stdout = _text(exc.stdout)
            stderr = _text(exc.stderr) or "command timed out"
        except Exception:
            try:
                self._kill_container(sandbox_id)
            except Exception:
                pass
            raise
        return {
            "exit_code": exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "duration_seconds": time.monotonic() - started,
            "timed_out": timed_out,
        }

    def stage_archive(
        self, sandbox_id: str, archive_base64: object, expected_digest: object
    ) -> tuple[str, int, int]:
        root = self._active_root(sandbox_id)
        if (root / ACCESS_POLICY_FILE).exists():
            raise RuntimeError("cannot stage after workspace access is configured")
        payload, members = _validate_staging_archive(archive_base64, expected_digest)
        workspace = root / "workspace"
        created: list[Path] = []
        try:
            with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as archive:
                for member in members:
                    destination = workspace.joinpath(*PurePosixPath(member.name).parts)
                    if destination.exists() or destination.is_symlink():
                        raise RuntimeError("staging archive would overwrite an existing path")
                    for parent in reversed(destination.parents):
                        if parent == workspace:
                            break
                        if parent.exists() and not parent.is_dir():
                            raise RuntimeError("staging archive has a file/directory collision")
                    missing_parents: list[Path] = []
                    parent = destination.parent
                    while parent != workspace and not parent.exists():
                        missing_parents.append(parent)
                        parent = parent.parent
                    for missing in reversed(missing_parents):
                        missing.mkdir(mode=0o700)
                        created.append(missing)
                    if member.isdir():
                        destination.mkdir(mode=0o700)
                        created.append(destination)
                    else:
                        source = archive.extractfile(member)
                        if source is None:
                            raise RuntimeError("staging archive file cannot be read")
                        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                        created.append(destination)
                        with os.fdopen(fd, "wb") as output:
                            shutil.copyfileobj(source, output)
        except Exception:
            for path in reversed(created):
                try:
                    path.unlink() if path.is_file() else path.rmdir()
                except OSError:
                    pass
            raise
        return hashlib.sha256(payload).hexdigest(), len(payload), len(members)

    def configure_workspace_access(self, sandbox_id: str, writable_paths: object) -> None:
        """Make the repository mount read-only except for explicit candidate paths."""
        root = self._active_root(sandbox_id)
        marker = root / ACCESS_POLICY_FILE
        if marker.exists():
            raise RuntimeError("workspace access is already configured")
        rules = _parse_workspace_access(writable_paths)
        workspace = root / "workspace"
        for path, recursive in rules:
            destination = workspace.joinpath(*PurePosixPath(path).parts)
            current = workspace
            for part in PurePosixPath(path).parts:
                current /= part
                if current.is_symlink():
                    raise ValueError(f"workspace access path contains a symlink: {path}")
            if recursive:
                if destination.exists() and not destination.is_dir():
                    raise ValueError(f"recursive workspace access path is not a directory: {path}")
                destination.mkdir(mode=0o700, parents=True, exist_ok=True)
            elif not destination.is_file():
                raise ValueError(f"exact workspace access path is not a staged file: {path}")
        payload = json.dumps(
            [{"path": path, "recursive": recursive} for path, recursive in rules],
            sort_keys=True,
            separators=(",", ":"),
        )
        temporary = root / f".{ACCESS_POLICY_FILE}.tmp"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, marker)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise

    def evaluate_sealed(
        self,
        sandbox_id: str,
        archive_base64: object,
        expected_digest: object,
        timeout_seconds: object,
    ) -> dict[str, Any]:
        """Evaluate cases without ever mounting sealed material in the worker."""
        root = self._active_root(sandbox_id)
        if not isinstance(timeout_seconds, (int, float)) or isinstance(timeout_seconds, bool):
            raise ValueError("invalid sealed evaluation timeout")
        timeout = float(timeout_seconds)
        if not 0 < timeout <= 3600:
            raise ValueError("invalid sealed evaluation timeout")
        payload, _ = _validate_staging_archive(archive_base64, expected_digest)
        cases = load_sealed_cases(payload)
        deadline = time.monotonic() + timeout
        passed = 0
        failures: list[str] = []
        safety: list[str] = []
        timed_out = False
        for case in cases:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                failures.append(f"{case['name']}: evaluation timed out")
                break
            scenario = worker_scenario(case)
            # This is the only input visible to the submission process.  The
            # assertion fields remain in this controller process.
            stdin = json.dumps(scenario, sort_keys=True, separators=(",", ":"))
            argv, child_env = self.build_sealed_worker_command(
                sandbox_id, root / "workspace", min(remaining, 120.0)
            )
            started = time.monotonic()
            try:
                proc = self.runner(argv, input=stdin, timeout=min(remaining, 120.0), env=child_env)
            except subprocess.TimeoutExpired:
                self._kill_container(sandbox_id, suffix="-sealed")
                timed_out = True
                failures.append(f"{case['name']}: worker timed out")
                break
            output = _text(proc.stdout)
            error = _text(proc.stderr)
            if (
                len(output.encode(errors="replace")) > MAX_WORKER_OUTPUT_BYTES
                or len(error.encode(errors="replace")) > MAX_WORKER_OUTPUT_BYTES
            ):
                safety.append("sealed worker output exceeded limit")
                failures.append(f"{case['name']}: oversized worker output")
                break
            if proc.returncode != 0:
                failures.append(f"{case['name']}: worker exited {proc.returncode}")
                continue
            try:
                decoded = json.loads(output)
            except json.JSONDecodeError:
                failures.append(f"{case['name']}: worker returned invalid JSON")
                continue
            ok, reason = check_worker_result(case, decoded)
            if ok:
                passed += 1
            else:
                failures.append(f"{case['name']}: {reason}")
            if time.monotonic() - started > min(remaining, 120.0):
                timed_out = True
                break
        return {
            "passed": passed,
            "total": len(cases),
            "failures": failures,
            "timed_out": timed_out,
            "safety_violations": safety,
        }

    def build_sealed_worker_command(
        self, sandbox_id: str, workspace: Path, timeout: float
    ) -> tuple[list[str], dict[str, str]]:
        del timeout
        child_env = self._podman_env()
        argv = [
            self.config.podman,
            "run",
            "--replace",
            "--interactive",
            "--rm",
            "--name",
            self._container_name(sandbox_id, suffix="-sealed"),
            "--network=none",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--read-only",
            f"--pids-limit={self.config.pids_limit}",
            f"--memory={self.config.memory}",
            f"--cpus={self.config.cpus}",
            f"--tmpfs=/tmp:rw,nosuid,nodev,noexec,size={self.config.tmpfs_size}",
            "--userns=keep-id",
            "--workdir",
            "/workspace",
            "--volume",
            f"{workspace}:/workspace:ro,Z",
            "--entrypoint",
            "python",
            self._sandbox_image(sandbox_id),
            "-B",
            "-I",
            "-c",
            WORKER_SOURCE,
        ]
        return argv, child_env

    def build_podman_command(
        self,
        sandbox_id: str,
        workspace: Path,
        spec: tuple[list[str], str, dict[str, str], str | None, float],
    ) -> tuple[list[str], dict[str, str]]:
        args, cwd, env, _stdin, _timeout = spec
        child_env = self._podman_env()
        child_env.update(env)
        access = self._workspace_access(sandbox_id)
        argv = [
            self.config.podman,
            "run",
            "--replace",
            "--interactive",
            "--rm",
            "--name",
            self._container_name(sandbox_id),
            "--network=none",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--read-only",
            f"--pids-limit={self.config.pids_limit}",
            f"--memory={self.config.memory}",
            f"--cpus={self.config.cpus}",
            f"--tmpfs=/tmp:rw,nosuid,nodev,noexec,size={self.config.tmpfs_size}",
            "--userns=keep-id",
            "--workdir",
            f"/workspace/{cwd}" if cwd != "." else "/workspace",
            "--volume",
            f"{workspace}:/workspace:{'ro' if access is not None else 'rw'},Z",
        ]
        if access is not None:
            for path, _recursive in access:
                source = workspace.joinpath(*PurePosixPath(path).parts)
                argv.extend(["--volume", f"{source}:/workspace/{path}:rw,Z"])
        for name in sorted(env):
            argv.extend(["--env", name])
        # A built environment image may inherit an application ENTRYPOINT
        # (for example a search engine image).  The sandbox always invokes an
        # explicit command, so override the entrypoint with its first program.
        argv.extend(["--entrypoint", args[0]])
        argv.extend([self._sandbox_image(sandbox_id), *args[1:]])
        return argv, child_env

    def freeze(self, sandbox_id: str) -> bytes:
        root = self._sandbox_path(sandbox_id)
        if not (root / "prepared").is_file():
            raise RuntimeError("sandbox is not prepared")
        archive = _deterministic_tar(root / "workspace")
        digest = hashlib.sha256(archive).hexdigest()
        marker = root / "frozen"
        if marker.exists():
            try:
                expected = marker.read_text(encoding="ascii").strip()
            except OSError as exc:
                raise RuntimeError("cannot verify frozen workspace marker") from exc
            if expected != digest:
                raise RuntimeError("frozen workspace content hash changed")
        else:
            marker.write_text(digest + "\n", encoding="ascii")
        return archive

    def destroy(self, sandbox_id: str) -> None:
        root = self._sandbox_path(sandbox_id)
        failures: list[str] = []
        for suffix in ("", "-sealed"):
            try:
                self._kill_container(sandbox_id, suffix=suffix)
            except Exception as exc:
                failures.append(f"{self._container_name(sandbox_id, suffix=suffix)}: {exc}")
        try:
            if root.exists():
                try:
                    shutil.rmtree(root)
                except PermissionError:
                    self._normalize_workspace_ownership(root)
                    shutil.rmtree(root)
        except OSError as exc:
            failures.append(f"workspace: {exc}")
        if failures:
            raise RuntimeError("sandbox cleanup failed: " + "; ".join(failures))

    def kill(self, sandbox_id: str) -> None:
        self.destroy(sandbox_id)

    def _kill_container(self, sandbox_id: str, *, suffix: str = "") -> None:
        result = self.runner(
            [
                self.config.podman,
                "rm",
                "--force",
                "--time",
                "0",
                self._container_name(sandbox_id, suffix=suffix),
            ],
            timeout=10,
            env=self._podman_env(),
        )
        if result.returncode != 0:
            detail = _text(result.stderr).strip()
            normalized = detail.lower()
            if "no such container" not in normalized and "not found" not in normalized:
                raise RuntimeError(detail or f"podman rm exited {result.returncode}")

    def _normalize_workspace_ownership(self, root: Path) -> None:
        """Reclaim files written through rootless Podman's user namespace."""
        result = self.runner(
            [
                self.config.podman,
                "unshare",
                "chown",
                "-R",
                "--no-dereference",
                "0:0",
                "--",
                str(root),
            ],
            timeout=30,
            env=self._podman_env(),
        )
        if result.returncode != 0:
            detail = _text(result.stderr).strip()
            raise RuntimeError(
                detail or f"podman unshare chown exited {result.returncode}"
            )

    def _check_rootless_oci(self) -> tuple[bool, str]:
        if self.uid_getter() == 0:
            return False, "agent must not run as root"
        if shutil.which(self.config.podman, path=self.environ.get("PATH")) is None:
            return False, "podman executable not found"
        try:
            proc = self.runner(
                [self.config.podman, "info", "--format", "json"], timeout=10, env=self._podman_env()
            )
            info = json.loads(proc.stdout) if proc.returncode == 0 else {}
            host = info.get("host", info.get("Host", {}))
            security = host.get("security", host.get("Security", {})) if isinstance(host, dict) else {}
            rootless = (
                bool(security.get("rootless", security.get("Rootless", False)))
                if isinstance(security, dict)
                else False
            )
            if not rootless:
                return False, "podman rootless check failed"
            image = self.runner(
                [self.config.podman, "image", "exists", self.config.image],
                timeout=10,
                env=self._podman_env(),
            )
            if image.returncode != 0:
                return False, "pinned sandbox image is unavailable"
            return True, "podman is rootless and pinned image is available"
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError, AttributeError) as exc:
            return False, f"cannot verify rootless podman: {exc}"

    def _require_healthy(self) -> None:
        failed = [item["name"] for item in self.doctor() if not item["passed"]]
        if failed:
            raise RuntimeError(f"sandbox security checks failed: {','.join(failed)}")

    def _podman_env(self) -> dict[str, str]:
        env = {name: value for name, value in self.environ.items() if name in PODMAN_HOST_ENV}
        env.setdefault("PATH", "/usr/bin:/bin")
        env.setdefault("XDG_RUNTIME_DIR", self._podman_runtime_dir())
        return env

    def _sandbox_path(self, sandbox_id: str) -> Path:
        return self.config.workspace_root / _sandbox_id(sandbox_id)

    def _active_root(self, sandbox_id: str) -> Path:
        root = self._sandbox_path(sandbox_id)
        if not (root / "prepared").is_file() or (root / "frozen").exists():
            raise RuntimeError("sandbox is not active")
        return root

    def _workspace_access(self, sandbox_id: str) -> tuple[tuple[str, bool], ...] | None:
        marker = self._sandbox_path(sandbox_id) / ACCESS_POLICY_FILE
        if not marker.exists():
            return None
        try:
            return _parse_workspace_access(json.loads(marker.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
            raise RuntimeError("workspace access policy is invalid") from exc

    @staticmethod
    def _container_name(sandbox_id: str, *, suffix: str = "") -> str:
        return f"aegis-{sandbox_id}{suffix}"


def _parse_command(value: object) -> tuple[list[str], str, dict[str, str], str | None, float]:
    data = _object(value, "command")
    if set(data) != {"argv", "cwd", "env", "stdin", "timeout_seconds", "network"}:
        raise ValueError("command has missing or unknown fields")
    argv = data["argv"]
    if not isinstance(argv, list) or not argv or any(not isinstance(arg, str) or "\0" in arg for arg in argv):
        raise ValueError("invalid command argv")
    cwd = data["cwd"]
    if not isinstance(cwd, str) or not _safe_relative(cwd):
        raise ValueError("invalid command cwd")
    raw_env = _object(data["env"], "command env")
    env: dict[str, str] = {}
    for name, value in raw_env.items():
        if (
            name not in ALLOWED_ENV
            or not ENV_NAME.fullmatch(name)
            or not isinstance(value, str)
            or "\0" in value
            or len(value) > 4096
        ):
            raise ValueError(f"environment variable is not allowed: {name}")
        env[name] = value
    stdin = data["stdin"]
    if stdin is not None and (not isinstance(stdin, str) or len(stdin.encode()) > 1_048_576):
        raise ValueError("invalid command stdin")
    timeout = data["timeout_seconds"]
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 3600:
        raise ValueError("invalid command timeout")
    if data["network"] not in {"none", "allowlist"}:
        raise ValueError("network must be 'none' or 'allowlist'")
    return list(argv), cwd, env, stdin, float(timeout)


def _parse_workspace_access(value: object) -> tuple[tuple[str, bool], ...]:
    if not isinstance(value, list) or len(value) > MAX_WRITABLE_PATHS:
        raise ValueError("writable_paths must be a bounded list")
    rules: list[tuple[str, bool]] = []
    seen: set[str] = set()
    for raw in value:
        data = _object(raw, "workspace access rule")
        if set(data) != {"path", "recursive"}:
            raise ValueError("workspace access rule has missing or unknown fields")
        path = data["path"]
        recursive = data["recursive"]
        if (
            not isinstance(path, str)
            or not path
            or path in {".", "./"}
            or not _safe_relative(path)
            or PurePosixPath(path).as_posix() != path
            or any(part in {"", "."} for part in PurePosixPath(path).parts)
        ):
            raise ValueError("invalid workspace access path")
        if not isinstance(recursive, bool):
            raise ValueError("workspace access recursive flag must be a bool")
        if path in seen:
            raise ValueError("duplicate workspace access path")
        seen.add(path)
        rules.append((path, recursive))
    if rules != sorted(rules):
        raise ValueError("workspace access rules must be in canonical order")
    return tuple(rules)


def _deterministic_tar(workspace: Path) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for path in sorted(workspace.rglob("*"), key=lambda item: item.as_posix()):
            relative = path.relative_to(workspace).as_posix()
            if path.is_symlink():
                raise RuntimeError(f"workspace contains forbidden symlink: {relative}")
            if not path.is_file() and not path.is_dir():
                raise RuntimeError(f"workspace contains unsupported file type: {relative}")
            info = archive.gettarinfo(str(path), arcname=relative)
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = 0
            if path.is_file():
                with path.open("rb") as source:
                    archive.addfile(info, source)
            else:
                archive.addfile(info)
    return output.getvalue()


def _validate_staging_archive(
    archive_base64: object, expected_digest: object
) -> tuple[bytes, tuple[tarfile.TarInfo, ...]]:
    if not isinstance(archive_base64, str) or len(archive_base64) > ((MAX_ARCHIVE_BYTES + 2) // 3) * 4 + 4:
        raise ValueError("staging archive exceeds compressed size limit")
    if not isinstance(expected_digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_digest):
        raise ValueError("expected digest must be a SHA-256 digest")
    try:
        payload = base64.b64decode(archive_base64, validate=True)
    except ValueError as exc:
        raise ValueError("staging archive is not valid base64") from exc
    if len(payload) > MAX_ARCHIVE_BYTES:
        raise ValueError("staging archive exceeds compressed size limit")
    if hashlib.sha256(payload).hexdigest() != expected_digest.lower():
        raise ValueError("staging archive digest mismatch")
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as archive:
            members = tuple(archive.getmembers())
    except (tarfile.TarError, OSError) as exc:
        raise ValueError("staging payload is not a valid tar archive") from exc
    if len(members) > MAX_ARCHIVE_ENTRIES:
        raise ValueError("staging archive has too many entries")
    total = 0
    seen: set[str] = set()
    for member in members:
        raw = member.name
        path = PurePosixPath(raw)
        if (
            not raw
            or raw in {".", "./"}
            or path.is_absolute()
            or ".." in path.parts
            or "\\" in raw
            or "\0" in raw
            or any(part in {"", "."} for part in path.parts)
        ):
            raise ValueError(f"unsafe staging path: {raw!r}")
        normalized = path.as_posix()
        if normalized in seen:
            raise ValueError(f"duplicate staging path: {normalized}")
        seen.add(normalized)
        if not (member.isfile() or member.isdir()):
            raise ValueError(f"unsupported staging entry type: {normalized}")
        total += member.size
        if member.size < 0 or total > MAX_EXPANDED_BYTES:
            raise ValueError("staging archive exceeds expanded size limit")
    return payload, members


def _verify_workspace_quota(workspace_root: Path, maximum_bytes: int) -> tuple[bool, str]:
    """Verify quota from kernel-visible filesystem properties, not a marker."""
    try:
        if not workspace_root.is_dir() or not os.path.ismount(workspace_root):
            return False, "workspace_root is not a distinct mounted filesystem"
        total = shutil.disk_usage(workspace_root).total
        if total > maximum_bytes:
            return False, f"workspace filesystem capacity {total} exceeds {maximum_bytes}"
        return True, f"workspace filesystem capacity {total} is within limit"
    except OSError as exc:
        return False, f"cannot verify workspace filesystem quota: {exc}"


def _marker_check(path: Path, expected: str) -> tuple[bool, str]:
    try:
        valid = path.is_file() and path.read_text(encoding="ascii").strip() == expected
        return valid, "policy marker valid" if valid else "policy marker missing or invalid"
    except OSError as exc:
        return False, f"cannot read policy marker: {exc}"


def _safe_relative(value: str) -> bool:
    path = PurePosixPath(value)
    return not path.is_absolute() and ".." not in path.parts and "\\" not in value and "\0" not in value


def _sandbox_id(value: object) -> str:
    if not isinstance(value, str) or not SAFE_ID.fullmatch(value):
        raise ValueError("invalid sandbox id")
    return value


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"{label} must be an object")
    return value


def _read_json_file(path: Path) -> dict[str, Any]:
    try:
        return _object(json.loads(path.read_text(encoding="utf-8")), "agent config")
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load agent config: {exc}") from exc


def _required_string(data: Mapping[str, Any], name: str) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not value or "\0" in value:
        raise ValueError(f"invalid {name}")
    return value


def _required_int(data: Mapping[str, Any], name: str) -> int:
    value = data.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"invalid {name}")
    return value


def _text(value: object) -> str:
    if value is None:
        return ""
    return value.decode(errors="replace") if isinstance(value, bytes) else str(value)


def main() -> int:
    try:
        line = sys.stdin.readline()
        if not line or sys.stdin.read(1):
            raise ValueError("agent requires exactly one JSON object")
        request = json.loads(line)
        response = SandboxAgent(AgentConfig.load()).handle(request)
        sys.stdout.write(json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n")
        return 0
    except Exception as exc:  # trust boundary: expose one sanitized failure object
        sys.stdout.write(
            json.dumps({"ok": False, "error": type(exc).__name__, "message": str(exc)}, separators=(",", ":"))
            + "\n"
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
