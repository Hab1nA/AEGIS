from __future__ import annotations

import base64
import hashlib
import io
import json
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aegis.sandbox.agent import (
    NETWORK_MARKER,
    QUOTA_MARKER,
    REQUIRED_CHECKS,
    AgentConfig,
    SandboxAgent,
)


class FakeRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[list[str], str | None, float | None, dict[str, str]]] = []

    def __call__(self, argv, *, input=None, timeout=None, env=None):
        self.calls.append((list(argv), input, timeout, dict(env or {})))
        if argv[1:4] == ["info", "--format", "json"]:
            return subprocess.CompletedProcess(
                argv, 0, json.dumps({"host": {"security": {"rootless": True}}}), ""
            )
        if argv[1:3] == ["image", "exists"]:
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[1:3] == ["rm", "--force"]:
            return subprocess.CompletedProcess(argv, 0, "", "")
        return subprocess.CompletedProcess(argv, 7, "output", "diagnostic")


class AgentFixture:
    def __init__(self, root: Path, *, environ: dict[str, str] | None = None) -> None:
        self.root = root
        self.mounts = root / "mounts"
        self.mounts.write_text("none / ext4 rw 0 0\n", encoding="ascii")
        self.interop = root / "missing-interop"
        self.controllers = root / "controllers"
        self.controllers.write_text("cpu io memory pids\n", encoding="ascii")
        self.network = root / "network.policy"
        self.network.write_text(NETWORK_MARKER + "\n", encoding="ascii")
        self.quota = root / "quota.policy"
        self.quota.write_text(QUOTA_MARKER + "\n", encoding="ascii")
        self.runner = FakeRunner()
        self.config = AgentConfig(
            workspace_root=root / "workspaces",
            image="example.invalid/aegis@sha256:" + "a" * 64,
            network_policy_marker=self.network,
            quota_policy_marker=self.quota,
        )
        self.agent = SandboxAgent(
            self.config,
            runner=self.runner,
            environ=environ or {"PATH": "/usr/bin"},
            uid_getter=lambda: 1000,
            mounts_path=self.mounts,
            interop_path=self.interop,
            controllers_path=self.controllers,
            quota_checker=lambda _root, limit: (
                limit == self.config.max_workspace_bytes,
                "test quota verified",
            ),
        )


class SandboxAgentTests(unittest.TestCase):
    def test_sealed_assertion_never_crosses_into_read_only_worker(self) -> None:
        secret = "SEALED_EXPECTED_VALUE_4e21"
        document = {
            "version": 1,
            "cases": [
                {
                    "name": "secret",
                    "steps": [{"op": "call", "symbol": "answer", "args": [], "expect": secret}],
                }
            ],
        }
        content = json.dumps(document).encode()
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as bundle:
            info = tarfile.TarInfo("cases.json")
            info.size = len(content)
            bundle.addfile(info, io.BytesIO(content))
        archive = output.getvalue()

        with (
            tempfile.TemporaryDirectory() as directory,
            patch("aegis.sandbox.agent.shutil.which", return_value="/usr/bin/podman"),
        ):
            fixture = AgentFixture(Path(directory))
            original = fixture.runner

            def runner(argv, *, input=None, timeout=None, env=None):
                if "-sealed" in " ".join(argv):
                    original.calls.append((list(argv), input, timeout, dict(env or {})))
                    return subprocess.CompletedProcess(
                        argv, 0, json.dumps({"results": [{"ok": True, "value": secret, "fixtures": {}}]}), ""
                    )
                return original(argv, input=input, timeout=timeout, env=env)

            fixture.agent.runner = runner
            fixture.agent.prepare("task")
            result = fixture.agent.evaluate_sealed(
                "task",
                base64.b64encode(archive).decode(),
                hashlib.sha256(archive).hexdigest(),
                10,
            )
            argv, stdin, _, env = original.calls[-1]
            workspace = fixture.config.workspace_root / "task" / "workspace"

        self.assertEqual((result["passed"], result["total"]), (1, 1))
        self.assertNotIn(secret, stdin or "")
        self.assertNotIn(secret, " ".join(argv))
        self.assertNotIn(secret, " ".join(env.values()))
        self.assertIn("--interactive", argv)
        self.assertTrue(any(item.endswith(":/workspace:ro,Z") for item in argv))
        self.assertFalse(any(workspace.rglob("cases.json")))

    def test_doctor_performs_all_required_checks(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("aegis.sandbox.agent.shutil.which", return_value="/usr/bin/podman"),
        ):
            fixture = AgentFixture(Path(directory))
            response = fixture.agent.handle({"version": 1, "operation": "doctor"})
        self.assertTrue(response["ok"])
        self.assertEqual([item["name"] for item in response["checks"]], list(REQUIRED_CHECKS))
        self.assertTrue(all(item["passed"] for item in response["checks"]))

    def test_doctor_fails_for_mount_root_secret_and_policy(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("aegis.sandbox.agent.shutil.which", return_value="/usr/bin/podman"),
        ):
            fixture = AgentFixture(Path(directory), environ={"PATH": "/usr/bin", "OPENAI_API_KEY": "x"})
            fixture.mounts.write_text("C: /mnt/c drvfs rw 0 0\n", encoding="ascii")
            fixture.network.unlink()
            fixture.agent.uid_getter = lambda: 0
            checks = {item["name"]: item for item in fixture.agent.doctor()}
        self.assertFalse(checks["windows_mounts_disabled"]["passed"])
        self.assertFalse(checks["rootless_oci"]["passed"])
        self.assertFalse(checks["network_none"]["passed"])
        self.assertFalse(checks["secret_absence"]["passed"])

    def test_strict_schema_and_identifier_validation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            agent = AgentFixture(Path(directory)).agent
            with self.assertRaisesRegex(ValueError, "unknown"):
                agent.handle({"version": 1, "operation": "doctor", "extra": True})
            with self.assertRaisesRegex(ValueError, "sandbox id"):
                agent.handle({"version": 1, "operation": "destroy", "sandbox_id": "../bad"})
            with self.assertRaisesRegex(ValueError, "unsupported operation"):
                agent.handle({"version": 1, "operation": "shell"})

    def test_prepare_exec_freeze_export_destroy_wire_compatibility(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("aegis.sandbox.agent.shutil.which", return_value="/usr/bin/podman"),
        ):
            fixture = AgentFixture(Path(directory))
            agent = fixture.agent
            self.assertEqual(
                agent.handle({"version": 1, "operation": "prepare", "sandbox_id": "task-1"}), {"ok": True}
            )
            workspace = fixture.config.workspace_root / "task-1" / "workspace"
            (workspace / "answer.py").write_text("print(42)\n", encoding="utf-8")
            result = agent.handle(
                {
                    "version": 1,
                    "operation": "exec",
                    "sandbox_id": "task-1",
                    "command": {
                        "argv": ["python", "answer.py"],
                        "cwd": ".",
                        "env": {"LANG": "C"},
                        "stdin": None,
                        "timeout_seconds": 3,
                        "network": "none",
                    },
                }
            )
            self.assertEqual(result["result"]["exit_code"], 7)
            run_argv, _, _, run_env = fixture.runner.calls[-1]
            self.assertNotIn("sh", run_argv[:2])
            for flag in (
                "--interactive",
                "--network=none",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--read-only",
            ):
                self.assertIn(flag, run_argv)
            self.assertEqual(run_env["LANG"], "C")
            frozen = agent.handle({"version": 1, "operation": "freeze", "sandbox_id": "task-1"})
            exported = agent.handle({"version": 1, "operation": "export", "sandbox_id": "task-1"})
            self.assertEqual(frozen["artifact"], exported["artifact"])
            self.assertEqual(len(bytes.fromhex(frozen["artifact"]["sha256"])), 32)
            self.assertEqual(
                hashlib.sha256(__import__("base64").b64decode(exported["archive_base64"])).hexdigest(),
                frozen["artifact"]["sha256"],
            )
            self.assertEqual(
                agent.handle({"version": 1, "operation": "destroy", "sandbox_id": "task-1"}), {"ok": True}
            )
            self.assertFalse((fixture.config.workspace_root / "task-1").exists())

    def test_exec_rejects_network_env_and_frozen_workspace(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("aegis.sandbox.agent.shutil.which", return_value="/usr/bin/podman"),
        ):
            fixture = AgentFixture(Path(directory))
            fixture.agent.prepare("task")
            base = {
                "argv": ["true"],
                "cwd": ".",
                "env": {},
                "stdin": None,
                "timeout_seconds": 3,
                "network": "none",
            }
            bad = dict(base, network="host")
            with self.assertRaisesRegex(ValueError, "network"):
                fixture.agent.execute("task", bad)
            bad = dict(base, env={"API_KEY": "secret"})
            with self.assertRaisesRegex(ValueError, "not allowed"):
                fixture.agent.execute("task", bad)
            fixture.agent.freeze("task")
            with self.assertRaisesRegex(RuntimeError, "not active"):
                fixture.agent.execute("task", base)

    def test_workspace_access_mounts_full_context_read_only_with_bounded_writes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = AgentFixture(Path(directory))
            fixture.agent.prepare("candidate")
            workspace = fixture.config.workspace_root / "candidate" / "workspace"
            (workspace / "src" / "adaptive").mkdir(parents=True)
            (workspace / "src" / "adaptive" / "logic.py").write_text("VALUE = 1\n")
            (workspace / "control.py").write_text("TRUSTED = True\n")
            fixture.agent.configure_workspace_access(
                "candidate",
                [
                    {"path": "src/adaptive", "recursive": True},
                ],
            )
            argv, _ = fixture.agent.build_podman_command(
                "candidate",
                workspace,
                (["true"], ".", {}, None, 3.0),
            )
            volumes = [argv[index + 1] for index, value in enumerate(argv[:-1]) if value == "--volume"]
            self.assertEqual(volumes[0], f"{workspace}:/workspace:ro,Z")
            self.assertEqual(
                volumes[1],
                f"{workspace / 'src' / 'adaptive'}:/workspace/src/adaptive:rw,Z",
            )
            self.assertFalse(any("control.py:/workspace/control.py:rw" in volume for volume in volumes))
            with self.assertRaisesRegex(RuntimeError, "after workspace access"):
                fixture.agent.stage_archive("candidate", "", "0" * 64)

    def test_workspace_access_rejects_missing_exact_and_unsafe_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = AgentFixture(Path(directory))
            fixture.agent.prepare("candidate")
            with self.assertRaisesRegex(ValueError, "not a staged file"):
                fixture.agent.configure_workspace_access(
                    "candidate", [{"path": "missing.py", "recursive": False}]
                )
            with self.assertRaisesRegex(ValueError, "invalid workspace access path"):
                fixture.agent.configure_workspace_access(
                    "candidate", [{"path": "../escape", "recursive": True}]
                )

    def test_freeze_rejects_symlink_that_could_expose_host_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = AgentFixture(Path(directory))
            fixture.agent.prepare("task")
            workspace = fixture.config.workspace_root / "task" / "workspace"
            try:
                (workspace / "escape").symlink_to(fixture.mounts)
            except OSError:
                self.skipTest("symlinks are not available")
            with self.assertRaisesRegex(RuntimeError, "forbidden symlink"):
                fixture.agent.freeze("task")

    def test_missing_security_marker_fails_closed_before_prepare(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("aegis.sandbox.agent.shutil.which", return_value="/usr/bin/podman"),
        ):
            fixture = AgentFixture(Path(directory))
            fixture.quota.unlink()
            with self.assertRaisesRegex(RuntimeError, "disk_quota_marker"):
                fixture.agent.handle({"version": 1, "operation": "prepare", "sandbox_id": "task"})
            self.assertFalse((fixture.config.workspace_root / "task").exists())

    def test_kill_uses_fixed_podman_argv_and_removes_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = AgentFixture(Path(directory))
            fixture.agent.prepare("task")
            fixture.agent.kill("task")
            cleanup_argv = [argv for argv, *_ in fixture.runner.calls if argv[1:3] == ["rm", "--force"]]
            self.assertEqual(
                cleanup_argv,
                [
                    ["podman", "rm", "--force", "--time", "0", "aegis-task"],
                    ["podman", "rm", "--force", "--time", "0", "aegis-task-sealed"],
                ],
            )
            self.assertFalse((fixture.config.workspace_root / "task").exists())

    def test_output_limit_explicitly_removes_main_container(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = AgentFixture(Path(directory))
            fixture.agent.prepare("task")

            class OutputLimitRunner(FakeRunner):
                def __call__(self, argv, *, input=None, timeout=None, env=None):
                    self.calls.append((list(argv), input, timeout, dict(env or {})))
                    if argv[1] == "run":
                        return subprocess.CompletedProcess(
                            argv, 125, "", "process output exceeded hard limit"
                        )
                    return subprocess.CompletedProcess(argv, 0, "", "")

            runner = OutputLimitRunner()
            fixture.agent.runner = runner
            result = fixture.agent.execute(
                "task",
                {
                    "argv": ["python", "flood.py"],
                    "cwd": ".",
                    "env": {},
                    "stdin": None,
                    "timeout_seconds": 3,
                    "network": "none",
                },
            )
            self.assertEqual(result["exit_code"], 125)
            self.assertIn(
                ["podman", "rm", "--force", "--time", "0", "aegis-task"],
                [argv for argv, *_ in runner.calls],
            )

    def test_exec_runner_exception_still_removes_main_container(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = AgentFixture(Path(directory))
            fixture.agent.prepare("task")

            class ExplodingRunner(FakeRunner):
                def __call__(self, argv, *, input=None, timeout=None, env=None):
                    self.calls.append((list(argv), input, timeout, dict(env or {})))
                    if argv[1] == "run":
                        raise OSError("podman client failed")
                    return subprocess.CompletedProcess(argv, 0, "", "")

            runner = ExplodingRunner()
            fixture.agent.runner = runner
            with self.assertRaisesRegex(OSError, "client failed"):
                fixture.agent.execute(
                    "task",
                    {
                        "argv": ["python", "work.py"],
                        "cwd": ".",
                        "env": {},
                        "stdin": None,
                        "timeout_seconds": 3,
                        "network": "none",
                    },
                )
            self.assertIn(
                ["podman", "rm", "--force", "--time", "0", "aegis-task"],
                [argv for argv, *_ in runner.calls],
            )

    def test_exec_timeout_explicitly_removes_main_container(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = AgentFixture(Path(directory))
            fixture.agent.prepare("task")

            class TimeoutRunner(FakeRunner):
                def __call__(self, argv, *, input=None, timeout=None, env=None):
                    self.calls.append((list(argv), input, timeout, dict(env or {})))
                    if argv[1] == "run":
                        raise subprocess.TimeoutExpired(argv, timeout or 0, output="partial")
                    return subprocess.CompletedProcess(argv, 0, "", "")

            runner = TimeoutRunner()
            fixture.agent.runner = runner
            result = fixture.agent.execute(
                "task",
                {
                    "argv": ["python", "slow.py"],
                    "cwd": ".",
                    "env": {},
                    "stdin": None,
                    "timeout_seconds": 3,
                    "network": "none",
                },
            )
            self.assertTrue(result["timed_out"])
            self.assertEqual(result["exit_code"], 124)
            self.assertIn(
                ["podman", "rm", "--force", "--time", "0", "aegis-task"],
                [argv for argv, *_ in runner.calls],
            )

    def test_destroy_is_idempotent_for_not_found_and_cleans_sealed_container(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = AgentFixture(Path(directory))
            fixture.agent.prepare("task")

            class NotFoundRunner(FakeRunner):
                def __call__(self, argv, *, input=None, timeout=None, env=None):
                    self.calls.append((list(argv), input, timeout, dict(env or {})))
                    return subprocess.CompletedProcess(argv, 1, "", "no such container")

            runner = NotFoundRunner()
            fixture.agent.runner = runner
            fixture.agent.destroy("task")
            fixture.agent.destroy("task")
            names = [argv[-1] for argv, *_ in runner.calls]
            self.assertEqual(names.count("aegis-task"), 2)
            self.assertEqual(names.count("aegis-task-sealed"), 2)
            self.assertFalse((fixture.config.workspace_root / "task").exists())

    def test_cleanup_reclaims_rootless_container_owned_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = AgentFixture(Path(directory))
            fixture.agent.prepare("task")
            root = fixture.config.workspace_root / "task"
            original_rmtree = __import__("shutil").rmtree
            calls = 0

            def permission_then_remove(path):
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise PermissionError("container uid owns workspace")
                original_rmtree(path)

            original_runner = fixture.runner

            def runner(argv, *, input=None, timeout=None, env=None):
                if argv[1:3] == ["unshare", "chown"]:
                    original_runner.calls.append(
                        (list(argv), input, timeout, dict(env or {}))
                    )
                    return subprocess.CompletedProcess(argv, 0, "", "")
                return original_runner(argv, input=input, timeout=timeout, env=env)

            fixture.agent.runner = runner
            with patch("aegis.sandbox.agent.shutil.rmtree", side_effect=permission_then_remove):
                fixture.agent.destroy("task")

            reclaim = [
                argv for argv, *_ in fixture.runner.calls if argv[1:3] == ["unshare", "chown"]
            ]
            self.assertEqual(len(reclaim), 1)
            self.assertEqual(
                reclaim[0][2:7],
                ["chown", "-R", "--no-dereference", "0:0", "--"],
            )
            self.assertEqual(Path(reclaim[0][-1]), root)
            self.assertFalse(root.exists())


if __name__ == "__main__":
    unittest.main()
