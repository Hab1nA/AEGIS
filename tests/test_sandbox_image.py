from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from aegis.sandbox.agent import NETWORK_MARKER, QUOTA_MARKER, AgentConfig, SandboxAgent
from aegis.sandbox.fake import FakeSandboxBackend
from aegis.sandbox.wsl import WslSandboxBackend
from tests.test_sandbox_agent import FakeRunner


class AgentImageFixture:
    def __init__(self, root: Path) -> None:
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
        (root / "workspaces").mkdir(parents=True, exist_ok=True)
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
            environ={"PATH": "/usr/bin"},
            uid_getter=lambda: 1000,
            mounts_path=self.mounts,
            interop_path=self.interop,
            controllers_path=self.controllers,
            quota_checker=lambda _root, limit: (
                limit == self.config.max_workspace_bytes,
                "test quota verified",
            ),
        )


class SandboxImageTests(unittest.TestCase):
    def test_agent_prepare_with_image_pins_marker_and_uses_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = AgentImageFixture(Path(directory))
            image = "example.invalid/aegis@sha256:" + "b" * 64
            fixture.agent.prepare("sandbox-1", image=image)
            marker = fixture.root / "workspaces" / "sandbox-1" / "image"
            self.assertEqual(marker.read_text(encoding="ascii").strip(), image)
            argv, _ = fixture.agent.build_podman_command(
                "sandbox-1",
                fixture.root / "workspaces" / "sandbox-1" / "workspace",
                (["python", "-c", "print(1)"], ".", {}, None, 10.0),
            )
            self.assertIn(image, argv)
            self.assertNotIn(fixture.config.image, argv)

    def test_agent_prepare_without_image_uses_default(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = AgentImageFixture(Path(directory))
            fixture.agent.prepare("sandbox-1")
            self.assertFalse(
                (fixture.root / "workspaces" / "sandbox-1" / "image").exists()
            )
            argv, _ = fixture.agent.build_podman_command(
                "sandbox-1",
                fixture.root / "workspaces" / "sandbox-1" / "workspace",
                (["python", "-c", "print(1)"], ".", {}, None, 10.0),
            )
            self.assertIn(fixture.config.image, argv)

    def test_agent_rejects_unpinned_or_missing_image(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = AgentImageFixture(Path(directory))
            with self.assertRaisesRegex(RuntimeError, "pinned"):
                fixture.agent.prepare("sandbox-1", image="example.invalid/aegis:latest")
            fixture.runner.calls.clear()

            def missing(argv, *, input=None, timeout=None, env=None):
                if argv[1:3] == ["image", "exists"]:
                    return subprocess.CompletedProcess(argv, 1, "", "missing")
                return subprocess.CompletedProcess(argv, 7, "", "diagnostic")

            fixture.runner = missing
            fixture.agent.runner = missing
            with self.assertRaisesRegex(RuntimeError, "unavailable"):
                fixture.agent.prepare(
                    "sandbox-2", image="example.invalid/aegis@sha256:" + "c" * 64
                )

    def test_agent_prepare_falls_back_to_digest_for_locally_built_image(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = AgentImageFixture(Path(directory))
            digest = "d" * 64

            def resolvable(argv, *, input=None, timeout=None, env=None):
                if argv[1:3] == ["image", "exists"]:
                    reference = argv[3]
                    ok = reference.startswith("sha256:")
                    return subprocess.CompletedProcess(
                        argv, 0 if ok else 1, "", ""
                    )
                return fixture.runner(argv, input=input, timeout=timeout, env=env)

            fixture.agent.runner = resolvable
            image = "localhost/aegis-evolution@sha256:" + digest
            fixture.agent.prepare("sandbox-3", image=image)
            marker = fixture.root / "workspaces" / "sandbox-3" / "image"
            self.assertEqual(marker.read_text(encoding="ascii").strip(), "sha256:" + digest)
            argv, _ = fixture.agent.build_podman_command(
                "sandbox-3",
                fixture.root / "workspaces" / "sandbox-3" / "workspace",
                (["python", "-c", "print(1)"], ".", {}, None, 10.0),
            )
            self.assertIn("sha256:" + digest, argv)

    def test_agent_scan_image_accepts_digest_only_reference(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = AgentImageFixture(Path(directory))
            runtime_dir = Path(directory) / "runtime"
            socket_dir = runtime_dir / "podman"
            socket_dir.mkdir(parents=True)
            (socket_dir / "podman.sock").write_text("", encoding="ascii")
            fixture.agent._podman_runtime_dir = lambda: str(runtime_dir)
            digest = "e" * 64
            trivy_calls: list[list[str]] = []

            def scanning(argv, *, input=None, timeout=None, env=None):
                if argv[:2] == ["trivy", "--version"]:
                    return subprocess.CompletedProcess(
                        argv, 0, "Version: 0.69.2", ""
                    )
                if argv[:2] == ["trivy", "image"]:
                    trivy_calls.append(list(argv))
                    return subprocess.CompletedProcess(
                        argv, 0, "no vulnerabilities", ""
                    )
                return fixture.runner(argv, input=input, timeout=timeout, env=env)

            fixture.agent.runner = scanning
            result = fixture.agent.scan_image("sha256:" + digest, timeout_seconds=60)
            self.assertEqual(result["image_sha256"], digest)
            self.assertEqual(result["staged_artifact_id"], "sha256:" + digest)
            self.assertEqual(len(trivy_calls), 1)
            self.assertIn("sha256:" + digest, trivy_calls[0])

    def test_agent_handle_accepts_build_and_scan_operations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = AgentImageFixture(Path(directory))

            def building(argv, *, input=None, timeout=None, env=None):
                if argv[1:4] == ["build", "--network", "none"]:
                    if "--iidfile" in argv:
                        target = Path(argv[argv.index("--iidfile") + 1])
                        target.write_text("sha256:" + "5" * 64, encoding="ascii")
                    return subprocess.CompletedProcess(argv, 0, "", "")
                if argv[1:3] == ["image", "inspect"]:
                    return subprocess.CompletedProcess(argv, 0, "12345", "")
                return fixture.runner(argv, input=input, timeout=timeout, env=env)

            fixture.agent.runner = building
            recipe = {
                "recipe_id": "sha256:" + "0" * 64,
                "parent_image": "example.invalid/aegis@sha256:" + "a" * 64,
                "build_steps": [{"argv": ["python", "-c", "print(1)"], "cwd": "."}],
                "network_policy": "offline",
                "dependencies": [],
                "max_output_bytes": 1024 * 1024,
            }
            result = fixture.agent.handle(
                {
                    "version": 1,
                    "operation": "build_image",
                    "recipe": recipe,
                    "dependencies": {},
                    "attempt_id": "sha256:" + "1" * 64,
                    "timeout_seconds": 300,
                }
            )
            staged = result["staged"]
            self.assertEqual(staged["exit_code"], 0)
            probe = fixture.agent.handle({"version": 1, "operation": "scanner_probe"})
            self.assertIn("available", probe)

    def test_wsl_backend_sends_image_in_prepare_payload(self) -> None:
        calls: list[dict[str, object]] = []

        def runner(argv, stdin="", timeout=0.0):
            payload = json.loads(stdin)
            calls.append(payload)
            if payload.get("operation") == "doctor":
                from aegis.sandbox.agent import REQUIRED_CHECKS

                checks = [
                    {"name": name, "passed": True, "detail": "ok"}
                    for name in REQUIRED_CHECKS
                ]
                return subprocess.CompletedProcess(
                    argv, 0, json.dumps({"ok": True, "checks": checks}), ""
                )
            return subprocess.CompletedProcess(argv, 0, '{"ok": true}', "")

        backend = WslSandboxBackend(runner=runner)
        image = "example.invalid/aegis@sha256:" + "d" * 64
        backend.doctor()
        backend.prepare("sandbox-1", image=image)
        self.assertEqual(calls[-1]["operation"], "prepare")
        self.assertEqual(calls[-1]["image"], image)
        backend.prepare("sandbox-2")
        self.assertNotIn("image", calls[-1])

    def test_fake_backend_tracks_per_sandbox_images(self) -> None:
        sandbox = FakeSandboxBackend()
        image = "example.invalid/aegis@sha256:" + "e" * 64
        sandbox.prepare("one", image=image)
        sandbox.prepare("two")
        self.assertEqual(sandbox.images["one"], image)
        self.assertIsNone(sandbox.images["two"])
        with self.assertRaises(ValueError):
            sandbox.prepare("three", image="example.invalid/aegis:latest")


if __name__ == "__main__":
    unittest.main()
