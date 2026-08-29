from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aegis.sandbox import CommandSpec, FakeSandboxBackend, WorkspaceAccessRule, WslSandboxBackend
from aegis.sandbox.wsl import REQUIRED_CHECKS


def completed(payload: dict[str, object], returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], returncode, json.dumps(payload), "agent diagnostic")


class FakeSandboxTests(unittest.TestCase):
    def test_lifecycle_and_freeze(self) -> None:
        backend = FakeSandboxBackend()
        backend.prepare("round-1")
        result = backend.exec("round-1", CommandSpec(("python", "-V")))
        artifact = backend.freeze("round-1")
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(len(artifact.digest), 64)
        with self.assertRaises(RuntimeError):
            backend.exec("round-1", CommandSpec(("python", "-V")))

    def test_workspace_access_is_explicit_and_single_assignment(self) -> None:
        backend = FakeSandboxBackend()
        backend.prepare("round-1")
        rules = (WorkspaceAccessRule("src/adaptive", recursive=True),)
        backend.configure_workspace_access("round-1", rules)
        self.assertEqual(backend.workspace_access["round-1"], rules)
        with self.assertRaisesRegex(RuntimeError, "already configured"):
            backend.configure_workspace_access("round-1", rules)

    def test_unhealthy_backend_fails_closed(self) -> None:
        backend = FakeSandboxBackend(healthy=False)
        with self.assertRaises(RuntimeError):
            backend.prepare("round-1")

    def test_command_validation(self) -> None:
        with self.assertRaises(ValueError):
            CommandSpec(("python",), cwd="../host")
        with self.assertRaises(ValueError):
            CommandSpec(())


class WslSandboxTests(unittest.TestCase):
    @staticmethod
    def healthy_doctor() -> dict[str, object]:
        return {
            "ok": True,
            "checks": [{"name": name, "passed": True} for name in REQUIRED_CHECKS],
        }

    def test_transport_does_not_use_shell_and_uses_json_stdin(self) -> None:
        calls: list[tuple[list[str], str, float]] = []

        def runner(argv: list[str], stdin: str, timeout: float) -> subprocess.CompletedProcess[str]:
            calls.append((argv, stdin, timeout))
            request = json.loads(stdin)
            if request["operation"] == "doctor":
                return completed(self.healthy_doctor())
            return completed(
                {
                    "ok": True,
                    "result": {
                        "exit_code": 0,
                        "stdout": "ok",
                        "stderr": "",
                        "duration_seconds": 0.2,
                    },
                }
            )

        backend = WslSandboxBackend(runner=runner)
        self.assertTrue(backend.doctor().passed)
        result = backend.exec(
            "task-1",
            CommandSpec(("python", "-c", "print('; still data')"), env={"LANG": "C"}),
        )
        self.assertEqual(result.stdout, "ok")
        self.assertEqual(
            calls[-1][0],
            [
                "wsl.exe", "--distribution", "AEGIS-Sandbox", "--",
                "/usr/bin/env", "AEGIS_SANDBOX_INTEROP_WARN=1",
                "/usr/local/bin/aegis-sandbox-agent",
            ],
        )
        request = json.loads(calls[-1][1])
        self.assertEqual(request["command"]["network"], "none")
        self.assertEqual(request["command"]["argv"][2], "print('; still data')")

    def test_interop_warn_only_relaxes_only_the_interop_check(self) -> None:
        calls: list[tuple[list[str], str, float]] = []

        def runner(argv: list[str], stdin: str, timeout: float) -> subprocess.CompletedProcess[str]:
            calls.append((argv, stdin, timeout))
            return completed(
                {
                    "ok": True,
                    "checks": [
                        {"name": "interop_disabled", "passed": False, "detail": "WSL interop is enabled"},
                        *(
                            {"name": name, "passed": True}
                            for name in REQUIRED_CHECKS
                            if name != "interop_disabled"
                        ),
                    ],
                }
            )

        relaxed = WslSandboxBackend(runner=runner)
        report = relaxed.doctor()
        self.assertTrue(report.passed)
        relaxed_detail = next(
            check.detail for check in report.checks if check.name == "interop_disabled"
        )
        self.assertIn("warn-only", relaxed_detail)

        strict = WslSandboxBackend(runner=runner, interop_warn_only=False)
        self.assertFalse(strict.doctor().passed)
        self.assertEqual(
            strict.transport_argv(),
            ["wsl.exe", "--distribution", "AEGIS-Sandbox", "--", "/usr/local/bin/aegis-sandbox-agent"],
        )

    def test_exec_requires_prior_passing_doctor(self) -> None:
        backend = WslSandboxBackend(runner=lambda *_: completed({"ok": True}))
        with self.assertRaisesRegex(RuntimeError, "doctor"):
            backend.exec("task-1", CommandSpec(("true",)))
        self.assertFalse(backend.doctor().passed)
        with self.assertRaisesRegex(RuntimeError, "doctor"):
            backend.exec("task-1", CommandSpec(("true",)))

    def test_environment_is_allowlisted(self) -> None:
        def runner(argv: list[str], stdin: str, timeout: float) -> subprocess.CompletedProcess[str]:
            return completed(self.healthy_doctor())

        backend = WslSandboxBackend(runner=runner)
        backend.doctor()
        with self.assertRaisesRegex(ValueError, "API_KEY"):
            backend.exec("task-1", CommandSpec(("true",), env={"API_KEY": "secret"}))

    def test_doctor_transport_error_is_report_not_exception(self) -> None:
        def runner(argv: list[str], stdin: str, timeout: float) -> subprocess.CompletedProcess[str]:
            raise subprocess.TimeoutExpired(argv, timeout)

        report = WslSandboxBackend(runner=runner).doctor()
        self.assertFalse(report.passed)
        self.assertEqual(set(report.failed_names()), set(REQUIRED_CHECKS))

    def test_agent_output_must_be_single_json_object(self) -> None:
        def runner(argv: list[str], stdin: str, timeout: float) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(argv, 0, '{}\n{"ok":true}', "")

        report = WslSandboxBackend(runner=runner).doctor()
        self.assertFalse(report.passed)

    def test_agent_failure_reports_bounded_escaped_redacted_stderr(self) -> None:
        secret = "credential-value"
        diagnostic = "first line\nAPI_KEY=" + secret + " \x00" + ("x" * 3000)

        def runner(argv: list[str], stdin: str, timeout: float) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(argv, 7, "ignored stdout", diagnostic)

        report = WslSandboxBackend(runner=runner).doctor()
        detail = report.checks[0].detail
        self.assertIn("exit code 7: stderr=first line\\nAPI_KEY=<redacted> \\u0000", detail)
        self.assertNotIn(secret, detail)
        self.assertIn("stdout=ignored stdout", detail)
        self.assertIn("...; stdout=ignored stdout", detail)
        self.assertLessEqual(len(detail), 2200)

    def test_agent_failure_uses_stdout_when_stderr_is_empty(self) -> None:
        def runner(argv: list[str], stdin: str, timeout: float) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(argv, 9, "Bearer credential-value\r\ndetail", "")

        report = WslSandboxBackend(runner=runner).doctor()
        detail = report.checks[0].detail
        self.assertIn("exit code 9: stdout=Bearer <redacted>\\r\\ndetail", detail)
        self.assertNotIn("credential-value", detail)

    def test_relative_export_destination_is_rejected(self) -> None:
        backend = WslSandboxBackend(runner=lambda *_: completed(self.healthy_doctor()))
        backend.doctor()
        with self.assertRaises(ValueError):
            backend.export("task-1", Path("relative.tar"))

    def test_export_verifies_content_and_kill_uses_agent_operation(self) -> None:
        archive = b"verified archive"
        operations: list[str] = []

        def runner(argv: list[str], stdin: str, timeout: float) -> subprocess.CompletedProcess[str]:
            request = json.loads(stdin)
            operations.append(request["operation"])
            if request["operation"] == "doctor":
                return completed(self.healthy_doctor())
            if request["operation"] == "export":
                return completed(
                    {
                        "ok": True,
                        "artifact": {
                            "sha256": hashlib.sha256(archive).hexdigest(),
                            "size_bytes": len(archive),
                        },
                        "archive_base64": base64.b64encode(archive).decode("ascii"),
                    }
                )
            return completed({"ok": True})

        backend = WslSandboxBackend(runner=runner)
        backend.doctor()
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory).resolve() / "artifact.tar"
            artifact = backend.export("task-1", destination)
            self.assertEqual(destination.read_bytes(), archive)
            self.assertEqual(artifact.digest, hashlib.sha256(archive).hexdigest())
        backend.kill("task-1")
        self.assertEqual(operations, ["doctor", "export", "kill"])

    def test_workspace_access_transport_is_strict_structured_data(self) -> None:
        requests: list[dict[str, object]] = []

        def runner(argv: list[str], stdin: str, timeout: float) -> subprocess.CompletedProcess[str]:
            request = json.loads(stdin)
            requests.append(request)
            if request["operation"] == "doctor":
                return completed(self.healthy_doctor())
            return completed({"ok": True})

        backend = WslSandboxBackend(runner=runner)
        backend.doctor()
        backend.configure_workspace_access(
            "candidate", (WorkspaceAccessRule("src/adaptive", recursive=True),)
        )
        self.assertEqual(
            requests[-1],
            {
                "version": 1,
                "operation": "configure_workspace_access",
                "sandbox_id": "candidate",
                "writable_paths": [{"path": "src/adaptive", "recursive": True}],
            },
        )

    def test_retryable_transport_failure_retries_then_succeeds(self) -> None:
        calls: list[str] = []

        def runner(argv: list[str], stdin: str, timeout: float) -> subprocess.CompletedProcess[str]:
            calls.append(json.loads(stdin)["operation"])
            if len(calls) < 3:
                return subprocess.CompletedProcess(argv, 3221225794, "", "")
            return completed({"ok": True})

        backend = WslSandboxBackend(runner=runner)
        with patch("aegis.sandbox.wsl.time.sleep") as sleeper:
            backend.destroy("task-1")
        self.assertEqual(calls, ["destroy", "destroy", "destroy"])
        self.assertEqual(sleeper.call_count, 2)

    def test_structured_agent_error_is_not_retried(self) -> None:
        calls: list[str] = []

        def runner(argv: list[str], stdin: str, timeout: float) -> subprocess.CompletedProcess[str]:
            calls.append(json.loads(stdin)["operation"])
            return subprocess.CompletedProcess(
                argv, 1, json.dumps({"ok": False, "message": "agent error"}), ""
            )

        backend = WslSandboxBackend(runner=runner)
        with patch("aegis.sandbox.wsl.time.sleep") as sleeper:
            with self.assertRaisesRegex(RuntimeError, "agent error"):
                backend.destroy("task-1")
        self.assertEqual(calls, ["destroy"])
        sleeper.assert_not_called()

    def test_non_retryable_operation_is_not_retried(self) -> None:
        calls: list[str] = []

        def runner(argv: list[str], stdin: str, timeout: float) -> subprocess.CompletedProcess[str]:
            request = json.loads(stdin)
            calls.append(request["operation"])
            if request["operation"] == "doctor":
                return completed(self.healthy_doctor())
            return subprocess.CompletedProcess(argv, 3221225794, "", "")

        backend = WslSandboxBackend(runner=runner)
        self.assertTrue(backend.doctor().passed)
        with patch("aegis.sandbox.wsl.time.sleep") as sleeper:
            with self.assertRaisesRegex(RuntimeError, "exit code"):
                backend.exec("task-1", CommandSpec(("true",)))
        self.assertEqual(calls, ["doctor", "exec"])
        sleeper.assert_not_called()

    def test_timeout_expired_retries_retryable_operation(self) -> None:
        calls: list[str] = []

        def runner(argv: list[str], stdin: str, timeout: float) -> subprocess.CompletedProcess[str]:
            calls.append(json.loads(stdin)["operation"])
            if len(calls) < 3:
                raise subprocess.TimeoutExpired(argv, timeout)
            return completed({"ok": True})

        backend = WslSandboxBackend(runner=runner)
        with patch("aegis.sandbox.wsl.time.sleep") as sleeper:
            backend.destroy("task-1")
        self.assertEqual(calls, ["destroy", "destroy", "destroy"])
        self.assertEqual(sleeper.call_count, 2)

    def test_retry_exhaustion_raises_after_attempts(self) -> None:
        calls: list[str] = []

        def runner(argv: list[str], stdin: str, timeout: float) -> subprocess.CompletedProcess[str]:
            calls.append(json.loads(stdin)["operation"])
            return subprocess.CompletedProcess(argv, 3221225794, "", "")

        backend = WslSandboxBackend(runner=runner)
        with patch("aegis.sandbox.wsl.time.sleep") as sleeper:
            with self.assertRaisesRegex(RuntimeError, "exit code"):
                backend.destroy("task-1")
        self.assertEqual(calls, ["destroy", "destroy", "destroy"])
        self.assertEqual(sleeper.call_count, 2)


if __name__ == "__main__":
    unittest.main()
