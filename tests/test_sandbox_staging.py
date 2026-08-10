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

from aegis.sandbox import FakeSandboxBackend, WslSandboxBackend
from tests.test_sandbox_agent import AgentFixture


def archive(entries: dict[str, bytes], *, symlink: tuple[str, str] | None = None) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as tar:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        if symlink:
            info = tarfile.TarInfo(symlink[0])
            info.type = tarfile.SYMTYPE
            info.linkname = symlink[1]
            tar.addfile(info)
    return output.getvalue()


class SandboxStagingTests(unittest.TestCase):
    def test_fake_stages_verifies_hash_and_refuses_writes_after_freeze(self) -> None:
        backend = FakeSandboxBackend()
        backend.prepare("task")
        payload = archive({"answer.py": b"print(42)\n"})
        digest = hashlib.sha256(payload).hexdigest()
        receipt = backend.stage_archive("task", base64.b64encode(payload).decode(), digest)
        self.assertEqual((receipt.digest, receipt.entries), (digest, 1))
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            backend.stage_archive("task", base64.b64encode(payload).decode(), "0" * 64)
        frozen = backend.freeze("task")
        with self.assertRaisesRegex(RuntimeError, "not runnable"):
            backend.stage_archive("task", base64.b64encode(payload).decode(), digest)
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "export.tar"
            exported = backend.export("task", destination)
            self.assertEqual(exported.digest, frozen.digest)
            self.assertEqual(hashlib.sha256(destination.read_bytes()).hexdigest(), frozen.digest)

    def test_agent_rejects_traversal_links_and_existing_paths(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temp,
            patch("aegis.sandbox.agent.shutil.which", return_value="/usr/bin/podman"),
        ):
            fixture = AgentFixture(Path(temp))
            fixture.agent.prepare("task")
            for payload in (
                archive({"../escape": b"x"}),
                archive({}, symlink=("link", "/etc/passwd")),
            ):
                with self.assertRaisesRegex(ValueError, "unsafe|unsupported"):
                    fixture.agent.stage_archive(
                        "task", base64.b64encode(payload).decode(), hashlib.sha256(payload).hexdigest()
                    )
            valid = archive({"safe/file.py": b"x"})
            encoded = base64.b64encode(valid).decode()
            digest = hashlib.sha256(valid).hexdigest()
            fixture.agent.stage_archive("task", encoded, digest)
            with self.assertRaisesRegex(RuntimeError, "overwrite"):
                fixture.agent.stage_archive("task", encoded, digest)
            fixture.agent.freeze("task")
            with self.assertRaisesRegex(RuntimeError, "not active"):
                fixture.agent.stage_archive("task", encoded, digest)

    def test_wsl_contract_prevalidates_and_verifies_agent_receipt(self) -> None:
        payload = archive({"main.py": b"pass\n"})
        digest = hashlib.sha256(payload).hexdigest()
        operations: list[str] = []

        def runner(argv: list[str], stdin: str, timeout: float) -> subprocess.CompletedProcess[str]:
            request = json.loads(stdin)
            operations.append(request["operation"])
            if request["operation"] == "doctor":
                checks = [
                    {"name": name, "passed": True}
                    for name in __import__("aegis.sandbox.wsl", fromlist=["REQUIRED_CHECKS"]).REQUIRED_CHECKS
                ]
                response = {"ok": True, "checks": checks}
            else:
                response = {
                    "ok": True,
                    "staged": {"sha256": digest, "size_bytes": len(payload), "entries": 1},
                }
            return subprocess.CompletedProcess(argv, 0, json.dumps(response), "")

        backend = WslSandboxBackend(runner=runner)
        self.assertTrue(backend.doctor().passed)
        receipt = backend.stage_archive("task", base64.b64encode(payload).decode(), digest)
        self.assertEqual(receipt.digest, digest)
        self.assertEqual(operations, ["doctor", "stage_archive"])


if __name__ == "__main__":
    unittest.main()
