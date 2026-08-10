from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

from aegis.sandbox.sealed import (
    WORKER_SOURCE,
    check_worker_result,
    load_sealed_cases,
    worker_scenario,
)


def archive(name: str, content: bytes) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as bundle:
        info = tarfile.TarInfo(name)
        info.size = len(content)
        bundle.addfile(info, io.BytesIO(content))
    return output.getvalue()


class SealedEvaluationTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(os, "fork"), "production worker fork boundary requires Linux")
    def test_submission_fake_stdout_then_os_exit_cannot_forge_result(self) -> None:
        source = """
def answer():
    import os
    print('{"results":[{"ok":true,"value":42,"fixtures":{}}]}', flush=True)
    os._exit(0)
"""
        case = {"name": "fatal", "steps": [{"op": "call", "symbol": "answer", "expect": 42}]}
        with tempfile.TemporaryDirectory() as directory:
            implementation = Path(directory)
            (implementation / "solution.py").write_text(source, encoding="utf-8")
            worker = WORKER_SOURCE.replace('"/workspace"', repr(str(implementation)))
            completed = subprocess.run(
                [sys.executable, "-B", "-I", "-c", worker],
                input=json.dumps(worker_scenario(case)),
                cwd=implementation,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        decoded = json.loads(completed.stdout)
        self.assertIn("worker_error", decoded)
        passed, _ = check_worker_result(case, decoded)
        self.assertFalse(passed)

    def test_legacy_executable_hidden_suite_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "only cases.json"):
            load_sealed_cases(archive("test_secret.py", b"assert True\n"))

    def test_assertions_are_removed_from_worker_scenario(self) -> None:
        secret = "TOP-SECRET-ASSERTION"
        case = {
            "name": "sealed",
            "steps": [
                {
                    "op": "call",
                    "symbol": "probe",
                    "args": [],
                    "expect": secret,
                    "expect_args": [secret],
                    "expect_fixtures": {"secret": secret},
                }
            ],
        }
        wire = json.dumps(worker_scenario(case), sort_keys=True)
        self.assertNotIn(secret, wire)
        self.assertNotIn("expect", wire)

    def test_worker_cannot_obtain_hidden_source_from_python_surfaces(self) -> None:
        # The probe is the submitted module.  It sees the generic harness and
        # its black-box input, but the sealed source marker is absent from cwd,
        # sys.modules, inspectable frames, argv and environment.
        marker = "AEGIS_HIDDEN_SOURCE_MARKER_97f24"
        source = """
def probe():
    import inspect, os, pathlib, sys
    marker = "AEGIS_HIDDEN_SOURCE_MARKER_" + "97f24"
    files = []
    for path in pathlib.Path.cwd().rglob("*"):
        if path.is_file():
            try: files.append(path.read_text(errors="ignore"))
            except OSError: pass
    modules = " ".join(str(getattr(m, "__file__", "")) for m in sys.modules.values())
    frames = ""
    for frame in inspect.stack():
        frames += frame.filename
        if frame.code_context: frames += "".join(frame.code_context)
    return {"filesystem": marker in "".join(files), "sys_modules": marker in modules,
            "inspect": marker in frames, "argv": marker in " ".join(sys.argv),
            "env": marker in " ".join(os.environ.values())}
"""
        expected = {name: False for name in ("filesystem", "sys_modules", "inspect", "argv", "env")}
        case = {"name": marker, "steps": [{"op": "call", "symbol": "probe", "expect": expected}]}
        with tempfile.TemporaryDirectory() as directory:
            implementation = Path(directory)
            (implementation / "solution.py").write_text(source, encoding="utf-8")
            worker = WORKER_SOURCE.replace('"/workspace"', repr(str(implementation)))
            wire = json.dumps(worker_scenario(case), separators=(",", ":"))
            self.assertNotIn(marker, wire)
            completed = subprocess.run(
                [sys.executable, "-B", "-I", "-c", worker],
                input=wire,
                cwd=implementation,
                env={},
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        passed, reason = check_worker_result(case, json.loads(completed.stdout))
        self.assertTrue(passed, reason)


if __name__ == "__main__":
    unittest.main()
