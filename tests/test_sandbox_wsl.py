from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from aegis.sandbox.wsl import _default_runner


class DefaultRunnerEncodingTests(unittest.TestCase):
    """Regression: _default_runner must not crash on non-host-codepage bytes."""

    def test_runner_survives_non_utf8_output(self) -> None:
        """The runner must not raise UnicodeDecodeError when the subprocess
        emits bytes that are not valid in the host locale encoding."""
        # Emit raw bytes 0xFF 0xFE which are invalid UTF-8 and invalid GBK.
        command = [
            "python",
            "-c",
            "import sys; sys.stdout.buffer.write(b'\\xff\\xfe\\x80\\x81')",
        ]
        result = _default_runner(command, stdin="", timeout=10)
        # Must not raise; invalid bytes are replaced with U+FFFD.
        self.assertEqual(result.returncode, 0)
        self.assertIn("\ufffd", result.stdout)

    def test_runner_uses_utf8_encoding(self) -> None:
        """The runner must decode subprocess output as UTF-8, not locale default."""
        command = [
            "python",
            "-c",
            "import sys; sys.stdout.buffer.write('日本語'.encode('utf-8'))",
        ]
        result = _default_runner(command, stdin="", timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "日本語")

    def test_runner_stderr_also_uses_utf8_with_replace(self) -> None:
        """stderr must also be decoded as utf-8 with replacement, not crash."""
        command = [
            "python",
            "-c",
            "import sys; sys.stderr.buffer.write(b'\\xff\\xfe')",
        ]
        result = _default_runner(command, stdin="", timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertIn("\ufffd", result.stderr)

    def test_runner_normal_json_roundtrip(self) -> None:
        """Sanity: the runner can carry a normal JSON doctor payload."""
        payload = json.dumps({"ok": True, "checks": []})
        command = ["python", "-c", f"print({payload!r})"]
        result = _default_runner(command, stdin="", timeout=10)
        self.assertEqual(result.returncode, 0)
        decoded = json.loads(result.stdout.strip())
        self.assertTrue(decoded["ok"])

    def test_timeout_does_not_wait_for_descendant_holding_output_handles(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pid_path = Path(directory) / "child.pid"
            child_script = (
                "import os,sys,time; "
                "open(sys.argv[1], 'w').write(str(os.getpid())); "
                "time.sleep(10)"
            )
            parent_script = (
                "import subprocess,sys,time; "
                f"subprocess.Popen([sys.executable, '-c', {child_script!r}, sys.argv[1]]); "
                "time.sleep(10)"
            )
            started = time.monotonic()
            try:
                with self.assertRaises(subprocess.TimeoutExpired):
                    _default_runner(
                        [sys.executable, "-c", parent_script, str(pid_path)],
                        stdin="",
                        timeout=0.2,
                    )
                self.assertLess(time.monotonic() - started, 2.0)
            finally:
                if pid_path.exists():
                    child_pid = int(pid_path.read_text(encoding="utf-8"))
                    try:
                        os.kill(child_pid, signal.SIGTERM)
                    except (OSError, ProcessLookupError):
                        pass

    def test_runner_times_out_when_child_never_reads_large_stdin(self) -> None:
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            _default_runner(
                [sys.executable, "-c", "import time; time.sleep(10)"],
                stdin="x" * (200 * 1024),
                timeout=0.5,
            )
        self.assertLess(time.monotonic() - started, 5.0)


if __name__ == "__main__":
    unittest.main()
