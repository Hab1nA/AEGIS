from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

from aegis.sandbox.sealed import WORKER_SOURCE, check_worker_result, worker_scenario
from aegis.taskpacks.builtin import load_builtin_python_taskpacks
from aegis.taskpacks.manifest import TaskPack, compute_tree_hash
from aegis.taskpacks.validation import ExecutionResult, validate_taskpack

_RAN = re.compile(r"Ran (\d+) tests?")


class RepositoryFixtureRunner:
    """Host runner restricted to the repository-owned inert test fixtures."""

    def __init__(self, fixture_root: Path) -> None:
        self.fixture_root = fixture_root.resolve()

    def run(self, pack: TaskPack, implementation_dir: str, suite: str) -> ExecutionResult:
        implementation = pack.path(implementation_dir)
        tests = pack.public_path if suite == "public" else pack.hidden_path
        for candidate in (pack.root, implementation, tests):
            resolved = candidate.resolve()
            if resolved != self.fixture_root and self.fixture_root not in resolved.parents:
                raise AssertionError("host runner refused a non-fixture path")
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PYTHONPATH"] = str(implementation)
        if suite in {"public", "hidden"}:
            document = json.loads((tests / "cases.json").read_text(encoding="utf-8"))
            failures = []
            worker = WORKER_SOURCE.replace('"/workspace"', repr(str(implementation)))
            for case in document["cases"]:
                completed = subprocess.run(
                    [sys.executable, "-B", "-I", "-c", worker],
                    cwd=implementation,
                    input=json.dumps(worker_scenario(case)),
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                try:
                    decoded = json.loads(completed.stdout) if completed.returncode == 0 else None
                except json.JSONDecodeError:
                    decoded = None
                ok, reason = check_worker_result(case, decoded)
                if not ok:
                    failures.append(f"{case['name']}: {reason}")
            return ExecutionResult(
                passed=not failures,
                tests_run=len(document["cases"]),
                exit_code=0 if not failures else 1,
                output_digest="; ".join(failures),
            )
        completed = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", str(tests), "-p", "test_*.py"],
            cwd=implementation,
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        output = completed.stdout + completed.stderr
        match = _RAN.search(output)
        return ExecutionResult(
            passed=completed.returncode == 0,
            tests_run=int(match.group(1)) if match else 0,
            exit_code=completed.returncode,
            output_digest=output[-1000:],
        )


class BuiltinTaskPackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Path(__file__).resolve().parents[1] / "taskpacks" / "python"
        cls.packs = load_builtin_python_taskpacks(cls.root)

    def test_exactly_twelve_unique_integrity_checked_packs(self) -> None:
        self.assertEqual(len(self.packs), 12)
        identities = {(pack.manifest.task_id, pack.manifest.version) for pack in self.packs}
        self.assertEqual(len(identities), 12)
        self.assertEqual(
            {path for path in self.root.iterdir() if path.is_dir()},
            {pack.root for pack in self.packs},
        )
        for pack in self.packs:
            self.assertEqual(
                pack.manifest.content_hash,
                compute_tree_hash(pack.root, exclude=frozenset({"manifest.json"})),
            )

    def test_layout_and_prompts_are_complete(self) -> None:
        for pack in self.packs:
            with self.subTest(task=pack.manifest.task_id):
                pack.verify_layout()
                prompt = pack.root / "prompt.md"
                self.assertTrue(prompt.is_file())
                text = prompt.read_text(encoding="utf-8").strip()
                self.assertGreaterEqual(len(text), 80)
                self.assertIn("solution.py", text)
                self.assertGreaterEqual(len(pack.manifest.mutant_dirs), 1)
                self.assertTrue(any(pack.public_path.glob("test_*.py")))
                self.assertTrue((pack.public_path / "cases.json").is_file())
                self.assertEqual([path.name for path in pack.hidden_path.iterdir()], ["cases.json"])
                public_text = "\n".join(
                    path.read_text(encoding="utf-8") for path in pack.public_path.glob("*.py")
                )
                self.assertNotIn("hidden", public_text.lower())
                self.assertNotIn("mutant", public_text.lower())

    def test_repository_fixtures_have_effective_suites(self) -> None:
        runner = RepositoryFixtureRunner(self.root)
        for pack in self.packs:
            with self.subTest(task=pack.manifest.task_id):
                report = validate_taskpack(pack, runner)
                self.assertTrue(report.valid, "; ".join(report.reasons))
                self.assertTrue(report.reference_public.passed, report.reference_public.output_digest)
                self.assertTrue(report.reference_hidden.passed, report.reference_hidden.output_digest)
                self.assertTrue(
                    not report.defect_public.passed or not report.defect_hidden.passed,
                    "defect unexpectedly survived both suites",
                )
                self.assertTrue(all(not result.passed for result in report.mutant_hidden))
                evidence_path = self.root / f"{pack.root.name}.validation.json"
                evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
                self.assertEqual(evidence["content_hash"], pack.manifest.content_hash)
                self.assertTrue(evidence["valid"])
                self.assertEqual(evidence["reasons"], [])
                names = ("reference_public", "reference_hidden", "defect_public", "defect_hidden")
                for name in names:
                    sealed = evidence[name]
                    live = getattr(report, name)
                    self.assertEqual((sealed["passed"], sealed["tests_run"]), (live.passed, live.tests_run))
                self.assertEqual(
                    [(item["passed"], item["tests_run"]) for item in evidence["mutant_hidden"]],
                    [(item.passed, item.tests_run) for item in report.mutant_hidden],
                )


if __name__ == "__main__":
    unittest.main()
