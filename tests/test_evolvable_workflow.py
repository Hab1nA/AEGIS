from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from aegis.evolvable.workflow import build_workflow
from aegis.strategy import WorkflowArtifact


class EvolvableWorkflowContractTests(unittest.TestCase):
    def test_default_entrypoint_returns_strict_workflow_for_every_role(self) -> None:
        for role in ("warrior", "judge", "prosecutor"):
            with self.subTest(role=role):
                workflow = WorkflowArtifact.from_json(dict(build_workflow(role, {"task": "bounded"})))
                self.assertLessEqual(workflow.max_steps or 0, 20)
                self.assertTrue(workflow.verification_checklist)

    def test_invalid_role_and_context_fail_closed(self) -> None:
        with self.assertRaises(ValueError):
            build_workflow("administrator", {})
        with self.assertRaises(TypeError):
            build_workflow("warrior", [])  # type: ignore[arg-type]

    def test_module_cli_preserves_workflow_abi(self) -> None:
        environment = os.environ.copy()
        source_root = str(Path(__file__).resolve().parents[1] / "src")
        inherited_path = environment.get("PYTHONPATH")
        environment["PYTHONPATH"] = (
            source_root if not inherited_path else source_root + os.pathsep + inherited_path
        )
        result = subprocess.run(
            [sys.executable, "-B", "-m", "aegis.evolvable.workflow", "--role", "warrior"],
            input=b'{"task":"bounded"}',
            capture_output=True,
            check=False,
            env=environment,
        )

        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", errors="replace"))
        workflow = WorkflowArtifact.from_json(json.loads(result.stdout.decode("utf-8")))
        self.assertLessEqual(workflow.max_steps or 0, 20)


if __name__ == "__main__":
    unittest.main()
