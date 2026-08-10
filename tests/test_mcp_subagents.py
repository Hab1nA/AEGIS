from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from aegis.agent_runtime import ACTION_SCHEMA, Action, ToolDispatcher
from aegis.mcp import (
    McpBridge,
    McpBridgeError,
    McpServerManifest,
)
from aegis.models import Role
from aegis.sandbox.fake import FakeSandboxBackend
from aegis.subagents import (
    SubagentLimits,
    SubagentManager,
    SubagentRuntimeError,
    SubagentSpec,
)


class _McpHandler(BaseHTTPRequestHandler):
    tools: tuple[str, ...] = ("echo", "add")

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            request = json.loads(raw.decode("utf-8"))
            method = request.get("method")
            params = request.get("params", {})
            if method == "tools/list":
                result = {"tools": [{"name": name} for name in self.tools]}
            elif method == "tools/call":
                name = params.get("name")
                arguments = params.get("arguments", {})
                if name == "echo":
                    result = {"output": arguments}
                elif name == "add":
                    result = {"sum": int(arguments.get("a", 0)) + int(arguments.get("b", 0))}
                else:
                    result = {"error": f"unknown tool {name}"}
            else:
                result = {"error": f"unknown method {method}"}
            response = {"jsonrpc": "2.0", "id": request.get("id"), "result": result}
        except Exception as exc:  # pragma: no cover - protocol server test helper
            response = {"jsonrpc": "2.0", "id": None, "error": str(exc)}
        body = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:  # pragma: no cover
        pass


class _McpServerFixture:
    def __init__(self) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _McpHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def endpoint(self) -> str:
        host, port = self.server.server_address
        return f"http://127.0.0.1:{port}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class McpBridgeTests(unittest.TestCase):
    def test_deploy_and_call_through_real_http(self) -> None:
        fixture = _McpServerFixture()
        try:
            manifest = McpServerManifest.create(
                name="demo",
                endpoint=fixture.endpoint,
                tool_names=("echo", "add"),
                version="1.0",
                rationale="warrior-deployed test server",
            )
            bridge = McpBridge()
            receipt = bridge.deploy(manifest)
            self.assertEqual(receipt["name"], "demo")
            self.assertIn("echo", receipt["tools_available"])
            result = bridge.call("demo", "add", {"a": 2, "b": 3})
            self.assertEqual(result.get("sum"), 5)
            with self.assertRaises(McpBridgeError):
                bridge.call("demo", "undeclared", {})
        finally:
            fixture.close()

    def test_deploy_requires_live_tool_listing(self) -> None:
        manifest = McpServerManifest.create(
            name="missing",
            endpoint="https://example.invalid/mcp",
            tool_names=("echo",),
            version="1.0",
            rationale="probe",
        )
        bridge = McpBridge()
        with self.assertRaises(McpBridgeError):
            bridge.deploy(manifest)

    def test_manifest_endpoint_policy(self) -> None:
        with self.assertRaises(McpBridgeError):
            McpServerManifest.create(
                name="bad",
                endpoint="http://example.com/mcp",
                tool_names=("x",),
                version="1",
                rationale="r",
            )
        with self.assertRaises(McpBridgeError):
            McpServerManifest.create(
                name="bad",
                endpoint="https://user:pass@example.com/mcp",
                tool_names=("x",),
                version="1",
                rationale="r",
            )
        loopback = McpServerManifest.create(
            name="ok",
            endpoint="http://127.0.0.1:9999",
            tool_names=("x",),
            version="1",
            rationale="r",
        )
        self.assertEqual(loopback.name, "ok")


class SubagentTests(unittest.TestCase):
    def test_script_subagent_spawn_poll_reclaim(self) -> None:
        manager = SubagentManager(limits=SubagentLimits(max_steps=8, timeout_seconds=30))
        spec = SubagentSpec.create(
            role="warrior",
            objective="write a marker and return its digest",
            context={},
            executor="script",
            script=(
                "import hashlib, os\n"
                "work = os.environ['AEGIS_SUBAGENT_WORKDIR']\n"
                "open(os.path.join(work, 'marker.txt'), 'w').write('subagent')\n"
                "print('done')"
            ),
            input_refs=(),
            limits=SubagentLimits(max_steps=8, timeout_seconds=30),
        )
        handle = manager.spawn(spec)
        self.assertEqual(handle["status"], "running")
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if manager.status(spec.subagent_id)["status"] != "running":
                break
            time.sleep(0.05)
        result = manager.reclaim(spec.subagent_id, timeout_seconds=30)
        self.assertEqual(result["exit_code"], 0)
        self.assertIn("done", result["summary"])
        self.assertTrue(result["evidence_id"].startswith("subagent-result-sha256:"))

    def test_timeout_subagent_is_killed(self) -> None:
        manager = SubagentManager(limits=SubagentLimits(max_steps=8, timeout_seconds=2))
        spec = SubagentSpec.create(
            role="warrior",
            objective="sleep forever",
            context={},
            executor="script",
            script="import time; time.sleep(60)",
            input_refs=(),
            limits=SubagentLimits(max_steps=8, timeout_seconds=2),
        )
        manager.spawn(spec)
        result = manager.reclaim(spec.subagent_id, timeout_seconds=10)
        self.assertTrue(result["timed_out"])
        self.assertNotEqual(result["exit_code"], 0)

    def test_concurrency_limit(self) -> None:
        manager = SubagentManager(
            limits=SubagentLimits(max_steps=8, timeout_seconds=5),
            max_concurrency=1,
        )
        first = SubagentSpec.create(
            role="warrior",
            objective="sleep",
            context={},
            executor="script",
            script="import time; time.sleep(3)",
            input_refs=(),
            limits=SubagentLimits(max_steps=8, timeout_seconds=5),
        )
        second = SubagentSpec.create(
            role="warrior",
            objective="second",
            context={},
            executor="script",
            script="print('second')",
            input_refs=(),
            limits=SubagentLimits(max_steps=8, timeout_seconds=5),
        )
        manager.spawn(first)
        with self.assertRaises(SubagentRuntimeError):
            manager.spawn(second)
        manager.reclaim(first.subagent_id, timeout_seconds=10)

    def test_runtime_actions_wired(self) -> None:
        dispatcher = ToolDispatcher(
            FakeSandboxBackend(), None, "subagent-rt"
        )
        warrior = dispatcher.allowed_actions(Role.WARRIOR)
        for action in (
            "aegis.spawn_subagent",
            "aegis.reclaim_subagent",
            "aegis.subagent_status",
        ):
            self.assertIn(action, warrior)
            self.assertIn(action, ACTION_SCHEMA["properties"]["action"]["enum"])
        self.assertNotIn(
            "aegis.spawn_subagent",
            dispatcher.allowed_actions(Role.PROSECUTOR),
        )

    def test_dispatcher_spawn_reclaim_end_to_end(self) -> None:
        manager = SubagentManager(limits=SubagentLimits(max_steps=8, timeout_seconds=30))
        dispatcher = ToolDispatcher(
            FakeSandboxBackend(),
            None,
            "subagent-dispatch",
            subagent_manager=manager,
        )
        handle = dispatcher.dispatch(
            Role.WARRIOR,
            Action.parse(
                json.dumps(
                    {
                        "action": "aegis.spawn_subagent",
                        "arguments": {
                            "objective": "compute",
                            "context": {},
                            "executor": "script",
                            "script": "print(2 + 3)",
                        },
                    }
                )
            ),
        )
        self.assertEqual(handle["status"], "running")
        result = dispatcher.dispatch(
            Role.WARRIOR,
            Action.parse(
                json.dumps(
                    {
                        "action": "aegis.reclaim_subagent",
                        "arguments": {
                            "subagent_id": handle["subagent_id"],
                            "timeout_seconds": 30,
                        },
                    }
                )
            ),
        )
        self.assertEqual(result["exit_code"], 0)
        self.assertIn("5", result["summary"])

    def test_runtime_executor_fails_closed_without_gateway(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "AEGIS_OPENAI_API_KEY": "",
                "AEGIS_OPENAI_BASE_URL": "",
            },
            clear=False,
        ):
            manager2 = SubagentManager(
                limits=SubagentLimits(max_steps=8, timeout_seconds=30)
            )
            spec2 = SubagentSpec.create(
                role="warrior",
                objective="run as a real runtime subagent",
                context={},
                executor="runtime",
                script=None,
                input_refs=(),
                limits=SubagentLimits(max_steps=8, timeout_seconds=30),
                model="deepseek-v4-flash",
            )
            manager2.spawn(spec2)
            result2 = manager2.reclaim(spec2.subagent_id, timeout_seconds=30)
        self.assertEqual(result2["exit_code"], 1)
        error = str(result2["output"].get("error", ""))
        self.assertIn("gateway", error.lower())


if __name__ == "__main__":
    unittest.main()
