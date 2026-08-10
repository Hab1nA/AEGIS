"""Sealed Python black-box evaluation protocol.

The trusted controller retains assertions.  The untrusted worker receives only
one action scenario and has no mount, module, argv or environment reference to
the sealed suite.
"""

from __future__ import annotations

import io
import json
import tarfile
from typing import Any, Mapping

MAX_SEALED_SUITE_BYTES = 1024 * 1024
MAX_WORKER_OUTPUT_BYTES = 64 * 1024
MAX_CASES = 128


# Kept dependency-free because it is passed to ``python -c`` in the pinned OCI
# image.  It deliberately contains no assertion logic or expected values.
WORKER_SOURCE = r"""
import builtins, importlib, json, math, os, sys, tempfile, threading
from decimal import Decimal
from pathlib import Path

objects = {}
fixtures = {}
temps = []
sys.path.insert(0, "/workspace")

def decode(v):
    if isinstance(v, list): return [decode(x) for x in v]
    if not isinstance(v, dict): return v
    if "$ref" in v: return objects[v["$ref"]]
    if "$iterator" in v: return iter(decode(v["$iterator"]))
    if "$tempdir" in v:
        name=v["$tempdir"]
        if name not in fixtures:
            t=tempfile.TemporaryDirectory(); temps.append(t); fixtures[name]={"kind":"tempdir","value":t.name}
        return fixtures[name]["value"]
    if "$fixture" in v:
        kind=v["$fixture"]; name=v["name"]
        if name not in fixtures:
            if kind == "clock": fixtures[name]={"kind":kind,"value":decode(v.get("value",0))}
            elif kind in {"raiser","flaky"}:
                fixtures[name]={"kind":kind,"count":0,"exception":v["exception"],
                                "failures":v.get("failures",0),"value":decode(v.get("value"))}
            else: raise ValueError("unsupported fixture")
        state=fixtures[name]
        if kind == "clock": return lambda: state["value"]
        def raiser():
            state["count"] += 1
            if kind == "flaky" and state["count"] > state["failures"]: return state["value"]
            raise getattr(builtins, state["exception"])()
        return raiser
    if v.get("$type") == "nan": return float("nan")
    if v.get("$type") == "decimal": return Decimal(v["value"])
    if v.get("$type") == "exception": return getattr(builtins, v["name"])
    return {k:decode(x) for k,x in v.items()}

def encode(v):
    if v is None or isinstance(v,(bool,int,str)): return v
    if isinstance(v,float): return {"$type":"nan"} if math.isnan(v) else v
    if isinstance(v,Decimal): return {"$type":"decimal","value":str(v)}
    if isinstance(v,Path): return {"$type":"path","value":str(v)}
    if isinstance(v,(list,tuple)): return [encode(x) for x in v]
    if isinstance(v,dict): return {str(k):encode(x) for k,x in v.items()}
    raise TypeError("unsupported result type")

def fixture_state():
    return {k:({"count":v["count"]} if v["kind"] in {"raiser","flaky"} else {"value":encode(v["value"])})
            for k,v in fixtures.items()}

def invoke(fn,args,kwargs,materialize):
    value=fn(*args,**kwargs)
    return list(value) if materialize else value

def run_step(step):
    op=step["op"]
    if op == "set_fixture":
        fixtures[step["name"]]["value"]=decode(step["value"]); return None, [], {}
    if op == "construct":
        args=decode(step.get("args",[])); kwargs=decode(step.get("kwargs",{}))
        objects[step["save"]]=getattr(importlib.import_module(step.get("module","solution")),step["symbol"])(*args,**kwargs)
        return None,args,kwargs
    if op in {"call","method"}:
        args=decode(step.get("args",[])); kwargs=decode(step.get("kwargs",{}))
        fn=(getattr(importlib.import_module(step.get("module","solution")),step["symbol"])
            if op=="call" else getattr(objects[step["object"]],step["method"]))
        return invoke(fn,args,kwargs,bool(step.get("materialize",False))),args,kwargs
    if op == "parallel_method":
        obj=objects[step["object"]]; method=step["method"]; workers=step["workers"]; repeat=step["repeat"]
        args=decode(step.get("args",[])); errors=[]
        def target():
            try:
                for _ in range(repeat): getattr(obj,method)(*args)
            except BaseException as exc: errors.append(type(exc).__name__)
        threads=[threading.Thread(target=target) for _ in range(workers)]
        [t.start() for t in threads]; [t.join() for t in threads]
        if errors: raise RuntimeError("parallel worker failed: "+errors[0])
        return None,args,{}
    if op == "mutate":
        target=objects[step["object"]]
        for part in step.get("path",[]): target=target[part]
        target.append(decode(step["value"])); return None,[],{}
    if op == "snapshot": return objects[step["object"]],[],{}
    raise ValueError("unsupported operation")

def evaluate(request):
    importlib.import_module("solution")
    results=[]
    for step in request["steps"]:
        try:
            value,args,kwargs=run_step(step)
            if "save_result" in step: objects[step["save_result"]]=value
            if "save_args" in step: objects[step["save_args"]]=args
            item={"ok":True,"value":encode(value),"fixtures":fixture_state()}
            if step.get("capture_args"): item["args_after"]=encode(args); item["kwargs_after"]=encode(kwargs)
        except BaseException as exc:
            item={"ok":False,"exception":type(exc).__name__,"fixtures":fixture_state()}
        results.append(item)
    return json.dumps({"results":results},sort_keys=True,separators=(",",":"))

request=json.loads(sys.stdin.read())
if hasattr(os,"fork"):
    read_fd,write_fd=os.pipe()
    child=os.fork()
    if child == 0:
        os.close(read_fd)
        null_fd=os.open("/dev/null",os.O_WRONLY)
        os.dup2(null_fd,1); os.dup2(null_fd,2); os.close(null_fd)
        try:
            payload=evaluate(request).encode("utf-8")
            if len(payload) <= 65536: os.write(write_fd,payload)
        finally:
            os.close(write_fd)
        os._exit(0)
    os.close(write_fd)
    chunks=[]; size=0
    while True:
        block=os.read(read_fd,8192)
        if not block: break
        size += len(block)
        if size > 65536: break
        chunks.append(block)
    os.close(read_fd)
    _,status=os.waitpid(child,0)
    payload=b"".join(chunks)
    if status != 0 or not payload or size > 65536:
        sys.stdout.write(json.dumps({"worker_error":"submission child did not return a valid result"}))
    else:
        sys.stdout.buffer.write(payload)
else:
    # Repository fixture verification on Windows only. Production is the
    # fail-closed WSL/Linux sandbox and always uses the forked boundary above.
    sys.stdout.write(evaluate(request))
"""


def load_sealed_cases(archive: bytes) -> tuple[Mapping[str, Any], ...]:
    """Load the sole declarative cases.json member; executable hidden files fail closed."""
    if len(archive) > MAX_SEALED_SUITE_BYTES:
        raise ValueError("sealed suite is too large")
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:*") as bundle:
        members = [member for member in bundle.getmembers() if member.isfile()]
        if len(members) != 1 or members[0].name not in {"cases.json", "tests/hidden/cases.json"}:
            raise ValueError("sealed suite v1 must contain only cases.json")
        source = bundle.extractfile(members[0])
        if source is None:
            raise ValueError("sealed cases cannot be read")
        raw = json.loads(source.read(MAX_SEALED_SUITE_BYTES + 1))
    if not isinstance(raw, dict) or set(raw) != {"version", "cases"} or raw["version"] != 1:
        raise ValueError("invalid sealed suite version")
    cases = raw["cases"]
    if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
        raise ValueError("sealed suite must contain 1..128 cases")
    for case in cases:
        if not isinstance(case, dict) or set(case) != {"name", "steps"}:
            raise ValueError("invalid sealed case")
        if not isinstance(case["name"], str) or not case["name"] or len(case["name"]) > 128:
            raise ValueError("invalid sealed case name")
        steps = case["steps"]
        if not isinstance(steps, list) or not 1 <= len(steps) <= 128:
            raise ValueError("sealed case must contain steps")
        for step in steps:
            _validate_step(step)
    return tuple(cases)


def worker_scenario(case: Mapping[str, Any]) -> dict[str, Any]:
    """Remove every assertion field before crossing into the worker."""
    return {
        "steps": [
            {
                key: value
                for key, value in step.items()
                if key not in {"expect", "raises", "expect_args", "expect_kwargs", "expect_fixtures"}
            }
            for step in case["steps"]
        ]
    }


def check_worker_result(case: Mapping[str, Any], raw: object) -> tuple[bool, str]:
    if not isinstance(raw, dict) or set(raw) != {"results"} or not isinstance(raw["results"], list):
        return False, "invalid worker result"
    results = raw["results"]
    if len(results) != len(case["steps"]):
        return False, "worker result count mismatch"
    for index, (step, result) in enumerate(zip(case["steps"], results, strict=True)):
        if not isinstance(result, dict) or not isinstance(result.get("ok"), bool):
            return False, f"step {index} returned an invalid result"
        if "raises" in step:
            if result.get("ok") is not False or result.get("exception") != step["raises"]:
                return False, f"step {index} expected {step['raises']}"
        elif result.get("ok") is not True:
            return False, f"step {index} raised {result.get('exception', 'unknown')}"
        elif "expect" in step and not _matches_expected(step["expect"], result.get("value")):
            return False, f"step {index} value mismatch"
        for expected_key, actual_key in (
            ("expect_args", "args_after"),
            ("expect_kwargs", "kwargs_after"),
            ("expect_fixtures", "fixtures"),
        ):
            if expected_key in step and result.get(actual_key) != step[expected_key]:
                return False, f"step {index} {actual_key} mismatch"
    return True, ""


def _matches_expected(expected: object, actual: object) -> bool:
    if isinstance(expected, dict) and expected.get("$type") == "path_suffix":
        if not isinstance(actual, dict) or actual.get("$type") != "path":
            return False
        value = actual.get("value")
        suffix = expected.get("value")
        return (
            isinstance(value, str) and isinstance(suffix, str) and value.replace("\\", "/").endswith(suffix)
        )
    return actual == expected


def _validate_step(step: object) -> None:
    if not isinstance(step, dict) or not isinstance(step.get("op"), str):
        raise ValueError("sealed step must be an object with op")
    allowed = {
        "op",
        "module",
        "symbol",
        "args",
        "kwargs",
        "save",
        "object",
        "method",
        "name",
        "value",
        "workers",
        "repeat",
        "path",
        "materialize",
        "save_result",
        "save_args",
        "capture_args",
        "expect",
        "raises",
        "expect_args",
        "expect_kwargs",
        "expect_fixtures",
    }
    if set(step) - allowed:
        raise ValueError("sealed step contains unknown fields")
    encoded = json.dumps(step, separators=(",", ":"))
    if len(encoded) > 64 * 1024:
        raise ValueError("sealed step is too large")
    if step["op"] not in {
        "call",
        "construct",
        "method",
        "set_fixture",
        "parallel_method",
        "mutate",
        "snapshot",
    }:
        raise ValueError("unsupported sealed operation")
