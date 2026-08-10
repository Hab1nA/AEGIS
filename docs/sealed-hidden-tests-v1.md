# Sealed task tests v1

Production scoring tests are declarative black-box scenarios, not Python test
modules. Both `public/` and `hidden/` require a `cases.json` archive member:

```json
{"version":1,"cases":[{"name":"edge","steps":[
  {"op":"call","symbol":"clamp","args":[1,2,0],"raises":"ValueError"}
]}]}
```

`public/test_*.py` may remain as Warrior-facing development feedback, but those
files are never used for scoring. `public/cases.json` is explicitly excluded
from the Warrior archive, just like the hidden suite.

The trusted WSL sandbox agent parses each cases document and retains `expect`,
`raises`, `expect_args`, `expect_kwargs`, and `expect_fixtures`. It sends a
submission worker only the operation, symbol, arguments, and fixture actions
needed for one black-box scenario. Legacy executable hidden suites (including
`test_*.py`) fail closed.

Supported v1 operations are `call`, `construct`, `method`, `set_fixture`,
`parallel_method`, `mutate`, and `snapshot`. Tagged values cover iterators,
NaN, decimals, exception classes, temporary directories, saved objects,
deterministic clocks, and deterministic raising callbacks. Unknown fields,
operations, archive members, oversized documents, and empty suites are rejected.

## Isolation boundary

- The worker harness forks before importing the submission, redirects the
  submission child's stdout/stderr to `/dev/null`, and receives structured
  results over a bounded private pipe. Consequently `print()` plus `os._exit()`
  cannot forge the harness result; premature exit produces a failed case.
- The worker runs in the pinned rootless Podman image with no network, no
  capabilities, a read-only root filesystem, resource limits, and the frozen
  submission mounted read-only at `/workspace`.
- `cases.json`, case names, assertions, expected values, and failure details are
  never mounted, imported, placed in worker argv/environment, or sent on stdin.
- The worker uses a generic harness. Consequently submission code cannot recover
  hidden source through filesystem traversal, `sys.modules`, `inspect`/frames,
  argv, or environment variables. It observes only ordinary black-box calls and
  their inputs.
- Worker stdout/stderr is untrusted: execution is time-bounded, process capture
  has a hard 1 MiB ceiling, the sealed protocol accepts at most 64 KiB per
  stream, and JSON shape/counts are validated before comparison.
- Public and hidden sealed cases run against a frozen artifact in a fresh judge
  sandbox. The post-run namespace comparison uses the union of paths, so edits,
  deletions, and newly created files all trip the non-compensable tamper gate.
- No pytest output, exit summary, cache, or node id participates in production
  scoring. The controller consumes only the typed `SealedEvaluationResult`.

After controller restart, `attach_warrior_workspace(task, sandbox_id)` restores
the task/seed ownership mapping without restaging. It revalidates the sealed pack
identity and content hash, is idempotent for the same mapping, and refuses a
conflicting sandbox. Artifact export and digest verification remain mandatory at
evaluation time.

This boundary does not prevent an implementation from hard-coding answers for
black-box inputs it happens to recognize. Task diversity, hidden case rotation,
paired seeds, and mutation validation address that testing limitation. It also
assumes the WSL agent, pinned image, task-pack publisher, and controller host are
trusted; compromise of those components is outside the submission sandbox
threat model.
