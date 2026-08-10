# AEGIS

AEGIS is a supervised adversarial software-engineering loop. A Warrior researches and implements a task, a Judge challenges the frozen result, and a Prosecutor audits both roles and their verified token efficiency. Lifecycle, budgets, hidden tests, scoring, and promotion remain deterministic control-plane decisions.

Role strategy proposals are evaluated automatically with a sealed 12-task by 2-seed paired experiment. Candidate and champion arms run independently through the real sandboxed role loop, hidden-test quality lock, and verified relay usage accounting. The campaign stops safely with the candidate still pending when its remaining budget cannot fund the next pair.

## Install and test

Requires Python 3.12+, a dedicated WSL2 distribution, rootless Podman, and an OpenAI-compatible relay.

```powershell
python -m pip install -e ".[dev]"
python -m unittest discover -s tests -v
```

Set secrets only in the host process; they are never copied into WSL:

```powershell
$env:AEGIS_OPENAI_API_KEY = "..."
$env:AEGIS_OPENAI_BASE_URL = "https://relay.example/v1"
$env:AEGIS_OPENAI_PROTOCOL = "auto"
$env:AEGIS_SEARCH_BASE_URL = "http://127.0.0.1:8888"
$env:AEGIS_ALLOW_INSECURE_SEARCH_LOOPBACK = "true"
$env:AEGIS_HTTPS_PROXY = "http://127.0.0.1:7897"
$env:AEGIS_DATA_DIR = "$env:LOCALAPPDATA\AEGIS"
```

The relay must use HTTPS. For local relay development only, loopback HTTP can be enabled explicitly with
`AEGIS_ALLOW_INSECURE_LOOPBACK=true`. Research likewise fails closed when
`AEGIS_SEARCH_BASE_URL` is absent. The supplied local SearxNG deployment is the only supported HTTP
research exception: it additionally requires `AEGIS_ALLOW_INSECURE_SEARCH_LOOPBACK=true` and accepts only
literal `127.0.0.1`/`::1` on port 8888. Public result retrieval remains pinned HTTPS.
When direct public HTTPS is unreliable, `AEGIS_HTTPS_PROXY` may opt into an unauthenticated local HTTP
CONNECT proxy. Only literal `127.0.0.1` or `::1` URLs with an explicit port are accepted. The controller
still resolves and approves each public destination address itself, tunnels that exact address rather than
the hostname, and verifies the destination TLS hostname after CONNECT; generic proxy environment variables
are ignored.
`AEGIS_OPENAI_PROTOCOL` defaults to `auto` (Responses first, then Chat capability fallback). Set it to
`chat` or `responses` when the relay contract is known, which avoids repeated endpoint probes and their
conservative token reservations on every new controller process.

## First safe run

1. Copy `configs/campaign.example.json`, replace every task-pack path with an absolute local path, and select exact relay model IDs.
2. Render the dedicated WSL installation bundle without changing the host:

   ```powershell
   aegis sandbox-bootstrap --image registry.example/aegis@sha256:<64-hex-digest>
   ```

3. Follow [the WSL runbook](docs/wsl-runbook.md), then require `aegis doctor` to pass. The repository-owned
   task image and local research-service assets are under `deploy/wsl/`.
4. Create the campaign, run the full-autonomy gate, then start only after every check passes:

   ```powershell
   aegis campaign-create configs/campaign.local.json
   aegis autonomy-local-acceptance
   aegis autonomy-preflight first-campaign
   aegis start first-campaign
   aegis status first-campaign
   aegis report first-campaign --format markdown
   ```

`autonomy-preflight` performs three explicit external probes: it asks the configured Warrior model to return
only `{"action":"submit","arguments":{"summary":"AEGIS_OK","payload":{}}}` under the production JSON
action schema, searches only `Python software engineering testing`, and fetches only
`https://example.com/`. It does not send repository files, task contents, hidden tests, campaign events, or
stored research. The same command also validates all 12 sealed task packs and the complete evolution
workspace read-only/write-overlay boundary in WSL/Podman. `start` and `resume` repeat this fail-closed gate.
Model requests default to a 900-second timeout. `AEGIS_OPENAI_TIMEOUT_SECONDS` may override it explicitly.
Each role may also set optional `reasoning_effort` to `none`, `low`, `medium`, or `high`; omit it for
relay-default behavior. The checked-in production DeepSeek smoke profiles use `high` with `16384` output
tokens. The older local profile remains deliberately low-cost and is not evidence for a full-autonomy run.

`autonomy-local-acceptance` never uses the network or starts a campaign. It stages a sanitized repository
context snapshot into disposable WSL/Podman sandboxes, runs the candidate validation suite, proves that a malicious
validation command cannot overwrite `src/aegis/orchestrator.py`, executes the fixed workflow canary, checks
that the host snapshot is unchanged, and destroys every sandbox. Taskpack prompts, manifests, and public tests
remain visible; `hidden`, `reference`, `defect`, `mutants`, and `*.validation.json` held-out assets are excluded.
The same exclusion is a fail-closed `evolution_held_out_assets_excluded` preflight check.

Before the formal campaign, use the dedicated two-round acceptance profile in an isolated state directory:

```powershell
$smokeData = "$env:LOCALAPPDATA\AEGIS-smoke-20260806"
aegis --data-dir $smokeData campaign-create configs/autonomy-smoke.example.json
aegis --data-dir $smokeData autonomy-preflight autonomy-smoke-v2
aegis --data-dir $smokeData start autonomy-smoke-v2
aegis --data-dir $smokeData autonomy-smoke-verify autonomy-smoke-v2
```

This profile forces exact-commit GitHub and declarative Skill collection, verified knowledge persistence, a
bounded Strategy candidate, and an exact DOI/arXiv paper excerpt before a dual-source code-evolution request.
Candidate generation must write an evolvable file before submission. The verifier requires the complete
12-by-2 code-candidate promotion evidence and proves that both ordinary second-round Warrior phases consumed
the promoted champion before deriving its successor. The dedicated profile reserves 800 requests and an
14-million-token per-dimension ceiling with 55/22.5/22.5 role shares. These are capacity limits, not prepaid
usage, and cover the 221-call shortest evidence chain plus three relay attempts with a bounded 16-KiB prompt
reserve. Skill and Strategy candidates
remain pending in this dedicated profile; ordinary campaigns still run their automatic
promotion schedulers. Run these network/API-consuming commands only with operator authorization. The isolated
`--data-dir` prevents the smoke registry, knowledge, skills, events, and champion from touching
`first-campaign`.

`pause` is durably recorded immediately. An in-flight gateway or promotion call is allowed to finish, but no next model request starts; resume replays only the incomplete phase from its durable checkpoint, so completed research, model work, freezing, hidden evaluation, and promotion are not charged or executed twice. `retry` is narrower: after full preflight it can reopen only a Warrior research or execution failure caused by `StepLimitExceeded`; the failed attempt and its budget remain in the event stream, and a cleaned workspace is recreated before the incomplete role phase is rerun. Integrity, sandbox, control, and all other failures remain terminal. A kernel-released per-campaign execution lock prevents a second CLI from resuming a controller that is still alive while allowing takeover after process death. `stop` synchronously saves an aborted state and destroys every campaign-owned sandbox; `kill` synchronously invokes the sandbox kill path and persists the result even when no controller process is running. Cleanup commands deliberately do not require gateway credentials, task-pack loading, or a passing sandbox doctor. The CLI refuses fake/test-mode campaigns for `start`. Offline research is allowed only in explicit test or demo configuration.

## Safety boundary

WSL2 is not a perfect security boundary: processes normally have the host user's authority when Windows integration is available. AEGIS therefore requires a dedicated distribution with Windows mounts and interop disabled, a rootless offline task container, and a separately mounted 64 MiB loopback ext4 workspace. Generated task code must never run on the Windows host. See [architecture](docs/architecture.md), [threat model](docs/threat-model.md), [task-pack authoring](docs/taskpack-authoring.md), and the [sealed hidden-test contract](docs/sealed-hidden-tests-v1.md).
