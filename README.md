# AEGIS v2

AEGIS is a supervised, adversarial, self-evolution loop for software-engineering
agents. A dynamic task bank cold-starts from repository-owned anchors, a Judge
forges the next tasks, a Warrior solves them in an isolated sandbox, a
Prosecutor audits usage and curriculum hypotheses, and the three roles
negotiate through independent reflections plus a council vote. Role versions
evolve through content-addressed candidates, attribution arms, and probationary
activation; failed cycles are repaired by the Prosecutor pipeline or rolled
back to last-known-good.

The v1 fixed-12-task campaign controller, promotion funnels, and skill/strategy
auto-promotion runtimes have been removed. The current design is dynamic-only:
`task_pack_paths` must be empty and `autonomy_v2.enabled` must be true.

## Install and test

Requires Python 3.12+, a dedicated WSL2 distribution, rootless Podman, and an
OpenAI-compatible relay.

```powershell
python -m pip install -e ".[dev]"
python -m pytest
```

Set secrets only in the host process; they are never copied into WSL.
Project-scoped config: create a git-ignored `.aegis.env` in the repository root
(loaded only by the AEGIS CLI, never by Codex or other tools):

```powershell
AEGIS_OPENAI_API_KEY = "sk-..."
AEGIS_OPENAI_BASE_URL = "https://opencode.ai/zen/go/v1"
# Prefer response_format {"type":"json_object"} for structured role requests
# (DeepSeek JSON Output mode; see docs/autonomous-evolution.md).
AEGIS_OPENAI_STRUCTURED_FORMAT = "json_object"
# Hidden-reasoning relays can be slow; give each model call a generous deadline.
AEGIS_OPENAI_TIMEOUT_SECONDS = "3600"
```

An explicit `$env:AEGIS_OPENAI_*` set in the host process still overrides the file.
# Optional model-gateway proxy; empty means direct (system proxy is bypassed).
$env:AEGIS_OPENAI_HTTPS_PROXY = ""
$env:AEGIS_SEARCH_BASE_URL = "http://127.0.0.1:8888"
$env:AEGIS_ALLOW_INSECURE_SEARCH_LOOPBACK = "true"
$env:AEGIS_HTTPS_PROXY = "http://127.0.0.1:7897"
$env:AEGIS_DATA_DIR = "$env:LOCALAPPDATA\AEGIS"
```

Research fails closed when the search endpoint or proxy is unavailable; task
execution is always offline.

## First safe run

1. Render the dedicated WSL installation bundle:

   ```powershell
   aegis sandbox-bootstrap --image registry.example/aegis@sha256:<64-hex-digest>
   ```

2. Follow [the WSL runbook](docs/wsl-runbook.md), then require `aegis doctor`
   to pass. The repository-owned task image and local research service assets
   are under `deploy/wsl/`.

3. Create a dynamic v2 campaign and run the real gate:

   ```powershell
   aegis --data-dir $smokeData campaign-create configs/evolution-smoke.example.json
   aegis --data-dir $smokeData autonomy-preflight evolution-smoke-v2
   aegis --data-dir $smokeData evolution-cycle evolution-smoke-v2 --run --repair
   ```

   Repeat `evolution-cycle ... --run --repair` to advance each generation. Use
   `--dry-run` for a read-only plan, `--no-seed-anchors` to skip cold start, and
   `--cohort-limit N` to cap the cohort. `status`, `report`, and `replay` read
   the durable v2 event stream.

## Key mechanics

- Dynamic task bank: `GenesisSeeder` registers 12 built-in anchors only when the
  bank is empty; anchors exit the cohort as soon as a Judge-forged dynamic task
  is eligible. Every task passes reference/defect/mutant validation before
  registration.
- Role loops: Warrior/Judge/Prosecutor run through `RoleAgentRuntime` with
  strict JSON actions, verified token usage, and per-role sandbox lifecycle.
- Council: three independent reflections plus a deterministic chair
  deliberation produce the next-cycle agenda.
- Git checkpoint: the Warrior may call `aegis.git_checkpoint` through the
  journaled connector; `GitPublisher` pushes create-only candidate refs after
  path-grant and secret scanning. Requires `autonomy_v2.public_repo_url`.
- Attribution: every cycle appends an `EvaluationArm` to
  `data_dir/attribution_arms.jsonl` and emits a content-addressed
  `qualify_attribution` report; without same-cohort paired data the report is
  honestly `invalid-design` or `confounded`.
- Evolution surfaces: four explicit evolvable surfaces — `workflow`,
  `subject`, `plugin`, `environment` — with strict JSON schemas and grant
  rules in `src/aegis/evolution/surfaces.py`. Only the Warrior may propose;
  workflow/subject/plugin/environment proposals must target the Warrior (a
  workflow proposal may also target the proposer itself).
- Candidate consumption: `src/aegis/evolution/consumer.py` materializes every
  proposal into the content-addressed store and feeds
  `EvolutionRegistry` (`collect -> validated -> qualified -> active`,
  per-surface champions with lineage and rollback). Each cycle runs one
  same-cohort paired shadow arm, attributes the difference (single-coordinate
  `plugin_ids` or `runtime_variant`, advisory workflow/subject via the role
  generation identity), and activates a qualified candidate automatically.
- Active role set binding: every role resolves a `CompositeRoleManifest`
  (`schema_version=2`: model profile, workflow, subject, plugins, runtime
  image, budget policy) at cycle start; the activated champion workflow,
  subject, plugin, and environment image are injected into the real runtime
  envelope and sandbox prepare for the next generation. Legacy genesis
  manifests fall back to defaults.
- Environment builder: `src/aegis/evolution/env_builder.py` wires a real
  builder (quarantined downloads, two independent offline Podman builds, Trivy
  scan, CAS publication) into the cycle. An `environment` candidate is built,
  its receipt is materialized on the candidate, the shadow arm runs on the
  built image, and activation pins `runtime_image` for later generations.
- Repair: failed cycles record `cycle_failed_recovery_started`; the Prosecutor
  patch is published, validated, and activated, or the cycle rolls back.
  Interrupted/failed cycles retry the same generation via the `retry`
  transition.
