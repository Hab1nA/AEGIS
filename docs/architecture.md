# AEGIS v2 architecture

## Control plane

The append-only `EventStore` is the source of truth. `CurriculumRegistry` and
`RoleRegistry` persist content-addressed objectives, constitutions, role
candidates, active sets, and cycle transitions; `ContentAddressedArtifactStore`
holds every evidence artifact (submission, judge review, quality lock,
prosecutor audit, council, task forge, validation, attribution, qualification,
activation).

`EvolutionCycleController` runs one generation: Warrior solve, Judge review,
deterministic quality lock, Prosecutor audit, three role reflections, council
deliberation, Judge task forge, trusted task validation/registration,
attribution, role-candidate qualification, and activation-set commit. Every
stage is durable before the next starts; `record_snapshot` is idempotent for
retries, and a failed/interrupted cycle can `retry` the same generation.

Between task validation and attribution the controller runs a
`candidate-evaluation` stage (`CANDIDATES_EVALUATED` state): it consumes every
evolution proposal from the cycle evidence, materializes it into the
content-addressed store, runs one same-cohort paired shadow arm for the
Warrior-target candidate, attributes the difference, and — when qualified —
qualifies and activates the candidate before the activation-set commit.

## Evolvable surfaces and candidates

`src/aegis/evolution/surfaces.py` defines the explicit contract. Each surface
has a strict JSON shape and a grant rule:

| surface | proposal rule | artifact kind |
|---|---|---|
| workflow | Warrior proposes; may target the proposer | `workflow` |
| subject | Warrior proposes; targets the Warrior | `subject` |
| plugin | Warrior proposes; targets the Warrior; sandbox-executed ABI only (no EXTERNAL) | `plugin` |
| environment | Warrior proposes; targets the Warrior; offline or brokered-public recipe | `environment` |

`EvolutionRegistry` persists the candidate lifecycle on the
`{campaign}:evolution:v2` event stream: `collected -> validated ->
qualified -> active`, with per-surface champions, parent lineage, rollback,
and a materialized-build attachment for environment receipts (the original
recipe stays the candidate identity; consumers resolve the built receipt
first). `cycle_ports.evaluate_candidates` rejects candidates whose surface is
enabled but has no runtime support, and rejects environment candidates whose
build or scan fails closed.

## Runtime binding of the active role set

`src/aegis/evolution/runtime.py` binds every active role to real runtime
inputs. Each role resolves a `CompositeRoleManifest` (schema v2) containing
`model_profile_sha256`, `workflow_artifact_id`, `subject_artifact_id`,
`plugin_artifact_ids`, `runtime_image`, and `budget_policy_sha256`. Legacy
genesis identities without a valid manifest fall back to defaults. The cycle
injects the resolved workflow/subject into the role prompt envelope, mounts
plugins through `SandboxPluginExecutor`, and prepares each sandbox with the
resolved runtime image.

## Environment builder

`src/aegis/evolution/env_builder.py` assembles the production builder over the
WSL agent: `QuarantineDownloadBroker` (research-transport fetch with per-hop
validation), `WslAgentOCIBuilder` (two independent offline Podman builds whose
image/SBOM digests must match), `TrivyScanner`, and
`CasEnvironmentArtifactStore`. `EnvironmentBuilder.build` publishes the intent,
receipt, provenance, scan, and an `environment` receipt artifact carrying the
digest-pinned `output_image`. The cycle builds environment candidates before
their shadow arm, materializes the receipt on the candidate, and activation
pins `runtime_image` so later generations prepare sandboxes with the built
image. Locally built images are resolved by their image id digest inside the
sandbox (`prepare` falls back from `repository@sha256:` to `sha256:`), and
`scan_image` accepts both reference forms.

## Role runtime

All three roles execute through `RoleAgentRuntime` and `ToolDispatcher`: the
model emits exactly one JSON action per turn, token usage is verified and
recorded, and sandbox actions stay inside a prepared WSL/Podman container with
per-role prepare/destroy and unique sandbox ids. Prosecutor and Judge contexts
are redacted (private reasoning and raw tool output replaced by digests).
Every model request is JSON-constrained — the gateway has only two modes
(`responses` and `chat_json_object`) with no plain-output or `json_schema`
path; chat payloads send `response_format: {"type":"json_object"}` and
responses payloads send the equivalent `text.format`. The gateway detects
relay-side truncation (`finish_reason: length`, or empty content with an
exhausted completion budget — common for hidden-reasoning models) and raises
`GatewayTruncationError`, which the runtime turns into an actionable
`model.response` rejection with usage accounting instead of a blind JSON parse
failure.

## Dynamic task bank

`DynamicTaskRegistry` is a hash-chained SQLite ledger. `GenesisSeeder` registers
the 12 built-in packs as `FIXED_ANCHOR` only on an empty bank. `TaskForge`
validates Judge-supplied archives (reference passes, defect/mutants killed) and
registers dynamic tasks as quarantined until their holdout delay elapses;
`select_dynamic_cohort` prefers eligible dynamic tasks and falls back to anchors
only when none exist.

## Trusted external writes

External writes go through the plugin broker: `aegis.git_checkpoint` is an
`EXTERNAL` action pinned to the Warrior generation, journaled intent-first by
`SqliteConnectorJournal`, and executed by `GitCheckpointConnector` over
`GitPublisher` (isolated clone, exact-base CAS, role path grants, secret scan,
create-only candidate refs). Remote credentials stay in the publisher
environment.

## Repair and retry

On cycle failure, `run_v2_cycle` records the original error, asks the Prosecutor
for a bounded patch (≤10 steps), then runs `RecoverySupervisor`: publish →
validate → activate the repaired role version, or roll back to
last-known-good. A control-plane `retry` transition returns a failed or
interrupted cycle to `created` for the same generation.

## CLI

`aegis evolution-cycle` (dry-run / run / repair), `campaign-create`, `doctor`,
`sandbox-bootstrap`, `autonomy-preflight` (v2 gates), `knowledge-search`,
`status`, `report`, and `replay`.
