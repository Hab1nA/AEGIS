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

## Role runtime

All three roles execute through `RoleAgentRuntime` and `ToolDispatcher`: the
model emits exactly one JSON action per turn, token usage is verified and
recorded, and sandbox actions stay inside a prepared WSL/Podman container with
per-role prepare/destroy and unique sandbox ids. Prosecutor and Judge contexts
are redacted (private reasoning and raw tool output replaced by digests).

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
