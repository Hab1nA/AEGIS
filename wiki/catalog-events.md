# 事件目录（catalog-events）

全部事件溯源事件。存储格式：SQLite 追加式事件流（[03](03-foundation.md)）；payload 均为 canonical JSON；`schema_version` 恒定首键（除标注）。流命名见各节。

## curriculum 主流（流 = `{campaign_id}`，registry.py:17-24）

| 事件 | payload 关键字段 |
|---|---|
| `constitution_recorded_v2` | constitution（含 protected_controls 7 项） |
| `objective_provisional_v2` | objective, status=provisional |
| `objective_probation_started_v2` | objective_id, effective_cycle, required_cycles, parent_objective_id |
| `objective_probation_observed_v2` | objective_id, snapshot_id, cycle_number, passed, evidence_id |
| `objective_activated_v2` | objective_id, previous_active_objective_id |
| `objective_rolled_back_v2` | objective_id, target_objective_id, reason |
| `curriculum_snapshot_recorded_v2` | snapshot, previous_cycle_state, cycle_state=created[, retry: true] |
| `cycle_state_changed_v2` | previous_state, action, state, resume_target, reason, evidence_id |

evidence_id 强制动作（17 个）：lock_cohort, collect_solutions, freeze_submission, record_judge_review, lock_quality, commit_curriculum_evidence, record_prosecutor_audit, record_independent_reflections, complete_council, lock_objective_governance, complete_task_forge, complete_task_validation, evaluate_candidates, lock_attribution, qualify_role_candidates, commit_activation_set, complete。

## 目标治理流（objectives.py:28-34，流内联于 campaign 主流或独立投影）

| 事件 | 要点 |
|---|---|
| `human_core_objective_recorded_v1` | 操作员内核（不可变） |
| `adaptive_objective_genesis_recorded_v1` | v1 自适应目标 |
| `adaptive_objective_amendment_proposed_v1` | 修正案（绑定同核 + 父血统） |
| `adaptive_objective_shadow_recorded_v1` | 影子证据（passed = quality∧integrity∧¬regression） |
| `adaptive_objective_amendment_decided_v1` | 仅 Prosecutor；effective=decided+1；3 影子门 |
| `adaptive_objective_probation_started_v1` | required_clean_cycles=2 |
| `adaptive_objective_probation_observed_v1` | outcome ∈ {continue, graduate, rollback} 必须匹配证据 |

## 动态任务流（dynamic_tasks/registry.py，哈希链 + 4 触发器）

| 事件 | payload | 转移 |
|---|---|---|
| `task_registered` | artifact_id, origin, creator_generation, source_spec_id, source_evidence_ids, eligible_generation, status, validation | → QUARANTINED / FIXED_ANCHOR / REJECTED |
| `holdout_recorded` | artifact_id, evaluated_generation, accepted, evidence_id | QUARANTINED → HOLDOUT_PASSED / REJECTED |
| `task_promoted_hof` | artifact_id | HOLDOUT_PASSED → HALL_OF_FAME |
| `task_retired` | artifact_id, reason ≤512 | HALL_OF_FAME → RETIRED |

## 周期阶段证据（cycle_runtime → CAS 工件，非事件流；transition 事件见上）

阶段 kind：submission, judge-review, quality-lock, judge-calibration, curriculum-evidence, prosecutor-audit, reflection:{role}, reflection-index, council, objective-governance, task-forge, task-validation, candidate-evaluation, attribution, qualification, activation, post-reflection:{role}, post-reflection-index, summary。
失败证据：`cycle-failure`（outcome_class/stage/error_type/error_message[:2000]）。

## 进化候选流（EvolutionRegistry，evolution/registry.py）

状态事件（registry.py:47-54 常量区）：候选 collected / validated / qualified / activated（`SURFACE_ACTIVATED`：candidate_id, surface, target_role, previous_champion_id, activation_evidence_id）/ rejected / superseded / revoked；每记录 CAS revision = 最近事件 hash。 probation 流 = `{campaign_id}/evolution-probation`：`evolution_probation_observed_v1` / `evolution_probation_breached_v1` / `evolution_probation_graduated_v1`（payload: candidate_id, surface, parent_candidate_id, cycle, delta）。

## 归因镜像（cycle_ports._append_arm）

- jsonl 账本 + `attribution-arm` CAS 工件 + 事件 `attribution_arm_recorded_v1`（流 `{campaign_id}/attribution`；payload: cycle, artifact 引用）。

## 策略流（strategy.py，_replay :479-619）

`strategy_initialized`、`strategy_candidate_created`、`strategy_experiment_started`、`strategy_experiment_observation`、`strategy_promoted` / `strategy_rejected`（别名 strategy_experiment_promoted/rejected）、`strategy_candidate_superseded`（仅 pending 且从未实验）、`strategy_rolled_back`（目标须历史 champion 且 source 为现任）。

## 角色流（roles/registry.py:19-24，流 `{campaign}:roles:v2`）

`role_candidate_collected_v2` / `role_candidate_validated_v2` / `role_candidate_qualified_v2` / `role_active_set_committed_v2`（CAS expected set） / `role_active_set_rolled_back_v2` / `role_objective_rebound_v2`。

## MCP 运行时流（mcp/registry.py:22-29，流 `{campaign}:mcp-runtime:v1`）

`mcp_candidate_recorded_v1`、`mcp_candidate_status_recorded_v1`（REJECTED/REVOKED 必带 reason）、`mcp_candidate_probation_started_v1`（required_observations 1..10000）、`mcp_candidate_probation_observed_v1`（一次失败即 REVOKED）、`mcp_registry_lease_acquired_v1` / `renewed_v1` / `released_v1`。

## 激活 saga 流（activation.py:14-19，流 `{campaign}:activation:v1`）

`activation_intent_recorded_v1` → `activation_harness_committed_v1` → `activation_role_committed_v1` → `activation_evolution_activated_v1` → `activation_mcp_activated_v1` → `activation_completed_v1`。schema legacy=1 / v2 / harness=3。次序约束在回放侧逐条复核（:376-417）。

## 修复流（repair_runtime.py:29-32，流 `repair:{incident_id}`）

`repair_runtime_started_v1`、`repair_runtime_step_intent_v1`、`repair_runtime_step_receipt_v1`、`repair_runtime_terminal_v1`。terminal 后封闭。

## 生成激活流（generation_activation.py:23-27，流 `activation:{activation_id}`）

`generation_activation_started_v1`、`generation_activation_boundary_intent_v1`、`generation_activation_boundary_receipt_v1`、`generation_activation_completed_v1`、`generation_activation_rolled_back_v1`。

## 运行时策略流（runtime_policy.py，经 EventStore CAS append）

`runtime_policy_genesis`、阶段修正案事件、`runtime_policy_immediate_amendment`（request_id/revision）、`runtime_policy_council_decided`（ratify/revise/rollback + replacement）、`runtime_policy_maintenance_armed`。

## 网关记账流（runtime_ledger.py:27-28，campaign 主流）

| 事件 | payload 要点 |
|---|---|
| `gateway_attempt_reserved` | attempt_id（内容地址）、AccountingContext 7 字段、policy_id、protocol、attempt_number、request_digest、conservative_usage（verified=False）、reserved_at |
| `gateway_attempt_settled` | 四元组定位唯一 reservation；GatewayAttemptResult（succeeded/usage/status/error_type）；runtime_seconds |

## 连接器（connectors/journal.py，SQLite 双表非事件流）

`connector_intents(request_id UNIQUE)` 与 `connector_receipts(request_id UNIQUE, intent_id)`；intent-first 幂等/冲突语义。

## 非事件流（单向审计 append）

- `attribution_arms.jsonl`（历史镜像）。
- sidecar 计量 `data/metering/gen-N.jsonl`（每请求一行，outcome/status/bytes）。
- probation 观察（上节）。
- knowledge / skill_registry：SQLite 哈希链事件（`knowledge` 触发器不可变；skill 事件 `candidate_registered` / `candidate_static_validated` / `candidate_promoted` / `champion_rolled_back` / `candidate_promoted_evaluated` / `candidate_revoked`，链哈希 `sha256(canonical_json({event_type, payload, previous_hash}))`）。
- dynamic_tasks 哈希链（同公式，见上）。
