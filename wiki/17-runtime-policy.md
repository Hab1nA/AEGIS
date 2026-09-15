# 17 运行时策略

## 定位

`runtime_policy.py`（2.1K 行）：事件溯源、可重放的运行期自治预算与流程参数。**Prosecutor 独享修正权**（ council 可追认）；宿主隔离与资源安全字段刻意不在 schema 内，任何修正案不能削弱 Windows/WSL 安全边界（:1-6）。

## 双 schema

- v1（legacy）：`_LEGACY_POLICY_FIELDS_V1`（:51-60），含已废弃的 max_cost_usd/max_steps 等。
- **v2（现行）**：`_POLICY_FIELDS_V2`（:109-114）= 成本信封 4 项（max_total_tokens / max_requests / max_model_invocations / max_active_runtime_seconds）+ 角色级（role_max_steps / role_max_output_tokens / role_research_action_budgets / role_max_read_bytes / role_max_write_bytes / role_max_tool_output_bytes / role_max_search_results / role_command_timeout_seconds / role_token_shares / role_reasoning_effort）+ 整数限额（gateway/subagent/candidate/cohort/council/holdout/依赖下载/population/sandbox 资源）+ 数值限额（各 timeout）。
- 严格字段集：多键/缺键即错；未知键若含宿主安全词（`_HOST_SAFETY_TERMS` :135-150：windows/wsl/host/safety/interop/drvfs/mount/broker 等）报"不可变"，否则报"不支持"。
- **角色字段的生效范围**：仅 `role_max_steps` / `role_max_output_tokens` /
  `role_command_timeout_seconds` 是活预算参数；其余 role_* 字段（read/write/tool_output/
  search/research_action_budgets）校验并存储但运行时钉回 FIXED 安全常量（`agent_runtime._refresh_policy` 注释），且被排除在修正案白名单外——对它们的修正案会无效。`role_token_shares` 与 `role_reasoning_effort` 为惰性 legacy 值（:474-476 注释；reasoning 由网关钉死，见 [14](14-gateway-accounting.md)）。
- v1→v2 一次性迁移：语义保持校验（`_v2_matches_v1`）+ CAS 持久化（:851-905）。

## 流程界限（`FLOW_FIELD_BOUNDS` :122-136）

Prosecutor 即时修正案可动的有界参数（公开名，config 与提示词共用派生）：

| 字段 | 界限 |
|---|---|
| cohort_limit | [1,12] |
| task_authoring_attempts | [1,4] |
| task_proposals_per_cycle | [1,8] |
| candidate_max_steps | [4,128] |
| council_max_messages | [2,64] |
| objective_history_window | [1,5] |
| candidate_evaluations_per_cycle | [0,4] |
| max_evolution_requests_per_run | [1,4] |
| sandbox_cpus / sandbox_memory_gib / sandbox_pids | [1,8] / [1,8] / [64,1024] |

界限在**修正案**层强制；genesis 默认由操作者全权，且操作者可通过 campaign config
`autonomy_v2.runtime_flow_parameters`（`config.py` `_FLOW_PRESET_FIELDS`）在**相同界限内**
预设其中 8 个无专属 campaign 字段的流程参数（candidate_max_steps/council_max_messages/
objective_history_window 已有专属字段，不在预设集内）；缺席名字保持内置 genesis 默认
（`cycle_ports._runtime_policy_genesis_values` 读取）。资源信封语义：默认 1 CPU/1GiB/256
pids；检察官可在界内上调——资源上限不是隔离完整性（成本信封本就可调），隔离由容器 flags
与冻结面保证（[16](16-sandbox.md)）。

## 修正案三通道

1. **即时修正案**（`request_patch_immediately` :1146-1209）：Prosecutor 在任意阶段边界经 `aegis.adjust_runtime_policy` 发起，**当步生效**；patch ∈ 成本信封 ∪ 流程界限；request_id 幂等/冲突；`base_policy_id` 陈旧即拒；空 patch 拒。council 追认（`record_council_decision` :1036-1084：ratify/revise/rollback，revise 必须指向更晚因果修订）。
2. **阶段修正案**（`request_patch_after_stage` :1304-1345）：下一阶段边界生效（direct successor 校验 :703-709）；v1 字段集。
3. **回滚修正案**（`request_rollback_immediately` / `request_rollback_after_stage`）：目标 policy 必须 v2 已知。

全部修正案事件落 CAS + EventStore；`ImmediateRuntimePolicyAmendment` 携带 evidence_refs。

## 版本解析

- `effective_for_cycle` / `effective_for_stage` / `latest_for_cycle`（:910-1024）：按 (cycle, ordinal, revision) 三元组取最新；maintenance armed 策略参与排序。
- `resume_stage_boundary`：崩溃恢复后取严格大于全部已持久化活动的边界（:1260-1279）。

## 维护模式（`arm_maintenance` :1086-1144）

消耗超限时冻结当前 values 并记录已消耗 usage（`consumed`）→ `maintenance_only=True`：运行时账本切到维护授权（仅 Prosecutor，[14](14-gateway-accounting.md)），直到 Prosecutor 补偿性修正案恢复可行预算。

## 消费记账（`_validate_consumed` :355-377）

cumulative 量 + role_tokens；有限非负。`maintenance_reasons` 由"consumed > limit"推导并强制一致（:470-497, :517-527）。

## 与 agent 协议的接口

`aegis.adjust_runtime_policy` 参数白名单：cost envelope 4 项 + `FLOW_FIELD_BOUNDS` 全部
11 个流程参数——system prompt 内的清单由 `_ADJUSTABLE_FLOW_PARAM_NAMES` 从
`FLOW_FIELD_BOUNDS` **派生**（`agent_runtime.py`），不再硬编码，杜绝再次漂移。信封携带
`runtime_policy_id` + consumed（Prosecutor 正确复制 base_policy_id 的前提，5b.3）。

## 边界

- 账本消费授权见 [14](14-gateway-accounting.md)；genesis 构造在 `cycle_ports._runtime_policy_genesis_values`（新字段加入 schema 时必须同步 genesis 默认值——strict 字段集）。
- paired-design 冻结：影子评测按 design_id 冻结 policy（评测中修正案不影响在评设计）。
