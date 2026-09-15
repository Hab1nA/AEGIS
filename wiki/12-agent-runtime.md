# 12 角色运行时

## 定位

`agent_runtime.py`（3.5K 行）是三个不可信模型角色的确定性工具循环：模型每步提出一个 JSON action，本模块验证并执行；模型文本绝不解释为主机命令，workspace 内容绝不跨主机边界（:1-6）。

## JSON 动作解析（`Action.parse` :139-177）

1. `json.loads`；失败则 `raw_decode` 抽取首个平衡 JSON 对象（中继在动作前叙述散文的情形）；
2. 必须 dict 且含 `"action"`；
3. 含 `"arguments"` → 嵌套形式，顶层多余键视为中继评论丢弃；
4. 无 `"arguments"` → 扁平形式，其余键全部作为参数；
5. 每个动作仍走精确参数校验器（`_exact` :1161-1165）。

## 每角色允许动作（`_PERMISSIONS` :204-282）

- **Warrior**（28 项）：研究组（search/fetch/import/recall/artifact_read、github.*/paper.*）、skill.list/stage、**evolution.request / aegis.propose_harness_change / aegis.deploy_mcp / aegis.mcp_call / aegis.deploy_dependency**、**aegis.spawn_subagent / reclaim / status**、workspace.read/write、sandbox.exec、strategy.propose、knowledge.search/remember、submit。
- **Judge**（19 项）：challenge.propose + 研究组 + skill + workspace.read + sandbox.exec + strategy.propose + knowledge + submit（无进化/子代理/MCP/写盘）。
- **Prosecutor**（18 项）：研究组 + skill.list + **aegis.order_rollback / aegis.adjust_runtime_policy** + workspace.read + strategy.propose + knowledge + submit（只读，无 sandbox.exec/write）。

插件效果天花板（`_PLUGIN_EFFECT_CEILINGS` :284-288）：Warrior=全部 EffectClass；Judge/Prosecutor={PURE, WORKSPACE_READ}。

## 运行时限制

- `RuntimeLimits` 默认（:113-136）：max_steps=20、read/write=256KiB、tool_output=512KiB、argv≤64 项、单参 ≤16KiB、timeout ≤300s、search ≤20。
- 固定安全界（:89-97）：角色级 steps ≤128、read/write ≤4MiB、tool_output ≤8MiB、search ≤200、research 动作预算 100 万（不再是可调预算参数）。
- 运行时策略可调：`role_max_steps`、`role_command_timeout_seconds`、`role_max_output_tokens`、`role_reasoning_effort`（`_refresh_policy` :3018-3050）。

## 请求信封（`_request` :3251-3451）

缓存友好布局（静态前置、动态置尾）：protocol_version / role / objective / context / required_action_groups / step / max_steps / 研究预算 / submission_deadline / observations（历史瘦身：content_base64 以 `omitted_from_history+encoded_characters` 代替 :3138-3153）/ 协议字段（`_ROLE_PROTOCOL_FIELDS` :294-464 按角色相关性裁剪 + 嵌套子动作按当前 allowed 过滤）/ active_runtime_policy_values / plugin_action_schemas / **workflow/subject 注入**（advisory guidance 语义，:3343-3353）。

system prompt（:3383-3426）：单 JSON 动作契约、不可改权限/测试/生命周期/晋升、仅 Prosecutor 可调 `aegis.adjust_runtime_policy`（可调参数白名单）。`output_schema` 的 action enum 收窄为当前 allowed_actions（:3444-3450）。

`_sanitize_context`（:3457-3467）：非 Warrior 的 context 删除含 reasoning/thought 的键与 {analysis, scratchpad, rationale}。

## 收敛控制

- `required_action_groups`：submit 前必须有全部成功观察（:2970-2987）；`eager_required_convergence`（完成后仅允许 submit）与 `ordered_required_action_gate`（聚焦 missing[0]）两模式（`_convergence_actions` :3173-3216）。
- 剩余步 ≤ missing+reserve 或研究预算吃紧 → 强制聚焦；`reserve = min(3, max_steps//4)`。
- 策略上限：strategy 提案 ≤8/去重、进化组 4 动作共享 `max_evolution_requests_per_run`、rollback 同限（:2875-2969）。

## 拒绝反馈与恢复

- 解析失败/动作不可用 → 拒绝观察附 `rejected_text[:400]` 供模型自纠（:2767-2783）。
- 兜底恢复链（:3079-3124）：`_trusted_next_action`（唯一可用动作且历史收据匹配）→ `_forced_submit_action`（deadline 到）→ 标记 `argument_recovery=deterministic_forced_submit`。
- `GatewayTruncationError` → 显式可行动观察（"只返回紧凑完整 JSON action"，:2714-2741）；usage 即使被拒也记账（:2742-2745）。
- 动作级恢复（`_FAILED_ACTION_RECOVERY` :101-110）：github.collect 失败 → 恢复 search/resolve/collect。
- 超步未提交 → `StepLimitExceeded` 附 trace `step:action:ok|rejected(...)`（:3126-3136）——E2E 诊断的关键证据。

## 关键动作语义

- `evolution.request` / `aegis.propose_harness_change`：走 `validate_evolution_proposal` / `validate_harness_code_content`（[04](04-evolution-surfaces.md)）；proposals 进收集。
- `aegis.adjust_runtime_policy`：patch 与 rollback_target 互斥必居一（:2010-2011）；参数白名单见 [17](17-runtime-policy.md)。
- `aegis.deploy_dependency`：digest-pinned 依赖 + ≤32 构建步 → environment 候选（:2115-2194）。
- `aegis.spawn_subagent`：策略键 subagent_max_*；会计绑定经 env 传递（[13](13-roles-plugins-mcp.md)）。
- submit：summary ≤16384；payload 含 strategy_proposals 即拒（策略走专道，:2493-2494）。

## 边界

- gateway 见 [14](14-gateway-accounting.md)；工具执行见 [13](13-roles-plugins-mcp.md)（broker）/ [16](16-sandbox.md)（沙盒）/ [15](15-research.md)（研究）。
- 一次性进化信封协议 schema：`EVOLUTION_PROTOCOL_SCHEMA`（surfaces.py:714-723）。
