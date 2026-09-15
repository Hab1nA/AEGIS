# 18 恢复与激活

## 定位

三个持久化、可重放、崩溃安全的编排器：修复编排（`repair_runtime.py` + `cycle_recovery.py`）、激活 saga 日志（`activation.py`）、生成激活回滚（`generation_activation.py`）。共同模式：intent-first 事件、幂等 probe→act→receipt、terminal 后封闭。

## 修复编排（`repair_runtime.py`）

- 事件 4 个：`repair_runtime_started_v1/step_intent_v1/step_receipt_v1/terminal_v1`；流 `repair:{incident_id}`（:583-585）。
- 结构：`IncidentReport`（brick_kinds/suspected_cause ≤2000/falsifier/confidence）→ `RepairPlan`（disposition: RETRY_AFTER_FIX | ROLLBACK | QUARANTINE | PROSECUTOR 回滚）→ 步骤链。
- 步骤枚举（:363-371）：BUILTIN_PROSECUTOR_ROLLBACK / ROLLBACK / QUARANTINE / PROSECUTOR_PATCH / CREATE_CANDIDATE / PUBLISH_CANDIDATE / VALIDATE_CANDIDATE / ACTIVATE_CANDIDATE。
- `_expected_steps`（:988-1002）按 disposition 决定路径：PROSECUTOR 目标 → 仅内建回滚；ROLLBACK/QUARANTINE → 单步；RETRY_AFTER_FIX → 5 步链（patch→candidate→publish→validate→activate）；验证失败 → REJECTED。
- 重放完整性：序列连续、intent 不可改、步骤不越径、terminal 后封闭（:865-876, :949-953, :984-985）；`_external` 先查投影收据（幂等）→ reconcile → perform → 落收据（:838-855）。
- 六端口 Protocol（:484-532）：Prosecutor 补丁源 / 候选创建 / 发布 / 验证 / 激活 / 事件存储——依赖注入，测试可全 fake。
- 发布回退：未配置 public_repo_url 时用确定性 CAS 发布器（`cycle_recovery.py:117-146`，new_commit=`e`*40）——测试/无远端模式。
- Prosecutor 补丁解析（`patch_from_prosecutor_submission` :406-444）：changes 恰 3 键、路径唯一无穿越、`warrior/` 前缀禁禁忌名、其余走 harness 授权根。

## 激活 saga（`activation.py`）

- 事件 6 个：`activation_intent_recorded_v1` / `activation_role_committed_v1` / `activation_evolution_activated_v1` / `activation_mcp_activated_v1` / `activation_harness_committed_v1` / `activation_completed_v1`；schema legacy=1/v2/harness=3；隔离流 `{campaign}:activation:v1`（:46-47）。
- `ActivationIntent`：内容寻址；harness 候选与期望 champion 成对出现；兼容 pre-MCP 旧意图（:80-103）。
- **回执次序约束**：harness → role → evolution → mcp → complete（record_* 各自校验前序已落 :213-299）；`receipts_complete` 判定声明的每个部分都有回执（:142-150）。
- `ActivationReconciler.reconcile()`（:447-485）：对每个 pending 记录按序执行幂等 probe（已完成则跳过）→ act → 记录回执；崩溃后重放续跑。
- `commit_activation_set`（`cycle_ports.py:5757-5860`）构造 intent：多候选激活（harness 批量路径）为每个 extra 候选建独立 intent，每个用**新鲜的 expected active set**（sequential saga）。

## 生成激活回滚（`generation_activation.py`）

A/B 槽位激活的通用机制（角色生成级别的发布工程）：

- 固定 8 步流水线 `PIPELINE`（:173-182）：stage → event-replay → doctor → startup-smoke → shadow → canary → active-manifest-cas → probation；`fence`/`rollback` 为失败路径动作；`_BACKEND_ACTIONS` 由 SlotBackend 执行、其余由 HealthProbe 执行。
- `activate()`：重放投影 → 幂等 start → 依序执行；每步先 reconcile 再 perform；任一步失败进入 `_recover`。
- **失败闭环回滚**（:545-580）：health-snapshot → `detect_brick`；无 bricked+fence+automatic_rollback 证据 → `ActivationBlockedError`（fail-closed）；回滚 manifest = expected manifest 写回原 slot revision+1；落 `generation_activation_rolled_back_v1` 含 failed_action 与 brick_kinds。
- 回执校验：MANIFEST_CAS/ROLLBACK 回执的 manifest 必须等于 intent 的 desired_manifest（:582-592）。
- `ActivationRequest.target_slot` 必须异于当前激活 slot（:120-121）。

## cycle 级失败处理

- FAILED/ABORTED 可 retry（[07](07-cycle-state-machine.md)）；`evolution-cycle --run --repair` 驱动 RecoverySupervisor。
- boot 探针失败（WSL-first）：宿主自动 rollback champion 到 last_known_good 再抛错（`cli.py` 薄客户端）。
- Prosecutor 回滚令：`aegis.order_rollback` → `_execute_rollback_order` 按面分派——harness 走 git ref 回翻；workflow/subject/plugin/environment 翻注册表至父代并重物化 role manifest（回滚 = 重新激活上一 champion）；fail-closed（回滚目标必须等于当前 champion 才执行，`cycle_ports.py:4914-4960`）。

## 边界

- 激活的注册表副作用：roles registry（[13](13-roles-plugins-mcp.md)）、evolution registry（[08](08-candidate-lifecycle.md)）、MCP 租约注册表（[13](13-roles-plugins-mcp.md)）、harness agent（[05](05-harness-evolution.md)）。
- 修复链的 Git 发布边界在 [15](15-research.md) §publisher。
