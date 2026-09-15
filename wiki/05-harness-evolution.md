# 05 Harness 代码进化

## 定位

harness-code 是最深的一层进化：Warrior 提交真实代码补丁，通过验证后补丁成为**下一代实际运行的系统代码**。全链：`checkpoint → validate → canary → (资格) → activate → (回滚)`，分布在发行版 harness agent（固定）、进化注册表、周期控制面三处。

## 信任模型：整树即运行树 + frozen 字节比对

WSL-first 下 champion worktree 的**全部**代码（含冻结文件）就是下一代运行的代码。冻结面的保证来自 harness agent 的独立信任锚——`_validate_frozen_paths`（`wsl_harness_agent.py`，`_validate_tree` 内调用）：

- 对 candidate/champion/回滚目标树与 campaign 钉住的 `source_ref` 执行 `git diff --name-only`；
- **每一条变更路径**必须通过 `validate_harness_path`（[04](04-evolution-surfaces.md)）——即变更只能落在允许根（或 meta 授权的 meta 根），冻结根/秘密/越树路径一律拒绝；
- `source_ref` 存于 `state.json`（campaign 创建时钉住，`_campaign_source_ref` 读取）；meta 标志在 checkpoint 时持久化到 `candidates/<token>.json`，validate/activate/rollback 复读同一标志——候选不能在链路中途切换 meta 语义。

结构校验 `_validate_tree`：禁 symlink/submodule、秘密路径/内容、单文件 ≤4MiB / 总量 ≤128MiB（`_MAX_FILE_BYTES`/`_MAX_TOTAL_BYTES` :47-48）。旧 campaign 无 source_ref 时 diff 检查自动跳过（向后兼容）。

## 全链六步

### 1. checkpoint（`wsl_harness_agent._checkpoint`）

- 请求：candidate_id、base_commit（必须等于当前 champion，:240-241）、changes（1..128 项）、meta_evolution_enabled。
- champion worktree 上开 detach worktree → 应用变更 → 提交（固定身份 `AEGIS Warrior <aegis@invalid>`）→ `_validate_tree` + frozen diff → 写 `refs/aegis/candidates/<token>`（CAS update-ref）。
- 幂等：candidate ref 已存在则校验树一致直接返回。

### 2. validate（`_validate`）

- candidate ref == candidate_commit；树 + frozen diff 重验；candidate 必须基于当前 champion（`_is_ancestor`）。

### 3. canary（`_canary`，2026-09-15 新增）

双臂因果评测（取代旧的"双臂同绑定"伪影臂）：

- **测试选择**：显式 `canary_command`（≤8 项短字符串）原样使用；否则按变更路径映射 `CANARY_ROOT_TESTS`（`harness.py:614-631`，如 `gateway/` → test_gateway_client.py；`evolution/` → 5 个进化测试），默认含 `tests/test_evolution_surfaces.py`，上限 `MAX_CANARY_TESTS`=6（:632-633）。
- **双臂执行**：champion worktree 与 candidate worktree 各跑 `compileall src/aegis`（≤120s）+ pytest 子集（默认 300s ≤3600s），`PYTHONPATH=<worktree>/src`，cwd=worktree（`_run_canary_arm`）。
- **判定**（`cycle_ports._evaluate_harness_candidate`）：baseline 失败 → 拒（"拒绝在未知地面上资格认定"）；candidate 失败 → 拒（零回归门槛）。
- 结果打包进 receipt detail（canonical JSON ≤4096B：baseline/candidate_arm/tests）。
- 固定 agent 跑测试——champion 代码永远不能选或跑自己的考卷。

### 4. 资格（durable qualification）

- 评测阶段：harness 候选**前置于** cohort 门 early-return（Fresh holdout 供给不卡 harness 面），产出 `harness_qualification_pending` + `harness_worktree`（candidate_commit/champion_commit/evidence_id）。
- durable 阶段（`cycle_ports._qualify_harness_candidate`）：注册表 VALIDATED→QUALIFIED（evidence=金丝雀/验证工件）；runtime binding 不变——新角色版本指向 champion 的 manifest artifact（版本号 bump 记录激活事件）；激活经 `ActivationReconciler.activate_harness`（[18](18-recovery-activation.md)）调用 agent `_activate`。
- **因果链闭环**：下一代 cycle 的 boot 探针在 champion worktree 上跑（[06](06-wsl-first-runtime.md)），champion 代码即候选代码； Prosecutor 可随时 `aegis.order_rollback`。

### 5. activate（`_activate`）

CAS 链：candidate ref 校验 → 树重验 → champion CAS（expected_champion 不符即拒）→ `update-ref refs/aegis/champion` + 重切 champion worktree + 写 state.json（last_known_good 保留前代）。

### 6. rollback（`_rollback`）

- 目标必须是 `state.last_known_good`；目标树重验（frozen diff 对当前 source_ref，meta 标志放宽为 True——历史合法树不因现行 meta 开关被误拒）；champion CAS 回翻 + worktree 重建。
- Prosecutor 的回滚令（`aegis.order_rollback`）经 `_execute_rollback_order` 分派（`cycle_ports.py:4934-4959`）。

## 操作者前进：advance_champion

宿主侧演进（冻结文件的正常维护）进入运行中 campaign 的通道（`_advance_champion`）：

- CLI `harness-advance <campaign> <target_ref>`：sync_mirror（刷新发行版镜像到新 pin）→ agent `advance_champion`（目标必须是当前 champion 的后代 + 树重验 + champion CAS 前翻 + `state.source_ref` 迁移）。
- 旧 champion 保留为 last_known_good；操作者命令非候选通道。

## 镜像同步

`sync_mirror`（`_sync_mirror`，agent 端）：bare mirror `/var/lib/aegis/source-mirror.git` 从 public source fetch，fail-closed 校验 pinned ref 可解析。生产 launch 前自动尽力执行（`cli.py:_run_v2_cycle_wsl_first`）；手动入口 `harness-sync`。

## host-canary 退化路径（test_mode）

仅配 `harness_repo`（宿主 git）时：`HarnessCanaryRunner.run`（`harness.py:693-733`）在宿主临时 clone 双臂跑金丝雀；激活只翻注册表 champion，**不落宿主仓库提交**（`HarnessRepo.activate` 无生产调用方）。生产语义在 WSL-first 路径。

## 宿主侧 harness 仓库发布（对照）

`HarnessRepo`/`GitPublisher`（[15](15-research.md) §publisher）面向公共 Git 边界的候选发布与 stable 晋级——与 WSL campaign 内的 champion 翻转是两条独立链；`publishing/promote_stable` 需要 qualified + probation_passed 双证据（`publisher.py:158-200`）。

## 边界

- harness agent 操作集封闭枚举：ensure_campaign/status/sync_mirror/checkpoint/validate/canary/activate/rollback/advance_champion/cleanup_candidate。
- 影子评测对 harness-code 不适用（binding 不变，差分是噪声）——这是 2026-09-15 用双臂 worktree 金丝雀替换同绑定路径的原因（`docs/autonomous-evolution.md` §4e）。
