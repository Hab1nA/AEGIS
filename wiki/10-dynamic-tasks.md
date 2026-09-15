# 10 动态任务供应链

## 定位

Judge 出题 → 控制面校验入库 → holdout 隔离 → 下一代 cohort → 晋级回归库。设计原则：**模型只声明任务内容，控制面拥有布局、哈希、验证与注册**；隐藏套件永不提前泄露。

## 任务身份与状态（`dynamic_tasks/models.py`）

- `DynamicTaskArtifact.artifact_id = dynamic-task-sha256:{archive_sha256}`（:136-137）——内容寻址，改一字节即新任务。
- `DynamicTaskStatus`（:52-58）：QUARANTINED（隔离等待 holdout 证明）→ HOLDOUT_PASSED → HALL_OF_FAME（回归库）；FIXED_ANCHOR（冷启动锚点）；REJECTED（验证失败）；RETIRED。
- `CohortTier`：FRESH_HOLDOUT / HALL_OF_FAME。
- 记录不变式（:274-310）：`eligible_generation > creator_generation`；invalid 验证 ⇒ REJECTED；DYNAMIC 起源必须携带研究源证据；REJECTED 不占 task_id（可修内容重投，同内容幂等）。

## 注册表（`dynamic_tasks/registry.py`）

- SQLite + 哈希链事件（4 个：task_registered / holdout_recorded / task_promoted_hof / task_retired）+ **4 个不可变触发器**（:64-71）。
- **holdout 延迟门**：`holdout_delay ≥ 1`（:271-272）；`eligible_generation = creator + delay`（:288）；holdout 证据在 eligible 之前 → `DynamicTaskEligibilityError`（"同代或过早的 holdout 无法证明任务"）——防"当天出题当天考"泄漏。
- 转移 CAS：revision（=最近事件 hash）不匹配 → 冲突（:407-408）。
- **cohort 选择** `select_dynamic_cohort`（:458-524）：Fresh 优先调度（最新课程不输哈希抽签）；确定性洗牌键 `sha256("dynamic cohort v1\0{gen}\0{artifact_id}")`；anchor 回填制渐进退役（动态题不足 limit 才补 anchor）。

## 声明式锻造（`dynamic_tasks/builder.py`）

Judge 经 `task_specs` 声明任务（纯文本/JSON，`forge_next_tasks` 阶段）；`TaskSpec.from_mapping`（:273-366）校验链：

1. 字段精确集（task_id/prompt/public_cases/public_test/hidden_cases/reference_solution/defect_solution/mutants/clauses/defect_clause_ids）；
2. public_test/reference/defect 必须 compile 通过的 Python；
3. cases：1..100 条，每条 {name, steps 1..128, clause_ids}；
4. clauses 1..16；**每个声明条款必须被 ≥1 个 case 引用**（覆盖核算）；**security_relevant 条款必须有 hidden case**；
5. mutants 1..8，每个溯源 ≥1 条款；
6. spec ≤256KiB（prompt 32KiB、源码 64KiB）。

`TaskPackBuilder`：`reserved_task_ids`（内置 + 非 rejected 库存）预检 → `materialize`（规范布局 + `contract.json` 条款/覆盖 + content_hash）→ `dry_run` → `commit`（三重校验 + 原子注册）。

## 三重校验（`taskpacks/validation.py`）

判据（:49-82，在真实 WSL 沙盒执行）：

1. **reference** 必须通过 public+hidden 全部；
2. public 与 hidden 各至少 1 个测试；
3. **defect** 必须被检测到（全过 = "defect implementation is not detected" 拒绝）；
4. **hidden 套件必须杀死全部 mutants**，存活者点名；
5. 至少 1 个 anti-hacking mutant。

`SandboxTaskPackRunner`（`taskpacks/runner.py`）：timeout ∈ (0,3600]；密封评估；failure_summary 前 8 条 × 200 字符；finally 销毁。

## 难度门与假设覆盖（`cycle_ports.py`）

- **难度门**（2026-08-31，5b.6）：champion 已全解当前课程（quality-lock 有 fully_solved）且新任务 hidden 全为纯 call 步骤 → 注册前硬拒（`_hidden_suite_is_plain_call` 判别）——堵"冠军全对仍出同构简单题"。
- **假设覆盖核算**（2026-08-31，5b.5）：forge artifact 持久化 `curriculum_hypotheses` + `curriculum_direction`；task-validation 按"条款文本覆盖假说 summary 关键词"产出 `hypothesis_coverage` / `uncovered_hypothesis_ids`；未覆盖假说经 `carried_over_hypotheses` 注入下代 forge context——出题者对上代未覆盖假设负责。

## 冷启动锚点（`dynamic_tasks/seed.py`）

- 空库注册 12 个内置锚点任务，经与 Judge 任务**完全相同**的 forge 边界（origin=FIXED_ANCHOR）；动态题可用后锚点回填退役（不一次性全退）。

## 任务供给与进化耦合

Fresh holdout 是影子评测的 fresh 证据源：无 Fresh cohort 时 fresh-required 面的候选滞留（[08](08-candidate-lifecycle.md) §3）；fresh-exempt 面（environment/plugin/mcp）不受影响。forge 失败产生 remediation obligation 与 `learning-degraded` 结局分类——诚实负结果而非静默。

## 任务包布局（`taskpacks/manifest.py`）

- `compute_tree_hash`：字典序路径+\0+字节+\0 串联 sha256；禁 symlink。
- v1 仅 python；目录互异、非符号链接、public 与 hidden 不嵌套；`verify_integrity` 树哈希 == content_hash。
- Warrior 工作区准备（`taskpacks/runtime.py:110-128`）：只含 defect 基线 + public 测试 + TASK.md；**cases.json 永不进 Warrior 归档**（:121）。
