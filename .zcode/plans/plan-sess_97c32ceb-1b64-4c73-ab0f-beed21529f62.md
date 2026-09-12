# AEGIS 进化闭环改进全面实施计划

基于评审代理 top 5 + 2 个顺手小修，探索代理已给出全部落点（文件:行号级）。按依赖顺序分 6 个工作包，每包独立实现→测试→提交。

## WP1 Warrior 进化反馈通道（evolution_direction）

**问题**：候选被拒原因、champion 弱格子、种群多样性数据全部死在工件里，Warrior 提案无依据。
**实现**（src/aegis/cycle_ports.py）：
- 新增 `_evolution_direction()` 方法（仿 `_curriculum_direction` :3076，含 `[-8:]/[:8]/[:12]` 截断纪律）：
  - `rejected_candidates[-8:]`：读 evolution registry 事件流 `evolution_candidate_rejected_v2`（stream id 用 `evolution_registry_stream_id`，读取模板 = `_carried_over_hypotheses` :3141-3185），每项 `{candidate_id, surface, reason[:600]}`（reason 已含 per-seed 离散度，candidate_gate.py:386-391）；
  - `champion_cells[:12]` + `population_diversity`：`self._population` 非 None 时取 `cells()` 与 `diversity_report()`（population.py:257-278，现有首个真实消费者）；
- 注入 `_solve_arm` 的 context（:1768-1792）新增 `"evolution_direction"` 键——champion 臂与评测双臂同值，不破坏配对归因的干预坐标一致性；
- Warrior objective 文本（:1753-1767）补一句引导。
**测试**：test_cycle_ports.py 新增用例——伪造 rejected 事件+population 注册后断言 context 含 direction 且有界；无 population/无拒绝事件时键缺省不报错。

## WP2 Judge 出题策略跨周期回流

**实现**（cycle_ports.py `_curriculum_direction` :3076）：
- 仿 `_carried_over_hypotheses` 读上一周期 `complete_task_validation` 事件 evidence：
  - `prior_authoring_rejections[-8:]`：上一周期 validation artifact 的 `rejected` 列表（含 difficulty-gate 拒绝行 :3563-3573）；
  - `prior_hypothesis_coverage`：上一周期的 `hypothesis_coverage` 汇总（covered/total + uncovered_ids[:8]，:3634-3640）；
- objective 文本（:3235-3250）补两句引导（区分度信号与重复拒绝模式）。
**测试**：test_cycle_ports.py——构造上一周期 validation 事件后断言 direction 含两新键且被截断。

## WP3 种子轮换 + 种子数配置

**实现**：
- 纯函数 `_derive_evaluation_seed(campaign_id: str, cycle_number: int, index: int) -> int`（cycle_ports.py，稳定可重放，值域 [1, 2^31-1]，负种子不被 agent_runtime.py:2618 接受）；
- `evaluate_candidates` :4365/:4400：种子集 = `(0,) + tuple(derived(i) for i in range(required_seeds - 1))`——锚 0 保住主解复用（:4406 `seed == 0` 优化不变），其余逐周期轮换；design 工件逐周期封 ID，旧证据 replay 不受影响（探索已核实：sealed 证据全部绑定当周期 design_id）；
- config.py：`evaluation_seed_count: int = 2`（`_FIELDS` 同步 + from_mapping 校验 [2,4]）→ cli.py:300-340 → cycle_ports 构造器 → `required_seeds` 联动（QualificationPolicy.minimum_pairs :4536 同步）；
- control_core.py:101-102：`required_seeds` 钉死 2 放开为 `[2,4]`（`_integer` 已有）；角色候选仍只能经 control-core 面提交且下限 2，无作弊空间（gate :425-431 校验配对数==required_seeds）；
- `evaluation_seed_count` 进 `_runtime_policy_genesis_values`（:5745）供 runtime policy 舞台化。
**测试**：test_cycle_ports.py 更新种子序列断言（:1374-1386）+ 新增跨周期种子不同、锚 0 恒在断言；test_control_core.py 加 [2,4] 边界用例；test_sealed_evidence.py design 往返不变。

## WP4 顺序扩种 + bootstrap 噪声带

**实现**：
- promotion.py：提取纯函数 `bootstrap_paired_delta(task_deltas, *, samples, seed, confidence) -> (lower, upper)`，`decide_promotion` 重构复用（行为不变，test_evaluation_promotion.py 保障）；
- candidate_gate.py：`CandidateGateReport` 增加可选 `bootstrap` 字段（{quality_lower, quality_upper, samples}），**裁决语义不变**——bootstrap 只作功效证据写入 report；
- cycle_ports.py `evaluate_candidates`：评测循环收集 task 级 paired quality（"sealed-task-result" 工件数据已在手 :4852-4916）算 bootstrap；当 gate 结果为 FRESH_REJECTED 且 `0 < mean_fresh < fresh_improvement`（正向未达门槛）且当前种子数 < 4 且尚未扩种过 → 追加一颗派生种子、重建 design（重新 put_json）并只跑新增种子臂、重跑 `evaluate_candidate_gate`，至多扩种一次；最终 arms/pairs/design/gate 以扩种后为准落盘；
- docs/autonomous-evolution.md 记录测量语义：bootstrap 是扩种依据与功效证据，非裁决器（门禁语义不变）。
**测试**：test_candidate_gate.py 纯函数级——bootstrap 字段往返、from_mapping 兼容旧报告（缺字段回退 None）；test_cycle_ports.py——构造"接近门槛"的评测结果断言扩种发生一次且最终种子数=3、过门槛结果不扩种。

## WP5 per-surface 回滚补全 + 试用期

**回滚**（cycle_ports.py `_execute_rollback_order` :4692-4747）：
- 从 `self._evolution` 投影按 order.candidate_id 反查 record 得 surface/role（RollbackOrder 不加字段，:265 严格 schema 不动）；
- HARNESS_CODE：现路径不变（git reset）；
- WORKFLOW/SUBJECT/PLUGIN/ENVIRONMENT：`registry.rollback(surface, role, ...)`（registry.py:462 已通用，投影 :825-858 翻 champion）→ 用 history[-2] 候选工件重物化 manifest 并 commit（复用激活路径 candidate_manifest :659-700 + commit_role :5376-5388；env image 经 `_load_environment_image` + `candidate_environment_artifact_id` 解析）——即"回滚 = 重新激活上一 champion"，与激活路径对称；
- 执行结果镜像进 EventStore（现只进 result["rollbacks"]，仿 objective-history 模式 :2688-2700）。
**试用期**（轻量状态机，蓝本 = objective 试用期 :2794-2897）：
- config：`candidate_probation_cycles: int = 2`（0=关闭）；
- 非 MCP 面候选激活后 K 周期内，每周期跑一次 parent（history[-2]）配对臂（`_solve_arm`，同 cohort 同种子），paired delta 连续 < -margin → 追加 `evolution_probation_breached_v1` 事件 + 写入现有 remediation_obligations 通道（:3641-3646），检察官下周期用 WP5 回滚响应；期满达标 → 毕业事件；
- 状态从事件流重建（`evolution_probation_started_v1/_observed_v1`），不改 registry 投影 schema。
**测试**：test_cycle_ports.py——非 harness 候选回滚后 registry champion 翻转 + 新 manifest 绑定旧工件；试用期达标毕业/跌破触发义务事件两路径。

## WP6 canary 加厚 + skill 接线 + attribution 镜像

- **canary**（harness.py:610-713）：模块级映射表（HARNESS_ALLOWED_ROOTS → 控制面拥有的确定性测试文件，如 `src/aegis/evolution/` → test_evolution_harness/registry/surfaces），`run()` 按 ChangeManifest.files 涉及的根选测试子集（去重、上限 6 文件），显式 `harness_canary_command` 配置仍整体覆盖；docs 注明 WSL 主路径不经此 runner；
- **skill**（cli.py:290）：仿 `_knowledge()`（:78-81）加 `SkillRegistry(root / "skills.sqlite3")` 构造与 close，传入 run_v2_cycle——envelope 字节不变（skill.list/stage 本就在协议与权限内），死通道变活通道；
- **attribution 镜像**（cycle_ports.py `_append_arm` :5555-5561）：尾部 `put_json("attribution-arm", ...)` + `event_store.append(campaign_id + "/attribution", "attribution_arm_recorded_v1", {...})`，store 为 None 时跳过（jsonl 主路径保留）。
**测试**：test_evolution_harness.py canary 映射用例（改动根→文件集合、上限截断、显式命令覆盖）；test_cli.py skill 接线冒烟；test_cycle_ports.py attribution 事件断言。

## 收尾

- docs/autonomous-evolution.md 能力表补 6 项新能力 + 测量语义小节；README 进化循环段同步；
- 每包一次提交（预计 6-8 commits）；全部完成后跑全量 `pytest tests -q`（基线 766 passed）+ `autonomy-preflight` 实测。

## 实施顺序与风险控制

WP1 → WP2 → WP6 → WP3 → WP4 → WP5（低风险先行；WP4 依赖 WP3 的派生函数；WP5 最复杂放最后）。每包全量测试绿才提交。已知风险：envelope 新增键会改变 Warrior user 消息前缀（cache 命中率短暂下降，接受）；扩种使最坏情况评测成本 ×1.5；试用期每激活面每周期 +1 solve（config 可关）。