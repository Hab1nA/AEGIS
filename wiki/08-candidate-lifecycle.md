# 08 候选生命周期

## 定位

Warrior 的进化提议从收集到激活/回滚的完整门槛链。注册表状态机：`COLLECTED → VALIDATED → QUALIFIED → ACTIVE`（append-only，`evolution/registry.py:47-54`），分支 SUPERSEDED / REVOKED / REJECTED。

## 1. 收集（`evolution/consumer.py`）

- 每 cycle 消费三个通道：`strategy.propose`、`evolution.request`、Prosecutor 审计中的 `role_candidates`（:277-383, :511-567），外加议会 reflection 中的 workflow 提案（`_consume_reflection_proposals` :292-397）。
- 收集即拒：非 Warrior 目标候选（**含 reflection 提案**，2026-09-16 起 judge/prosecutor 目标的 workflow 反思提案在收集层拒绝而非注册后搁置）、未启用表面、非 Warrior 提议者——给明确原因，不注册、不烧评测名额（:75-106）。
- 内容物化进 CAS（`materialize_artifact`），表面校验在提议时已过（[04](04-evolution-surfaces.md)）。

## 2. 验证与选择（`cycle_ports.evaluate_candidates` :4024 起）

- 入口预算：runtime policy `candidate_evaluations_per_cycle` ∈ [0,4]（默认 1；0=禁用；`runtime_policy.py`）； genesis 可由 campaign config `autonomy_v2.runtime_flow_parameters` 在同界限内预设（2026-09-16，[17](17-runtime-policy.md)）。
- FIFO 选择：优先 MCP 试用期候选，否则首个 Warrior-target VALIDATED（:4393-4410）。
- **stale 预拒绝**（2026-09-15）：候选 parent ≠ 当前 champion → 直接 REJECTED（superseded）——这类候选注定过不了激活的血缘检查，不再消耗评测名额；2026-09-16 起**循环排空**整个 stale 前缀（每个被拒候选以队列中下一个为替补，直至出现 parent 存活者，:4417-4452）。
- 非 Warrior 滞留候选每 cycle 诚实拒绝（:4445-4460）。
- harness-code 候选前置于 cohort 门 early-return（金丝雀路径，[05](05-harness-evolution.md)），且支持预算内批量评测 + sequential activation saga（:4452-4490 附近）。

## 3. 影子评测的 cohort 门（`_candidate_gate_cohort`）

- 过滤 REJECTED；无 FRESH_HOLDOUT 成员且面要求 fresh → None（候选**滞留**非拒绝，"candidate retained until a Fresh holdout cohort exists"）。
- 无 HOF 层时回填更早世代的 FIXED_ANCHOR 作回归 peer。
- **fresh_required=False 的面**（environment/plugin/mcp，`_FRESH_EXEMPT_SURFACES`）：HOF/anchor-only cohort 即合法设计——出题供给断供不再阻塞能力扩展面进化（2026-09-15）。

## 4. 影子评测（paired sealed arms）

- 种子：确定性派生（anchor 0 + 按 campaign/cycle/slot 哈希，`cycle_ports.py:284-312`）；数量 `evaluation_seed_count` 默认 2 夹 [2,4]；噪声带自动扩种至多 1 次（`_should_expand_seeds` :315-330）。
- 双臂：baseline（seed 0 可复用主解，`baseline_source=main-solve`）vs candidate（candidate_runtime 绑定注入，[09](09-evaluation-attribution.md)）。
- 预算语义：一个周期一个配对评测工件（状态机结构），预算=1 时与旧行为一致。
- 评测产物：design/gate report/arms 全 CAS 绑定（design_id/pair_id/evaluator_fingerprint），durable 阶段逐项复验（:5561-5685）。

## 5. 候选门禁（`attribution/candidate_gate.evaluate_candidate_gate`）

默认策略（`CandidateGatePolicy` :163-175）：required_seeds=2、fresh_improvement=0.02、regression_noninferiority_margin=0.01、min_seed_delta_floor=-0.10、cost_savings_path=0.10、enforce_cost_limit=False（**成本永不作硬门**，`control_core.py:124-125` 禁止开启）、fresh_required=True（按面豁免）。

判定序列（:435-668，全程 ε=1e-12，非补偿）：

1. 种子数不符 → INVALID_DESIGN；
2. 任一臂 integrity 失败 → INTEGRITY_REJECTED；
3. fresh 缺失且 required → NO_FRESH_EVIDENCE；regression 缺失 → INVALID_DESIGN；
4. per-seed 下限：任一 seed fresh/regression delta < -0.10 → 拒（防灾难单 seed 藏在均值里）；
5. mean regression < -0.01 → REGRESSION_REJECTED；
6. fresh 豁免面：全 seed 回归非劣 → **QUALIFIED（regression-only）**；
7. enforce_cost_limit 且超支 → COST_REJECTED（默认关）；
8. 合格三路：mean fresh ≥ 0.02；fresh 双臂饱和 1.0 + mean regression ≥ 0.02；质量非劣 + 成本节省 ≥10%；
9. reason 附加每 seed 明细（n=2 功效透明，:409-414）；bootstrap 附档（任务聚类 10,000 重采样）不参与判定（:306-315）。

gate 不过但 attribution 过 → 强制 NOT_QUALIFIED（`cycle_ports.py:4799-4808`）。

## 6. durable 资格与激活（:5517-5875）

- 全部 CAS 绑定复验（design/gate/arms/pair_ids）；CONFOUNDED 归因阻断晋升（:5601-5615）。
- `registry.qualify` → QUALIFIED；`registry.activate` 要求 QUALIFIED 且 **parent == 当前 champion**（staleness 检查 :481-485）。
- 激活 saga：`ActivationIntent` → journal → reconciler 按 harness→role→evolution→mcp 顺序幂等执行（[18](18-recovery-activation.md)）。workflow/subject/plugin/environment champion 逐面翻注册表；harness champion 翻 git ref；MCP 走租约注册表。
- 激活后 warrior 角色版本 commit、active set 绑定（下一代 envelope 携带新 workflow/subject/plugin/image）。

## 7. 试用期（probation，非 harness 面）

`_observe_candidate_probation`（cycle_ports:5085-5231）：

- 窗口 `candidate_probation_cycles` ∈ [0,16] 默认 2（`config.py:110, 281-283`）。
- 每周期对每个仍在窗口内的面 champion：parent binding 跑一次 seed-0 求解，`delta = champion_quality - parent_quality`。
- **breach 条件（2026-09-15 修正）**：`delta < -margin`（真非劣；旧实现 `delta < +margin` 方向反转已修）。
- 单面 breach 不阻断其余面观察；breach 事件注入 Prosecutor audit context（`probation_breaches`）诱导 `aegis.order_rollback`；窗口期满写毕业事件。
- 主解未覆盖评测 cohort 的周期整窗跳过（防 anchor 回填制造虚假回归，:5130-5140）。
- 状态从事件流重建（`evolution_probation_observed/breached/graduated_v1`）。

harness 面 champion 无试用期：由下一代 boot 探针（失败自动回滚）+ Prosecutor 回滚令监管。

## 8. 种群归档（MAP-Elites，`evolution/population.py`）

- 资格即登记：行为描述符 (surface, 改动根×3, failure_mode 哈希, objective 哈希)（:59-78）；格子默认 128（policy `population_max_cells`，:4887-4889）；溢出丢最老。
- **fitness = 合格路径边际**（`_population_fitness` :333-360，2026-09-15 修复）：fresh 路=fresh 均值；饱和路=1+regression 均值；成本路=1+节省比；不可排形 0.5。同格严格更优才替换——此前恒 1.0 使格内迭代死代码。
- 归档当前只做登记与多样性报告，不驱动父代选择（已知边界）。

## 数值速查

| 门槛 | 默认 | 位置 |
|---|---|---|
| fresh 提升 | ≥0.02（seed 均值） | candidate_gate.py:166 |
| 回归非劣界 | ≥-0.01 | candidate_gate.py:167 |
| per-seed 灾难下限 | -0.10 | candidate_gate.py:169 |
| 成本节省路 | ≥10% | candidate_gate.py:171 |
| 试用期 | 2 周期，非劣 -0.01 | config.py:110 / cycle_ports |
| holdout 延迟 | 1 代（最小防泄漏） | config.py:80 |
| 评测预算 | [0,4] 默认 1 | runtime_policy.py:129 |
