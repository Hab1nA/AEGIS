# 09 评测与归因

## 定位

三个互补的确定性评测层：**评分**（一次密封执行得多少分）、**门禁**（配对证据是否强到可激活）、**归因**（候选是否唯一变更坐标）。全部非补偿、内容寻址、可重放。

## 密封评分（`evaluation/scoring.py`）

- `score_quality`（:65-80）：`correctness = 0.25*public + 0.75*hidden`；`score = 0.80*correctness + 0.15*robustness(mutant) + 0.05*static_checks`。
- **非补偿**：存在 safety_violations 或 tamper 证据 → 直接 `QualityResult(0.0, False)`（:74-79）。
- 篡改检测 `detect_tampering`（:45-62）：提交哈希变更、保护前缀（hidden//scorer//control/）变更、绝对路径/`..`。

## 密封评测协议（`sandbox/sealed_evaluation.py` + `evolution/arm_evaluation.py`）

- 双 suite（public/hidden）独立沙盒（suite_sandbox_ids 恰 2 个、相异）；staging digest 回执；评估后 export 比对基线哈希得 changed_paths，非空 → integrity 违规（`arm_evaluation.py:312-332`）。
- `TaskArmResult.score`：integrity 失败 = 0；否则 0.25 public + 0.75 hidden（`sealed_evaluation.py:316-320`）。
- `SuiteResult.integrity_passed` = 非 timeout 且无违规（:285-287）；套件为空 → safety 标记 quality=None。
- **任务分层**（`_evaluation_tier` :348-353）：cohort 的 fresh-holdout → FRESH tier；hall-of-fame → REGRESSION tier。
- `evaluate_frozen_workspace`（:388-446）：冻结工作区 +密封任务 → `ArmEvaluation`（总 quality 12 位舍入 + FRESH/REGRESSION 两个 TierEvaluation；fresh_quality 可为 None 表示该 tier 无任务）。
- 限额：workspace ≤32MiB、overlay ≤8MiB/64 文件（仅 7 种文本后缀，`tests/` 永不被 overlay）、评测 timeout ≤3600s。

## 候选门禁（`attribution/candidate_gate.py`）

详见 [08](08-candidate-lifecycle.md) §5。关键结构：`SealedCandidateArm` 绑定字段（design_id/cohort_id/task_artifact_ids/evaluator_fingerprint/runtime_policy_id）全有或全无（:75-84）；配对两臂绑定模式一致、evidence 相异（:136-149）；`CandidateGateReport.report_id` 恒定（bootstrap 附档不参与身份 :306-315）。

## 因果归因（`attribution/evaluation.py`）

`qualify_attribution` 的 fail-closed 序列（:64-204）：

1. observation 重复 / 不足 minimum_pairs → INVALID_DESIGN；
2. **干预坐标判定**（:89-122）：合法单表面干预恰好改变一个坐标 ∈ {plugin_ids, runtime_variant, mcp_binding_ids}——坐标集合跨行不一致、出现结构性变更（cycle/task/seed/teammate）、变更坐标 >1、cohort key 漂移 → **CONFOUNDED**；
3. integrity / safety 失败 → 非补偿拒绝；
4. 三合格路（`QualificationPolicy` 默认 quality_improvement=0.02 / noninferiority_margin=0.01 / minimum_cost_saving=0.10）：
   - QUALITY_IMPROVEMENT：`quality_delta ≥ 0.02`；
   - cost 路前置：usage 未验证 → UNVERIFIED_USAGE（只挡成本路）；baseline_cost=0 → INVALID_DESIGN；
   - COST_EFFICIENCY：质量非劣 且 成本节省 ≥10%；
5. 兜底 NOT_QUALIFIED。

`EvaluationArm`（`models.py:76-211`）全字段：quality/cost_units/usage_verified/safety_passed/integrity_passed + 干预坐标（plugin_ids/runtime_variant/mcp_binding_ids）+ role_generations。每 cycle 镜像写 jsonl + `attribution-arm` 工件 + `attribution_arm_recorded_v1` 事件（data-dir 重建后归因可重放，`cycle_ports._append_arm`）。

跨 cycle 角色对比被如实判 CONFOUNDED——完整因果需要同 cohort 配对实验（这是影子评测存在的原因）。

## Hall-of-Fame 晋级（`evaluation/promotion.py`）

- `PromotionPolicy` 默认：required_tasks=12、seeds_per_task=2、bootstrap_samples=10_000、bootstrap_seed=0xAE615、confidence=0.95、quality_improvement=0.02、max_token_increase=0.10、noninferiority_margin=-0.01、token_saving=0.10（:31-42）。
- **任务聚类 bootstrap**（:88-110）：重采样在任务簇层面——任务内 seed 是重复测量，聚类防止相关 seed 人为收窄区间。
- 两条晋级路（:156-159）：quality_win（quality_lower > 0.02 且 token ≤1.10×）；efficiency_win（quality_lower ≥ -0.01 且 saving_lower ≥ 0.10）。safety/usage 未验证非补偿拒绝。
- HOF 状态机本体在 `dynamic_tasks/registry.py`（HOLDOUT_PASSED → HALL_OF_FAME，revision CAS，[10](10-dynamic-tasks.md)）。

## 晋级实验的密封任务集（`strategy.py`）

策略晋升实验要求恰好 12 任务 × 2 种子（:701-704）；task_ids 哈希为密封集 `sha256("AEGIS sealed promotion task\0{exp}\0{task}")`（:408-412）；观察按哈希后 id 持久化，重复 (task,seed) 拒绝。

## 种群归档

见 [08](08-candidate-lifecycle.md) §8（MAP-Elites，fitness=合格路径边际）。

## 边界

- 密封执行依赖沙盒（[16](16-sandbox.md) evaluate_sealed）；evaluator fingerprint 进 design 与 gate 绑定——评测器身份漂移 = 设计失效。
- 门禁与归因刻意分离（candidate_gate.py:1-6 docstring）：归因证唯一坐标，门禁证证据强度；两者都过才可晋升。
