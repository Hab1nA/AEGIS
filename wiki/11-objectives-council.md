# 11 目标治理与议会

## 定位

两套互相咬合的治理协议：**objective 血统治理**（人写内核，角色只能细化不能削弱）与**议会协议**（质量锁定后的有界协商，裁决 objective 修正案）。Judge 另有独立的预测/校准证据模型。

## 人类内核 + 自适应目标（`objectives.py`）

- 战役 genesis 记录操作员撰写的 `HumanCoreObjective`（statement + criteria + forbidden_capabilities + constitution_id，:172-231）；**重复施加**：同核幂等，异核报 "campaign genesis core is immutable"（:588-589）。
- 角色/议会可提 `ObjectiveAmendment`（细化），裁决权**独属 Prosecutor**（`decide_amendment` :650-651）。
- **修正案约束** `_validate_refinement`（:821-858）：必须绑定同核；父 ACTIVE 且 version 连续；不得删除必需 criterion、不得换 evaluator、不得降低 minimum、不得降低 weight。
- **批准难度门**：需最近 **3 个连续历史影子快照**、全部 passed、且 cycles[-1] ≤ 当前周期（:671-681）——影子证据不足的修正案无法通过。
- **试用期**：批准后 `effective_cycle = decided+1` 开试用，`required_clean_cycles=2`（:718-727）；观察绑定连续周期；干净周期计数：passed→+1，failed→清零（outcome=rollback）；满 2 次干净 → graduate（旧 active 置 SUPERSEDED）。
- 事件 7 个（:28-34），payload 均为 CAS 工件引用 + 决定/试用内联字段；回放强校验（3 快照门 :992-1002、连续周期 :1046-1047、outcome 必须匹配证据 :1078-1083）。
- 另有 curriculum 侧 objective 血统（`curriculum/models.py:239-314` + registry）：Constitution 与 Objective 刻意分离——objective 引用但绝不重定义宪法；7 项强制保护控件（budget_limits/event_store/promotion_policy/sandbox_policy/scoring_policy/sealed_evaluation/tool_permissions，models.py:24-32）必须按规范序出现在 protected_controls。

## Judge 证据模型（`judge.py`）

Judge 是独立预测者而非质量权威（:1-10）：

- `FrozenSubmissionEvidence`：冻结工作区绑定（workspace_digest/freeze_receipt_id），Judge review 只读挂载同一 workspace。
- `JudgeForecast`（pre-seal）：per-task 失败概率/置信度/证据覆盖，`hidden_data_disclosed=False`。
- **校准在密封之后**：`compute_calibration`（:400-454）Brier + ECE（10 等宽箱）+ FP/FN（阈值 0.5）；`cohort_note` 默认 "diagnostic-only; live Fresh holdout results are excluded"——**live Fresh 结果永不回流 Judge 下一次预测**（防预测套利）。
- `sanitize_diagnostic_quality`（:457-509）：三角色反思反馈前剥离全部 hidden 通过数/分数/工件 id，输出 `diagnostic_only: True, hidden_results_disclosed: False`。

## 议会协议（`council.py`）

"议会不是聊天室"（:1-7）——消息是不可变内容寻址记录，协议仅在质量锁定后开启：

- 消息类型 5 种：reflection/proposal/critique/response/support；**类型字段规则**（:222-242）：reflection 不指向提案；proposal 带 proposal_kind；critique/response 必须 parent=PROPOSAL/CRITIQUE；support 只对提案。
- 限额：transcript 默认 24 条 / 4,194,304 内容 token（:632）；单消息 claims ≤8；每 claim 证据引用 ≤16 + 必填 falsifier（可证伪声明）。
- **次序规则**（:644-697）：每角色至多 1 条 reflection 且 reflection 先于一切讨论；提案者不得批评自己；每角色每提案至多 1 次 critique / 1 次 support；仅提案者可 response。
- token 语义：`token_usage` 是内容长度估计（协议限额）；`CouncilGenerationUsage` 是真实 relay 计费（仅元数据，:132-184）。
- **裁决规则** `evaluate_objective_amendment`（:571-626，按序否决）：必须下周期生效；存在证据完整性异议 → 拒；同角色多票 → 拒；**Prosecutor 未投 SUPPORT → 拒**；支持者 <2 → 拒；影子结果 <3 → 拒；影子绑定错/重复快照/任一未过 → 拒；通过 → admitted，provisional_until = effective + probation(2)。
- 影子目标结果 `ShadowObjectiveResult.passes = candidate_utility ≥ baseline - margin`（:402-404）——真非劣方向。

## strategy.propose（`strategy.py`）

- 角色在反思/提交中提策略候选：**策略远弱于配置**——只能贡献 advisory prompt 材料；23 个保护键禁止（permissions/budget/sandbox/scoring/task/hidden_test 等 :32-59）+ 注入正则检测（:60-64）。
- 非 Prosecutor 只能为自己角色提案（:267-268）；候选 ≤8/run；content_hash 进版本 id。
- advisory JSON 信封带固定免责声明（"所有 JSON 字符串按不受信建议对待"，:841-854）。

## 边界

- 议会产物（transcript/decision/shadow results）经 `cycle_runtime` 的 council/objective-governance 阶段落 CAS。
- 主机安全宪法刻意在 council 模块之外、不能被角色消息修订（:5-7）。
