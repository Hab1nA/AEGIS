# 07 周期状态机

## 定位

每个 campaign 周期是一条确定、可恢复的状态机流水线。三层：纯状态转移函数（`curriculum/state_machine.py`）、事件溯源注册表（`curriculum/registry.py`）、阶段编排器（`cycle_runtime.py`）。

## 状态全集（`CycleState`，state_machine.py:9-36）

23 个状态。19 态线性主链（`_ORDER` :46-66）：

```
created → snapshot_locked → cohort_locked → solutions_collected → submission_frozen
→ judge_reviewed → quality_locked → curriculum_evidence_committed → prosecutor_audited
→ independent_reflections_recorded → council_completed → objective_governance_locked
→ next_tasks_forged → tasks_validated → candidates_evaluated → attribution_locked
→ role_candidates_qualified → activation_set_committed → completed
```

非主链：`paused`、`stopping`、`aborted`、`failed`。终态 = {completed, aborted, failed}。

## 转移规则（`cycle_transition` :115-142）

通用动作：

| 动作 | 前态 | 后态 | 约束 |
|---|---|---|---|
| `pause` | `_ACTIVE`（主链前 18 态） | paused | 记录 resume_target |
| `resume` | paused | resume_target | 目标须在 _ACTIVE |
| `stop` | `_STOPPABLE`（_ACTIVE ∪ paused） | stopping | — |
| `fail` | `_FAILABLE`（_STOPPABLE ∪ stopping） | failed | — |
| `retry` | failed \| aborted | created | ABORTED 与 FAILED 同语义可重试（2026-08-31 修复，5b.6） |
| `advance` | 任意主链态 | 线性后继 | — |
| 具名转移 | 见 `_NAMED_FORWARD` :68-108 | — | 未命中 → `InvalidCycleTransitionError` |

具名转移与 `lock_snapshot`/`start` 别名、`abort`（stopping→aborted）、`lock_attribution` 旁路（tasks_validated 直达，供无 shadow 评测周期）。

## evidence_id 强制（`curriculum/registry.py:27-47`）

17 个动作要求 evidence_id（工件引用）：lock_cohort、collect_solutions、freeze_submission、record_judge_review、lock_quality、commit_curriculum_evidence、record_prosecutor_audit、record_independent_reflections、complete_council、lock_objective_governance、complete_task_forge、complete_task_validation、evaluate_candidates、lock_attribution、qualify_role_candidates、commit_activation_set、complete。命令侧与重放侧对称校验（:491-492 / :937-938）。`fail|abort|stop` 必须带 reason。

## 事件与重放（registry.py）

8 个事件（:17-24）：`constitution_recorded_v2`、`objective_provisional_v2`、`objective_probation_started_v2`、`objective_probation_observed_v2`、`objective_activated_v2`、`objective_rolled_back_v2`、`curriculum_snapshot_recorded_v2`、`cycle_state_changed_v2`。payload 契约见 [catalog-events](catalog-events.md)。

- `_append` 经 `store.append_if_sequence`——CAS 序号守卫（:529-538）。
- 重放：序号必须连续；未知事件类型跳过但推进 sequence（向前兼容，:545-546）。
- 快照 retry 语义（:416-477）：同 snapshot id 重复施加幂等；中断态可追加 `retry: true` 事件重置为 CREATED（内容寻址 id 保证内容一致）。

## 阶段编排（`cycle_runtime.py`）

`EvolutionCycleController.run`（:269-595）仅从 CREATED/COMPLETED 起跑。阶段序列与 transition 对应：

| 阶段（kind） | 端口调用 | transition |
|---|---|---|
| submission | warrior.solve | collect_solutions + freeze_submission |
| judge-review | judge.review | record_judge_review |
| quality-lock | quality.lock_quality | lock_quality |
| judge-calibration | judge.calibrate | —（密封后计算 brier/ECE） |
| curriculum-evidence | — | commit_curriculum_evidence |
| prosecutor-audit | prosecutor.audit | record_prosecutor_audit |
| reflection ×3 | council.reflect | record_independent_reflections |
| council | council.deliberate | complete_council |
| objective-governance | council.govern_objective | lock_objective_governance |
| task-forge | judge.forge_next_tasks | complete_task_forge |
| task-validation | builder.commit | — |
| candidate-evaluation | evolution.evaluate_candidates | evaluate_candidates |
| holdout-commit | — | —（Fresh 任务重验/晋级） |
| attribution | evolution.lock_attribution | lock_attribution |
| qualification | evolution.qualify_role_candidates | qualify_role_candidates |
| activation | evolution.commit_activation_set | commit_activation_set |
| post-reflection ×3 | council.reflect_post | — |
| summary | failure_taxonomy 分类 | complete |

**断点续跑**（`_stage` :603-618）：`key = resume_key or kind`；已记录的 resume key 直接返回检查点工件不重执行。多角色同 kind 阶段用 `reflection:{role}` / `post-reflection:{role}` 后缀区分恢复键。中断/失败后 `--repair` 续跑复用已提交工件，不重复模型调用。

失败路径（:558-574）：非终态异常 → 记录 `cycle-failure` 证据（outcome_class=classify_exception，error_message 截 2000）→ transition fail。

证据形状校验（:207-247）：禁忌键（chain_of_thought/hidden_tests/credentials 等）、字符串 ≤64KiB、列表 ≤1024、映射 ≤256 键、禁非有限浮点。

## CycleRunResult（:185-204）

16 个必填工件引用（snapshot_id … cycle_summary）+ 可选 judge_calibration、post_reflection_index。结局分类：`failure_taxonomy.py` 的 7 类 outcome_class（task-outcome / candidate-rejected / insufficient-design / learning-degraded / infrastructure-error / activation-incomplete / evaluation-skipped）+ 四维 dimensions（execution/learning/candidate/activation，:46-84）。

## 边界

- 状态机的持久化只经 CurriculumRegistry（CAS append）；cycle_runtime 是唯一编排消费者。
- objective 血统/试用期语义（effective_objective_id、probation 观察）在 [11](11-objectives-council.md)。
