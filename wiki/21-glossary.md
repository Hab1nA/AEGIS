# 21 术语表

| 术语 | 定义 | 详见 |
|---|---|---|
| AEGIS | Adversarial Evolutionary Generative Intelligence System；冻结权重的对抗进化系统 | [01](01-overview.md) |
| Warrior / Judge / Prosecutor | 解题者 / 出题者 / 检察官三角色；仅 Warrior 可提议进化，仅 Prosecutor 可裁决 objective 修正案与下令回滚 | [01](01-overview.md) |
| cycle | 一个完整进化周期：19 态状态机流水线（出题→解题→评审→审计→议会→锻造→评测→归因→激活） | [07](07-cycle-state-machine.md) |
| generation | 角色代际：一次角色版本提升（role-version），携带 workflow/subject/plugin/image 绑定 | [13](13-roles-plugins-mcp.md) |
| surface（可进化面） | 七类进化对象：workflow / subject / plugin / environment / harness-code / mcp / control-core | [04](04-evolution-surfaces.md) |
| harness-code | 系统自身源码的进化表面；激活后代码真实驱动下一代运行 | [05](05-harness-evolution.md) |
| meta evolution | 对进化机器自身（registry/consumer/surfaces/harness/recovery）的进化；需显式授权 | [04](04-evolution-surfaces.md) |
| 冻结面 | 模型不可修改的子系统（评测/沙盒/发布/记账/配置/控制面）；由允许根白名单 + frozen 字节比对强制 | [04](04-evolution-surfaces.md) |
| frozen 字节比对 | harness agent 将候选/回滚树与 campaign 钉住的 source_ref 做 diff，全部变更路径必须在允许根内的信任锚 | [05](05-harness-evolution.md) |
| champion / parent / last_known_good | 当前激活候选 / 候选的血缘父代（必须是激活时的 champion）/ 回滚目标（上一代 champion） | [08](08-candidate-lifecycle.md) |
| candidate | 一次进化提议的注册实例：COLLECTED→VALIDATED→QUALIFIED→ACTIVE | [08](08-candidate-lifecycle.md) |
| 影子评测（paired arms） | 同 cohort、同种子下 champion 绑定与候选绑定的配对密封求解；seed 0 基线可复用主解 | [08](08-candidate-lifecycle.md) |
| fresh / regression | 评测任务的两组证据：新锻造 holdout 任务（FRESH）与回归库任务（HALL_OF_FAME/anchor） | [09](09-evaluation-attribution.md) |
| 非劣（noninferiority） | 候选相对基线退化不超过 margin（默认 0.01）；门禁/试用期/objective 影子的共同语义 | [08](08-candidate-lifecycle.md) |
| holdout | 新任务的隔离期：锻造后 1 代才可入 cohort（防泄漏），重验通过才可晋升 HOF | [10](10-dynamic-tasks.md) |
| HOF（Hall of Fame） | 回归任务库；重验通过的 holdout 任务晋升入内，供跨代回归评测 | [10](10-dynamic-tasks.md) |
| 三重校验 | 任务注册门：reference 全过 + defect 被检出 + hidden 杀死全部 mutants | [10](10-dynamic-tasks.md) |
| 难度门 | champion 全解当前课程时，纯 call 隐藏套件的新任务被硬拒 | [10](10-dynamic-tasks.md) |
| sealed evaluation | 密封评测：public/hidden 双 suite 独立沙盒，worker 只见单场景无套件线索 | [09](09-evaluation-attribution.md)、[16](16-sandbox.md) |
| integrity / safety | 评测完整性（套件未被篡改、未超时）与安全性（无违规）；失败非补偿（不可被高分抵消） | [09](09-evaluation-attribution.md) |
| 归因（attribution） | 因果资格认定：候选必须是唯一变更坐标（plugin_ids/runtime_variant/mcp_binding_ids 之一），否则 CONFOUNDED | [09](09-evaluation-attribution.md) |
| 试用期（probation） | 激活后的跨周期非劣观察；breach 诱导 Prosecutor 回滚（objective 试用期=2 干净周期） | [08](08-candidate-lifecycle.md)、[11](11-objectives-council.md) |
| runtime policy | 运行期预算与流程参数（v2 schema）；Prosecutor 经有界修正案调整 | [17](17-runtime-policy.md) |
| maintenance mode | 预算耗尽后的冻结状态：仅 Prosecutor 可继续，直至补偿性修正案 | [17](17-runtime-policy.md) |
| WSL-first | 生产周期在发行版内由 champion 树执行的架构；宿主为薄客户端 | [06](06-wsl-first-runtime.md) |
| boot 探针 | launch 的 Tier 1：严格隔离子进程导入 champion entrypoint 并握手；失败自动回滚 | [06](06-wsl-first-runtime.md) |
| gateway sidecar | 发行版内唯一持中继凭据的固定进程：HTTPS 转发 + JSONL 计量 + SSRF 钉扎 | [06](06-wsl-first-runtime.md) |
| checkpoint / activate / rollback | harness agent 的候选提交 / champion CAS 前翻 / CAS 回翻操作 | [05](05-harness-evolution.md) |
| canary | 双 worktree（champion vs candidate）确定性测试子集对比；零回归门槛 | [05](05-harness-evolution.md) |
| content addressing | 一切身份 = `前缀-sha256:` + sha256(canonical_json(payload))；载入即重算校验 | [03](03-foundation.md) |
| CAS（compare-and-set） | 乐观并发原语：事件序列号、revision、git update-ref、force-with-lease 的共同模式 | [03](03-foundation.md) |
| fail-closed | 校验失败/证据缺失/依赖不可用时拒绝而非降级（少数显式降级除外：Trivy/可复现性/interop warn-only） | 全文 |
| intent-first | 先持久化意图再执行，回执事后补记；崩溃后重放续跑而非重做 | [18](18-recovery-activation.md) |
| provenance | 溯源记录：请求/最终 URL、sha256、size、media_type、重定向链、UTC 时间 | [15](15-research.md) |
| 供应链（task supply） | Judge 锻造→校验→holdout→cohort 的任务流水线；断供只影响 fresh-required 面 | [10](10-dynamic-tasks.md) |
| MAP-Elites / population | 资格候选按行为描述符归档的有界网格；fitness=合格路径边际 | [08](08-candidate-lifecycle.md) |
| outcome_class | 周期结局七分类：task-outcome / candidate-rejected / insufficient-design / learning-degraded / infrastructure-error / activation-incomplete / evaluation-skipped | [07](07-cycle-state-machine.md) |
| E2E 台账 | `docs/autonomous-evolution.md` 中按轮次记录的真实运行验收与修复史 | [19](19-operations.md) |
