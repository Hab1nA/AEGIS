# AEGIS 项目 Wiki

> **AEGIS** = Adversarial Evolutionary Generative Intelligence System。
> 冻结模型权重，在隔离沙箱与不可变安全宪法围栏内，通过「出题—解题—证据门控」的对抗进化循环持续提升解题者（Warrior）能力；每一次自我进化都可归因、可审查、可回滚。

本 wiki 记录每处设计细节。行号引用（`file:line`）基于撰写时的工作区状态，语义以源码为准。

---

## 给人类读者的阅读路径

| 你想了解 | 直接去 |
|---|---|
| 这个项目是什么、核心思想 | [01-overview](01-overview.md) |
| 系统如何组织（进程/数据/信任层） | [02-architecture](02-architecture.md) |
| 进化如何发生（候选生命周期/门禁） | [08-candidate-lifecycle](08-candidate-lifecycle.md) → [09-evaluation-attribution](09-evaluation-attribution.md) |
| AI 如何"改自己的代码" | [05-harness-evolution](05-harness-evolution.md) |
| 安全边界为什么可信 | [20-threat-model](20-threat-model.md) + [04-evolution-surfaces](04-evolution-surfaces.md) |
| 怎么跑起来 | [19-operations](19-operations.md) |
| 某个术语是什么意思 | [21-glossary](21-glossary.md) |

## 给 Agent 的导航规则

1. **本页为唯一入口**：所有页面从 `INDEX.md` 或 `manifest.json` 可达；`manifest.json` 是机器可读页面清单（名称/摘要/关键文件）。
2. **文件名即稳定标识**：`NN-topic.md` 编号反映依赖顺序（03 基础层 → 04-08 进化层 → 09-18 子系统层 → 19-21 运维/参考层）。引用页面时使用相对链接（如 `07-cycle-state-machine.md`）。
3. **每页统一结构**：`## 定位`（模块职责与为什么）→ `## 关键机制`（逐条 file:line）→ `## 常量`（若适用）→ `## 边界`（谁调用它/它调用谁）。
4. **事实查询优先两份目录页**：[catalog-limits](catalog-limits.md)（全部数值限额，值+file:line）、[catalog-events](catalog-events.md)（全部事件类型+payload 字段）。写代码前先查目录页，再进对应子系统页核对语义。
5. **行号会漂移**：修改源码后，以 `catalog-limits.md` 中的常量名/正则为锚重新 grep，勿盲信行号。
6. **与 `docs/` 的分工**：`docs/autonomous-evolution.md` 是带验收记录的历史台账；本 wiki 是设计现状。冲突时以源码 + 本 wiki 为准，验收记录看 docs。

---

## 页面目录

| 页 | 主题 | 一句话摘要 | 主要源码 |
|---|---|---|---|
| [01](01-overview.md) | 总览 | 三角色对抗进化循环、设计主旨、信任分层哲学 | — |
| [02](02-architecture.md) | 架构 | Windows 宿主 ↔ WSL 发行版双域、四固定 agent、数据布局 | `evolution/wsl_*.py`、`wsl_cycle_runtime.py` |
| [03](03-foundation.md) | 基础层 | 内容寻址、事件存储、CAS 工件、执行锁、envfile | `models.py`、`artifacts.py`、`event_store.py` |
| [04](04-evolution-surfaces.md) | 可进化面契约 | 七类表面、授权规则、路径白名单、冻结面 | `evolution/surfaces.py` |
| [05](05-harness-evolution.md) | Harness 代码进化 | checkpoint→validate→canary→activate→rollback 全链、frozen 字节比对信任锚 | `evolution/wsl_harness_agent.py`、`harness.py` |
| [06](06-wsl-first-runtime.md) | WSL-first 运行时 | 双层启动、supervisor 协议、网关 sidecar、cycle_status/cancel | `evolution/wsl_supervisor*.py`、`gateway_sidecar.py`、`wsl_cycle_runtime.py` |
| [07](07-cycle-state-machine.md) | 周期状态机 | 23 状态、具名转移、evidence_id 强制、断点续跑 | `curriculum/state_machine.py`、`curriculum/registry.py`、`cycle_runtime.py` |
| [08](08-candidate-lifecycle.md) | 候选生命周期 | 收集→验证→影子评测→资格→激活→试用期，全部门槛数值 | `cycle_ports.py`、`evolution/registry.py`、`evolution/consumer.py` |
| [09](09-evaluation-attribution.md) | 评测与归因 | 密封评分、候选门禁、因果归因、bootstrap、种群归档 | `attribution/*`、`evaluation/*`、`evolution/arm_evaluation.py` |
| [10](10-dynamic-tasks.md) | 动态任务供应链 | 任务注册表、声明式锻造、三重校验、难度门、holdout | `dynamic_tasks/*`、`taskpacks/*` |
| [11](11-objectives-council.md) | 目标治理与议会 | objective 血统/修正案/试用期、三方议事协议与裁决规则 | `objectives.py`、`council.py`、`judge.py` |
| [12](12-agent-runtime.md) | 角色运行时 | JSON 动作协议、信封结构、收敛控制、恢复机制 | `agent_runtime.py` |
| [13](13-roles-plugins-mcp.md) | 角色/插件/MCP | 角色注册表、代际 bundle、插件 ABI 与 broker、MCP 桥与租约 | `roles/*`、`plugins/*`、`mcp/*` |
| [14](14-gateway-accounting.md) | 网关与记账 | Responses 协议网关、attempt 级记账、frozen 用量、预算授权 | `gateway/*`、`runtime_ledger.py`、`usage_accounting.py` |
| [15](15-research.md) | 研究网关 | IP 钉扎传输、SSRF 防护、溯源、隔离导入、知识/技能库 | `research/*`、`knowledge.py`、`skill_registry.py` |
| [16](16-sandbox.md) | 沙盒 | WSL agent JSON 协议、容器加固、密封评测、镜像持久化、资源信封 | `sandbox/*` |
| [17](17-runtime-policy.md) | 运行时策略 | v2 字段集、即时/阶段修正案、流程界限、维护模式 | `runtime_policy.py` |
| [18](18-recovery-activation.md) | 恢复与激活 | 修复编排、激活 saga 日志、生成激活回滚 | `cycle_recovery.py`、`repair_runtime.py`、`activation.py` |
| [19](19-operations.md) | 运维手册 | CLI 命令、配置、部署、preflight、E2E 惯例 | `cli.py`、`configs/`、`deploy/wsl/` |
| [20](20-threat-model.md) | 威胁模型摘要 | 保护资产、对手、强制控制、残余风险 | `docs/threat-model.md` |
| [21](21-glossary.md) | 术语表 | 全部领域术语 | — |
| [catalog-limits](catalog-limits.md) | 限额目录 | 全部数值常量：值 + file:line | — |
| [catalog-events](catalog-events.md) | 事件目录 | 全部事件溯源事件：流、payload 契约 | — |
