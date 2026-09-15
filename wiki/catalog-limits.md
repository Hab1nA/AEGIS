# 限额目录（catalog-limits）

全部数值常量与限额。**行号为快照**，修改源码后按常量名重新 grep。路径相对 `src/aegis/`。

## 角色运行时（agent_runtime.py）

| 常量 | 值 | 位置 |
|---|---|---|
| MAX_EVOLUTION_REQUESTS | 1 | :86 |
| MAX_EVOLUTION_SOURCE_REFS | 5 | :87 |
| FIXED_ROLE_MAX_STEPS | 128 | :92 |
| FIXED_ROLE_MAX_READ_BYTES / MAX_WRITE_BYTES | 4 MiB | :93-94 |
| FIXED_ROLE_MAX_TOOL_OUTPUT_BYTES | 8 MiB | :95 |
| FIXED_ROLE_MAX_SEARCH_RESULTS | 200 | :96 |
| FIXED_ROLE_RESEARCH_ACTION_BUDGET | 1,000,000 | :97 |
| RuntimeLimits 默认 | steps 20 / read+write 256KiB / tool_out 512KiB / argv 64 项 / 单参 16KiB / timeout 300s / search 20 | :113-123 |
| 强制收敛 reserve | min(3, max_steps//4) | :3107 |
| submit summary 上限 | 16384 字符 | :2489 |
| feedback items / rationale | 1..8 / ≤2000 | :2526-2567 |
| sandbox.exec 默认 timeout | 60s | :2467 |
| research.search query | ≤1000 字符 | :1180 |
| 子代理 spawn | objective ≤4096B、input_refs ≤16 | :2221-2232 |

## 子代理（subagents.py / subagent_worker.py）

| 常量 | 值 | 位置 |
|---|---|---|
| MAX_SUBAGENT_OBJECTIVE/CONTEXT/INPUT_REFS | 4096B / 64KiB / 16 | subagents.py:28-30 |
| SubagentLimits 默认 | steps 8 / timeout 180s / result 65536B | :50-52 |
| 并发 | 默认 2 ∈ [1,16] | :221-226 |
| worker 捕获上限 | 1 MiB | subagent_worker.py:24 |

## 网关（gateway/）

| 常量 | 值 | 位置 |
|---|---|---|
| 默认 timeout | 900s（env 默认 "900"） | client.py:43, :90 |
| RetryPolicy | 6 次 / base 0.5s / max 4.0s，`min(4.0, 0.5*2^n)` | :108-110, :253 |
| 可重试 HTTP | {408,409,429} ∪ ≥500 − {400,404,405,415,422} | :128, :284 |
| HTTP body 截断 | 1000 字符 | types.py:45 |
| temperature / seed | [0,2] / [0, 2147483647] | types.py:104-109 |
| thinking 预算 | 65,536（effort=max） | __init__.py:5 |
| 传输块 / connect 上限 / poll 量子 | 64 KiB / 30s / 5s | transport.py:65, :94, :230 |
| build_role_request 默认输出 | 4096 tokens | protocols.py:81 |

## 账本与用量

| 常量 | 值 | 位置 |
|---|---|---|
| ledger 并发写重试 | 16 次 | runtime_ledger.py:258, :320 |
| maintenance 限额 | 3 attempts/invocation；grace 3；1 invocation/policy/cycle | :453-454, :487-488 |
| usage anomaly 四类 | output 超预留 / reasoning>output / cached>input / zero_output+非空文本 | usage_accounting.py:94-109 |
| 兜底估算 | ceil(chars/3) in、ceil(len/3) out，verified=False | :87-88 |

## 门禁与归因（attribution/ + evaluation/）

| 常量 | 值 | 位置 |
|---|---|---|
| CandidateGatePolicy | seeds 2 / fresh 0.02 / margin 0.01 / max_cost +0.10 / floor -0.10 / savings 0.10 / fresh_required True | attribution/candidate_gate.py:163-175 |
| QualificationPolicy | quality 0.02 / max_cost 0.10 / margin 0.01 / saving 0.10 / pairs 1 | attribution/models.py:338-344 |
| PromotionPolicy | tasks 12 × seeds 2 / samples 10,000 / seed 0xAE615 / conf 0.95 / 0.02 / +0.10 / -0.01 / 0.10 | evaluation/promotion.py:31-42 |
| 评分权重 | 0.25 public + 0.75 hidden → 0.8 corr + 0.15 robust + 0.05 static；integrity/safety 失败=0 | evaluation/scoring.py:70-79 |
| bootstrap | 任务聚类、10,000 重采样 | promotion.py:88-110 |

## 候选生命周期（cycle_ports.py / runtime_policy.py / config.py）

| 常量 | 值 | 位置 |
|---|---|---|
| candidate_evaluations_per_cycle | [0,4] 默认 1 | runtime_policy.py:129 / cycle_ports genesis |
| evaluation_seed_count | 默认 2 夹 [2,4]；扩种至多 1 次 | config.py:278-280 / cycle_ports:315 |
| candidate_max_extra_steps | 默认 24（流程界限 [4,128]） | configs / runtime_policy.py:125 |
| candidate_probation_cycles | 默认 2 ∈ [0,16]；非劣 -0.01 | config.py:110 |
| task_holdout_delay_cycles | 默认 1（registry 强制 ≥1） | config.py:80 / registry.py:271 |
| cohort_limit / task_authoring_attempts / task_proposals_per_cycle | [1,12] / [1,4] / [1,8]，默认 3/2/3 | runtime_policy.py:122-124 |
| population_max_cells | 默认 128（代码默认 256） | cycle_ports genesis :6775 / population.py:32 |
| 试用期 breach | delta < -margin（-0.01） | cycle_ports.py:5197 区域 |

## 密封评测与工作区（evolution/）

| 常量 | 值 | 位置 |
|---|---|---|
| MAX_WORKSPACE_BYTES / overlay | 32 MiB / 8 MiB / 64 文件 | evolution/arm_evaluation.py:29-31 |
| 评测 timeout | ≤3600s | sealed_evaluation.py:401 |
| sealed suite / worker 输出 / cases | 1 MiB / 64 KiB / 1..128 | sandbox/sealed_evaluation.py:15-17 |
| 单 case timeout | min(remaining, 120)s | sandbox/agent.py:881 区域 |

## 动态任务（dynamic_tasks/ + taskpacks/）

| 常量 | 值 | 位置 |
|---|---|---|
| 任务归档 / 文件数 / 单文件 | 16 MiB / 512 / 2 MiB | dynamic_tasks/forge.py:18-20 |
| TASK_SPEC | 总 256KiB / prompt 32KiB / 源 64KiB / cases ≤100 / mutants ≤8 / clauses 1..16 | dynamic_tasks/builder.py:25-29, :294 |
| case name / steps / clause_ids 列表 | 128 字符 / 1..128 步 / ≤8 | builder.py:79-117 |
| 沙盒验证 timeout | (0, 3600]s | taskpacks/runner.py:27 |
| 密封评估 timeout | 120s ×2 suite | taskpacks/runtime.py:195-201 |
| failure_summary | 前 8 条 × 200 字符 | runner.py:100-104 |

## 环境构建（environments/）

| 常量 | 值 | 位置 |
|---|---|---|
| build_count | 恰 2 | environments/runtime.py:87-88 |
| build steps / step timeout | ≤32 / ≤1800s | models.py:149, :113 |
| max_output_bytes / receipt size | [1,8GiB] / ≤16GiB | models.py:154, :255 |
| 依赖 | ≤256（policy 上限 1024）；单依赖下载 ≤1GiB/300s | models.py:312 / runtime.py:597-598 |
| 构建/扫描总时限 | 86,400s / 600s | runtime.py:599-600 |
| step argv | 1..32 项、单项 ≤4096 | models.py:106-110 |

## 沙盒（sandbox/）

| 常量 | 值 | 位置 |
|---|---|---|
| 暂存归档 | 16MiB 压缩 / 64MiB 展开 / 4096 条目 | sandbox/types.py:13-15 |
| exec | argv ≤64×16KiB、stdin ≤1MiB、timeout ≤3600s、输出 >1MiB kill | agent.py / wsl.py 常量区 |
| 可写路径 | ≤64 条 | agent.py:79 |
| 容器默认 | 1 CPU / 1GiB / pids 256 / tmpfs 256m noexec | agent.py:970-991（可被策略信封 [1,8]/[1,8]/[64,1024] 覆盖） |
| 镜像归档（save_image） | timeout 3600s；内容寻址幂等 | agent.py（2026-09-15） |
| campaign 卷 | ext4 ≤8 GiB | bootstrap.py:20 |
| workspace | 恰 64 MiB | bootstrap.py:19 |

## harness（evolution/surfaces.py + wsl agents）

| 常量 | 值 | 位置 |
|---|---|---|
| MAX_HARNESS_CHANGES / FILE / TEXT / ITEM | 64 / 768KiB / 2000B / 512B | surfaces.py:48-51 |
| subject / workflow | 16KiB+2KiB / 数组 1..16×2000B、steps ≤1000 | surfaces.py:264-265, :218-261 |
| agent 树限 | 单文件 4MiB / 总 128MiB / changes 1..128 | wsl_harness_agent.py:47-48, :243 |
| 金丝雀 | 根映射默认+显式覆盖、≤6 文件、pytest ≤300s、compile ≤120s | harness.py:632-633 / wsl_harness_agent.py |
| supervisor 请求/响应/周期结果 | 64KiB / 1MiB / 245,760B | wsl_supervisor_agent.py:29-31, :57 |
| Tier2 rlimit | NOFILE 256 / FSIZE 4GiB / CPU 8h / AS 4GiB | wsl_supervisor_agent.py:616-629 |
| 探针 rlimit | NOFILE 64 / FSIZE 64KiB / CPU 600s / AS 2GiB | :605-614 |
| sidecar body | req ≤64MiB / resp ≤256MiB | gateway_sidecar.py:22-23 |
| GitPublisher | timeout (0,3600] 默认 120s、单次重试；checkpoint 文件 ≤768KiB | publishing/publisher.py:84-86 / connectors/git_checkpoint.py:24 |

## 研究与存储（research/ + 基础层）

| 常量 | 值 | 位置 |
|---|---|---|
| URL 文本 | ≤2048 无控制字符、https:443、禁凭据/fragment/私网 IP | research/url_security.py:52-94 |
| broker 下载 / 重定向 | 16MiB / ≤5 跳 | research/broker.py:15-32 |
| SearxNG | 响应 2MiB、结果 ≤100、loopback:8888 | research/searxng.py:33-34 / url_security.py:103-104 |
| PDF | 8MiB / 256 页 / 页文本 64KiB / 输出 1MiB / pypdf 6.14.2 | research/pdf_extractor.py:19-24 |
| github 快照 | 2048 文件 / 8MiB / 64MiB 总 / 元数据 4MiB | research/github_collector.py:103-119 |
| skill bundle | 64 文件 / 256KiB / 7 后缀 | research/github_skill_bundle.py:15-17 |
| 导入清单 | 1MiB / 64MiB / 2048 文件 / 权限 ≤32 / 依赖 ≤128 | research/imports.py:22-29 |
| 归档校验 | 10,000 条 / 256MiB / 单文件 64MiB / 压缩比 100 | research/archive.py:12-17 |
| 知识库 | summary 16KiB / blob 8MiB ×128 / 快照描述 512KiB / query 512B | knowledge.py:23-33 |
| CAS 工件默认 | 64MiB（镜像归档走旁路 blobs 目录） | artifacts.py:49 |
| 插件源 | 单文件 64KiB / ≤8 / 总 192KiB；I/O 64KiB(1MiB)/256KiB(4MiB)/timeout 30(300) | plugins/abi.py:22-24, :133-141 |
| 插件能力 | mem 512MiB[16MiB,4GiB]、pids 64[1,512]、max_actions 32[1,128] | plugins/abi.py:179-186 |
| MCP | tools 1..64×128 字符、结果 256KiB、响应读 2MiB、timeout 15s[1,300]、授权 1..64、租约 300s[1,86400] | mcp/bridge.py, registry.py, evolution.py 各处 |
| 议会 | 24 条 / 4,194,304 token；claims ≤8；证据引用 ≤16；裁决 history 3 / probation 2 | council.py:632, :209, :100, :578-580 |
| 策略 | submit 32KiB / proposals 8 / 实验 12 任务×2 种子 | strategy.py:26-30, :701-704 |
| 目标治理 | 批准门 3 连续影子 / 试用期 2 干净周期 | objectives.py:672-681, :725 |
| 事件存储 busy | 8 次 × 2^attempt | event_store.py:48-49 |
