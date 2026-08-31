# AEGIS v2

AEGIS 是一个面向软件工程智能体的受监督、对抗式、自我进化循环系统。动态任务库从仓库自有的锚点（anchors）冷启动，Judge（法官）锻造下一批任务，Warrior（战士）在隔离沙箱中求解任务，Prosecutor（检察官）审计使用情况与课程假设，三个角色通过独立反思外加委员会投票进行协商。角色版本通过内容寻址候选、归因分支（attribution arms）和试用期激活来进化；失败的循环由 Prosecutor 管道修复，或回滚到最后已知良好状态（last-known-good）。

v1 的固定 12 任务战役控制器、晋升漏斗（promotion funnels）以及技能/策略自动晋升运行时已被移除。当前设计仅支持动态模式：`task_pack_paths` 必须为空，且 `autonomy_v2.enabled` 必须为 true。

## 安装与测试

需要 Python 3.12+、专用的 WSL2 发行版、无根（rootless）Podman，以及一个兼容 OpenAI 的中继服务。

```powershell
python -m pip install -e ".[dev]"
python -m pytest
```

仅在宿主机进程中设置密钥；它们绝不会被复制进 WSL。
项目级配置：在仓库根目录创建一个被 git 忽略的 `.aegis.env` 文件（仅由 AEGIS CLI 加载，Codex 或其他工具绝不会加载）：

```powershell
AEGIS_OPENAI_API_KEY = "sk-..."
AEGIS_OPENAI_BASE_URL = "https://apihub.agnes-ai.com/v1"
# 结构化角色请求固定使用 Responses + json_object；agnes-2.5-flash 以
# 顶层 reasoning_effort 开启 thinking（budget_tokens 打满 65536）。
# （参见 docs/autonomous-evolution.md）。
AEGIS_OPENAI_STRUCTURED_FORMAT = "json_object"
# 隐藏推理（hidden-reasoning）中继服务可能较慢；为每次模型调用设置充裕的超时时间。
AEGIS_OPENAI_TIMEOUT_SECONDS = "3600"
```

在宿主机进程中显式设置的 `$env:AEGIS_OPENAI_*` 仍会覆盖该文件。
# 可选的模型网关代理；留空表示直连（绕过系统代理）。
$env:AEGIS_OPENAI_HTTPS_PROXY = ""
$env:AEGIS_SEARCH_BASE_URL = "http://127.0.0.1:8888"
$env:AEGIS_ALLOW_INSECURE_SEARCH_LOOPBACK = "true"
$env:AEGIS_HTTPS_PROXY = "http://127.0.0.1:7897"
$env:AEGIS_DATA_DIR = "$env:LOCALAPPDATA\AEGIS"
```

当搜索端点或代理不可用时，研究功能采用失败即关闭（fails closed）策略；任务执行始终离线进行。

## 首次安全运行

1. 渲染专用的 WSL 安装包：

   ```powershell
   aegis sandbox-bootstrap --image registry.example/aegis@sha256:<64-hex-digest>
   ```

2. 按照 [WSL 运行手册](docs/wsl-runbook.md) 操作，然后要求 `aegis doctor` 通过。仓库自有的任务镜像与本地研究服务资源位于 `deploy/wsl/` 下。

3. 创建动态 v2 战役并运行真实门禁（gate）：

   ```powershell
   aegis --data-dir $smokeData campaign-create configs/evolution-smoke.example.json
   aegis --data-dir $smokeData autonomy-preflight evolution-smoke-v2
   aegis --data-dir $smokeData evolution-cycle evolution-smoke-v2 --run --repair
   ```

   重复执行 `evolution-cycle ... --run --repair` 以推进每一代。使用 `--dry-run` 生成只读计划，使用 `--no-seed-anchors` 跳过冷启动，使用 `--cohort-limit N` 限制队列规模。`status`、`report` 和 `replay` 读取持久的 v2 事件流。

## 关键机制

- 动态任务库：`GenesisSeeder` 仅在任务库为空时注册 12 个内置锚点。每个任务在注册前都必须通过 reference/defect/mutant 校验。Fresh 任务优先入选下一轮 cohort（Judge 的新题立即被采用），锚点按需回填、渐进退役。校验失败不烧 task_id（可改名重投），拒绝原因与 per-case 失败明细回传给下一轮 forge。
- 角色循环：Warrior/Judge/Prosecutor 通过 `RoleAgentRuntime` 运行，使用严格的 JSON 动作、经过校验的令牌用量，以及每个角色独立的沙箱生命周期。forge context 携带上周期校验错误、remediation 义务、检察官课程假设与 council 议程——"失败一次，不再重复失败"。
- 委员会：三次独立反思加上一次主席审议，生成下一周期的议程；objective 修正需要包含检察官在内的 2/3 多数支持。
- Git 检查点：Warrior 可以通过日志连接器（journaled connector）调用 `aegis.git_checkpoint`；`GitPublisher` 在路径授权与密钥扫描之后，仅推送只创建（create-only）的候选引用。需要 `autonomy_v2.public_repo_url`。
- 归因：每个周期都会向 `data_dir/attribution_arms.jsonl` 追加一个 `EvaluationArm`，并生成内容寻址的 `qualify_attribution` 报告；如果没有同队列配对数据，报告会如实标记为 `invalid-design` 或 `confounded`。
- 候选评估：影子评测的冠军基线直接复用本周期主循环 solve（同 cohort、同绑定、完整步数），每个 seed 只需跑候选臂；双臂步数对齐主循环（`candidate_max_extra_steps=24`，preflight 校验不超过 `max_agent_steps`）。合格门槛改为 seed 均值判定（fresh 提升 ≥0.02）加每-seed 地板（≥−0.10），单 seed 噪声不再一票否决。未启用的面在收集阶段即被拒绝，不占用每周期唯一的评估名额。
- 进化面：`workflow`、`subject`、`plugin`、`environment`（以及受控的 harness-code）在 `src/aegis/evolution/surfaces.py` 中有严格的 JSON 模式与授权规则。只有 Warrior 可以提出提案；插件可以是源码内嵌（`sources` + 空 `image_digest`，entrypoint `("python3", "<file>")`，入口函数 `handle(action, arguments)`），在沙箱内以 stdin/stdout JSON 协议真实执行。
- 环境构建器：两次独立构建的 digest 一致性作为可复现性证据记录在 receipt 上（默认 `require_reproducible=False`，可配置强制）；Trivy 缺失或拒绝时降级为 `scanner_passed=False` 证据，不阻断构建。
- 活跃角色集绑定：每个角色在周期开始时解析一个 `CompositeRoleManifest`（`schema_version=2`：模型配置、workflow、subject、插件、运行时镜像、预算策略）；被激活的 champion workflow、subject、plugin 和环境镜像会注入到下一代的实际运行时封套与沙箱准备中。旧的 genesis 清单回退到默认值。
- 检察官实权：`aegis.adjust_runtime_policy` 除成本信封外还可调有限流程参数（`cohort_limit`、`task_authoring_attempts`、`task_proposals_per_cycle`、`candidate_max_steps`、`council_max_messages`，均有界）；审计的课程假设与 role_candidates 提名进入 forge/候选管道，结果如实反馈。
- 修复：失败的周期会记录 `cycle_failed_recovery_started`；Prosecutor 补丁被发布、校验并激活，否则周期回滚。中断/失败的周期通过 `retry` 转换重试同一代。
