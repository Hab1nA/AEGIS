# 13 角色 / 插件 / MCP

## 定位

三个"模型能力的延伸"子系统：角色代际注册表（谁在运行）、插件 ABI 与 broker（受控工具扩展）、MCP 桥（外部工具服务）。

## 角色注册表（`roles/registry.py`）

- 事件 6 个：`role_candidate_collected_v2/validated_v2/qualified_v2`、`role_active_set_committed_v2/rolled_back_v2/objective_rebound_v2`；隔离流 `{campaign}:roles:v2`（:57-60）。
- 候选状态：COLLECTED→VALIDATED→QUALIFIED→ACTIVE；SUPERSEDED/REVOKED。
- `commit_active_set`（:248-285）：CAS expected_current_active_set_id；全部候选 QUALIFIED 且绑同一 objective；激活时旧候选→SUPERSEDED。
- 血缘校验（:416-428）：仅 version 1 可无父；否则父须同角色同 constitution 且 version+1。

## 代际 bundle（`roles/generation.py`）

`GenerationBundle`：一次完整三角色代际的不可变清单——generation_id/parent 内容寻址、`controller_abi ∈ [1,1_000_000]`、source_commit（40hex）、roles 恰为 (warrior, judge, prosecutor)、每角色 `RoleGeneration`（model_profile_sha256/workflow/subject/plugin ids/runtime_image OCI 摘要/budget_policy_sha256）。checkpoint 插件把进化产物钉进 Warrior 的不可变 bundle。

## 角色执行适配器（`roles/runtime.py`）

- `RoleGenerationRuntime.execute`：沙盒内固定 runner `/opt/aegis/bin/role-generation-runner`（:25，ABI 不可改）；`--json-abi 1`；stdin=请求 JSON。
- 请求 ≤128KiB context / objective ≤4KiB；收据 ≤256KiB 严格 JSON（拒重复键/非有限数）+ **attestation 12 字段全量交叉验证**（:643-702）；禁止 stderr；插件 ≤32 个。
- workspace 授权：WARRIOR 仅 `output/` 递归可写，其他角色无（:546-550）。
- `BrokerRolePolicy.direct_plugin_execution` 必须为 False（:135-136）——插件必经 broker。

## 子代理（`subagents.py` + `subagent_worker.py`）

- 每个子代理一个有界 Python 子进程：`python -m aegis.subagent_worker <spec.json> <workdir> <result.json>`；父进程不触碰 worker 文件系统，轮询回收，失控 kill。
- spec（≤64KiB canonical）：subagent_id=内容 sha256；executor ∈ {script, runtime}；limits 默认 steps=8/timeout=180s/result=64KiB；并发默认 2 ∈[1,16]。
- worker：`LocalWorkspaceSandbox`（真实主机命令限 workdir、无网络、弹 PYTHONPATH）；runtime 执行器跑真 `RoleAgentRuntime`（动作面收窄为 workspace.read/write + submit；research 刻意不可用 :201）；**会计绑定**经 env `AEGIS_SUBAGENT_ACCOUNTING_BINDING`（4 键）→ 子 AccountingContext stage=`subagent:{id}`——子代理用量入父账本（:160-192）。
- 结果原子写 + 超限降级链（:261-270）；evidence_id=`subagent-result-sha256:`。

## 插件 ABI（`plugins/abi.py`）

- `PluginManifest` 全字段：plugin_id（反域名式）、version 严格 semver、abi_version ∈[1,1000]（policy 只允许 {1}）、image_digest（源码插件必须空，否则 OCI 摘要钉定）、entrypoint（源码插件必须 `("python3", "<源文件>")`，暴露 `handle(action, arguments)`）、roles、actions、capabilities、provenance_sha256、sources。
- **源码插件**：base64 Python 内嵌，单文件 ≤64KiB / ≤8 个 / 总量 ≤192KiB（:22-24）；运行时 stage 进沙盒 `/tmp/aegis-plugin-<digest16>/`，stdin 传 JSON 参数、stdout 收 JSON 结果（`agent_runtime.py:832-914`）。
- `EffectClass`：PURE / WORKSPACE_READ / WORKSPACE_WRITE / EXTERNAL；效果-幂等一致性（pure/read 必须 READ_ONLY；变更动作必须带 operation id）；写效果 ⇔ 可写授权；EXTERNAL ⇔ BROKERED_PUBLIC 网络。
- `ActionSpec`：input/output 严格 object schema（additionalProperties=False）；in 64KiB(≤1MiB)、out 256KiB(≤4MiB)、timeout 30s(≤300)。
- 进化面约束（surfaces.py:288-335）：候选插件效果 ⊆ {PURE, WORKSPACE_READ, WORKSPACE_WRITE}——EXTERNAL 不可提议；源码插件不得声明 workspace_write（返回数据让调用方写）。

## ToolBroker（`plugins/runtime.py`）

- 不可演化 fail-closed broker（:1-6）：绝不 import 插件代码；跨界值按不可信 JSON 重验；自带迷你 JSON-Schema 校验器（不支持的关键字一律拒 :497-584）。
- **一次性 grant**：issue_grant（operation-id 契约按效果类；EXTERNAL 需 connector+journal 成对）→ execute **先消费再过信任边界，失败不恢复**（:738-740）；nonce 复用拒绝。
- 证据规则（:427-438）：WORKSPACE_WRITE 仅 diff 证据（before≠after 强制，路径须落在可写授权内）；EXTERNAL 必须 intent+external receipt；只读不得带副作用证据。
- 外写链：插件动作 → broker → journal 先记 intent（`connectors/journal.py`，request_id 幂等/冲突语义）→ 控制面连接器**再校验**不可信参数后执行（`connectors/git_checkpoint.py`：EffectClass.EXTERNAL 校验、changes ≤64、单文件 ≤768KiB、base_commit 40/64hex、输出哈希绑定）。

## MCP（`mcp/bridge.py` + `registry.py` + `evolution.py`）

- **候选不可变**：`McpCandidate`（binding+授权矩阵+manifest 三者一致，tool 集恰等）只定义"提议什么"；`McpToolAuthorization` 审批不变量 `rank(risk) ≤ rank(stage)`（L0-L3 风险 vs discovery/observation/operation/administration 四阶，evolution.py:99-100）。
- **桥**（bridge.py）：server 跑在控制面侧，沙盒保持离线；Warrior 经 `aegis.mcp_call` 调用。JSON-RPC 2.0 子集；端点 https 或 loopback http；DNS 解析后 private/loopback（非本地端点）即拒，**每次 RPC 前重验 DNS pin**（:251-253）；禁重定向；响应读 ≤2MiB、结果 ≤256KiB。`deploy` 做 tools/list 活性检查；`deploy_candidate` 做 catalog 与 binding 的一致性 + schema sha 漂移检测。
- **租约注册表**（registry.py）：事件溯源流 `{campaign}:mcp-runtime:v1`；状态机 PROPOSED→VALIDATED→QUALIFIED→PROBATION→ACTIVE→REVOKED（ACTIVE 仅可撤销）；**所有变更需活租约**（默认 300s ∈[1,86400]，token 64 字符）；probation 观察 1..10000 次，**一次失败立即 REVOKED**（:421-428）；ACTIVE 只能走 `activate_from_evolution`（evolution 注册表保持 proposal/qualification 权威，此投影独占运行时事务）。

## 边界

- 插件/MCP 进化的收集与资格在 [08](08-candidate-lifecycle.md)；角色激活 saga 在 [18](18-recovery-activation.md)。
- research 动作（github./paper.）的底层在 [15](15-research.md)。
