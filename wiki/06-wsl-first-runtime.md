# 06 WSL-First 运行时

## 定位

生产周期在发行版内、由 champion 树的代码执行。宿主是薄客户端：准备 campaign → 启动 → 轮询 → 收结果。三个组件：supervisor（双层启动 + 异步周期）、gateway sidecar（凭据边界 + 计量）、cycle_status/cancel（结果回传协议）。

## 双层启动（`evolution/wsl_supervisor_agent.py`）

`launch_cycle` 请求字段：`{version, operation, operation_id, campaign_id, expected_commit, request_payload, gateway_credentials}`（:136-144）。凭据不进回执绑定哈希（:159-166）。

### Tier 1：boot 探针（`_launch_probe`）

- 严格沙盒子进程：`unshare --user --map-root-user --mount --pid --fork --kill-child --mount-proc` + `setpriv --no-new-privs --bounding-set=-all`（:343-363）+ 微型 rlimit（NOFILE 64/FSIZE 64KiB/CPU 600s/AS 2GiB，`_limit_probe_child`）。
- 固定 `_BOOTSTRAP`：import `aegis.evolution.cycle_entrypoint`、确认 `run_cycle` 可调用、打印 import + heartbeat 事件（不执行周期）。
- 失败 → receipt `status=boot_failed` + typed failure_kind（import_failed/heartbeat_failed/launch_failed/probe_runtime_failed/output_limit）；宿主自动回滚到 last_known_good 后抛错（`cli.py` 薄客户端）。

### Tier 2：真实周期执行器（`_launch_cycle`）

- 先启动 sidecar（`_start_sidecar`）：固定模块 `aegis.gateway_sidecar`，凭据 env 注入，loopback 随机端口，stdout 一行 `{"event":"listening","port":N}`；计量文件 `data/metering/gen-<N>.jsonl`。
- 分离子进程：`sys.executable -c _CYCLE_BOOTSTRAP`，env `PYTHONPATH=<champion worktree>/src` + `AEGIS_OPENAI_BASE_URL=http://127.0.0.1:<port>/v1` + `AEGIS_CYCLE_STATUS_PATH`；**无任何凭据变量**（`_cycle_env` 刻意排除）。
- rlimit（`_limit_cycle_child`）：NOFILE 256 / FSIZE 4GiB / CPU 8h / AS 4GiB / CORE 0。
- 固定 `_CYCLE_BOOTSTRAP` 拥有状态文件：`running` → 执行 `run_cycle(payload)` → `completed`（cycle_result ≤245760B）/ `failed`（error ≤1024B）。champion 只拥有 `run_cycle` 的实现——"可进化 hook，不可选模块/命令"契约保持（`cycle_entrypoint.py` docstring）。
- generation 由 agent 从 `cycles/gen-N` 目录计数分配（`_next_generation`），payload 附带 `data_root`（campaign/data）与 `source_commit`（champion）。
- launch 立即返回 receipt `status=launched`（cycle_generation + cycle_pid）。

### 周期结果协议

- `cycle_status {campaign_id, generation}`：读 status.json → `{status, metering, cycle_result?, error?, exit_code?}`；pid 已死但无终态 → 标记 failed（孤儿防护，`_cycle_pid_exited`）。
- `cancel_cycle`：pid 归属校验（`/proc/<pid>/cmdline` 含 status 路径）后 killpg，状态置 cancelled。
- 单活动周期约束：launch 前 `_ensure_no_active_cycle` 扫描全部 gen 状态，有 launched/running 即拒绝。

## 客户端（`evolution/wsl_supervisor.py`）

- `launch_cycle(..., gateway_credentials=)`：凭据校验（HTTPS base_url 必需、4 键白名单）；回执哈希排除凭据字段（与 agent 侧一致）。
- `CycleLaunchReceipt`：16 个 legacy 字段 + 可选 `cycle_generation`/`cycle_pid`；`launched` 状态要求探针握手 + pid 齐备（:100-118）；旧 16 字段回执继续可重放（legacy 分支 :66-70）。
- 轮询循环（`cli.py:_run_v2_cycle_wsl_first`）：15s 间隔；`completed` → 回传 cycle_result + boot receipt + `gateway_metering`；**零计量对账**——声称有 artifacts 但 sidecar 计量请求数为 0 → 拒绝（记账绕过守卫）；`failed/cancelled` → 抛错；wall_time 超限 → cancel 后抛错。

## 网关 sidecar（`gateway_sidecar.py`）

- 唯一持中继凭据的进程；只转发 `POST /v1/responses`，其它 404；不跟随重定向；请求体 ≤64MiB、响应 ≤256MiB。
- **SSRF 防护**：启动时 `validate_url_target`（[15](15-research.md)）解析上游并拒绝非公网地址；连接钉住已验证 IP、SNI/证书仍校验原域名（`_PinnedHTTPSConnection`，防 DNS rebinding）。
- **计量**：每次请求一行 JSONL（ts/duration/outcome/status/request_bytes/response_bytes）；`metering_summary` 聚合供宿主对账。
- 生命周期：supervisor stdin 管道关闭即退出（stdout summary 行）。
- 回执：仅 loopback bind；发行版单用户 + netns private 下无 token（威胁模型已记录）。

## 发行版内标准执行器（`wsl_cycle_runtime.py`）

`execute_standard_cycle(payload)` = 发行版内的 `run_v2_cycle` 组装：

- 校验：action/campaign_id/config 一致性/test_mode 禁入/data_root 必须在 campaign volume 下（`_validated_data_root`）。
- 组件：EventStore/CAS/注册表（data root 下）+ `LocalAgentSandboxBackend`（doctor 必过）+ `ModelGateway(GatewayConfig.from_env())`（指向 sidecar）+ `LocalHarnessBackend` + McpBridge + 环境构建器（[16](16-sandbox.md)）+ research。
- 结果投影 `_bounded_result`：maintenance/repair/completed 三形状，附 `runtime_identity.executed_commit`；≤240KB。
- 默认 `cycle_entrypoint.run_cycle` 即委托本函数（`cycle_entrypoint.py`）——evolved 候选可以改写周期流程本身，但 frozen 字节比对 + supervisor 协议 + sidecar 边界在它的权限之外。

## 本地传输后端（`sandbox/wsl.py` / `evolution/harness_backend.py`）

- `LocalAgentSandboxBackend(WslSandboxBackend)`：仅覆写 `transport_argv`（`["/usr/bin/env", "AEGIS_SANDBOX_INTEROP_WARN=1", agent]`），协议/校验/固定 agent 路径全不变。
- `LocalHarnessBackend(WslHarnessBackend)`：同理，`transport_argv=(agent_path,)`。

## 边界

- 宿主→发行版唯一通道仍是 wsl.exe JSON agent（[02](02-architecture.md)）；发行版→宿主无反向通道。
- 凭据流向单向：宿主 env → launch 请求 → supervisor env → sidecar env；champion 进程 env 刻意排除。
- 旧发行版 agent 不认识新操作（sync/advance/canary/put）时：sync 为尽力而为（警告带回响应）；advance/canary 给出明确的"刷新发行版"错误。
