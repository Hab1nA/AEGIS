# 14 网关与记账

## 定位

模型流量的唯一出入口（`gateway/`）与三层记账：attempt 级预留账本（`runtime_ledger.py`）、frozen 用量构造（`usage_accounting.py`）、campaign 成本信封（`runtime_policy.py`，见 [17](17-runtime-policy.md)）。设计核心：**传输 attempt（含重试）都消耗 provider 资源，各需 reserve/settle；用量语义冻结在可进化根之外**。

## 网关（`gateway/client.py`）

- 协议固定：`POST {base_url}/responses`，载荷无条件 `text={"format":{"type":"json_object"}}`（:365）；system prompt 必须含 "json"。无 chat/plain/json_schema 兼容模式。
- `GatewayConfig`（:39-73）：base_url 必须 HTTP(S)、禁 URL 凭据、http 仅显式 loopback 且 `allow_insecure_loopback=True`；env 键 `AEGIS_OPENAI_BASE_URL/API_KEY/TIMEOUT_SECONDS`（默认 900s）+ `AEGIS_ALLOW_INSECURE_LOOPBACK`；`__repr__` 永远脱敏 key。
- `RetryPolicy` 默认：6 次、0.5s 基础、4s 上限，`delay = min(4.0, 0.5*2^attempt)`（:108-110, :253）。可重试：HTTP {408,409,429} ∪ ≥500（除 400/404/405/415/422）、URLError/Timeout/ConnectionError/OSError（Windows DNS 抖动会抛裸 FileNotFoundError，:231-236）、`GatewayTruncationError`。
- **截断显式化**（:305-316）：`status=="incomplete"` 或有 incomplete_details → 抛 `GatewayTruncationError`（携带 usage 入账）——截断响应绝不当模型输出返还。
- 文本提取 `_extract_text`（:372-412）：优先 output_text；否则倒序取最后一个 message 项（agnes 隐藏推理模型 reasoning 项在前、output_text 可能缺失）；剥离 ```json 围栏。
- **conservative 预留**（:318-332）：每次 attempt 在网络 I/O 前构造保守上界（输入字节数 + max_output_tokens，verified=False）供账本预留；成功后以真实 usage 结算。
- observer 绑定一次禁重绑（:185-198）——替换 observer 会造成漏账或双账。
- runtime policy 感知：绑定 provider 后每次 complete 现场重建 retry/timeout（键 gateway_max_attempts 等，:162-174）。

## 传输（`gateway/transport.py`）

- **子进程隔离**：阻塞 TLS 握手可握住 GIL 冻结 controller；网络等待放子进程，父进程可硬性 deadline 并终止（:28-81）。
- **大响应死锁修复**：子进程 64KiB 分块读响应再一次性发送（:63-71）——旧实现先 join 后 recv 在响应超管道缓冲时互相等待。
- Windows 用 worker-thread 路径（阻塞 SSL read 可无视 socket timeout，:274-277）；connect 阶段单独 30s 封顶（死路由不烧完整 deadline :84-110）。
- 代理仅认 `AEGIS_OPENAI_HTTPS_PROXY`，绝不继承系统/WinINET 代理（:43-56）；`_NoRedirect` 拒绝一切重定向（防 Authorization 重放他 origin）。

## Frozen 用量（`usage_accounting.py`）

- 位于一切可进化根之外——喂预算/fitness/审计的数字属于评分函数，agent 不得改产生它们的代码（:1-12）。`TokenUsage` 的唯一定义/构造点；`gateway/types.py:9-13` 仅 re-export。
- `extract_usage` 三分支（:46-88）：responses 形状（input/output_tokens + details）；chat 形状（prompt/completion_tokens，agnes hub 实测行为）；兜底 chars/3 启发式（verified=False）。
- **不可能数字 → anomaly + verified=False**（`_finalize` :91-119）：output 超预留、reasoning>output、cached>input、**output=0 而文本非空**（零是"可能"数字，显式标记防免费输出申报）。anomalies 进角色证据与 Prosecutor `usage_anomalies`。

## Attempt 账本（`runtime_ledger.py`）

- 事件：`gateway_attempt_reserved` / `gateway_attempt_settled`；attempt_id = 内容地址（context+policy+protocol+attempt_number+request_digest，:573-600）。
- `before_attempt`（reserve）：解析 AccountingContext（campaign/cycle/stage/role/invocation/paired_design/stage_ordinal）→ 选 policy（paired design 或 stage boundary）→ **预算授权 `_authorize`** → CAS append（16 次并发重试）。
- **授权判定**（:357-427）：v2 投影四量（max_total_tokens/max_requests/max_model_invocations/max_active_runtime_seconds）任一超即 `RuntimeBudgetExceeded`（传输 I/O **之前**拒绝）；**waste 池**：失败 attempt 计 waste 三项、以病态上限防失败风暴无限自旋；子代理单独预算（失败子 attempt 不占子预算）。
- **维护模式**（:429-488）：超预算后 policy 置 maintenance_only；仅 Prosecutor + stage=maintenance 可继续（convergence grace：同 invocation 曾用父 policy 限 3 attempts）；maintenance 每 policy 每 cycle 限 1 invocation × 3 次传输尝试。
- `after_attempt`（settle）：按四元组找唯一 reservation；幂等；失败结算 conservative usage 入 waste。
- 重放完整性：严格字段集、归属校验、attempt_id 重算比对、settlement 先于 reservation 即错（:626-737）。
- **绑定拓扑**：observer 创建与绑定在 frozen 侧（`cycle_ports.py:6553-6560`、`subagent_worker.py:180-192`），但调用点在可进化的 `gateway/client.py:217/353`——因此 2026-09-15 加了 sidecar 计量三方对账（[06](06-wsl-first-runtime.md)）：sidecar 观测 vs 账本 vs cycle 产物交叉核验。

## 边界

- 凭据边界：宿主 env / `.aegis.env` → sidecar（生产，[06](06-wsl-first-runtime.md)）；宿主路径直接 env。
- 预算数字来源：`autonomy_budget.py` 结构性底线（v2 每 cycle 8 个模型阶段、min requests 48、role shares 0.55/0.225/0.225，:8-31）——preflight 容量检查用，非运行时执行器。
