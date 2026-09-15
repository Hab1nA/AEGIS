# 03 基础层

## 定位

全部子系统的公共地基：内容寻址身份、追加式事件存储、CAS 工件、跨进程锁、项目级环境加载。设计母题贯穿全仓：**内容寻址身份、append-only、乐观 CAS、fail-closed**。

## canonical_json 与内容寻址（`models.py`）

- `canonical_json(value)`（`models.py:89-97`）：`freeze_json` → `json.dumps(ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",",":"))`。全仓事实标准——任何内容寻址 id 都是 `前缀 + sha256(canonical_json(payload))`。
- `freeze_json`/`thaw_json`（:58-86）：递归不可变化（list→tuple、dict→MappingProxyType），拒绝非有限 float、非字符串键。
- `Role` StrEnum（:100-103）：warrior / judge / prosecutor 三角色。
- 设计约束：`models.py` 零内部依赖（:1-7），防循环依赖。
- 例外：`publishing/models.py:18-25` 有本地 `canonical_json`（ensure_ascii=True），用于 Git 边界的 ASCII 安全。

## 事件存储（`event_store.py`）

- SQLite WAL 单表 `events(campaign_id, sequence>0, UNIQUE(campaign_id,sequence))`（:32-42）——每 campaign 一条独立序列流。
- **CAS 追加** `append_if_sequence(campaign_id, expected_sequence, ...)`（:164-218）：BEGIN IMMEDIATE 内比对 MAX(sequence)，不匹配抛 `EventStoreSequenceConflict`（:24-25）。这是全仓"重复施加=幂等或冲突"语义的底座。
- 无 CAS 的 `append`（:118-162）直接 MAX+1，用于单向审计流（计量、probation）。
- payload 必须 canonical JSON 可序列化（:132-135）；created_at 时区感知归一 UTC。
- 读：`read(campaign_id, after_sequence, limit)`（:231-251）；`max_sequence`（:253-262）。
- busy 退避：8 次、2^attempt（:48-49, :115）。

## CAS 工件（`artifacts.py`）

- `ContentAddressedArtifactStore`：kind `[a-z][a-z0-9-]{0,63}`（:15）；`artifact_id = {kind}-sha256:{64hex}` 且前缀必须等于 kind（:16, :27-43）；路径 `{root}/{kind}/{digest}`（:130-136）。
- 写入原子性：`.staging-` 临时文件 + fsync + `os.link`（create-only，容忍 FileExistsError）+ 目录 fsync（:86-110）。已存在目标先验证再复用（:82-84）。
- 默认上限 64MiB（:49）；`put_json` = canonical_json + `put_bytes`（:66-69）。
- **每次读取全量验证**（:138-148）：拒 symlink、必须常规文件、sha256+size 必须匹配内容地址。
- 消费方：`cli.py:341`、`subagent_worker.py:168`、`wsl_cycle_runtime.py:144`。

## 跨进程执行锁（`execution_lock.py`）

- `CampaignExecutionLock`：非阻塞 OS 文件锁（Windows `msvcrt.locking(LK_NBLCK)` / POSIX `fcntl.flock(LOCK_EX|LOCK_NB)`，:33-40），冲突抛 `CampaignAlreadyRunningError`；内核在进程死亡时自动释放（:17）。
- 锁路径 `{data_dir}/locks/campaign-{sha256(campaign_id)[:24]}.lock`（:20-21）。CLI 在 `evolution-cycle --run` 外层持有（`cli.py:1308` 附近）。

## envfile（`envfile.py`）

- `.aegis.env` 项目级加载：8 键白名单（`_RELAY_KEYS` :17-28）——AEGIS_OPENAI_BASE_URL / API_KEY / USER_AGENT / TIMEOUT_SECONDS、AEGIS_SEARCH_BASE_URL、AEGIS_ALLOW_INSECURE_SEARCH_LOOPBACK、AEGIS_DATA_DIR、AEGIS_HTTPS_PROXY。
- `setdefault` 语义：显式进程环境永远优先（:47-74）；不写机器/用户级环境。
- CLI 入口最早调用（`cli.py:1189` 附近）。

## 领域值对象（`models.py` 其余 + 各子模块 models）

统一模式（curriculum/dynamic_tasks/attribution/publishing/activation 均复用）：

- 全部 frozen dataclass + slots；`from_mapping` 严格字段集（多键/缺键即错）。
- 内容寻址 id 在 `__post_init__` 或工厂内重算比对——载入即验证，防篡改。
- "重复施加"语义三档：同内容幂等返回；同 id 异内容/非法前态 → 冲突异常；非法转移 → 状态机错误。

## 边界

- 本层被一切子系统调用，自身只依赖 stdlib。
- 事件流命名约定：campaign 主流用 `campaign_id`；子系统隔离流用 `{campaign_id}:{子系统}:v{N}`（roles/mcp/activation）或 `campaign_id + "/后缀"`（attribution、probation、计量）；修复流 `repair:{incident_id}`；生成激活流 `activation:{activation_id}`。全表见 [catalog-events](catalog-events.md)。
