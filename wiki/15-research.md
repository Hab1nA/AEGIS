# 15 研究网关

## 定位

角色的一切外网读取经 `research/` 受控网关：IP 钉扎传输、逐跳 SSRF 校验、强制溯源、隔离导入（校验≠授权）。知识/技能库是只进不出的隔离存储。

## URL/地址校验（`research/url_security.py`）

`validate_url_target` 十条规则（:52-94）：文本 ≤2048 无控制字符；scheme ∈ policy（默认仅 https）；禁 URL 凭据；必须有 hostname；端口 ∈ allowed（443）；`localhost`/`*.localhost` 拒；解析出全部 IP；每个 IP 必须**公网**（is_global 且非 private/loopback/link_local/multicast/reserved/unspecified，:38-49）；fragment 拒；归一化空 path。
Loopback 窄例外（:101-140）：仅 http、仅字面量 127.0.0.1/::1、仅端口 8888、不做 DNS——本地 SearxNG 专用。

## 传输层（`research/http.py`）

- 手写 HTTP/1.1 客户端，**连接钉扎**：直连策略批准的 IP 字面量，SNI/证书仍校验 hostname（`SocketTLSTransport` :29-48）；不碰 DNS/系统代理。
- `PinnedHTTPSFetcher`：单响应；每地址最多 3 次重试且仅限 OSError/CDN 早断；peer 复核必须在 allowed 集合（:591-611）。
- **重定向绝不自跟随**：解析器返回 location 给上层，broker 每跳重新校验（:272）。
- 响应解析硬化（:209-273）：头部总量/行长上限、禁 obs-fold/无名头/重复头、transfer-encoding 仅 chunked 且不与 content-length 并存、204/304 空 body。
- `WslLoopbackHTTPFetcher`：WSL 内经 curl（无 shell argv、`--noproxy * --proto =http`）取本地 SearxNG（WSL localhost 转发不可靠，:412-490）。
- `LoopbackProxyTLSTransport`：显式本地 CONNECT 代理（`AEGIS_HTTPS_PROXY`）。

## Broker（`research/broker.py`）

策略强制门面：search（query ≤1000、limit ≤100、结果 URL 逐一重校验——搜索结果不可信）；fetch（≤16MiB、**每次跳转前重新 validate_url_target** 抗 rebinding、响应 URL 必须等于请求、重定向 ≤5、终态 2xx、产出 `Provenance.now`：sha256/size/media_type/redirect_chain）。

## 溯源与导入（`research/imports.py` + `runtime_imports.py`）

- 三类导入：github / paper / skill（`ResearchImportKind`）。
- **校验 ≠ 安装/执行**（:1-6）：产物 `execution_granted=False`；技能权限白名单 `{research.fetch, research.search, sandbox.exec, workspace.read, workspace.write}` 且禁止控制面词（budget/promotion/prosecutor/secret 等 :106-121）。
- github：精确 commit 快照——tree 必须 `truncated=False`、逐文件 git blob sha1 校验、27 种文本后缀白名单、UTF-8 无控制字符；snapshot_sha256 内容寻址（`github_collector.py`）。
- paper：仅 doi:/arxiv: 标识；Semantic Scholar/arXiv 元数据字段白名单 + 标识符必须匹配请求；arXiv XML 禁 DOCTYPE/ENTITY（防 XXE）；文本分页摘录 ≤256 条 × 64KiB；PDF 必须经沙箱 extractor 且绑定源哈希（:494-518）。
- `bind_research_import`：manifest 候选的 source_url/sha256/size 必须与 provenance 三方一致（`runtime_imports.py:85-110`）。

## PDF 沙箱抽取（`research/pdf_extractor.py`）

PDF 字节永不进控制面代码：单文件 tar stage 进沙箱、`python3 -I -c <固定脚本>`（pypdf 6.14.2 版本校验、拒加密 PDF、页数 ≤256、逐页 sha256、输出 ≤1MiB）；doctor 必须含 network_none 通过；finally destroy。

## 知识库（`knowledge.py`）

- 不可变跨轮知识：SQLite + **8 个 BEFORE UPDATE/DELETE 触发器**物理不可变（:252-328）；artifact_id 恒等于 `"sha256:{sha256}"`；同哈希幂等但元数据必须全等（否则 ConflictError）。
- 研究快照（github/paper/skill）归档：descriptor ≤512KiB + blob ≤128 个（单 blob ≤8MiB）+ locator 唯一典序。
- 知识是**建议性**数据：只存溯源与证据，绝不执行/安装/信任所存内容（:1-5）。角色经 `knowledge.search/remember` 动作访问。

## 技能库（`skill_registry.py` + `skill_validation.py`）

- **隔离注册表**：只存不透明字节 + 不可变清单；无 import/exec/解压/宿主加载路径；离开注册表的唯一形式是确定性 tar 给 `stage_archive`（:1-7）。
- 候选状态机 candidate → validated_pending → champion（superseded/revoked）；事件哈希链 + **10 个不可变触发器**；`synchronous=FULL`。
- 静态校验 8 检查（`skill_validation.py:78-87`）：身份/内容哈希、UTF-8、控制字符、依赖空、权限白名单、禁 shebang、禁危险入口（entrypoint/installer 赋值）。
- 晋级 CAS：`promote_evaluated` 要求 expected_champion_id + revision（"champion changed since evaluation was sealed"）；smoke+full 双相评测 safety/quality 全 verified 才 promotable。
- github→skill 确定性转换（`github_skill_bundle.py`）：必须含根级 SKILL.md、≤64 文件/256KiB、只输出声明式文本（从不执行源内容）。

## 归档防御（`research/archive.py`）

免解压 ZIP/TAR 校验：条目 ≤10000、展开 ≤256MiB、单文件 ≤64MiB、压缩比 ≤100、禁 symlink/设备/fifo、路径穿越全拒。

## 边界

- 消费方：`agent_runtime.py`（研究动作组）、`cli.py`/`wsl_cycle_runtime.py`（broker 组装）、`environments/`（依赖下载经同一 URL 策略）。
- skill.list/stage 是 Warrior 真实动作（CLI 构造 SkillRegistry 后接线）；stage 只产出沙箱 tar。
