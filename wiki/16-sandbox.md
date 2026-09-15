# 16 沙盒

## 定位

`AEGIS-Sandbox` 发行版内的固定 agent（`sandbox/agent.py`，1.5K 行）提供全部隔离执行：任务命令、镜像构建/扫描、密封评测、工作区暂存/冻结、镜像持久化。宿主/发行版经 JSON 协议访问，协议接受数据、从不下发命令或路径。

## 协议（`sandbox/agent.py`）

- 单次调用：stdin 一个 JSON 请求 → stdout 一行 JSON 响应；操作集封闭枚举（:38-54）：doctor / scanner_probe / prepare / build_image / scan_image / stage_archive / configure_workspace_access / exec / evaluate_sealed / freeze / export / destroy / kill / save_image / load_image / image_exists。
- exec：任意 argv（无命令白名单），但 cwd 必须安全 POSIX 相对、env 白名单（仅 CI/LANG/LC_ALL/NO_COLOR/PYTHONHASHSEED/TZ/TERM，`wsl.py:45`）、**network 恒 "none"**（请求层写死非 none 即拒 :257；allowlist 从未实现是有意为之）。
- 传输与限额：argv ≤64 项 ×16KiB、stdin ≤1MiB、timeout ≤3600s、输出 >1MiB kill+exit 125、暂存 ≤16MiB 压缩/64MiB 展开/4096 条目（`wsl.py`/`agent.py` 常量区，全表见 [catalog-limits](catalog-limits.md)）。
- doctor 7 项必需检查（windows_mounts/interop/rootless_oci/cgroup_v2/network_none/disk_quota/secret_absence，`wsl.py:35-43`）全过才允许任何操作；interop 默认 warn-only（WSL binfmt 振荡的兼容，:200-221）。

## 容器加固（`build_podman_command` :959-1010）

`podman run --replace --network=none --cap-drop=ALL --security-opt=no-new-privileges --read-only --pids-limit --memory --cpus --tmpfs=/tmp:rw,nosuid,nodev,noexec,size=256m --userns=keep-id`；工作区默认 `:ro`，仅 `configure_workspace_access` 显式声明的路径（≤64 条、须已 staged、一次性配置）以 `:rw` 重挂（:767-847）。

**资源信封**（2026-09-15）：runtime policy 的 `sandbox_cpus/sandbox_memory_gib/sandbox_pids`（[1,8]/[1,8]/[64,1024]）经 prepare 请求持久化到 per-sandbox `resources.json`，podman flags 按其覆盖固定默认（`_resource_flags`）；默认维持 1 CPU / 1GiB / 256 pids。修正案通道见 [17](17-runtime-policy.md)。

## 密封评测（`sandbox/sealed_evaluation.py`）

- worker 源码内嵌（`WORKER_SOURCE`，与控制面无共享断言逻辑）：控制面保留断言，worker 只见单 action 场景——无挂载/模块/argv/env 线索指向密封套件。
- 限额：suite ≤1MiB、worker 输出 ≤64KiB、cases 1..128、单 case `min(remaining,120)s`。
- worker 超时/输出超限 → safety violations（integrity 失败 = 0 分语义，[09](09-evaluation-attribution.md)）。

## 工作区生命周期

1. `prepare(sandbox_id, image?, resources?)`：镜像必须已存在（digest 优先、sha256:id 回退；**缺失 fail-closed**）；幂等重入。
2. `stage_archive`：tar 暂存 + digest/size/entries 回执校验。
3. `configure_workspace_access`：声明可写路径。
4. `exec` / `evaluate_sealed`。
5. `freeze`/`export`：确定性 tar + sha256；export 独占创建防覆盖宿主数据。
6. `destroy`/`kill`：finally 语义（runner/evaluator 均保证清理）。

## 镜像构建与扫描（`build_image`/`scan_image`）

- recipe（[04](04-evolution-surfaces.md)）→ 合成 Containerfile（只生成 FROM/COPY/RUN 三种指令）→ `podman build --network=none --iidfile`；步骤 ≤32、单步 timeout ≤1800s、总 timeout ≤86400s、输出 ≤8GiB。
- Trivy 扫描 `--exit-code 1 --ignore-unfixed`（≤3600s）；**崩溃/超时降级为 scanner_passed=False 证据**（除非 policy `require_scanner_passed=True`，`environments/runtime.py:790-838`）。
- 双构建：reproducibility 降级为 receipt 证据（`require_reproducible` 默认 False）；构建 attempt 无网络/秘密/宿主挂载（:229-230）。
- 发布链：BuildReceipt（builder_identity/output_image/sbom/provenance/vulnerability_report/sources/reproducible/scanner_passed）→ validate → CAS publish → PublicationReceipt 五字段交叉核验。

## 镜像持久化（2026-09-15）

- `save_image`：digest-pinned 镜像 → `podman save -o <path>`；路径校验（绝对/无 `..`/必须在 allowed_root 内）；内容寻址幂等（已存在直接哈希回执）。
- `load_image`：归档恢复进本地 store；`image_exists`：双形式探测（repo@digest / sha256:id）。
- cycle 集成：环境候选构建成功后自动归档到 `data/artifacts/blobs/<digest>.tar` + `image_blobs.json` 索引（`cycle_ports._persist_image_blob`）；role prepare 前探测镜像缺失 → 自动从归档恢复（`_restore_image_blob`/`_image_available`）——发行版重装/GC 不再永久丢失进化资产。
- prepare 本身保持 fail-closed（恢复失败照样拒）。

## 后端客户端（`sandbox/wsl.py`）

- `WslSandboxBackend`（宿主经 wsl.exe）与 `LocalAgentSandboxBackend`（发行版内，[06](06-wsl-first-runtime.md)）共享全部协议/校验；request 非法结构、回执缺失、staging 不一致均 fail-closed。
- 幂等操作（doctor/prepare/freeze/export/destroy/kill）传输丢失可重试（:53-55）；agent 侧结构化错误（ok:false）永不重试。

## 边界

- 密封任务评估由 taskpacks runner 与 arm_evaluation 驱动（[10](10-dynamic-tasks.md)、[09](09-evaluation-attribution.md)）。
- 环境构建器在 cycle 内为 environment 候选自动构建（[08](08-candidate-lifecycle.md)）；构建产物即 runtime_image 候选证据。
- 发行版 provisioning（卷/服务/agent 安装）：`sandbox/bootstrap.py` 生成计划（默认 dry-run，`--apply` 只写 staging root），操作员手动执行（[19](19-operations.md)）。
