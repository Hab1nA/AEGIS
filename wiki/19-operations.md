# 19 运维手册

## 定位

操作者视角：安装、配置、部署、日常命令、E2E 惯例。

## 安装与配置

- 纯 stdlib，`pip install -e .`（开发额外 pytest/mypy/ruff）。
- 项目级中继配置：仓库根 `.aegis.env`（git-ignored，8 键白名单，显式 env 优先；[03](03-foundation.md) §envfile）：
  ```
  AEGIS_OPENAI_BASE_URL=https://apihub.agnes-ai.com/v1
  AEGIS_OPENAI_API_KEY=sk-...
  AEGIS_OPENAI_TIMEOUT_SECONDS=3600   # thinking max + 65K 输出建议值
  ```
- 模型要求：`agnes-2.5-flash` + `reasoning_effort: "max"`（65,536 thinking 预算）；Responses 协议 + json_object 固定。
- `AEGIS_OPENAI_USER_AGENT`：Cloudflare 前置中继可能按浏览器 UA 拦截（网关默认 Chrome 串，:118-126）。

## 配置文件（`configs/`）

- `evolution-smoke.example.json`：4 软表面、`max_agent_steps=24`（**对 agnes 偏紧**，建议 96）、max_requests 500。
- `evolution-full.example.json`：全部 7 表面 + harness 进化 + meta + 自动激活；`max_agent_steps=96`、max_requests 2000、wall_time 28800。正式跑采用此形态。
- 关键字段：`public_repo_url` + `harness_source_ref`（40hex pin，必须与 WSL source mirror 一致）、`harness_canary_command`、`environment_output_repository`、角色 `budget_share` 必须恰为 0.55/0.225/0.225（`autonomy_budget.py` 强制）。
- 配置一经 `campaign-create` 绑定不可改（immutable creation snapshot 校验，`cli.py:92-117`）；改配置 = 新 campaign。

## WSL 发行版部署

1. 生成计划：`python -m aegis.sandbox.bootstrap`（默认 dry-run；`--apply` 只写 staging root）——产出 wsl.conf（interop/automount 禁）、containers.conf（netns private、default_capabilities=[]）、systemd 单元、卷准备脚本、5 个固定 agent wrapper。
2. 操作员手动执行清单（`bootstrap.py:262-273`）：建 aegis 用户、装 rootless podman、导入基础镜像（`deploy/wsl/Containerfile.aegis`，digest-pinned python+pytest）、mkfs 卷、启服务、**pip 安装 aegis 包进发行版**。
3. **刷新纪律**：宿主源码改动后必须 `pip install --force-reinstall --no-deps` 同步进发行版（否则旧 agent 不认识新操作：sync_mirror/advance_champion/canary/资源信封等）。
4. `deploy/wsl/`：SearxNG 服务（loopback:8888 + 代理出网）与 `aegis-search-run.py`。

## 日常命令

| 命令 | 用途 |
|---|---|
| `campaign-create <config.json>` | 注册 campaign（绑定配置） |
| `autonomy-preflight <campaign>` | v2 门禁预检（26 项，含容量底线/面配置/WSL doctor） |
| `evolution-cycle <campaign> --run [--repair]` | 跑一个周期；FAILED/ABORTED 可 retry 续跑 |
| `--no-candidate-eval` | 跳过候选评测（纯学习周期） |
| `evolution-cycle <campaign> dry-run` | 不落账演练 |
| `status / report / replay` | 状态/报告/重放 |
| `harness-sync <campaign>` | 手动刷新 WSL source mirror 到 pin（生产 launch 前已自动尽力执行） |
| `harness-advance <campaign> <target_ref>` | 把宿主前进的新 pin 推进运行中 campaign（mirror 刷新+champion 前进+source_ref 迁移） |

执行锁：`evolution-cycle --run` 持跨进程文件锁（崩溃自释放）；并发第二个进程立即报错。

## 生产路径 vs 宿主路径

- 非 test_mode + harness 进化启用 → **WSL-first**（[06](06-wsl-first-runtime.md)）：launch+poll，数据落发行版 campaign volume。
- test_mode / 无 harness → 宿主 in-process（数据落宿主 --data-dir），沙盒仍经 WSL。
- 两者不可混用数据；切换即新 campaign。

## E2E 惯例（源自 docs/autonomous-evolution.md 台账）

- 真实两代 smoke：真实 WSL/Podman + 真实模型连跑两代 `--run --repair`，十类证据 artifact 齐全、preflight 全过为通过线。
- 已知模型瓶颈：agnes-2.5-flash 长程组合弱（Warrior 求解阶段步数超限/工具参数构造失败率高，2026-09-14/15 两轮复现）——`max_agent_steps=96` 起步；失败 trace 看 `StepLimitExceeded` 的 `step:action:ok|rejected(...)`。
- 401 → 刷新 `.aegis.env` 的 key；偶发 relay JSON 围栏/截断由网关兜底（[14](14-gateway-accounting.md)）。

## 诊断入口

- 周期事件：`<data>/events.sqlite3` 按 campaign 读；断点续跑看最后 `cycle_state_changed_v2`。
- WSL-first 周期：发行版 `campaigns/<key>/cycles/gen-<N>/status.json` + `data/metering/gen-<N>.jsonl`。
- 试用期/激活：`evolution-probation` 流 + activation 流（[catalog-events](catalog-events.md)）。
