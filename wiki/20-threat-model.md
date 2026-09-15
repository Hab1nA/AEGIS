# 20 威胁模型摘要

权威版本：`docs/threat-model.md`（简）与 `docs/autonomous-evolution.md` §5 信任边界。本页是面向设计者的摘要与机制映射。

## 保护资产

1. 宿主（Windows + WSL 发行版完整性）——模型能力的物理边界之外。
2. 中继凭据——只存在于宿主 env 与发行版 sidecar 进程。
3. 评测完整性——隐藏测试、密封套件、评分器、evaluator fingerprint。
4. 用量记账——预算数字与账本（评分函数的一部分）。
5. 晋级决策链——事件流、归因、门禁证据。

## 对手模型

- **不可信模型角色**（Warrior/Judge/Prosecutor）：提示注入、越权提议、用量谎报、评测套利、task 供给操纵。
- **不可信内容**：任务归档、研究导入、插件源码、MCP server、web 内容——全部按数据消费。
- **被进化的代码本身**（harness-code 候选）：一旦激活即运行整树——最高危对手。

## 强制控制 → 机制映射

| 威胁 | 控制机制 | 参考 |
|---|---|---|
| 模型改评分/考卷/牢笼 | 冻结根 + harness agent frozen 字节比对（整树 vs pinned source_ref 的 diff 全部路径过白名单） | [04](04-evolution-surfaces.md)、[05](05-harness-evolution.md) |
| 模型改预算/记账 | usage_accounting/runtime_ledger 在可进化根外；账本 observer 一次绑定；sidecar 计量三方对账（零计量+有产物即拒） | [14](14-gateway-accounting.md)、[06](06-wsl-first-runtime.md) |
| 用量谎报 | TokenUsage frozen 构造 + 不可能数字 anomaly（含 zero_output）+ verified=False 降级进审计 | [14](14-gateway-accounting.md) |
| 评测套利 | 密封双 suite 独立沙盒、cases.json 永不进 Warrior 工作区、篡改检测=0 分、evaluator fingerprint 进 design 绑定 | [09](09-evaluation-attribution.md)、[16](16-sandbox.md) |
| 隐藏测试泄漏 | Fresh holdout 隔离 1 代、Judge 校准只用 diagnostic cohort、反思反馈脱敏（hidden_results_disclosed=False） | [10](10-dynamic-tasks.md)、[11](11-objectives-council.md) |
| 候选无因果晋升 | 单坐标干预归因 + CONFOUNDED 阻断 + 配对门禁非补偿闸 + 试用期/金丝雀 | [08](08-candidate-lifecycle.md)、[09](09-evaluation-attribution.md) |
| 越权命令执行 | 跨域只有固定 JSON agent；supervisor payload 禁 argv/command/cwd/executable/module/path 键；boot 探针 namespace+setpriv；任务容器 cap-drop/all + read-only + network none | [02](02-architecture.md)、[06](06-wsl-first-runtime.md)、[16](16-sandbox.md) |
| 凭据泄漏 | 凭据单向流（宿主 env→sidecar）；champion env 刻意排除；回执哈希排除凭据；publisher 错误不回显 argv/URL/env | [06](06-wsl-first-runtime.md)、[15](15-research.md) |
| SSRF/内网探测 | URL 十条规则 + 全公网 IP 校验 + IP 钉扎 + 每跳重校验 + 重定向不自跟随 + 云元数据主机拒绝 | [15](15-research.md) |
| 外部写失控 | 外写必经 journaled connector（intent-first + 再校验）；publisher fail-closed 隔离 clone + force-with-lease CAS + 秘密三重拒绝 | [13](13-roles-plugins-mcp.md)、[15](15-research.md) |
| 导入物执行 | 校验≠授权（execution_granted=False）；技能隔离注册表无宿主加载路径；沙箱 stage-only | [15](15-research.md) |
| 血缘伪造/搭车晋升 | 一切身份内容寻址 + 载入重算；激活 staleness（parent==champion）；stale 预拒绝 | [03](03-foundation.md)、[08](08-candidate-lifecycle.md) |
| 进化改进化机器 | meta 门控（registry/consumer/surfaces/harness 需显式授权）+ control-core 禁触宿主信封 | [04](04-evolution-surfaces.md) |

## 残余风险（明确接受）

- gateway/client 在可进化根内：低报 usage（0 是"可能数字"以外的合法数）理论可行——由 sidecar 计量对账与 anomalies 缓解；WSL-first 前由冻结字节比对间接覆盖。
- sidecar loopback 无 token：发行版单用户 + netns private 下接受（威胁模型已记录）。
- 资源信封可被检察官上调至 8GiB/8CPU：成本与 wall-time 风险而非隔离风险。
- Tier 2 执行器不进 namespace（需 spawn podman）：以 rlimits + 树完整性 + 计量代替；逃逸到发行版用户权限即止（发行版本身无 Windows 通道）。
- 难度引导/假设覆盖判定为关键词级（非语义）；学习目标退化为纯 call 题由难度门硬拒，但语义质量仍依赖 Judge 能力。

## 验证惯例

- 负面路径单测（越权路径/秘密内容/树不一致/金丝雀回归/冒烟失败全部拒绝或回滚）。
- 真实三代/五代 e2e（激活→激活→回滚；meta 开关前后对照）。
- Mimosa 深度扫描：exec 类 code-injection findings 属沙盒设计内行为（隔离即边界），非漏洞。
