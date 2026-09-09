# 安全扫描 findings 复核记录

Mimosa 静态扫描（scan-2026-09-09T18-15-41.031Z-294adc8c5d69，9 findings）逐项
人工复核结论。上一轮（2026-08，round5b6）10 findings 亦全数为既有误报，模式
一致：扫描器将沙箱执行接口误判为代码注入。

| # | 位置 | 类型 | 结论 | 依据 |
|---|---|---|---|---|
| 1-5 | `sandbox/backend.py:49`、`sandbox/fake.py:119`、`sandbox/owned.py:81`、`sandbox/wsl.py:241`、`subagent_worker.py:42` | 代码注入 | 误报 | 均为 `def exec(self, ...)` 沙箱命令执行接口的**方法定义**，非 Python 内建 `exec()` 调用；扫描器按名字匹配 |
| 6 | `evaluation/promotion.py:119` | 弱随机 | 设计使然 | `random.Random(policy.bootstrap_seed)` 服务于 bootstrap 置信区间的**可复现重放**（固定 seed 哲学），非密码学用途 |
| 7 | `research/pdf_extractor.py:38` | 跨文件污点 | 误报 | `_EXTRACT_SCRIPT` 为发送进沙箱的固定脚本字面量；`path` 为沙箱内 staging 后受控 argv，跨文件关联到测试文件属静态分析误链 |
| 8 | `agent_runtime.py:635` | 路径穿越 | 误报（防御存在） | 插件 staging 前显式校验：非绝对路径、`posixpath.normpath` 无 `..` 段、必须位于 `plugin_dir` 之下 |
| 9 | `research/paper_collector.py:338` | XML 实体扩展 | 误报（防御存在） | `ET.fromstring` 前以 `_XML_DECLARATION`（IGNORECASE，`<!\s*(?:DOCTYPE\|ENTITY)\b`）拒绝一切 DTD/实体声明，billion laughs 无法构造 |

结论：9/9 无需代码修改。复核未宣称项目整体安全；运行期边界以
`autonomy-preflight` 与沙箱隔离实测为准。
