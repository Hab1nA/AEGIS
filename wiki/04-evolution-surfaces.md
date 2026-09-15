# 04 可进化面契约

## 定位

`evolution/surfaces.py` 是 Warrior 自我进化授权规则的唯一本体：定义七类可进化表面、严格 JSON 形状、授权规则与内容校验器。候选内容在进入进化注册表前物化进 CAS，永远作为不可信数据消费（模块 docstring :1-7）。

## 七类表面（`EvolutionSurface` :54-61）

`workflow` / `subject` / `plugin` / `environment` / `harness-code` / `mcp` / `control-core`。

授权规则（`validate_evolution_proposal` :674-711）：

- **仅 Warrior 可提议**（:685-687）——Judge/Prosecutor 不可提议（对抗结构：出题者与检察官保持控制面约束）。
- plugin/environment/subject/harness-code/mcp/control-core **只能 target Warrior**（:689-700）；workflow 只能 target 提议者自己（:701-704）。议会 reflection 的 workflow 提案通道在收集层执行同一规则：非 Warrior 目标收集即拒、不注册（`consumer.py` `_consume_reflection_proposals`，2026-09-16 起——非 Warrior 面尚无 shadow 归因路径）。
- 表面须在配置 `autonomy_v2.evolution_surfaces` 白名单内：默认仅 workflow/subject/plugin/environment（`config.py:90-95, 253`）；mcp 与 control-core 恒需显式启用。

## 各表面内容契约

| 表面 | 校验器 | 形状要点 |
|---|---|---|
| workflow | `validate_workflow_content` :218-261 | 恰 7 字段；6 个 string 数组（各 1..16 项、每项 ≤2000B）；max_steps ∈ [1,1000] 或 null。语义为 advisory guidance（`agent_runtime.py:3343-3353` 注入信封） |
| subject | `validate_subject_content` :268-285 | content_markdown ≤16KiB + rationale ≤2KiB；advisory 角色主提示 |
| plugin | `validate_plugin_content` :293-335 | PluginManifest；效果 ⊆ {PURE, WORKSPACE_READ, WORKSPACE_WRITE}（:288-290，EXTERNAL 禁止）；源码插件不得声明 workspace_write（:320-329）；详见 [13](13-roles-plugins-mcp.md) |
| environment | `validate_environment_content` :409-425 | EnvironmentRecipe：parent_image 必须 digest-pinned（:421-422）；offline recipe 禁依赖（:423-424）；详见 [16](16-sandbox.md) |
| harness-code | `validate_harness_code_content` :539-611 | 严格 JSON 补丁：base_commit（40/64hex）、checkpoint_ref（`refs/heads/candidate/warrior/gen-<hex>` :45）、changes 1..64 项、objective/rationale ≤2000B、failure_mode/expected_fix/regression_risk/evidence_ref；详见 [05](05-harness-evolution.md) |
| mcp | `validate_mcp_content` :428-435 | McpCandidate（不可变绑定+授权矩阵）；详见 [13](13-roles-plugins-mcp.md) |
| control-core | `validate_control_core_content` :438-447 | ControlCorePolicy（in-WSL 控制策略，`evolution/control_core.py`）；不能命名宿主安全信封 |

## harness-code 路径白名单与冻结面

`validate_harness_path`（:132-175）是"agent 不能改自己的考卷/牢笼/评分器"的执行点：

**允许根**（`HARNESS_ALLOWED_ROOTS` :73-80）：`agent_runtime.py`、`plugins/`、`gateway/`、`roles/`、`research/`、`evolution/`。

**冻结根**（`HARNESS_FORBIDDEN_ROOTS` :82-94）：`sandbox/`、`publishing/`、`connectors/`、`taskpacks/`、`evaluation/`、`dynamic_tasks/`、`curriculum/`、`attribution/`、`tests/`、`docs/`、`config.py`。语义（:64-71 注释）：评测侧、安全边界、外写边界、归因标准刻意封闭。

**meta 控制文件**（`HARNESS_FORBIDDEN_FILES` :96-108）：`evolution/registry.py`、`evolution/consumer.py`、`evolution/surfaces.py`、`evolution/harness.py`——仅 `meta_evolution_enabled` 显式授权时可改（:159-162）。

**meta 允许根**（`META_ALLOWED_ROOTS` :110-113）：`cycle_recovery.py`、`repair_runtime.py`。

路径卫生（:132-158）：POSIX 相对、无 `\` / NUL / `..` / `.git` 段 / 秘密文件名（`HARNESS_SECRET_PATH_PARTS` :115-127、后缀 .key/.pem/.p12/.pfx :129）。

**双层执行**：运行时层（本模块，宿主/发行版控制面在提议校验时调用）+ 信任锚层（harness agent 对整树与 pinned source_ref 做 diff，所有变更路径必须过 `validate_harness_path`——见 [05](05-harness-evolution.md) §frozen 字节比对）。两层共同保证"整树即运行树"时冻结面依然冻结。

## 补丁形状（`_harness_changes_from_mapping` :482-536）

- 1..`MAX_HARNESS_CHANGES`(64) 项；每项恰 `{path, delete, content_base64, executable}`。
- 单文件 ≤ `MAX_HARNESS_FILE_BYTES`(768KiB)（:49, :521）；delete 项不得带内容/executable（:509-513）；base64 严格解码；含 `PRIVATE KEY` 即拒（:523-524）；路径唯一（:525-527）。

## 边界

- 调用方：`agent_runtime.py`（`evolution.request`/`aegis.propose_harness_change` 动作校验）、`cycle_ports.py`（收集与评测）、`wsl_harness_agent.py`（信任锚 diff 检查）。
- `EVOLUTION_PROTOCOL_SCHEMA`（:714-723）是发给模型的协议 schema；信封内嵌可执行协议细节经 `_ROLE_PROTOCOL_FIELDS` 裁剪（[12](12-agent-runtime.md)）。
