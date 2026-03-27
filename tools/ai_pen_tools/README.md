# AI 渗透外部工具接入说明

本目录用于定义 **AI 渗透测试外部工具说明文件**。

- 目录默认路径：`/code/tools/ai_pen_tools`
- 可在配置中修改：`ARL.AI_PEN_EXTERNAL_TOOL_DIR`
- 说明文件格式：`*.yaml` / `*.yml` / `*.json`
- 仅 `enabled: true` 的说明会被加载

## AI 管理默认开关

AI 管理中以下 4 个开关默认开启：

1. `启用AI渗透测试`
2. `启用AI渗透-MCP`
3. `启用AI渗透-外部工具白名单执行器`
4. `启用AI渗透-AI规划`

若你希望“即开即用”可扩展工具，请保持以上 4 项为开启状态。

## 生效条件

1. AI 管理中开启 `AI渗透外部工具白名单执行器`
2. `AI_PEN_EXTERNAL_TOOLS` 包含工具 `id`（逗号分隔）
3. 工具说明文件命中当前风险（`match` 条件）
4. 可执行文件在容器内可找到（`bin` 或配置路径）

## 最小配置

```yaml
id: custom_tool
enabled: true
description: 自定义渗透测试工具
exec:
  bin: custom-tool
  args_template:
    - "--url"
    - "{target_url}"
match:
  payload_types: ["replay"]
result:
  success_regex: ["vulnerable", "success"]
  hit_decision: "verified"
  hit_confidence: 0.9
  hit_reason: "custom_tool 命中漏洞特征"
```

## 可扩展 AI 工具接入步骤

1. 将工具二进制放到容器可访问路径（建议在宿主机项目目录 `tools/` 下，并通过 compose 挂载到 `/code/tools`）。
2. 在本目录新增工具说明文件，例如 `mytool.yaml`（不要使用 `.example` 后缀）。
3. 在 AI 管理的 `AI_PEN_EXTERNAL_TOOLS` 中加入该工具 `id`（如：`sqlmap,httpx,mytool`）。
4. 执行一次 AI 渗透测试任务，查看 `AI渗透` 结果里的 `external_tool_runs` 与 `tool_trace` 是否命中。

## 字段说明

- `id`: 工具标识（白名单用）
- `enabled`: 是否启用
- `description`: 描述
- `config_bin_key`: 可选，读取 `Config` 中同名字段作为二进制路径覆盖

- `exec.bin`: 可执行文件名或绝对路径
- `exec.timeout_sec`: 单工具执行超时（5-300）
- `exec.args_template`: 参数模板（数组）

模板变量：
- `{target_url}`
- `{risk_type}`
- `{risk_name}`
- `{payload_type}`
- `{task_id}`

- `match.payload_types`: 命中 payload 类型才执行
- `match.risk_types`: 命中风险类型才执行
- `match.risk_keywords`: 风险关键字（包含匹配）
- `match.requires_query`: 目标 URL 必须包含查询参数

- `result.success_regex`: 命中即判为正向证据
- `result.negative_regex`: 命中即判为负向证据
- `result.hit_decision`: `verified` / `likely_false_positive` / `needs_manual_review`
- `result.hit_confidence`: 0-1
- `result.hit_reason`: 正向命中原因
- `result.negative_decision`: 负向命中时判定
- `result.negative_confidence`: 0-1
- `result.negative_reason`: 负向命中原因
- `result.verification_step`: 执行阶段标识

## 白名单示例

`AI_PEN_EXTERNAL_TOOLS` 示例：

```text
sqlmap,httpx,custom_tool
```

若仅希望启用自定义工具：

```text
custom_tool
```

## 说明

- `sqlmap` / `httpx` 内置默认说明，即使本目录为空也可用。
- 若本目录存在同名 `id`（如 `sqlmap`），将覆盖内置说明。
