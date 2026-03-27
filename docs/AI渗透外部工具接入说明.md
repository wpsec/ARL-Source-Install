# AI渗透外部工具接入说明

## 1. 目标

为 AI 渗透测试提供“可扩展工具框架”：

- 用户将工具可执行文件部署到容器可访问路径
- 用户在指定目录新增工具说明文件（YAML/JSON）
- 系统按说明自动匹配风险并调用工具执行

## 2. 目录与配置

- 默认说明目录：`/code/tools/ai_pen_tools`
- 配置项：`ARL.AI_PEN_EXTERNAL_TOOL_DIR`
- 环境变量：`ARL_AI_PEN_EXTERNAL_TOOL_DIR`

工具说明请参考：
- `tools/ai_pen_tools/README.md`
- `tools/ai_pen_tools/*.yaml.example`

## 3. 执行条件

同时满足以下条件才会执行外部工具：

1. AI 管理中启用 `AI渗透外部工具白名单执行器`
2. `AI_PEN_EXTERNAL_TOOLS` 白名单包含工具 `id`
3. 工具说明文件中 `match` 条件命中当前风险
4. 工具二进制可执行且可在容器中找到

## 4. 兼容策略

- 内置了 `sqlmap`、`httpx` 的默认说明，即使目录为空也可用。
- 若目录中存在同名 `id`，将覆盖内置说明。

## 5. 建议流程

1. 先放置 `.yaml.example` 的拷贝文件（改为 `.yaml`）
2. 在小范围任务中验证命中与输出
3. 再加入生产白名单 `AI_PEN_EXTERNAL_TOOLS`
