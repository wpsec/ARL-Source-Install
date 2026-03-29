# AI渗透测试MCP总体方案

## 1. 总目标与边界

- 核心目标：找到可复现的漏洞入口、风险入口
- 输出对象：给渗透测试/红队工程师可继续深挖的高价值入口
- 明确边界：不做自动化后渗透、不做横向移动、不做高风险攻击链自动扩展

## 2. ARL AI MCP

1. 模型支持多轮 `tool_call`，不是一次性建议。
2. 运行时存在闭环：`调用工具 -> 回填结果 -> 再决策`。
3. 工具采用统一注册协议，不允许散落在 `if/else` 硬编码。
4. 每次任务有预算与治理：调用预算、超时、并发、审计日志、可回放轨迹。
5. 最终输出兼容现有结论结构：`decision/confidence/reason`，并可追溯每一步证据。

## 3. 架构改造主线

### 3.1 抽离 MCP Runtime（核心）

新增模块：`ai_pen_mcp_runtime`

职责：

- 执行 agent loop
- 管理工具注册与调用
- 管理预算、超时、重试、审计
- 产出完整轨迹

输入：

- 候选目标（candidate）
- 任务上下文（task/site/url/vuln/nuclei_result/wih）
- 工具集（tool registry）
- 预算配置（max turns/max tool calls/timeout/concurrency）

输出：

- `decision/confidence/reason`
- `steps`
- `tool_calls`
- `tool_results`
- `stop_reason`
- `budget_used`

替换点：

- 替换 `commonTask._verify_ai_pen_candidate` 当前硬编码执行流程

### 3.2 统一工具协议

统一 Tool Schema：

- `name`
- `description`
- `input_schema`
- `execute(context, params) -> ToolResult`

内置探针统一工具化：

- `http_fetch`
- `payload_probe`
- `idor_probe`
- `api_doc_probe`
- `jwt_probe`
- `websocket_probe`

外部工具纳入同一协议：

- `sqlmap`
- `httpx`
- 未来扩展工具（来自白名单目录）

迁移点：

- 将 `_run_ai_pen_external_tools` 迁入 runtime tool registry 调用链

### 3.3 模型调用模式升级为 Agent Turn

从“单次 planner”升级为“可循环决策”：

1. 模型返回 `tool_call`
2. runtime 执行工具
3. 回填标准化结果
4. 模型继续决策
5. 直到完成或预算耗尽

停止条件：

- `final_decision`
- `budget_exhausted`
- `timeout`
- `guardrail_blocked`
- `manual_required`

### 3.4 数据模型与审计

集合：`ai_pen_test_result` 增补字段：

- `agent_trace`
- `tool_calls`
- `tool_results`
- `stop_reason`
- `budget_used`
- `runtime_version`

兼容策略：

- 保留 `tool_trace` 作为摘要，避免报表改动过大
- 保持现有 `decision/confidence/reason/status` 字段语义

### 3.5 前端展示

任务详情 `AI渗透` 详情弹窗扩展：

- 新增 “Agent轨迹” 时间线
- 展示每轮思考动作、调用工具、结果摘要、停止原因
- 支持折叠查看原始 `tool_call/tool_result`

## 4. 安全与治理

### 4.1 调用边界

- 工具白名单机制
- 参数 JSON Schema 校验
- 目标范围限制（仅任务 scope）
- 出网限制（域名/IP allowlist）
- 禁止访问内网保留地址及元数据地址

### 4.2 运行治理

- 单工具超时
- 总预算（turn/call/time）
- 并发上限
- 失败重试策略（退避）
- 高频失败自动熔断

### 4.3 高风险工具分级

- `sqlmap` 等高风险工具单独开关
- 按任务级/租户级设置风险等级
- 默认低侵入模式，必要时人工确认升级

## 5. 分阶段上线

### P0：本地 MCP runtime + 内置探针工具化

交付：

- `ai_pen_mcp_runtime` 基础 loop
- 内置探针全部按统一协议注册
- 兼容原落库与页面

验收：

- 至少支持 2 轮以上 tool_call 闭环
- 失败可回退现有规则链路

### P1：外部工具协议统一 + 轨迹落库 + 前端轨迹展示

交付：

- `sqlmap/httpx` 纳入统一 tool registry
- `agent_trace/tool_calls/tool_results` 落库
- 前端“Agent轨迹”时间线

验收：

- 支持任务级回放
- 单次任务完整审计可追溯

### P2：标准 MCP Server 可选接入

交付：

- 支持对接标准 MCP Server
- 支持第三方工具生态扩展

验收：

- 第三方工具可按统一协议纳管
- 安全边界与预算治理不被绕过

## 6. 能力矩阵

AI渗透能力应按“基础能力矩阵 -> 场景映射 -> 产品偏置 -> 文库增强”的顺序构建。

基础能力建议保持以下 profile：

- `api_surface_analysis`
- `authn_session_analysis`
- `authz_object_reference_analysis`
- `token_jwt_analysis`
- `client_side_input_flow_analysis`
- `server_side_injection_analysis`
- `file_handling_analysis`
- `realtime_channel_analysis`
- 等等

原则：

- 产品画像只做优先级偏置，不主导验证主链
- PoC 文库只做知识增强，不直接决定结论

## 7. 浏览器增强与认知图谱

### 7.1 浏览器增强策略

执行分层：

- 第一层：HTTP 轻量验证（默认）
- 第二层：浏览器增强（高价值目标触发）

浏览器增强仅做低侵入采集：

- 资源树
- JS 清单
- 运行时 XHR/fetch 请求
- DOM 表单摘要

不做：

- 激进反检测对抗
- 自动绕验证码
- 高风险交互攻击

### 7.2 认知图谱最小化落地

先做任务级 JSON 图谱摘要，不强依赖图数据库。

建议产物：

- `task_ai_pen_graph_summary`
- `node_count/edge_count`
- `top_paths/top_params`
- `auth_cluster/file_cluster/object_ref_cluster`

作用：

- 给 planner/verifier 提供多点关联推理上下文
- 不再仅靠“单条风险”线性判断

## 8. AI 调度与误报抑制（整合）

### 8.1 AI 智能调度（PoC）

采用 `Rule First + AI Re-rank`：

1. 规则召回候选（防漏）
2. AI 在候选池内重排（防幻觉）
3. 白名单和预算约束执行（防失控）

约束：

- AI 不得捏造 tag/keyword/template
- 证据不足必须保守策略
- AI 异常必须 fail-open 回退

### 8.2 误报抑制

- 信息泄漏：格式+语义+作用域联合判定
- 渗透结果：差分复验与最小复现证据
- 无证据默认 `manual_review`

建议统一字段：

- `ai_decision`
- `ai_confidence`
- `ai_reason`
- `review_status`
- `review_version`
- `evidence_pack`

## 9. 容器与 Worker 架构优化（整合）

### 9.1 当前痛点

- 单 worker 容器多队列多进程混跑，资源互抢
- `arlweb` 同时承载 web 重任务与 AI 相关任务，排队冲突明显

### 9.2 推荐路线

Phase A（低风险）：

- 按队列拆 worker 容器（`arltask/arlheavy/arlweb/arlgithub`）

Phase B（重点）：

- 新增 `arlai` 队列，AI任务独立消费者 `worker_ai`

Phase C（中长期）：

- `worker_poc/worker_capture/worker_intel` 深度解耦
- 按队列弹性扩缩容

验收指标示例：

- `arlweb` backlog 峰值下降 >= 30%
- AI 结果落库延迟下降 >= 40%
- 主任务后 10 分钟 AI 落库覆盖率 >= 95%

## 10. 实施清单（按优先级）

### 第一优先级（立即执行）

1. 落地 `ai_pen_mcp_runtime` 与统一 Tool Schema
2. 内置探针工具化并接入 agent loop
3. 增加预算/超时/审计/回放基础能力

### 第二优先级（短期）

1. 外部工具协议统一
2. 轨迹落库与前端时间线
3. AI 调度与误报抑制统一字段

### 第三优先级（中期）

1. 浏览器增强与图谱摘要深度融合
2. `arlai` 队列与 worker 独立扩缩容
3. 标准 MCP Server 对接
