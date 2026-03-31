# AI渗透测试MCP总体方案

## 1. 目标定位

- 目标版本：`v4.5.x`
- 文档同步版本：`v4.5.34`（截至 `2026-03-31`）
- 能力下限：至少具备 `PortSwigger Web Security Academy` 核心 Web 漏洞能力
- 架构要求：必须是真正的 `Agent MCP`，不是“规则驱动 + AI 点缀 + MCP 外壳”
- 运行边界：默认低副作用、强审计、可回放、可人工接管，不做自动化后渗透和横向移动
- 系统定位：`互联网资产侧的高价值漏洞入口发现器 + 低副作用验证器`

一句话目标：

- `以 PortSwigger 方法论为能力下限，以 Agent MCP 为执行架构，以高价值漏洞入口发现、真漏洞优先和低副作用验证为默认模式。`

## 2. 当前问题与根因

当前 AI 渗透测试已具备：

- 候选汇聚
- 统一工具注册
- MCP 审计产物（`agent_trace/tool_calls/tool_results/stop_reason/budget_used`）
- `run_agent_loop` 本地闭环骨架
- 基础 HTTP/IDOR/API 文档/JWT/GraphQL/WebSocket/Socket.IO/路径穿越/Web 策略验证
- 浏览器情报补充
- 登录/会话/登出验证链
- 高价值目标家族提取与排序
- 结果轨迹、导出字段与量化统计数据面

但当前主要问题，已经不再是“完全不会测”，而是“如何更稳定地给工程师真入口、少给水洞”：

1. `commonTask` 仍然主导大部分执行逻辑
2. planner 更像“给建议”，不是“每轮决策的大脑”
3. runtime 更像“带审计的工具执行器”，不是“多轮推理闭环”
4. 被动参数提取 -> 参数类型标签 -> payload 编排 -> proof 判定 还没有完全收成单引擎
5. 结果虽然已可量化，但“工程师优先看什么入口”还需要更强的优先级视图
6. 基准靶场与标注回归尚未建完，阶段 F 还没有形成真正的量化基线
7. `ARL/docker/dicts/dict` 已完成第一阶段资源封装，但尚未升级为“带预算/节流/熔断治理”的受控自动链资源

## 3. 能力下限：按 PortSwigger 体系定义

AI 渗透测试至少要覆盖以下能力族：

1. 站点与接口面建图
   - `site / url / fileleak / wih / js / browser runtime / API 文档` 统一建图

2. 登录与会话
   - 登录表单识别
   - CSRF 提取
   - Cookie / Redirect / Session 状态维护
   - 登录成功/失败/锁定识别
   - 最小弱口令验证

3. 访问控制
   - 未授权访问
   - 水平越权
   - 垂直越权
   - 对象引用缺陷

4. 输入类注入
   - XSS
   - DOM XSS
   - SQLi
   - SSTI
   - 命令执行

5. 服务端间接访问
   - SSRF
   - XXE
   - 文件读取
   - 路径穿越

6. 文件处理
   - 上传
   - 下载
   - 导出
   - 模板
   - 附件

7. Token / 认证协议
   - JWT
   - OAuth/OIDC 入口
   - 认证接口重放
   - Token 相关弱点

8. 实时通道
   - WebSocket
   - SockJS / Socket.IO

9. 配置与敏感暴露
   - `actuator/env`
   - `configprops`
   - `beans`
   - `mappings`
   - 调试接口
   - 敏感文件/配置泄露

10. Web 安全策略
   - CORS
   - Cache
   - Header 安全策略
   - 暴露型错误配置

## 4. 架构目标：从“假 MCP”升级为“真 Agent MCP”

目标状态必须满足：

1. 模型每轮决定下一步，而不是代码写死
2. 工具结果必须回喂模型继续推理
3. runtime 持有会话状态，而不是一次性请求
4. 登录、认证、API、文件处理都走统一工具协议
5. `commonTask` 只负责候选准备和落库，不再主导执行分支
6. 每轮轨迹可回放、可解释、可人工接管

### 4.1 当前“假 MCP”的表现

- `runtime` 有 `ToolSchema`，但执行入口仍由 `commonTask._verify_ai_pen_candidate` 的分支驱动
- planner 可以给出 `payload/next_actions/tool_plan`，但执行链并不完全由模型控制
- 结果更多是“代码判定后附带 AI 文案”，而不是“多轮模型-工具闭环”

### 4.2 真 Agent MCP 的目标流程

每一轮固定为：

1. 读取候选上下文、历史观察、会话状态
2. 模型输出：
   - `tool_call`
   - `reason`
   - `expected_signal`
   - `stop_if`
3. runtime 校验工具参数与安全边界
4. 执行工具
5. 将标准化结果回填 memory
6. 模型继续下一轮
7. 直到：
   - `final_decision`
   - `manual_required`
   - `budget_exhausted`
   - `guardrail_blocked`
   - `timeout`

## 5. 工具分层设计

### 5.1 采集层

- `http_fetch`
- `head_probe`
- `extract_links`
- `extract_forms`
- `extract_headers`

### 5.2 会话层

- `session_start`
- `session_request`
- `follow_redirect`
- `cookie_jar_update`
- `extract_csrf_token`

### 5.3 认证层

- `login_probe`
- `credential_probe`
- `detect_login_success`
- `logout_probe`
- `token_replay`

### 5.4 业务验证层

- `idor_probe`
- `api_doc_probe`
- `file_probe`
- `upload_probe`
- `graphql_probe`
- `websocket_probe`
- `config_probe`

### 5.5 利用证据层

- `xss_probe`
- `sqli_probe`
- `ssrf_probe`
- `ssti_probe`
- `xxe_probe`
- `cmdi_probe`

## 6. 高价值目标发现策略

高价值目标不能只靠少量示例路径，而应按“目标家族”识别。

当前代码已统一为以下家族：

1. 接口说明 / Schema 家族
   - `swagger/openapi/api-docs/redoc/knife4j`

2. GraphQL 家族
   - `graphql/graphiql/graphql-playground/apollo`

3. 认证协议家族
   - `openid/jwks/oauth2/token/introspect/userinfo`

4. 配置暴露家族
   - `actuator/env/configprops/heapdump/loggers`

5. 管理 / 诊断家族
   - `actuator/jolokia/prometheus/metrics/mappings/beans/conditions`

6. 认证入口家族
   - `login/signin/passport/sso/cas/oauth/token/auth/login/connect/token`

7. 文件处理家族
   - `upload/import/download/export/attachment/template/avatar/report`

8. 敏感文件 / 配置家族
   - `.env/.git/config/application.yml/bootstrap.yml/web.config/config.php`

9. 路径穿越家族
   - `../ ..\ %2e%2e etc/passwd win.ini`

10. 实时通道家族
   - `websocket/ws/wss/socket.io/sockjs/engine.io`

11. Web 策略家族
   - `cors/cache-control/csp/x-frame-options/hsts`

候选排序统一依据：

- 任务范围
- 状态码优先（优先 `200/201/206`）
- 高价值家族排名
- 认证/文件/对象引用/配置暴露信号
- 知识命中
- 浏览器运行时信号
- 高价值关键词与匹配 URL

## 7. 登录与弱口令：为什么还没有默认启用 `ARL/docker/dicts/dict` 全量字典

当前仓库中确实存在弱口令字典：

- [user.txt](/Users/eric.sy.wu/Documents/Github/newui/ARL-Source-Install/ARL/docker/dicts/dict/user.txt)
- [pass.txt](/Users/eric.sy.wu/Documents/Github/newui/ARL-Source-Install/ARL/docker/dicts/dict/pass.txt)

但它**还没有作为受控字典集默认接入 AI 渗透 Agent 主链**。原因已经不再是“没有登录工具链”，而是以下能力仍未完全收口：

1. `session_start / extract_csrf_token / credential_probe / detect_login_success / session_request / logout_probe` 已具备，但“大字典消费”还没有独立的安全治理层
2. 验证码/锁定/风控识别已有基础判定，但还没与“受控字典开关、重试预算、节流策略”完全联动
3. 缺少“人工显式启用 + 站点级最大尝试数 + 速率限制 + 熔断”一整套字典治理协议
4. 缺少靶场与量化回归来证明“引入受控字典后误报、误伤、副作用可控”
5. 字典资源虽已完成 preview/计数封装，但还不是 runtime 可声明预算与策略的受控资源对象

也就是说：

- `ARL/docker/dicts/dict` 不是没价值
- 而是**当前 AI 渗透执行链只适合跑最小默认凭证集，还不适合默认消费全量字典**

### 7.1 正确接入方式

弱口令字典不能直接粗暴接入 Agent 主链，而应分层：

#### 第一层：最小默认凭证集

用途：

- 默认低副作用验证
- 面向无验证码、无明显锁定、无高风险风控登录面

来源：

- 产品默认凭证
- 极小用户名/密码组合
- AI 从产品画像推测出的高置信默认口令
- 受控字典资源中筛出的安全 preview 组合（如 `admin/admin`、`root/root`、`admin/123456`）

当前状态：

- 已完成 `ARL/docker/dicts/dict/user.txt + pass.txt` 的第一阶段资源封装
- 已可输出 `controlled_dict_ready/user_count/pass_count` 到登录上下文摘要
- 当前仅消费极小、安全、可解释的 preview 组合，不默认展开为全量字典尝试

#### 第二层：受控字典集

来源：

- `ARL/docker/dicts/dict/user.txt`
- `ARL/docker/dicts/dict/pass.txt`

用途：

- 仅在满足以下条件时启用：
  - 人工显式开启
  - 风险级别允许
  - 目标无验证码 / 无明显锁定
  - 速率、次数、并发受控

#### 第三层：禁止默认启用的大规模爆破

原则：

- 不进入默认 AI 渗透自动链
- 必须人工确认
- 必须有严格节流与熔断

### 7.2 接入原则

字典接入必须满足：

1. 每站点最大尝试数限制
2. 每轮退避
3. 命中锁定/验证码/风控即停止
4. 全程审计
5. 默认仅跑最小默认凭证集，不直接跑全量字典

## 8. 分阶段实施计划

### 阶段 A：真 Agent Loop

目标：

- 把控制权从 `commonTask` 挪到 runtime

交付：

- `AiPenMcpRuntime.run_agent_loop`
- 模型每轮输出 `tool_call/final_decision/manual_required`
- 工具结果回喂模型

验收：

- 至少支持 3 轮真实闭环
- 执行路径不再主要由 `if/else` 写死

当前状态（截至 `2026-03-31`）：

- `AiPenMcpRuntime.run_agent_loop` 已落地，且已具备 3 轮闭环测试
- `agent_trace/tool_calls/tool_results/stop_reason/budget_used` 已可落库与导出
- 但主控制权仍主要在 `commonTask._verify_ai_pen_candidate`
- 结论：`部分完成，未达最终验收`

### 阶段 B：Session / Login 能力

目标：

- 打通真正的登录入口验证链

交付：

- `session_start`
- `session_request`
- `extract_csrf_token`
- `login_probe`
- `credential_probe`
- `detect_login_success`

验收：

- 能识别登录成功/失败/锁定/验证码阻断
- 能以最小默认凭证集做低副作用验证

当前状态（截至 `2026-03-31`）：

- 已具备 `session_start / session_request / extract_csrf_token / login_probe / credential_probe / detect_login_success / logout_probe`
- `weak_password_probe` 已能在预算内自动扩展为登录后会话闭环
- 已可输出 `session_summary`、认证后资源访问证据、退出有效性证据
- 已完成受控字典资源 preview 封装，并接入登录上下文可观测摘要
- 受控字典集尚未接入默认自动链的大规模尝试治理
- 结论：`基本完成`

### 阶段 C：PortSwigger 核心能力包

目标：

- 达到 PortSwigger 核心能力下限

优先能力：

1. 登录/会话
2. API/OpenAPI/GraphQL
3. JWT/认证链
4. IDOR/访问控制
5. 文件处理
6. SQLi
7. XSS/DOM XSS
8. SSRF/SSTI/XXE

验收：

- 每类至少 1 条标准化主动验证链
- 每类至少 1 套“成立证据”标准

当前实现状态（截至 2026-03-31）：

- `C-Core（主动验证能力）`：基本完成
  - 已具备：前端 JS / runtime API / 表单字段（含隐藏字段）提取
  - 已具备：参数汇总后自动生成 tool plan 并调用 MCP
  - 已具备：`SQLi/XSS/DOM XSS/SSTI/CMDI/SSRF/XXE/JWT/IDOR/文件上传下载` 基础自动验证链
  - 已具备：认证链（JWT + OAuth/OIDC + token replay）语义降噪与分级判定
  - 已具备：上传/下载类接口自动探测与证据化输出

- `C-AutoPassive（被动参数提取 -> AI分析 -> MCP自动测）`：部分完成
  - 已有能力：多源参数汇总（JS/runtime/form/api-doc/hidden）与图谱摘要
  - 已补能力：`path_traversal_probe / web_policy_probe / socketio_probe / websocket_probe` 已接入主链
  - 差距：参数类型标签 -> payload 编排 -> 全链路验证 仍未统一为单引擎
  - 差距：`垂直越权` 及部分实时通道深测能力仍需补强
  - 差距：`CORS/Cache/Security Headers/Error Exposure` 虽已有探针，但统一 proof engine 仍未完全收口

- 口径结论：
  - 按阶段 C 最低口径：可用
  - 按“工程师提效型被动扫描 + 自动验证”口径：未达 100%

- `C-AutoPassive=100%` 验收建议（开发优先级）：
  1. 参数资产图：统一收敛 `JS/runtime/form/api-doc/hidden` 参数并打类型标签
  2. 参数驱动编排器：按参数类型自动触发 `SQLi/报错注入/上传/下载/IDOR/SSRF/路径穿越/Web策略` MCP 链
  3. 统一证据引擎：所有 payload 走 `基线 + 对照 + proof_type` 判定，避免仅靠文本 heuristics
  4. 并行补齐专项探针：`path_traversal_probe`、`web_policy_probe`、`sockjs/socket.io probe`

### 阶段 D：高价值目标通用化

目标：

- 不依赖个别示例路径

交付：

- `site/url/fileleak/wih/js/runtime` 统一高价值目标提取器
- 按目标家族排序

当前状态（截至 `2026-03-31`）：

- 已统一为高价值家族提取器，覆盖 `site/url/fileleak/wih/browser/runtime/login`
- 已输出 `high_value_summary/high_value_family/high_value_family_rank/high_value_keywords`
- 已接入候选排序、AI planner、重试、导出与统计
- 结论：`主干完成`

### 阶段 E：结果与轨迹产品化

目标：

- 用户看得懂 Agent 为什么这样测

交付：

- Agent 时间线
- 工具调用树
- 请求/响应证据对照
- 会话状态摘要
- 支持沿用历史 session/tool_plan 重试

当前状态（截至 `2026-03-31`）：

- 后端数据面已具备：`agent_trace/tool_calls/tool_results/stop_reason/budget_used/session_summary/tool_plan_source`
- 已支持历史 `session/tool_plan/tool_results` 沿用重试
- 已补导出字段与 `/ai_pen_test/stats/` 轨迹维度统计
- 差距：前台仍缺更完整的 Agent 时间线、工具调用树与证据对照产品化呈现
- 结论：`后端基本到位，前台未完全收口`

### 阶段 F：基准靶场与回归

目标：

- 建立真正可量化的 Agent 能力评估

交付：

- 登录/默认口令靶场
- JWT 靶场
- API 文档靶场
- Actuator / 配置暴露靶场
- IDOR / SQLi / XSS / 文件处理 / SSRF 靶场

验收：

- 每次升级可量化：
  - 覆盖率
  - 误报率
  - 成功率
  - 平均轮数
  - 平均工具调用数

当前状态（截至 `2026-03-31`）：

- `/ai_pen_test/stats/` 已输出 `quant_metrics`、`capability_benchmarks`、`phase_f_readiness`、`engineer_focus_queue`
- 已可统计：覆盖率、误报率、成功率、平均轮数、平均工具调用数
- 已可按 `risk_type / payload_type / high_value_family / verification_step` 查看分能力 benchmark
- 已可输出“工程师优先队列”及“具体入口 Top 列表”所需的 readiness/priority 数据面
- 差距：登录/JWT/API文档/Actuator/IDOR/SQLi/XSS/文件/SSRF 靶场与标注样本尚未建立
- 结论：`指标数据面已具备，靶场基线未完成`

## 9. 结论

真正要解决的，不是“再多加几个工具”，而是：

- 把 `AI渗透` 从“规则驱动 + AI装饰”升级为“模型驱动 + 工具闭环”
- 把 `ARL/docker/dicts/dict` 从“仓库资源 preview”继续升级为“Agent 可声明预算/节流策略的受控资源”
- 把“少量固定示例路径”升级为“通用高价值目标家族”

最终标准：

- `PortSwigger 能力下限`
- `Agent MCP 真闭环`
- `会话/认证可打`
- `弱口令字典可受控接入`

当前口径结论（截至 `2026-03-31`）：

- 按阶段 C 最低口径：`已达标，可用`
- 按整份方案最终口径：`未全部完成`
- 按“互联网资产高价值漏洞入口发现器”口径：`已具备基础渗透测试能力，进入持续完善阶段`
- 已接近完成的阶段：`B / C-Core / D / E(后端数据面)`
- 仍需继续推进的阶段：`A / C-AutoPassive / E(前台产品化) / F`

建议下一步优先级：

1. 阶段 C / 7：完成参数单引擎与受控字典资源封装，继续提升“真漏洞入口”挖掘能力
2. 阶段 F：建立最小靶场与正负样例集，把误报率和入口价值真正量化
3. 阶段 A：继续把控制权从 `commonTask` 挪到 runtime，减少执行路径写死
