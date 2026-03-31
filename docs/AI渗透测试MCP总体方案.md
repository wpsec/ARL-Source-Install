# AI渗透测试MCP总体方案

## 1. 目标定位

- 目标版本：`v4.5.0`
- 能力下限：至少具备 `PortSwigger Web Security Academy` 核心 Web 漏洞能力
- 架构要求：必须是真正的 `Agent MCP`，不是“规则驱动 + AI 点缀 + MCP 外壳”
- 运行边界：默认低副作用、强审计、可回放、可人工接管，不做自动化后渗透和横向移动

一句话目标：

- `以 PortSwigger 方法论为能力下限，以 Agent MCP 为执行架构，以低副作用验证为默认模式。`

## 2. 当前问题与根因

当前 AI 渗透测试已具备：

- 候选汇聚
- 统一工具注册
- MCP 审计产物（`agent_trace/tool_calls/tool_results/stop_reason/budget_used`）
- 基础 HTTP/IDOR/API 文档/JWT/WebSocket 验证
- 浏览器情报补充

但仍存在典型“假 Agent MCP”问题：

1. `commonTask` 仍然主导大部分执行逻辑
2. planner 更像“给建议”，不是“每轮决策的大脑”
3. runtime 更像“带审计的工具执行器”，不是“多轮推理闭环”
4. 登录、会话、CSRF、验证码、认证状态并没有形成真正工具链
5. 弱口令能力没有接到 AI 渗透 Agent 主链，只在传统 `weak_brute` / 其他链路中存在

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

高价值目标不能只靠少量示例路径，而应按“目标家族”识别：

1. 接口说明 / Schema 家族
   - `swagger/openapi/api-docs/redoc/knife4j/graphql schema`

2. 管理 / 诊断家族
   - `actuator/jolokia/prometheus/metrics/configprops/mappings/beans/conditions/loggers`

3. 认证入口家族
   - `login/signin/passport/sso/cas/oauth/token/auth/login/connect/token`

4. 文件处理家族
   - `upload/import/download/export/attachment/template/avatar/report`

5. 敏感文件 / 配置家族
   - `.env/.git/config/application.yml/bootstrap.yml/web.config/config.php`

候选排序统一依据：

- 任务范围
- 状态码优先（优先 `200/201/206`）
- 路径价值
- 认证/文件/对象引用/配置暴露信号
- 知识命中
- 浏览器运行时信号

## 7. 登录与弱口令：为什么现在没用 `ARL/docker/dicts/dict`

当前仓库中确实存在弱口令字典：

- [user.txt](/Users/eric.sy.wu/Documents/Github/newui/ARL-Source-Install/ARL/docker/dicts/dict/user.txt)
- [pass.txt](/Users/eric.sy.wu/Documents/Github/newui/ARL-Source-Install/ARL/docker/dicts/dict/pass.txt)

但它**目前没有接入 AI 渗透 Agent 主链**，原因不是“没有字典”，而是架构上尚未完成以下能力：

1. 没有 `login_probe / credential_probe / detect_login_success` 工具
2. 没有会话层，无法稳定维护 Cookie / CSRF / Redirect
3. 没有验证码/风控识别后的止损策略
4. 没有最小凭证集与大字典分级治理
5. 没有把“登录入口识别”升级成“登录验证链”

也就是说：

- `ARL/docker/dicts/dict` 不是没价值
- 而是**当前 AI 渗透执行链还没有真正能安全消费它的工具层**

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

- 阶段 C 已达成可用完成态（100% 可用口径）
- 已覆盖能力链路与成立证据标准：
  - 登录/会话：`session_start -> extract_csrf_token -> credential_probe -> detect_login_success`，以登录成功/阻断信号判定
  - API/OpenAPI/GraphQL：`api_doc_probe/graphql_probe` 多端点探测，基于结构响应摘要判定
  - JWT/认证协议：`jwt_probe + token_replay + OAuth/OIDC 协议端点探测`，基于弱密钥/alg=none/令牌字段/协议语义分级判定
  - IDOR/访问控制：`idor_probe` 多对象变异，一致性与敏感字段差异评分分级判定
  - 文件处理：`upload_probe/file_probe`，基于上传成功特征与下载响应特征判定
  - SQLi：`sqli_probe`，覆盖 `error_based/boolean_based/time_based` 证据判定
  - XSS/DOM XSS：`xss_probe + js_context`，覆盖弹窗执行证据与 `dom_xss_proof_type` 结构化证据
  - SSRF/SSTI/XXE/CMDI：对应探针覆盖专项 proof（元数据命中、模板表达式执行、外部实体文件读取、命令输出）

### 阶段 D：高价值目标通用化

目标：

- 不依赖个别示例路径

交付：

- `site/url/fileleak/wih/js/runtime` 统一高价值目标提取器
- 按目标家族排序

### 阶段 E：结果与轨迹产品化

目标：

- 用户看得懂 Agent 为什么这样测

交付：

- Agent 时间线
- 工具调用树
- 请求/响应证据对照
- 会话状态摘要
- 支持沿用历史 session/tool_plan 重试

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

## 9. 结论

真正要解决的，不是“再多加几个工具”，而是：

- 把 `AI渗透` 从“规则驱动 + AI装饰”升级为“模型驱动 + 工具闭环”
- 把 `ARL/docker/dicts/dict` 从“仓库里存在的文件”升级为“Agent 可安全消费的受控资源”
- 把“少量固定示例路径”升级为“通用高价值目标家族”

最终标准：

- `PortSwigger 能力下限`
- `Agent MCP 真闭环`
- `会话/认证可打`
- `弱口令字典可受控接入`
