# AI渗透测试MCP总体方案

## 1. 目标定位

- 目标版本：`v4.5.x`
- 文档同步版本：`v4.5.64`（截至 `2026-04-01`）
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
5. 结果虽已可量化，且已具备基础工程师优先级视图，但仍需继续和基线/误报抑制联动
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
   - 对象引用缺陷（以未授权访问视角为主）
   - 访问控制异常线索
   - 越权相关仅保留人工复核线索，不自动定性

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

当前状态（截至 `2026-04-01`）：

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

当前实现状态（截至 2026-04-01）：

- `C-Core（主动验证能力）`：基本完成
  - 已具备：前端 JS / runtime API / 表单字段（含隐藏字段）提取
  - 已具备：参数汇总后自动生成 tool plan 并调用 MCP
  - 已具备：`SQLi/XSS/DOM XSS/SSTI/CMDI/SSRF/XXE/JWT/IDOR/文件上传下载` 基础自动验证链
  - 已具备：认证链（JWT + OAuth/OIDC + token replay）语义降噪与分级判定
  - 已具备：上传/下载类接口自动探测与证据化输出

- `C-AutoPassive（被动参数提取 -> AI分析 -> MCP自动测）`：部分完成
  - 已有能力：多源参数汇总（JS/runtime/form/api-doc/hidden）与图谱摘要
  - 已补能力：`path_traversal_probe / web_policy_probe / socketio_probe / websocket_probe` 已接入主链
  - 已补能力：`parameter_probe_families` 已可把参数标签统一映射为 `IDOR/路径穿越/SSRF/JWT/上传下载/SQLi/XSS` 家族，并驱动低副作用参数编排
  - 已补能力：参数感知 payload 编排已可优先命中 query 参数，并在无 query 时回退利用 `sample_interfaces` 的 `GET/POST` 线索构造真实接口探针
  - 已补能力：`request_template_mode/content_type/params/summary` 已随验证结果落库，并接入统计、工程师优先入口与导出链，能直接区分 `query/form/json/body` 模板入口
  - 已补能力：`受控 payload 模板库` 已落地，`SQLi/XSS/SSRF/CMDI/SSTI/XXE` 会按 `request_mode/content_type` 选择受控变体；AI planner 也可回 `payload_variant`，由执行链安全映射到模板 payload
  - 已补能力：`payload_variant/payload_expected_signal/payload_proof_candidates/proof_type/proof_signals/proof_summary` 已统一进入验证日志、结果落库、重试更新、统计与导出链，不再只是运行时临时信息
  - 已补能力：已新增 `proof_family` 证据家族（如 `auth_bypass/surface_exposure/realtime_exposure/response_differential/sensitive_disclosure`），工程师可按更高层证据类型快速筛选“更像真入口”的结果
  - 已补能力：高价值 `admin/dashboard/account/current/profile` 路径的无登录直访开始收敛为 `unauth_access` 证据家族，用于优先发现真正值得工程师接手的未授权入口
  - 已补能力：`unauth_access_hit/type/reason` 已进入结果落库、统计、`Phase F readiness`、工程师优先入口与导出链，未授权直访能力已从“验证链命中”推进到“可筛选、可排序、可导出”的结果层
  - 已补能力：`replay` 已可自动扩展 `api/me/userinfo/account/current/manage/actuator/admin/dashboard` 等高价值未授权复核目标，并在多响应里自动选择更强的未授权证据，不再只盯最后一个响应
  - 已补能力：`unauth_actuator_surface` 与 `unauth_health_endpoint` 已分层，`actuator/health/info` 这类公开健康检查默认降为 `needs_manual_review`，降低把存活探针当成真入口的噪声
  - 已补能力：`unauth_probe_summary` 已进入结果层，会把一轮未授权复核中的 `targets/success/blocked/login_wall/health_like` 收成摘要，用于解释“为何当前不判未授权”并进一步压低误报
  - 已补能力：`unauth_negative_type` 已结构化进入结果、统计、导出与工程师优先入口，并已反向驱动 `Phase F readiness` 收紧口径；当某类能力当前只有“鉴权拦截/登录墙/健康检查”负信号而无正向命中时，不再乐观记为 `covered`
  - 已补能力：`proof_strength` 与 `decision_guard_action/reason` 已接入最终裁决、工程师优先排序与导出链；`access_control`、`health_only`、`auth_blocked/login_wall/guarded_mixed` 这类高误报信号现在会主动触发结果降级与原因解释
  - 已补能力：已修正 `redirect -> dir` 子串误判，减少 URL 跳转参数被错误打到路径穿越链的噪声
  - 差距：参数类型标签 -> payload 编排 -> proof/evidence 判定 主干已通，当前主要剩余是把这套守门逻辑继续和阶段 F 基线样本联动
  - 差距：`未授权访问` 与 `访问控制线索` 的结果分流已具基础，但仍需继续压误报；部分实时通道深测能力仍需补强
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
- AI渗透工作台已补：`未授权概览 / 阶段 F 能力就绪度 / 工程师优先能力 / 裁决守门概览 / 最小基线概览` 卡片、`证据家族/证据强度/守门动作/未授权负信号` 筛选、结果列表行内证据速览、右侧 `proof_summary/request_template_summary/unauth_probe_summary/decision_guard_reason` 证据总览，以及最小基线缺口列表
- 差距：前台主体已基本到位，但仍可继续补更细的 Agent 时间线组织与靶场基线联动
- 结论：`前后台主链已基本打通，前台进入收尾优化`

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

当前状态（截至 `2026-04-01`）：

- `/ai_pen_test/stats/` 已输出 `quant_metrics`、`capability_benchmarks`、`phase_f_readiness`、`engineer_focus_queue`
- 已可统计：覆盖率、误报率、成功率、平均轮数、平均工具调用数
- 已可按 `risk_type / payload_type / high_value_family / verification_step` 查看分能力 benchmark
- 已可按 `request_template_mode` 查看模板入口分布，并在工程师入口列表中直接查看 `request_template_summary`
- 已可输出 `unauth_negative_type/unauth_negative_summary`，直接区分“被鉴权挡住 / 登录墙 / 只有健康检查面”等未授权负信号
- 已可输出 `unauth_access_overview`，在 stats 顶层直接汇总未授权正向命中、负信号主导类型和建议动作
- 已可输出 `decision_guard_summary`，并按 `proof_strength / decision_guard_action` 量化“守门压制了多少激进结论、主导守门动作是什么”
- 已可输出 `minimal_baseline_summary`，按第一版 10 个最小正负样例给出 `passed/partial/failed/missing`、`top_gaps` 与 `recommended_action`，并在前台工作台直接展示
- 已可输出“工程师优先队列”及“具体入口 Top 列表”所需的 readiness/priority 数据面，并在前台工作台直接展示
- 差距：当前已具“基线摘要”，但真实靶场、标注样本与自动跑批入口尚未建立
- 结论：`指标与最小基线数据面已具备，真实靶场基线未完成`

最小基线建议（第一版）：

- 第一目标不是“把所有漏洞类型一次做全”，而是先做一套能证明“真入口更多、误报更少”的最小考卷
- 第一批建议只覆盖最有价值、最符合当前系统定位的 5 条主线：
  - `未授权真入口`
  - `未授权负信号降噪`
  - `Actuator/配置暴露`
  - `API 文档暴露`
  - `JWT/认证链`

建议先落 10 个最小样例：

1. `unauth_admin_positive`
   - 场景：无凭证访问 `/admin` 或 `/admin/dashboard` 可直接进入后台
   - 预期：`decision=verified`
   - 预期证据：`proof_family=unauth_access`，`proof_type=unauth_admin_portal`
   - 守门预期：不应被 `downgrade_*`

2. `unauth_profile_positive`
   - 场景：无凭证访问 `/api/me`、`/userinfo`、`/account/current` 返回账户资料
   - 预期：`decision=verified`
   - 预期证据：`proof_family=unauth_access`，`proof_type=unauth_profile_data`
   - 守门预期：`proof_strength` 至少为 `medium`

3. `unauth_login_wall_negative`
   - 场景：访问高价值路径最终跳到登录页或返回明确登录墙
   - 预期：不应为 `verified`
   - 预期证据：`unauth_negative_type=login_wall`
   - 守门预期：优先出现 `downgrade_negative_signal`

4. `unauth_auth_blocked_negative`
   - 场景：访问高价值路径被 `401/403` 拦截
   - 预期：不应为 `verified`
   - 预期证据：`unauth_negative_type=auth_blocked`
   - 守门预期：优先出现 `downgrade_negative_signal`

5. `unauth_health_only_negative`
   - 场景：无凭证只能访问 `/actuator/health`、`/actuator/info`
   - 预期：`decision=needs_manual_review` 或 `likely_false_positive`
   - 预期证据：`proof_type=unauth_health_endpoint`，`unauth_negative_type=health_only`
   - 守门预期：优先出现 `downgrade_health_only`

6. `actuator_env_positive`
   - 场景：无凭证访问 `/actuator/env`、`/manage/env` 返回敏感配置或环境信息
   - 预期：`decision=verified`
   - 预期证据：`proof_family=sensitive_disclosure` 或 `surface_exposure`
   - 守门预期：不应因 `health_only` 类规则被误降级

7. `actuator_health_negative`
   - 场景：仅 `/actuator/health` 可访问，不返回高价值敏感字段
   - 预期：不应为 `verified`
   - 预期证据：可保留 `unauth_access` 线索，但必须低优先级
   - 守门预期：应出现 `downgrade_health_only` 或进入 `health_only`

8. `api_doc_positive`
   - 场景：`/swagger-ui/`、`/v3/api-docs`、`/openapi.json` 可直接访问
   - 预期：`decision=verified` 或高优先级 `needs_manual_review`
   - 预期证据：`proof_family=surface_exposure`
   - 补充要求：应进入 `phase_f_readiness` 的 `API文档/GraphQL`

9. `jwt_none_positive`
   - 场景：JWT `alg=none` 或等价弱校验链存在
   - 预期：`decision=verified`
   - 预期证据：`proof_family=auth_bypass`
   - 守门预期：不应被 `downgrade_negative_signal`

10. `jwt_auth_enforced_negative`
   - 场景：JWT 接口对无效 token、none token、错误 client 均明确拒绝
   - 预期：不应为 `verified`
   - 预期证据：应更偏 `likely_false_positive` 或保守 `needs_manual_review`
   - 守门预期：应保留“鉴权生效”的负向解释

每个样例至少要校验这 6 个字段：

- `decision`
- `proof_family`
- `proof_type`
- `proof_strength`
- `decision_guard_action`
- `unauth_negative_type`

第一版最小验收指标建议：

- 未授权正样例命中率：`>= 80%`
- 未授权负样例误报率：`<= 10%`
- `health_only` 误报为 `verified`：`必须为 0`
- `auth_blocked/login_wall` 误报为 `verified`：`必须为 0`
- `decision_guard` 命中的负样例中，成功降级率：`>= 80%`
- 平均轮数与平均工具调用数：先记录基线，不在第一版设硬阈值

落地顺序建议：

1. 先做 5 个未授权/Actuator 样例
2. 再补 2 个 API 文档样例
3. 最后补 2 个 JWT 样例
4. 第一轮不追求 `SQLi/XSS/文件/SSRF` 全覆盖，先把“高价值入口 + 降噪”基线立住

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

当前口径结论（截至 `2026-04-01`）：

- 按阶段 C 最低口径：`已达标，可用`
- 按整份方案最终口径：`未全部完成`
- 按“互联网资产高价值漏洞入口发现器”口径：`已具备基础渗透测试能力，进入持续完善阶段`
- 已接近完成的阶段：`B / C-Core / D / E`
- 仍需继续推进的阶段：`A / C-AutoPassive(收尾) / F`

建议下一步优先级：

1. 阶段 C / 7：完成参数单引擎与受控字典资源封装，继续提升“真漏洞入口”挖掘能力
   - 当前已完成：参数探针家族、受控字典 preview 资源封装、接口级 payload 编排、请求模板摘要落库、受控 payload 模板库与 `payload_variant` 选择、`proof_summary/proof_family` 结果链打通，以及 `proof_strength/decision_guard` 对最终裁决、人工优先级和误报抑制的第一阶段收口
   - 下一步重点：让这套守门逻辑进一步和阶段 F 的正负样例基线联动，持续降低水洞
2. 阶段 F：建立最小靶场与正负样例集，把误报率和入口价值真正量化
3. 阶段 A：继续把控制权从 `commonTask` 挪到 runtime，减少执行路径写死
