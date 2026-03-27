# AI渗透测试 + MCP 开发规划（总设计）

## 1. 目标与定位

本功能目标是新增一条“可执行”的 AI 渗透测试链路，用于对已发现风险进行二次验证与误报收敛。

核心定位：
- `AI去噪分析`：以文本分析为主，不主动测试。
- `渗透测试（现有 penetration_test）`：规则/工具链主动测试。
- `AI渗透测试（本规划）`：基于前期结果 + AI 推理 + MCP 工具调用，执行可控的验证动作并产出“有效/疑似误报/需人工复核”结论。

与现有功能关系：
- 与 `penetration_test` 不冲突，可独立开关。
- `AI渗透测试` 重点消费 `风险 / PoC风险 / 信息泄漏 / 渗透测试结果`，做进一步验证。
- 不替换现有扫描器，只做“后验证 + 提升命中质量”。
- 边界控制：不做内网横向移动与纵深渗透，目标是“打开突破口 + 证明漏洞可利用性”。

## 2. 用户侧需求映射

### 2.1 新建任务

新增任务选项：
- 字段：`ai_penetration_test`（默认建议关闭，灰度后可改默认开启）
- 文案：`AI渗透测试`
- 说明：开启后对任务中的风险结果执行 AI+MCP 二次验证。

触发策略：
- 当 `ai_penetration_test=true` 时，在 `vuln/nuclei_result/wih` 等阶段产出后触发 AI 渗透验证。
- 与 `penetration_test` 无依赖关系，可同时开启或单独开启。

### 2.2 新功能页面（任务详情）

在任务详情页新增 tab：
- 名称：`AI渗透`
- 位置：`WAF识别` 右侧
- 用途：展示 AI 渗透测试记录、payload、证据、结论与可复现信息。

建议字段：
- `target / vuln_url / source_module / vuln_type / risk_name`
- `payload_type / payload / verification_step`
- `evidence_snippet / http_status / response_hash_diff`
- `decision`（`verified`/`likely_false_positive`/`needs_manual_review`）
- `confidence / reason / model / tool_trace / save_date`

## 3. 总体架构

## 3.1 执行阶段

建议新增阶段：`ai_pen_test`

执行时机：
1. `nuclei_scan/afrog_scan/penetration_test/web_info_hunter` 产出后
2. 汇总候选记录
3. 分批执行 AI+MCP 验证
4. 落库并回写任务阶段统计

## 3.2 数据流

输入来源：
- `vuln`（含 penetration_test、web_info_hunter 等来源）
- `nuclei_result`
- `wih`（敏感信息线索）
- `site/url/service`（上下文：title/body/finger/http_server）

处理流程：
1. 候选提取与去重（URL+类型+参数签名）
2. 风险分类（XSS/注入/信息泄露/鉴权/JWT/API/WebSocket/业务逻辑）
3. AI 生成验证计划（受模板约束）
4. MCP 工具执行验证（只在任务 scope 内）
5. AI 归因与结论输出（严格 JSON）
6. 保存 `ai_pen_test_result` + 任务统计

## 4. MCP 能力设计

## 4.1 最小可用工具集（MVP）

第一阶段建议先做这些工具：
- `http_fetch`：GET/HEAD 拉取页面与资源
- `http_replay`：按指定方法、参数、header 重放请求
- `dom_probe`：定位 JS/DOM 变量、sink/source 线索
- `keyword_verify`：验证敏感关键词是否真实存在且可利用
- `api_doc_extract`：提取 Swagger/OpenAPI/Postman 参数结构
- `param_mutate`：参数拼接与值变异（轻量）

第二阶段扩展：
- `workflow_runner`：登录态与多步业务流程
- `idor_probe`：对象 ID 替换与越权探测
- `sqli_probe` / `cmdi_probe` / `ldap_probe`：分类型验证器

## 4.2 OWASP 能力覆盖要求（纳入 AI 渗透验证）

必须覆盖（按阶段推进）：
- 身份与会话：
  - JWT 安全测试：未验签、签名缺陷、弱签名爆破、`alg/header` 参数注入、过期与受众校验缺陷
  - 登录接口爆破与账户策略检测（限频/锁定/验证码）
- Web 与注入：
  - SQL 注入、命令注入、LDAP 注入
  - XSS（反射型、存储型、DOM）
  - CSRF、SSRF
- 文件与解析：
  - 文件上传漏洞、任意文件读取/下载、XXE
- API：
  - REST API 参数拼接与越权测试（IDOR）
  - WSDL/SOAP API 参数提取与调用验证
  - Swagger/OpenAPI/Postman 文档解析后自动构造测试请求
- 实时通信：
  - WebSocket 握手、鉴权、消息注入与越权订阅检查

执行深度约束：
- 以“可证明漏洞有效”为停止条件，不追求深度攻击链。
- 单目标按预算执行，避免高风险动作与过度流量。

## 4.3 MCP 自动授权策略

必须做安全边界：
- 只允许访问当前任务 `scope` 目标。
- 禁止访问内网保留网段与本地元数据地址（如 `169.254.169.254`）。
- 禁止任意文件系统写入、禁止 shell 任意执行。
- 每条工具调用记录 `trace_id`、参数、结果摘要。

授权模式建议：
- `strict`：逐类白名单（默认）
- `task_scoped`：任务范围自动授权
- `manual`：每次人工确认（调试期）

## 5. 模型策略（AI + MCP）

建议双模型分层：
- `Planner（思考型）`：负责验证计划与步骤编排
- `Verifier（低成本模型）`：负责批量结果归因与结构化输出

推荐策略：
- 默认 `Planner` 开启较强推理（温度低，稳定优先）
- `Verifier` 走低成本模型以控费
- 失败自动降级到“规则验证 + 人工复核建议”

## 6. AI管理配置扩展

在 `AI管理` 新增 `AI渗透测试` 配置区：
- `AI_PEN_TEST_ENABLE`：总开关
- `AI_PEN_TEST_MODEL_PROFILE_ID`：模型配置
- `AI_PEN_TEST_MAX_CASES_PER_TASK`：每任务最大验证数
- `AI_PEN_TEST_TIMEOUT_SEC`
- `AI_PEN_TEST_CONCURRENCY`
- `AI_PEN_TEST_MODE`：`observe` / `verify` / `aggressive`
- `AI_PEN_TEST_MCP_AUTH_MODE`：`strict/task_scoped/manual`

SOP/提示词配置：
- 新增模板文件：`ARL/docker/ai/sop/default_ai_pen_test.yaml`
- 场景 ID 建议：`ai_pen_test`

### 6.1 当前已落地（M1.1）

已在代码中落地最小可用配置（可在 AI 管理中直接设置）：
- `AI_PEN_TEST_ENABLE`
- `AI_PEN_MCP_ENABLE`
- `AI_PEN_MCP_MAX_TOOL_CALLS`
- `AI_PEN_MCP_TIMEOUT_SEC`

当前最小 MCP 执行链：
- 基线重放：`http_fetch(get)`
- Payload 探针：`payload_probe(get)`（按风险类型自动拼接探针参数）
- 证据匹配：证据片段命中、响应差异、Payload 回显
- WAF 处理：命中智能跳过时自动标记 `skipped` 并保留原因

说明：
- `ai_penetration_test=true`（任务开关）且 `AI_PEN_TEST_ENABLE=true`（AI 管理开关）时才会实际执行。
- 结果会写入 `ai_pen_test_result`，并在 AI 对话日志中写入 `ai_pen_test_plan / ai_pen_test_exec`。

### 6.2 tools/poc 知识索引脚本

新增索引脚本（面向 worker 可读路径）：
- `ARL/app/tools/build_ai_pen_knowledge_index.py`

默认输入：
- `tools/poc/POC`
- `tools/poc/vulhub`
- `tools/poc/PoC-in-GitHub`

默认输出：
- `ARL/docker/ai/sop/ai_pen_knowledge_index.json`

示例命令：

```bash
python3 /code/app/tools/build_ai_pen_knowledge_index.py
```

## 7. 数据模型与接口

## 7.1 新增集合

集合名建议：`ai_pen_test_result`

关键字段：
- `task_id`
- `source_collection`（`vuln/nuclei_result/wih`）
- `source_id`
- `target` / `vuln_url`
- `risk_type` / `risk_name`
- `payload` / `payload_type`
- `steps`（执行步骤）
- `tool_trace`（MCP 调用摘要）
- `evidence`
- `decision`
- `confidence`
- `reason`
- `model/provider/profile`
- `status`（`ok/error/skipped`）
- `save_date`

索引建议：
- `(task_id, save_date desc)`
- `(task_id, decision)`
- `(source_collection, source_id)`

## 7.2 API 建议

- `GET /ai_pen_test/`：列表查询
- `POST /ai_pen_test/retry/`：重试指定记录
- `POST /ai_pen_test/batch_run/`：对任务批量执行
- `POST /ai_pen_test/delete/`：删除记录
- `GET /ai_pen_test/stats/`：统计

AI日志场景：
- `ai_pen_test_plan`
- `ai_pen_test_exec`
- `ai_pen_test_decision`

## 8. 部署方案（重点讨论项）

## 8.1 方案对比

方案 A：在现有 worker 安装大量工具  
- 优点：接入快  
- 风险：镜像膨胀、升级慢、稳定性差

方案 B：新增 `ai_pt_worker + mcp_toolbox`（推荐）  
- 优点：职责隔离，工具可独立升级，风险可控  
- 风险：编排稍复杂

建议采用方案 B：
- `arl_worker` 负责调度与业务逻辑
- `mcp_toolbox` 负责工具执行
- `ai_pt_worker` 专门跑 AI 渗透队列（如 `arlpentest`）

## 8.2 Kali 相关建议

不建议直接把完整 Kali 注入主 worker。  
建议：
- 按能力选择最小工具集镜像（Debian/Ubuntu + 必要组件）
- 对重型工具单独 sidecar
- 每个工具版本固定并做健康检查

## 9. 验证场景（与你提供示例对齐）

DOM XSS 示例：
- 输入：`verify.js` 命中 `dom_xss`
- 动作：定位 sink/source，生成上下文 payload，重放验证
- 输出：可复现触发链或误报结论

信息泄露示例：
- 输入：`umi.xxx.js` 命中 `secret_key`
- 动作：访问资源、定位 `accesskey` 上下文、判断是否真实敏感值
- 输出：`verified` 或 `likely_false_positive`

JWT 示例：
- 输入：发现 `Authorization: Bearer` 与 JWT 结构 token
- 动作：校验签名算法/验签流程/`kid` 与 header 注入点，尝试弱签名与配置缺陷验证
- 输出：`verified`（可伪造/可绕过）或 `needs_manual_review`

WebSocket 示例：
- 输入：站点存在 `ws://`/`wss://` 端点
- 动作：检测握手鉴权、消息权限隔离、订阅主题越权
- 输出：`verified` 或 `likely_false_positive`

## 10. 迭代里程碑

M0（设计冻结）
- 配置项、数据模型、页面交互、MCP 策略评审通过

M1（基础可用）
- 新建任务开关 + `AI渗透` 页面
- 候选提取与只读验证（不主动攻击）

M2（可执行验证）
- MCP 最小工具集
- 支持 XSS/信息泄露/简单注入/JWT 基础验证

M3（业务与接口场景）
- Swagger/OpenAPI 参数自动拼接测试
- IDOR/登录流程/WebSocket/REST/WSDL 场景

M4（稳定化与灰度）
- 成本控制、失败重试、审计与报表
- 分阶段放量

## 11. 验收指标

效果指标：
- 误报率下降
- 已验证高价值风险占比提升
- 人工复核耗时下降

稳定性指标：
- 单任务 AI 渗透阶段失败率
- MCP 工具超时率
- 平均验证耗时与 Token 成本

安全指标：
- 越权访问命中率为 0
- 非 scope 目标请求率为 0

## 12. 与 `tools/poc` 三类库协同（重点）

`tools/poc` 下三类资源都应纳入训练与评估闭环：

1. `tools/poc/POC/`（渗透测试文库）  
- 价值：沉淀了大量 PoC、测试文档、实战经验与方法论。  
- 用法：提炼“漏洞类型 -> 验证步骤 -> payload 模式 -> 证据标准”模板，喂给 AI 计划器与 verifier。

2. `tools/poc/vulhub/`（靶场）  
- 价值：可复现漏洞环境与实操路径，覆盖多类漏洞链路。  
- 用法：作为回归测试基准，验证 AI+MCP 的命中率、误报率、复现实验稳定性。

3. `tools/poc/PoC-in-GitHub/`（JSON 语料）  
- 价值：社区最新 PoC 结构化情报，更新频率高。  
- 用法：构建“漏洞特征词、payload 片段、影响组件”知识索引，增强召回与别名覆盖。

落地原则：
- 首期不强依赖在线检索上述库，优先离线索引化与评估集化。
- 以这些库持续更新 AI 渗透测试 SOP、payload 模板与误报规则。

## 13. 待决策清单（进入开发前必须确认）

1. 默认是否开启 `ai_penetration_test`
2. MCP 自动授权默认模式（建议 `strict`）
3. Planner/Verifier 模型组合与成本预算
4. 是否在首期接入登录态业务流程验证
5. 部署采用 `sidecar` 还是“主 worker 直装工具”

## 14. 开发顺序建议（落地执行）

1. 先实现数据面与 UI：任务开关、`AI渗透` 页面、结果落库
2. 再接入 AI 计划器：只输出验证步骤，不执行
3. 再接 MCP：先只读验证（fetch/replay/keyword verify）
4. 最后扩展主动 payload 验证与业务逻辑场景

---

本规划用于冻结需求与实施边界。确认后按里程碑逐步开发，不一次性大爆炸上线。
