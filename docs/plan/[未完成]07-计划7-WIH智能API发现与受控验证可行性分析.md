# 计划 7：通用 Web/API 资产证据图与智能验证可行性分析

状态：[未完成][需求重构]，仅完成方案评估，未实施。

## 一、重新定位

本计划不建设“Vue/React/qiankun API 解析器”，而建设一个**框架无关、证据驱动、自适应调度的 Web/API 信息搜集引擎**。

Vue、React、Angular、qiankun、无界、SSR、传统 MVC、GraphQL、SOAP、WebSocket 和移动端后端，都只是不同的目标形态和证据来源，不能成为核心数据模型的前提。

```text
任意 Web/API 目标
       ↓
TargetProfileResolver
       ↓
多源证据采集
       ↓
EvidenceGraph
       ↓
Asset / API / Parameter / Schema Registry
       ↓
AdaptiveScheduler
       ↓
受控验证与证据聚合
       ↓
WihRecord 兼容输出 → ARL 人工复核
```

本计划的目标不是自动利用漏洞，而是：

- 发现尽可能完整的资产、页面、脚本、接口、参数、协议和文档关系；
- 减少不同工具对同一资源的重复请求；
- 根据目标特征动态选择低成本、高信息量的策略；
- 对需要主动请求的候选进行只读、限量、可审计验证；
- 输出带来源、证据、状态、置信度和人工复核理由的结果。

## 二、设计原则

1. **证据优先**：确定值、模板值、运行时值和推断值必须分开保存，推断不能冒充事实。
2. **目标自适应**：不预设目标一定是前端应用；先识别形态，再决定是否启用浏览器、JS 深解析或协议专用策略。
3. **一次获取，多方消费**：响应、脚本、文档和运行时请求进入任务级 Registry，爬虫、URLFinder、WIH 和 Parser 共享。
4. **信息增益优先**：优先处理能带来新资产、新接口或新证据的候选，不盲目扩大请求数量。
5. **安全分级**：被动发现、安全读取和专门安全测试严格分开；WIH 不自动执行写操作、越权、注入或压力测试。
6. **结果可解释**：每条 API 记录都能回答“从哪里发现、为什么认为有效、是否访问过、用什么 profile 访问、结果是什么”。
7. **兼容优先**：不改变现有 HTTP API、Mongo 文档、导出字段和 `WihRecord` 公共语义。

## 三、支持范围与目标形态

| 目标形态 | 默认策略 | 可选增强 |
|---|---|---|
| 未知 Web 站点 | HTTP、HTML、Header、链接、表单、重定向和错误响应 | 目标画像和自适应队列 |
| 传统 MVC/服务端渲染 | HTML 页面、表单 action、静态资源、目录和错误页 | 模板路由与参数关系 |
| SSR/混合渲染 | HTML 初始数据 + 脚本 + 页面请求 | 浏览器运行时补证 |
| SPA | 路由、脚本、request wrapper、运行时请求 | JS 结构化解析 |
| 微前端 | 应用挂载、资源图、路由和调用关系 | qiankun/无界作为适配器 |
| API-only/网关/BFF | OpenAPI、Postman、错误响应、Header、路径族 | 受控 Endpoint 验证 |
| GraphQL | `/graphql`、query、variables、operationName | Schema 和操作分类 |
| SOAP/WSDL | XML 文档、service、binding、port、operation | 受控只读 Operation 识别 |
| WebSocket/SSE | 握手地址、协议、事件名、消息形态 | 运行时浏览器采集 |
| 移动端/桌面端后端 | 用户提供的 HAR、OpenAPI、代理导出和已授权运行时流量 | 调用图和认证 profile 对比 |
| 混淆、压缩或动态生成应用 | 低成本字符串预筛 | 浏览器运行时或定向结构解析 |
| 云函数、CDN、反向代理 | Host、路径前缀、重定向、响应和证书关系 | BFF/网关路由画像 |

覆盖边界：无法从静态资源得到的运行时接口，可以通过浏览器或用户提供的流量证据补充；无法确认副作用和授权范围的请求，只进入 `pending/skipped`，不强行访问。

## 四、现有能力与主要缺口

| 能力 | 当前实现 | 缺口 |
|---|---|---|
| HTML、页面链接、iframe、表单、JS 文件 | `wih_page_intel`、爬虫、URLFinder | 资源关系和跨策略消费仍需统一 |
| JS API 线索 | `wih_js_intel` | 参数、调用上下文、脚本关系和动态值不完整 |
| OpenAPI/Swagger、Postman | `wih_api_doc` | 需要统一文档队列、参数/schema/auth 和 Endpoint Registry |
| GraphQL 请求识别 | JS/浏览器情报 | Schema、操作类型和字段关系未完整接入 |
| WSDL/SOAP | 当前主要是 URL/文本发现 | 缺少安全 XML Operation 解析 |
| 浏览器运行时请求 | `browser_intel_scan` 已有实现和测试 | 尚未稳定成为主 WIH 的事件源 |
| Endpoint Probe | `wih_endpoint_probe` | 需要安全分级、认证 profile、响应对比和证据聚合 |
| 结果写回 | `WihRecord` 和现有 Mongo 结果 | 缺少应用/路由/调用点/参数/验证状态的统一详情 |

计划 6 已完成统一 API 契约和 shadow metrics 的前两批，但 `ApiCandidateRegistry`、`ApiDocumentQueue` 和统一 Endpoint 消费仍是后续工作。计划 7 应复用计划 6，不再创建另一套孤立解析链路。

## 五、统一目标架构

```text
Celery / DomainTask
          ↓
WebAssetScanOrchestrator
          ↓
TargetProfileResolver
          ↓
DiscoveryContext
 ├─ ResponseRegistry
 ├─ EvidenceGraph
 ├─ CandidateRegistry
 ├─ ApiCandidateRegistry
 ├─ EndpointRegistry
 ├─ RequestScheduler
 ├─ WafPolicy
 └─ DiscoveryLedger
          ↓
┌─────────────────────────────────────────────┐
│ Evidence Collectors                          │
│ HTTP / HTML / Script / Document / Browser    │
│ GraphQL / SOAP / WebSocket / External Intel  │
└─────────────────────────────────────────────┘
          ↓
┌─────────────────────────────────────────────┐
│ Normalizers and Parsers                      │
│ URL / Route / API / Parameter / Schema       │
│ Protocol / Response Shape / Auth Hint        │
└─────────────────────────────────────────────┘
          ↓
              EvidenceGraph
          ↓
┌─────────────────────────────────────────────┐
│ AdaptiveScheduler                            │
│ priority / information gain / budget / WAF  │
└─────────────────────────────────────────────┘
          ↓
┌─────────────────────────────────────────────┐
│ SafeVerifier                                 │
│ passive / safe-read / auth-boundary compare  │
└─────────────────────────────────────────────┘
          ↓
EvidenceAggregator → WihRecord → ARL 人工复核
```

### 5.1 组件职责

- `TargetProfileResolver`：根据响应 Header、HTML、脚本比例、路由、协议和文档信号生成目标画像，不绑定前端框架。
- `EvidenceCollector`：只采集一种证据类型，所有网络请求必须经 `RequestScheduler`。
- `EvidenceGraph`：保存资源、关系、来源、深度、置信度和证据时间线。
- `CandidateRegistry`：保存所有资产候选和状态，不因优先级排序而删除低优先级候选。
- `ApiCandidateRegistry`：保存 API 文档和 API 调用点，聚合多个来源。
- `EndpointRegistry`：按规范化 URL、method、请求体摘要、认证 profile 和 API 类型区分 Endpoint。
- `AdaptiveScheduler`：按目标画像和信息增益选择下一步策略，负责预算、公平性和 WAF 隔离。
- `SafeVerifier`：只执行被允许的被动或安全读取验证，不负责漏洞利用。
- `EvidenceAggregator`：将响应状态、响应结构、来源和认证对比组合为人工复核候选。

## 六、EvidenceGraph 统一模型

### 6.1 节点类型

```text
target       目标
origin       协议、域名、端口和证书来源
application  应用或服务边界
route        页面或接口路由
asset        HTML、JS、CSS、图片、source map 等资源
document     OpenAPI、Postman、GraphQL、WSDL 等文档
endpoint     API Endpoint
parameter    路径、Query、Header、JSON、Form、GraphQL 参数
schema       请求、响应、GraphQL 或 WSDL 类型关系
service      HTTP、WebSocket、SOAP 或其他服务
identity     认证 profile 和权限上下文
response     已获取响应及其结构摘要
```

### 6.2 关系类型

```text
served_by       页面/脚本由 origin 提供
imports         资源引用或动态导入
navigates_to    页面导航到路由
calls           页面/脚本调用 Endpoint
documents       文档描述 Endpoint
observes        浏览器运行时观察到请求
redirects_to    重定向关系
references      文档或脚本引用其他资源
same_origin    同源关系
auth_required   认证对比证据
```

每条关系必须包含：

```text
task_id
source_type
source_url
source_detail
parent_node
depth
priority
confidence
input_signature
observed_at
```

### 6.3 Endpoint 最小契约

```text
endpoint_id
url
path_template
method
api_type
origin
application
route
operation
parent_document
parameter_evidence
request_body_type
request_shape_hash
response_shape_hash
auth_hint
request_semantics       read_only/write/unknown
sources
evidence_ids
verification_status
verification_reason_codes
manual_review_required
confidence
status
```

旧 `WihRecord` 继续由兼容 adapter 生成；详细证据优先存放在任务内 Registry、详情文档或受控诊断数据中，默认不保存 Authorization、Cookie、API Key 和完整敏感响应。

## 七、自适应发现流程

### 7.1 基础发现

所有目标先经过低成本基础发现：

1. 获取初始响应并登记 URL、状态码、Header、Content-Type、body hash 和响应大小。
2. 识别重定向、同源边界、页面类型、协议、脚本比例和文档信号。
3. 提取 HTML 链接、表单、iframe、资源和显式 API 文档引用。
4. 生成初始 `TargetProfile` 和候选队列。

### 7.2 目标画像

画像只用于选择策略，不作为漏洞结论：

```text
server_rendered
spa_or_hybrid
micro_frontend
api_only
document_first
graphql_signal
soap_signal
websocket_signal
script_obfuscated
unknown
```

例如：

- `server_rendered` 优先页面、表单、链接和错误响应；
- `spa_or_hybrid` 优先脚本和运行时请求；
- `api_only` 优先文档、路径族和响应特征；
- `graphql_signal` 才加入 GraphQL 专用解析；
- `soap_signal` 才加入安全 XML/WSDL 解析；
- `unknown` 保留通用路径，不因画像不明而盲目启动所有高成本策略。

### 7.3 信息增益调度

候选优先级建议基于：

```text
score = 新证据预期数量 × 置信度
        ÷ (请求成本 + 时间成本 + WAF 风险)
```

优先处理：

- 能发现新应用、路由、文档或 Endpoint 的资源；
- 多来源交叉确认的候选；
- 低成本且尚未被其他策略覆盖的响应；
- 已有调用关系但尚未解析参数或响应形状的 Endpoint。

当候选超过预算、连续多个策略无新增证据、WAF 风险升高或请求 profile 已覆盖时，候选进入 `pending/skipped`，不继续放大请求。

## 八、API 与调用点发现

### 8.1 静态证据

识别但不限定于：

- `fetch`、axios、XHR 和常见 request wrapper；
- URL 模板、HTTP method、Query、JSON、Form 和 Header 参数名；
- OpenAPI/Swagger、Postman、GraphQL、WSDL 文档地址；
- 页面操作、按钮 handler、service 方法、Controller 和模块名称；
- 动态 import、资源 manifest、路由配置和 source map 引用。

值类型必须分开：

```text
literal       静态确定值
template      /users/${id} 等模板值
runtime       只有执行后可获得的值
inferred      根据命名或上下文推断的值
```

### 8.2 运行时证据

浏览器采集仅在目标画像或静态覆盖不足时启用：

- 记录请求 URL、method、Content-Type、参数名、响应状态和触发页面；
- 记录 GraphQL operation type、operationName 和 query hash；
- 记录 WebSocket/SSE 握手地址和事件形态；
- 运行时发现的新文档和 Endpoint 立即回流 Registry；
- 默认不持久化 Cookie、Authorization、完整请求体和完整响应体。

### 8.3 微前端案例定位

用户提供的 BSC/qiankun 链路是一个高价值样本，目标产物应是：

```text
主壳 /
└── application=bsc
    ├── mount_path=/bsc
    ├── route=/web-sql
    ├── entry bundle
    ├── dynamic chunks
    ├── operation=查看表结构
    └── endpoint=getTableFieldByTableName
```

但同一模型也适用于：

- 传统 MVC 页面中的表单 action；
- Nuxt/Next/SSR 页面中的初始 JSON 和后续请求；
- API-only 网关中的 OpenAPI 路径；
- 移动端 HAR 中没有页面路由、只有调用关系的接口；
- WebSocket 页面中没有 REST URL、只有握手和消息事件的服务。

## 九、受控验证与人工复核

### 9.1 验证级别

| 级别 | 默认状态 | 行为 |
|---|---|---|
| L0 被动发现 | 开启 | 只消费已经获取的响应、脚本、文档和运行时证据 |
| L1 安全读取 | 开启 | GET/HEAD 及明确无副作用的读取请求，单 profile、有限重试 |
| L2 认证边界对比 | 显式开启 | 无 Authorization、无效凭证、已授权测试 profile 的受控对比 |
| L3 专门安全测试 | 不属于 WIH | 越权、注入、写操作、业务逻辑、爆破和压力测试转专门流程 |

默认安全规则：

- PUT、PATCH、DELETE 永不自动发送；
- 未确认只读语义的 POST 只发现、不访问；
- 只有显式 allowlist 或已确认无副作用的 POST 才能进入 L1；
- 不执行凭证爆破、Token 猜测、高复杂度 GraphQL、任意文件上传或写入型 SOAP 操作；
- 外域、越界重定向、认证缺失、WAF 阻断和预算耗尽必须显示明确状态。

### 9.2 认证异常候选

对可能存在匿名放行的 API，只做有限对比：

```text
anonymous       无 Authorization
invalid_auth    明确无效凭证
authorized      用户提供的授权测试身份，可选
```

对比状态码、Content-Type、响应结构 hash、长度区间、敏感字段类别、错误信息和兄弟接口认证要求，输出：

```text
verification_status = auth_anomaly_candidate
reason_codes = anonymous_2xx / invalid_auth_same_shape / sibling_requires_auth
manual_review_required = true
```

`auth_anomaly_candidate` 只是人工复核候选，不等于已确认漏洞。人工还需确认接口是否应公开、返回数据是否敏感、网关和业务服务的授权边界以及测试是否在授权范围内。

### 9.3 状态机

```text
discovered
  → queued
  → fetching
  → fetched
  → parsed
  → verified_read
  → auth_anomaly_candidate

任意阶段也可能进入：
failed / degraded / blocked / skipped / pending / covered
```

状态迁移由确定性代码控制，AI 只能用于摘要、聚类和人工复核排序，不能直接决定状态或漏洞等级。

## 十、效率与准确性

### 10.1 请求复用

- 页面、脚本、动态资源、API 文档和 Endpoint Probe 全部使用任务级 `ResponseRegistry`。
- 缓存键包含 URL、method、认证 profile、请求体摘要和扫描 profile。
- single-flight 合并并发 miss；同一响应由多个 Parser 消费。
- 统一 API 文档队列接收 JS、页面、URLFinder、浏览器和外部情报的新发现。

### 10.2 分层解析

1. 先用低成本规则筛选 API、协议和文档信号。
2. 只对高价值脚本、文档和调用点做结构化深解析。
3. vendor、低置信度模板和重复资源按信息增益降级。
4. 浏览器只用于静态分析无法确认的运行时关系。
5. 外部工具输出必须通过同一 Registry 归一化，不能绕过状态和来源记录。

### 10.3 WAF 与资源隔离

`api_verify`、`crawler`、`directory`、`wih`、`browser` 使用独立并发、超时、重试和熔断策略。API 验证触发的 WAF 默认只暂停 `api_verify`，不影响普通页面采集和其他策略。

## 十一、技术路线

### 第一阶段：Python 通用证据层

- 实现 `TargetProfileResolver`、`EvidenceGraph`、候选注册和统一请求 profile；
- 复用计划 6 的 `ApiCandidateRegistry`、`ApiDocumentQueue` 和 `EndpointRegistry`；
- 接入 HTML、脚本、文档、浏览器、GraphQL、SOAP、WebSocket/SSE 等 Collector；
- 先完成 L0/L1，L2 只做显式开关下的认证边界对比。

### 第二阶段：自适应调度和覆盖质量

- 建立信息增益评分、策略选择、候选预算和低收益停止条件；
- 补 OpenAPI 参数/schema/auth、GraphQL Schema、WSDL Operation 和运行时调用关系；
- 统一来源、响应结构、认证对比和人工复核证据；
- 用传统 MVC、SSR、SPA、API-only、微前端和协议样本建立跨场景 golden corpus。

### 第三阶段：Rust 后置数据加速

Rust 只处理无副作用、批量 CPU 逻辑：

- HTML/JS 文本扫描；
- URL、路由和 Endpoint 归一化；
- 参数候选提取；
- 关系和候选去重；
- 响应结构、指纹和优先级计算。

Rust 不负责目标画像的最终决策、认证、网络、WAF、漏洞判断、Mongo、Redis、Celery 或浏览器控制。只有 Python 基线证明 CPU 为瓶颈，且满足 CPU p95 降低 30% 或吞吐达到 1.5 倍，才扩大 Rust 范围。

## 十二、实施批次

### 第 1 批：框架无关契约和安全边界冻结

- [ ] 冻结 `TargetProfile`、EvidenceGraph 节点/关系和 Endpoint 契约；
- [ ] 冻结 L0/L1 默认开启、L2 显式开启、L3 不进入 WIH 自动链路；
- [ ] 冻结目标范围、重定向、认证 profile、敏感信息和原始响应保存策略；
- [ ] 建立传统 MVC、SSR、SPA、API-only、GraphQL、SOAP、WebSocket、HAR 和未知系统 golden corpus。

### 第 2 批：统一响应和证据图

- [ ] 接入 `ResponseRegistry`、`EvidenceGraph`、`CandidateRegistry` 和 `RequestScheduler`；
- [ ] 所有 Collector 使用统一请求 profile、single-flight、WAF 类别和阶段预算；
- [ ] 完成重复请求、来源聚合、worker 重启和幂等回归。

### 第 3 批：通用目标画像与基础 Collector

- [ ] 实现未知目标、传统 MVC、SSR、SPA、API-only 和文档优先画像；
- [ ] 接入 HTTP、HTML、脚本、API 文档、Header、错误响应和外部情报；
- [ ] 微前端只作为可选资源图适配器，不影响通用路径。

### 第 4 批：API/协议统一解析

- [ ] 复用计划 6 第 3 批的 `ApiCandidateRegistry` + `ApiDocumentQueue`；
- [ ] JS 新发现文档在当前任务内回流；
- [ ] OpenAPI/Postman/GraphQL/WSDL/SOAP/WebSocket 统一进入 Endpoint/Protocol Registry；
- [ ] 保留确定值、模板值、运行时值和推断值的差异。

### 第 5 批：运行时补证和自适应调度

- [ ] 目标画像不足时才启用 browser runtime；
- [ ] 建立信息增益评分、候选优先级和低收益停止规则；
- [ ] 接入 HAR/代理导入，支持无页面 API-only 目标；
- [ ] 每个策略输出新增证据、请求成本和停止原因。

### 第 6 批：受控验证和 ARL 人工复核

- [ ] 实现 L1 安全读取、L2 认证边界对比和 `api_verify` 独立调度；
- [ ] 输出 `auth_anomaly_candidate`、`blocked`、`skipped`、`pending`、`failed` 和 `degraded`；
- [ ] ARL 展示 Endpoint、参数摘要、调用链、来源、响应状态、认证对比和人工复核理由；
- [ ] 不自动执行 L3 专门安全测试。

### 第 7 批：性能和 Rust 评估

- [ ] 比较统一前后的唯一请求、重复请求、缓存命中、网络等待和新增证据量；
- [ ] 对 HTML/JS 解析、归一化、去重和排序建立 Python 基线；
- [ ] 仅对满足性能门禁的 CPU 热点实施 Rust 批处理；
- [ ] 完成 40 目标协同回归、64 目标性能门禁和 ARM64/amd64 smoke。

## 十三、验收标准

### 覆盖和准确性

- 同一方案同时支持传统 MVC、SSR、SPA、微前端、API-only、GraphQL、SOAP、WebSocket/SSE、HAR 和未知系统；
- 能区分确定、模板、运行时和推断证据；
- 同一路径不同 method、请求体、认证 profile 和协议语义不被错误合并；
- 同一 Endpoint 多来源去重但完整保留 `sources`、父资源、操作和证据链；
- API Endpoint 集合不低于现有 golden，不因统一去重减少有效结果。

### 协同和效率

- 同一任务同一请求 profile 只发生一次真实获取，其他策略消费缓存；
- JS、文档、浏览器和外部情报的新候选能回流当前任务 Registry；
- 请求数、缓存命中、重复请求、策略成本、WAF 阻断和新增证据量可复算；
- 低收益策略能够停止，不因“工具齐全”而强制执行全部阶段；
- 关键阶段 p95 墙钟时间不因统一层恶化超过 5%。

### 安全和可审计

- 默认不执行写操作、越权、注入、爆破、高复杂度 GraphQL、任意上传和压力测试；
- 外域、越界重定向、WAF、超时、预算耗尽和认证缺失均有明确状态；
- `auth_anomaly_candidate` 只能进入人工复核，不自动升级为漏洞；
- 日志和 Mongo 默认不保存 Token、Cookie、API Key 和完整敏感响应；
- API 验证触发的 WAF 不影响 crawler、directory 和普通 WIH；
- worker 重启和单批失败不会造成重复写入或静默丢失。

### 性能和部署

- 40 目标用于验证跨工具协同和重复请求下降；64 目标用于最终性能门禁；
- Rust 热点 CPU p95 降低至少 30% 或吞吐达到 Python 1.5 倍；
- Rust 接入后端到端阶段耗时不恶化超过 5%；
- ARM64 与 amd64 使用同一套 Python、Rust、Docker smoke 和结果一致性测试。

## 十四、与现有计划的关系

- 计划 2 提供 `DiscoveryContext`、ResponseRegistry、CandidateRegistry、RequestScheduler 和 WAF 隔离；计划 7 在其上增加目标画像和证据图。
- 计划 5 负责站点/服务指纹，不把 API Endpoint、参数或 Schema 混入指纹文件。
- 计划 6 负责 API 契约、文档解析、Endpoint Registry 和文档队列；计划 7 增加通用目标形态、调用关系、运行时证据和人工复核。
- `WihRecord`、Mongo 文档、HTTP API 和导出字段保持兼容；新增证据优先通过内部 Registry 和详情 adapter 暴露。
- Python 继续负责业务状态、认证 profile、网络、预算、WAF、浏览器、Mongo、Redis、Celery 和外部工具；Rust 只负责后置纯数据处理。

## 十五、最终判断与下一步

该需求可行，而且比“继续给 WIH 增加更多独立解析器”更有价值。但只有在下面的顺序成立时，才会得到通用、优雅、聪明的信息搜集工具：

```text
统一响应和证据图
  → 目标画像
  → 自适应 Collector
  → API/协议 Registry
  → 信息增益调度
  → 受控验证
  → 证据聚合和人工复核
  → 基准证明后 Rust 化
```

下一步不是先做 qiankun 解析，也不是先重写 WIH，而是先实施计划 6 第 3 批的统一候选/文档队列，并把本计划的框架无关契约、L0/L1/L2 安全边界和跨场景 golden corpus 一起冻结。完成后再按目标画像逐步接入浏览器、协议解析和 ARL 复核展示。
