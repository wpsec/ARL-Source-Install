# 计划 6：统一 API 解析与 Endpoint Registry 重构

状态：第 1-7 批解析器面已实施（2026-09-05，见文末实施进度；其中第 6 批为"GraphQL 文档 Parser 完成，运行时事件接入未完成"，顺延第 8 批——2026-09-06 用户决策 P0-05）；第 4-6 批 Review 整改轮 2 代码已实施（2026-09-06：T1/T2/T3 + P1-08/P1-09 + P2-13；P0-05 事件接入与 P1-12 仍归第 8 批/T8；第 8 批起未开始）。契约冻结面见 [06-附录A](<../completed/[已完成]06-附录A-API契约冻结清单.md>)。

## 一、总体结论

当前 API 能力并非完全缺失，而是分散在 WIH、URLFinder、页面情报、JS 情报和浏览器采集模块中：

- REST、OpenAPI/Swagger、Postman 已有基础解析能力；
- GraphQL 当前能够发现请求和 `/graphql` 入口，但还不是完整 Schema 解析；
- WSDL/SOAP 当前没有真正的 XML Operation 解析器；
- 浏览器采集能力已存在，但没有稳定接入主 WIH 编排链路；
- JS 发现的 Swagger/OpenAPI 地址可能在当前任务内只写入记录，不重新进入 API 文档解析队列；
- 不同模块之间缺少统一的 API 文档、Endpoint、参数和来源数据契约。

本计划不继续增加孤立的 API 解析器，而是建立一个任务级统一 API 发现层：

```text
页面 / JS / URLFinder / WIH / 浏览器运行时
                         ↓
                 ApiCandidateRegistry
                         ↓
                 ApiDocumentQueue
                         ↓
                    ApiParser
       ┌───────────┬───────────┬───────────┬───────────┐
       ↓           ↓           ↓           ↓           ↓
   OpenAPI       Postman     GraphQL     WSDL/SOAP   JS/运行时
       └───────────┴───────────┴───────────┴───────────┘
                         ↓
                  UnifiedApiEndpoint
                         ↓
                 EndpointRegistry
                  ┌──────┴──────┐
                  ↓             ↓
              WIH/URL Probe   Nuclei/风险阶段
```

“统一”只存在于 API 发现和数据编排层；页面爬虫、JS 静态分析、浏览器采集、Endpoint 探测仍然是可独立降级的策略。

## 二、目标与非目标

### 2.1 目标

1. 页面、JS、URLFinder、WIH 和浏览器发现的 API 文档与 Endpoint，在同一任务内互相可见。
2. 同一 API 文档或 Endpoint 在同一请求 profile 下只获取一次。
3. JS 新发现的 OpenAPI、Swagger、Postman、GraphQL、WSDL 地址能够回流当前任务的文档队列。
4. 将不同格式统一为 `UnifiedApiEndpoint`，供 WIH、URL Probe 和后续风险扫描消费。
5. 保留现有 HTTP API、Mongo 文档、导出字段和 `WihRecord` 兼容语义。
6. 记录来源、父文档、解析状态、参数摘要、鉴权提示和置信度，支持结果追溯。
7. 通过预算、大小限制、引用深度限制和 WAF 隔离，避免 API 文档解析扩大请求风暴。
8. 先以 Python 实现正确性和协同，再根据 CPU 基准将归一化、去重、排序等纯函数迁移到 Rust。

### 2.2 非目标

- 本计划不实施 BOLA、BFLA、SQL 注入、越权、暴力破解或业务逻辑攻击。
- 不默认发送 GraphQL introspection 请求；需要显式配置、授权范围和独立预算。
- 不默认执行任意 SOAP 操作或构造业务请求体。
- 不把 API Parser 改造成新的网络扫描器；文档和 Endpoint 获取统一由 Python `RequestScheduler` 管理。
- 不在本阶段重写浏览器、Nmap、WIH Go 工具或整个 Rust WIH。
- 不把完整参数值、Cookie、Authorization、API Key 或密钥写入日志、Mongo 或统一 Endpoint 记录。

## 三、现有能力和问题冻结

| 能力 | 当前实现 | 当前阶段 | 本计划处理 |
|---|---|---|---|
| REST URL | 页面、JS、WIH、URLFinder 提取 | `wih_page_intel`、`wih_js_intel`、URLFinder、WIH | 统一进入 Endpoint Registry |
| OpenAPI/Swagger | JSON/YAML，解析 paths、servers、host、basePath、schemes | `wih_api_doc` | 补参数、Schema、鉴权、引用和版本关系 |
| Postman | Collection 和 request 递归解析 | `wih_api_doc` | 统一变量、父集合、请求体和来源 |
| GraphQL 请求 | `/graphql`、query、variables、operationName | `wih_js_intel`、可选 `browser_intel_scan` | 统一请求形态，增加 Schema/操作分类 |
| GraphQL Schema | 尚无完整 Schema 解析 | 未形成独立阶段 | 作为受控可选能力接入 |
| WSDL/SOAP | 仅可能被 URL/文本发现 | 暂不支持 | 新增安全 XML 解析和 Operation 归一化 |
| 浏览器运行时 API | 仓库有实现和测试 | 未稳定接入主 WIH | 改为事件源，不再单独形成孤岛 |
| API 探测 | WIH Endpoint Probe | `wih_endpoint_probe`、followup | 只消费 Registry 中待探测 Endpoint |

当前主 WIH 顺序大致为：

```text
wih_primary_scan
  → wih_urlfinder_extract
  → wih_endpoint_probe
  → wih_endpoint_ai_fill
  → wih_page_intel
  → wih_api_doc
  → wih_js_intel
  → wih_endpoint_followup_probe
  → wih_urlfinder_sensitive
  → wih_url_probe
  → 结果写入
```

该顺序存在两个结构性问题：

1. 后执行的 JS 阶段发现 API 文档后，文档可能只进入记录集合，不重新调度 `wih_api_doc`。
2. 页面、JS、浏览器和文档解析各自维护结果，Endpoint 缺少统一去重、状态和父子关系。

## 四、统一上下文和数据模型

### 4.1 依赖统一发现上下文

本计划依赖统一发现上下文重构提供的任务级能力：

```text
DiscoveryContext
 ├─ ResponseRegistry
 ├─ CandidateRegistry
 ├─ DiscoveryLedger
 ├─ RequestScheduler
 ├─ WafPolicy
 └─ SourceAggregator
```

API 层新增：

```text
ApiCandidateRegistry
ApiDocumentQueue
EndpointRegistry
ApiParser
```

API Parser 只消费 `ResponseRegistry` 中的响应和事件，不自行重复请求页面或 JS。需要获取 API 文档或 Endpoint 时，提交给统一 `RequestScheduler`。

### 4.2 API 文档候选

内部 `ApiDocumentCandidate` 至少包含：

```text
task_id
url
type_hint             # openapi/swagger/postman/graphql/wsdl/unknown
source
sources
parent_target
parent_url
depth
priority
status                # discovered/queued/fetching/fetched/parsed/failed/skipped
input_signature
request_profile       # api_doc
confidence
parser_version
error_type
created_at
```

文档候选幂等键：

```text
task_id + api_doc + canonical_url + request_profile + input_signature
```

### 4.3 UnifiedApiEndpoint

统一 Endpoint 输出至少包含：

```text
endpoint_id
url
path_template
method
api_type              # rest/graphql/soap
source
sources
parent_document
parent_target
base_url
api_version
operation_id
tags
parameters
request_body_type
request_body_schema
response_schema
auth_hint
security_requirements
schema_available
graphql_operation     # query/mutation/subscription/unknown
graphql_operation_name
graphql_query_hash
soap_action
wsdl_service
wsdl_port
confidence
status                # discovered/queued/probed/covered/failed/degraded/pending/skipped
input_signature
```

字段规则：

- `parameters` 只记录名称、位置、类型摘要、是否必需，不保存实际敏感值。
- `request_body_schema` 和 `response_schema` 保存规范化摘要或引用，不无限复制大型文档。
- `auth_hint` 只记录 `none/basic/bearer/api_key/cookie/oauth2/mTLS/unknown` 等类型。
- `security_requirements` 只保留名称和类型，不保留 Token、Secret、Cookie 或 Authorization 内容。
- 未解析完成的 `$ref`、WSDL 类型或 GraphQL 类型必须明确标记，不得伪装成完整 Schema。

Endpoint 幂等键（2026-09-06 用户决策，P1-12：纳入 api_type；契约冻结，代码待 T8 实施）：

```text
task_id + canonical_url + method + api_type + input_signature
```

- `input_signature` 必须已含协议内部 operation identity：GraphQL = operation type + operation name + query hash；SOAP = operation/soapAction；REST = 请求参数或 operation_id 摘要。无需再单独拼接 operation_id，由测试证明其稳定进入 `input_signature`。
- Registry 尚未切生产（`API_UNIFIED_ENABLE` 默认 False），本次改 key 无需历史数据迁移。
- 同一 URL 使用不同 Header、认证上下文或请求 profile 时，必须保留为不同的请求观察，不得错误合并。现行代码拼接形态见附录A §4.2（T8 实施前不改写，指向说明见附录A §4.13）。

## 五、统一解析契约

所有 Parser 使用同一接口：

```text
parse(document_artifact, parse_options)
  → {
      documents: [...],
      endpoints: [...],
      candidates: [...],
      diagnostics: {
        parser,
        input_count,
        output_count,
        deduplicated_count,
        unresolved_ref_count,
        rejected_count,
        error_type,
        status
      }
    }
```

Parser 不负责：

- HTTP 请求；
- DNS、WAF、代理和网络重试；
- Mongo、Redis、Celery 写入；
- AI 判断；
- 发送任意业务参数或攻击性 Payload。

Parser 必须负责：

- 文档格式识别；
- 结构解析和有界引用解析；
- URL、HTTP 方法和参数归一化；
- 来源和父文档关系；
- 置信度和诊断信息；
- 异常输入的显式失败状态。

## 六、各格式实施方案

### 6.1 OpenAPI/Swagger

保留当前 JSON/YAML 解析能力，扩展为：

1. OpenAPI 2、OpenAPI 3、Swagger 兼容格式识别。
2. 解析 `paths`、HTTP 方法、`servers`、`host`、`basePath`、`schemes`。
3. 解析 path、query、header、cookie、form、body 参数。
4. 解析 `requestBody`、响应状态和响应 Schema 摘要。
5. 解析 `components`、`definitions`、`parameters`、`responses`、`securitySchemes`。
6. 解析本地 `$ref`，限制最大深度、总引用数和循环引用。
7. 外部 `$ref` 默认不自动获取；需要独立开关、同源校验和文档预算。
8. 识别 API 版本、operationId、tags 和服务地址关系。
9. 文档中出现的其他域名进入候选图，但必须经过范围和 DNS/WAF 策略。

验证重点：

- `servers` 与旧版 `host/basePath/schemes` 组合结果一致；
- 相对路径、绝对路径、协议相对地址不产生错误 URL；
- 同一路径多个 method 全部保留；
- 本地引用解析不会递归失控；
- 未解析引用不能导致整个文档被伪装为成功。

### 6.2 Postman Collection

1. 递归解析 `item` 嵌套目录和 request。
2. 归一化 method、URL、path variable、query、header、body。
3. 解析 collection、folder、request 名称作为来源详情。
4. 支持变量引用，但只保存变量名和脱敏模板。
5. 解析 raw、urlencoded、formdata、file 等请求体类型摘要。
6. 不把示例 Token、Cookie、Secret 和环境变量真实值写入结果。
7. Postman 中的多个环境地址按候选地址处理，仍受目标范围约束。

### 6.3 GraphQL

分为“请求识别”和“Schema 解析”两层：

#### 请求识别

- 识别 `/graphql`、`/api/graphql` 等高置信度路径线索；
- 从 JS、页面和浏览器网络事件识别 `query`、`variables`、`operationName`；
- 记录 HTTP method、请求体类型、变量名称和 query hash；
- 从 GraphQL 文本中分类 Query、Mutation、Subscription；
- 不保存完整敏感变量值；
- 无法解析操作类型时标记 `unknown`，不强行分类。

#### Schema 解析

- 支持合法 GraphQL SDL 文本或已获得的 introspection 响应；
- 提取 type、field、argument、scalar、enum、input 和关系摘要；
- 记录 `schema_available`、schema hash 和解析失败原因；
- introspection 默认关闭，只在明确配置和授权范围内启用；
- 设置响应大小、类型数量、字段数量和嵌套深度上限；
- Schema 解析失败不影响普通 GraphQL Endpoint 记录。

存储面（2026-09-06 用户决策，P0-04；契约见附录A §4.13，代码已于整改轮 2 实施，实施面登记附录A §4.14）：

- 规范措辞：Schema 摘要进入当前任务 context 的有界诊断面；stage metrics 仅记录状态与计数；第 8 批再决定是否纳入 Endpoint Registry 资产面。
- `context.metrics` 只放整数计数：`graphql_schema_success_total`、`graphql_schema_degraded_total`、`graphql_schema_failed_total`、`graphql_schema_skipped_total`、`graphql_request_total`；诊断摘要（schema_hash、kind、types/enums/inputs/scalars、type_count/field_count、truncated、status、error_type）承载于 context 内临时诊断面，必须有明确字节上限（不得只依赖类型数/字段数上限）。
- 当前批不落 Mongo；不保存 Schema 原文、变量值、Token、Header；Schema 结构错误必须 failed、预算截断必须 degraded，不得标完整成功；摘要丢失可重新解析，不作为持久化事实源。

技术建议：Python 先采用已有依赖或经过依赖审查的 GraphQL parser；Rust 只负责已规范化文本的批量 hash、去重和候选排序，不在第一阶段重写 GraphQL 语义解析器。

### 6.4 WSDL/SOAP

新增安全 XML Parser，支持：

1. `definitions`、`service`、`port`、`binding`、`portType`、`operation`。
2. SOAP 1.1/1.2 绑定、endpoint location 和 `soapAction`。
3. message、part、XSD 类型的有限摘要。
4. WSDL 导入关系和同源 XSD 引用的有界解析。
5. 输出 `api_type=soap`、method 语义、服务地址、operation 和参数摘要。

安全约束：

- 禁用 DTD、外部实体和外部网络实体解析，防止 XXE/SSRF；
- 限制 XML 文件大小、元素深度、节点数量和引用数量；
- 外部 import/include 默认不请求；
- 解析错误标记 `failed/degraded`，不能当作“无接口”；
- 只生成 Endpoint 资产，不自动调用真实 SOAP Operation。

### 6.5 JS 和浏览器运行时

JS 解析继续定位为“候选提取器”，不扩张为完整 JavaScript 语义执行器：

- 静态提取 `fetch`、axios、XHR、baseUrl、路径模板和文档入口；
- 浏览器运行时产生网络请求事件，直接写入 `ApiCandidateRegistry`；
- JS 或浏览器发现 Swagger/OpenAPI/Postman/WSDL/GraphQL 地址时发布 `ApiDocumentCandidate`；
- 文档队列在当前任务内继续消费，不等到下一次任务；
- 同一 ResponseRegistry 响应被多个 Parser 消费，不重复下载；
- 动态拼接无法确定完整 URL 时保留模板和低置信度候选，不猜测具体路径。

## 七、任务编排和阶段重组

### 7.1 新的 API 流水线

```text
初始页面响应
  → page_intel / js_intel / URLFinder / browser event
  → ApiCandidateRegistry
  → API 文档候选去重和排序
  → RequestScheduler(api_doc)
  → ResponseRegistry
  → Unified ApiParser
  → EndpointRegistry
  → WIH endpoint probe / URL Probe
  → 增量结果回写
```

### 7.2 队列消费规则

- 页面、JS、浏览器和 URLFinder 可以随时发布新文档候选；
- `ApiDocumentQueue` 持续消费，直到队列为空或该阶段预算耗尽；
- 新解析出的文档必须重新进入队列，但受 `max_depth`、`max_documents` 和 `max_new_candidates` 限制；
- Endpoint 新增后进入 Endpoint Registry，不能只写成普通文本记录；
- 首轮 Endpoint Probe 和文档解析分离，避免文档获取阻塞页面发现；
- 文档解析失败只影响当前文档，其他候选继续执行；
- 相同 Endpoint 的后续来源只追加 `sources` 和证据，不重复探测。

### 7.3 与现有 WIH 阶段的兼容

第一阶段不删除现有阶段和 `WihRecord`：

| 现有输出 | 统一层映射 |
|---|---|
| `api_doc_url` | `ApiDocumentCandidate` |
| `api_doc_endpoint` | `UnifiedApiEndpoint` |
| `urlfinder_url` | Endpoint 或普通 URL Candidate |
| `wih_endpoint` | `UnifiedApiEndpoint` 的探测结果 |
| `wih_url_probe` | Endpoint Registry 中的 probe observation |
| `graphql` 记录 | `api_type=graphql` 的 Endpoint |

统一层先生成兼容旧记录的 adapter，再逐步让 WIH 和 URL Probe 直接消费 Endpoint Registry。Mongo 原有文档和导出字段不改变，新增诊断优先进入结构化 stage metrics 和日志。

## 八、请求复用、WAF 和预算

### 8.1 请求 profile

至少区分：

```text
api_doc
api_endpoint_probe
graphql_schema_optional
soap_endpoint_observe
browser
```

同一任务中，URL、method、认证上下文、Header 摘要和 profile 相同才允许复用缓存响应。不同认证上下文不能错误共享响应。

### 8.2 WAF 隔离

- API 文档获取、普通 Endpoint 探测、GraphQL Schema 可选请求和浏览器请求使用独立流量类别；
- API Endpoint Probe 触发 WAF 时，只暂停 probe 类请求；
- 文档获取失败不能被 probe 熔断连坐；
- 只有确认主机级封禁时才暂停该站点全部 API 请求，并标记 `degraded/host_waf_blocked`；
- WAF 阻断不能转换为空 Endpoint 或“无 API”。

### 8.3 独立预算

建议新增配置：

```text
API_UNIFIED_ENABLE=false
API_UNIFIED_FALLBACK_ENABLE=true
API_DOCUMENT_STAGE_TIMEOUT_SEC=120
API_DOCUMENT_MAX_TARGETS=200
API_DOCUMENT_MAX_SIZE_BYTES=5242880
API_DOCUMENT_MAX_DEPTH=3
API_DOCUMENT_MAX_REF_COUNT=500
API_EXTERNAL_REF_ENABLE=false
GRAPHQL_SCHEMA_ENABLE=false
GRAPHQL_SCHEMA_MAX_SIZE_BYTES=2097152
GRAPHQL_SCHEMA_MAX_DEPTH=20
WSDL_PARSE_ENABLE=true
WSDL_MAX_SIZE_BYTES=5242880
API_ENDPOINT_PROBE_MAX_TARGETS=500
```

默认值必须经过当前任务基线验证；配置读取、Celery 生命周期、Mongo 和 Redis 仍由 Python 管理。

## 九、技术路线和性能优化

### 9.1 第一阶段：Python 正确性优先

- 使用现有 Python 编排和请求调度；
- 复用 `ResponseRegistry`，避免 Parser 自行发 HTTP；
- 文档 Parser 只处理单份响应，队列负责有界批量；
- Endpoint 统一去重、排序和来源聚合；
- 所有 Parser 以结构化 diagnostics 记录成功、失败、跳过和降级。

### 9.2 第二阶段：解析和索引优化

- 文档按 content-type、文件头和 URL 线索优先分类；
- OpenAPI/Swagger 先解析结构，Schema 按需有界展开；
- Postman 和 WSDL 递归解析使用显式队列，避免无限递归；
- Endpoint Registry 按 §4.3 幂等键建索引：canonical URL、method、api_type，operation identity 经 `input_signature` 承载，不再单列 operation_id（2026-09-06 用户决策 P1-12；契约冻结，代码待 T8 实施）；
- 同一文档产生的 Endpoint 批量写入和批量去重；
- 不因排序直接删除低优先级 Endpoint，低优先级进入 pending 队列。

### 9.3 第三阶段：Rust 后置加速

仅在 Python 结果和指标稳定后，将以下纯数据逻辑批量迁移到既有 `ARL/native/arl_accel`：

- URL、method、API type 归一化；
- Endpoint canonical key 和 query hash；
- 参数、来源和版本关系去重；
- 候选排序、来源合并和指纹计算。

Rust 不负责 YAML/XML/GraphQL 语义解析的首版实现，不访问 HTTP、DNS、Mongo、Redis、Celery、浏览器或外部工具。

Rust 失败时只回退当前批次 Python，并记录：

```text
stage
batch_id
error_type
input_count
output_count
fallback_count
```

## 十、实施批次

### 第 1 批：接口和结果语义冻结

- 冻结当前 `WihRecord`、`api_doc_*`、`wih_endpoint`、`urlfinder_url` 字段；
- 冻结 `UnifiedApiEndpoint` 和 `ApiDocumentCandidate` schema；
- 建立 OpenAPI、Postman、GraphQL、WSDL 的最小 golden corpus；
- 明确敏感字段脱敏和外部引用默认关闭策略。

### 第 2 批：观测和响应复用

- 接入 API 文档和 Endpoint 的统一请求 profile；
- 统计总请求、唯一请求、缓存命中、重复请求和跨策略复用；
- 不改变现有输出，只记录 shadow metrics；
- 验证同一页面/JS/文档不会被重复获取。

### 第 3 批：ApiCandidateRegistry 和 ApiDocumentQueue

- 实现候选注册、来源聚合、状态机和幂等键；
- 统一接收 page_intel、js_intel、URLFinder 和浏览器事件；
- 将 JS 发现的 API 文档重新调度到当前任务；
- 增加深度、数量、大小和阶段预算。

### 第 4 批：OpenAPI/Swagger 统一解析

- 接入 JSON/YAML 解析；
- 补 paths、servers、host、basePath、schemes、method、参数和 Schema 摘要；
- 实现本地 `$ref` 有界解析和 unresolved 状态；
- 兼容输出 `api_doc_url`、`api_doc_endpoint`。

### 第 5 批：Postman 统一解析

- 递归解析 Collection；
- 统一 URL、method、header、query、path variable 和 body 摘要；
- 变量和环境地址脱敏；
- 解析失败只影响当前 Collection。

### 第 6 批：GraphQL 能力补齐

（2026-09-06 用户决策，P0-05 选项二：本批只交付 GraphQL 文档解析器；下列"统一 JS、页面和浏览器 GraphQL 请求事件"与 Registry 接入面顺延第 8 批。）

- 统一 JS、页面和浏览器 GraphQL 请求事件；
- 提取 query、variables 名称、operationName、操作类型和 query hash；
- 增加 GraphQL Endpoint Registry；
- 设计可选 Schema 解析和显式 introspection 开关；
- 增加大小、深度、类型数和字段数预算。

### 第 7 批：WSDL/SOAP 支持

- 引入经过依赖审查的安全 XML 解析方案；
- 解析 service、port、binding、portType、operation、message 和 soapAction；
- 禁用 XXE、外部实体和默认外部引用；
- 生成 `api_type=soap` Endpoint，不自动执行业务 Operation。

### 第 8 批：Endpoint Registry 和消费方接入

独立门禁（2026-09-06 用户决策，P0-05 选项二；同步登记附录A §七）：

- JS、页面、浏览器三来源进入同一 Endpoint Registry 并按 sources 合并，不重复建资产；
- 浏览器 query 值、变量值、敏感 header 不得外流。

- WIH endpoint probe 只消费 Registry 的待处理 Endpoint；
- URL Probe 消费统一候选，不再自行维护重复列表；
- Endpoint 新来源自动合并 `sources`；
- 将新子域、新 API 文档和新 API Endpoint回流统一发现上下文；
- 保留旧路径显式 fallback。

### 第 9 批：阶段调度和 WAF 隔离

- API 文档、Endpoint Probe、GraphQL Schema 和浏览器请求分流；
- 增加阶段、provider、文档和批次 metrics；
- 单文档失败、单批失败和 WAF 阻断均有明确状态；
- 验证 API 文档解析不会拖垮普通爬虫和 WIH。

### 第 10 批：Rust 纯数据层和性能门禁

- 以 Python 结果为基线接入批量 Rust 归一化和去重；
- Rust/Python golden 结果集合严格一致；
- Rust 只在 CPU 指标满足门禁后扩大范围；
- 端到端耗时不得因接入 Rust 恶化超过 5%。

### 第 11 批：全量回归和发布验收

- 40 个目标验证数据联通、文档回流、重复请求和 WAF 隔离；
- 64 个目标执行最终性能门禁；
- arm64 与 amd64 执行同一套 Parser、Registry、Rust 和 Docker smoke；
- 通过观测期后再评估删除旧的分散 API 解析路径。

## 十一、测试要求

### 11.1 解析正确性

- OpenAPI 2/3、Swagger JSON/YAML；
- `servers` 与 `host/basePath/schemes`；
- path/query/header/cookie/body 参数；
- `components`、`definitions`、本地 `$ref`、循环引用和未解析引用；
- Postman 多层 `item`、变量、raw/urlencoded/formdata；
- GraphQL Query/Mutation/Subscription、variables、operationName、query hash；
- GraphQL SDL 和 introspection 响应的受控解析；
- WSDL service/port/binding/portType/operation/message/soapAction；
- 非法 JSON/YAML/XML、超大文档、深层嵌套和异常编码。

### 11.2 协同和去重

- 页面、JS、URLFinder、WIH 发现同一文档只获取一次；
- JS 发现 Swagger 后当前任务内重新进入 API 文档队列；
- 浏览器发现的 GraphQL 请求进入同一 Endpoint Registry；
- 同一 Endpoint 多来源保留完整 `sources`；
- 同一 URL 不同 method 全部保留；
- 同一 URL 不同认证上下文不错误合并；
- worker 重启、任务重试和队列重复投递不重复写入；
- 单个 Parser 失败不影响其他 Parser 和其他站点。

### 11.3 安全和边界

- XML 外部实体、DTD 和外部引用默认关闭；
- OpenAPI 外部 `$ref` 默认关闭；
- GraphQL introspection 默认关闭；
- 文档大小、递归深度、引用数和 Endpoint 数量均受预算限制；
- 日志、metrics、Mongo 和导出不包含 Token、Cookie、API Key、Secret 或完整敏感变量；
- 目标范围、DNS/WAF 和代理策略在提速后仍然生效；
- 不把解析失败或 WAF 阻断记录为空结果。

## 十二、指标和验收标准

必须记录：

```text
api_document_candidates_total
api_document_candidates_by_source
api_document_queue_depth
api_document_fetch_total
api_document_cache_hit_total
api_document_parse_success_total
api_document_parse_failed_total
api_document_unresolved_ref_total
api_endpoint_discovered_total
api_endpoint_deduplicated_total
api_endpoint_by_type
api_endpoint_by_method
api_endpoint_sources_count
graphql_request_total
graphql_schema_success_total
wsdl_operation_total
api_probe_total
api_probe_waf_blocked_total
api_probe_pending_total
api_probe_failed_total
api_stage_wall_time
api_stage_cpu_time
api_stage_network_wait_time
rust_batch_total
rust_fallback_total
```

验收条件：

- JS 新发现的 API 文档可以在当前任务内完成解析或进入明确的 `pending/failed/degraded` 状态；
- REST、OpenAPI/Swagger、Postman、GraphQL、WSDL/SOAP 的来源和状态可追溯；
- 同一任务同一请求 profile 下重复请求显著下降；
- API Endpoint 结果集合不低于现有 golden 基线；
- 同一路径不同 HTTP method 不丢失；
- GraphQL 请求识别与 Schema 解析状态明确区分；
- WSDL/SOAP 能输出 Operation 摘要，解析失败不伪装为空结果；
- API 文档解析或 Endpoint 探测的 WAF 阻断不影响普通爬虫和其他流量类型；
- 不改变现有 HTTP API、Mongo 文档结构和导出字段；
- Python Parser 与 Rust 纯数据层输出集合一致；
- Rust 热点 CPU p95 降低至少 30%，或吞吐达到 Python 的 1.5 倍；
- Rust 接入后端到端阶段耗时不恶化超过 5%；
- 40 目标协同回归通过，64 目标最终性能验收通过；
- amd64 与 arm64 使用同一套测试和 smoke test 通过。

## 十三、发布和回滚策略

采用 shadow → 双写兼容 → 小范围启用 → 全量切换：

1. `API_UNIFIED_ENABLE=false` 时只采集对照 metrics，不改变现有结果。
2. 开启后同时保留旧阶段输出和统一 Registry 输出，比较 Endpoint 集合。
3. 统一层失败时仅当前文档或批次回退旧 Parser，记录原因和次数。
4. 统一 Endpoint 结果稳定后，再让 WIH Probe 和 URL Probe 以 Registry 为唯一候选入口。
5. 观测期确认无结果减少、无重复写入、无敏感信息泄露后，才清理旧的分散 API 解析代码。

## 十四、与现有计划的关系

- 计划 5 负责站点/服务指纹规范化；本计划消费页面和 API 响应，但不把 API Schema 混入站点指纹文件。
- 统一发现上下文计划负责 ResponseRegistry、CandidateRegistry、RequestScheduler 和 WAF 隔离；本计划在其上增加 API 专用 Registry 和队列。
- WIH 专项计划继续保留任务预算、周期复用和结果写回约束；本计划只重组 API 文档与 Endpoint 的发现和消费链路。
- Rust 继续是纯数据处理加速层，不成为第二套 API 业务系统。

## 十五、实施进度

### 第 1 批：接口和结果语义冻结（2026-09-05 完成）

| 交付 | 位置 | 说明 |
|---|---|---|
| 统一数据契约代码面 | `ARL/app/services/api_unified_models.py` | `ApiDocumentCandidate`/`UnifiedApiEndpoint`/`ParameterSpec`/`SecurityRequirementSummary`/`ParseOptions`/`ParseDiagnostics`/`ParseResult`、三层幂等键、脱敏守卫、`to_legacy_records()` 兼容 adapter、§8.3 配置默认常量；纯 stdlib，未接入任何运行时链路（`API_UNIFIED_ENABLE` 默认 False 语义） |
| golden corpus | `ARL/test/fixtures/api_unified/`（12 文件 + `expected/` 2 文件） | OpenAPI2/3 JSON+YAML 镜像、循环/未解析/外部引用、Postman 模板与泄露样本、GraphQL 三操作+SDL、WSDL+同源 XSD+XXE、非法/深嵌套边界 |
| 基线生成器 | `scripts/api-unified-golden.py` | 现行 `ApiDocScanner` 网络无关基线；`--check` 漂移检测 |
| 契约回归 | `ARL/test/test_api_unified_models.py` | 29 项：字段面/枚举/幂等键/脱敏/legacy 格式/基线漂移/目标期望下界 |
| 冻结清单 | `docs/completed/[已完成]06-附录A-API契约冻结清单.md` | 旧记录面、§4 契约、脱敏策略、G1-G8 现状缺口（即第 4-7 批验收差异面） |

本批不改任何运行时行为：无新 Config 键、无阶段接线、`app.services.__init__` 不导出新模块。
下一步为第 2 批（观测与响应复用 shadow metrics），前置依赖 `discovery_context`（已在库）的
`ResponseRegistry`/请求 profile 对照统计。

### 第 2 批：观测和响应复用（2026-09-05 完成）

| 交付 | 位置 | 说明 |
|---|---|---|
| 无副作用读取原语 | `discovery_context.ResponseRegistry.peek` / `DiscoveryContext.peek_response` | 不登记 consumer、不动 LRU、不产生 hit/miss 指标；返回不含 body 的快照 |
| shadow 观测 | `ARL/app/services/api_unified_shadow.py` | 文档/探测的 总请求、唯一、重复、缓存命中、跨策略复用、期望网络、空响应、失败 计数；`api_doc` 桶命中数恒 0 作为第 3 批切换生效证据锚；观测异常计数且绝不阻断扫描 |
| 接线 | `api_doc_scan.run()` fetch 前后、`wih_endpoint_probe._probe_one()` profile 后与异常路径 | 只加观测，不改任何记录输出 |
| 回归 | `test/test_api_unified_shadow.py` 8 项 | 含输出不变性验证：同一文档跨 Scanner 实例仅一次网络请求、两次运行记录集合一致 |
| 冻结登记 | 06-附录A §4.5 | 全部指标键与口径入冻结清单 |

验证：全量本地套件（`--continue-on-collection-errors`）下 `test_api_unified*` 零失败，
collection-error 集合与改动前基线完全一致（34 项均为既有本地依赖缺失）。
本批发现并规避一处既有测试污染：部分既有用例注入 fake `app.utils` 后不还原，
新测试改为收集期捕获真实模块引用 + `_safe_domain_fns()` 局部替换域函数，免疫顺序。
下一步为第 3 批：`ApiCandidateRegistry` + `ApiDocumentQueue`（候选注册、状态机、幂等键、
JS 发现文档回流当前任务、深度/数量/大小/阶段预算），并将获取路径切换到统一 profile（届时 §4.5
`cross_bucket_hit` 应转正）。

### 第 3 批：ApiCandidateRegistry 和 ApiDocumentQueue（2026-09-05 完成）

| 交付 | 位置 | 说明 |
|---|---|---|
| 候选注册表 | `ARL/app/services/api_candidate_registry.py` · `ApiCandidateRegistry` | 文档候选以规范化 URL 唯一、`sources` 聚合（G8 替代面）；状态机按 `_DOC_TRANSITIONS` 合法边强制，非法迁移拒绝改态；Endpoint 资产 `scoped_idempotency_key` 唯一，同 URL 不同 method 不合并、新来源只追加 `sources` |
| 有界消费队列 | 同模块 · `ApiDocumentQueue.run()` | 回流通道三条：`_collect_seed_candidates` 种子、输入记录 `api_doc_url`（page_intel/js_intel 产物）、候选图 `endpoint`+`intel_record_type=api_doc_url`；解析新引用以 depth+1 再入队；预算闸＝深度/数量/大小/阶段时限（时限与 `provider_http` 剩余预算取小）；单文档失败隔离为 `failed`，残余候选保持开放态供 finalizer 下一轮周期显影；账本 `covered` 重投跳过（WIH 主扫描先例同窗口口径） |
| 统一获取 profile | `web_info_intel_utils.fetch_text` 新增 `request_profile`/`mirror_html_get` | 默认 `html_get` 既有调用零变化；`api_doc` 桶 miss→复用 `html_get` 桶并回填统一桶（不二次请求）→miss 才真实抓取；真实抓取按需镜像 `html_get`（直写 registry，不发 PageFetched、不计 actual_duplicate）保持旧消费者复用面 |
| 解析复用 | `api_doc_scan.ApiDocScanner` 新增 `collect_seed_candidates()`/`parse_document()` 公开入口 | 第 3 批不改解析实现（第 4 批统一 Parser 接管）；旧记录面输出与 legacy 逐字节一致由测试锁定 |
| 编排接线 | `wih_orchestrator` | `API_UNIFIED_ENABLE=False`（默认）保持 `wih_api_doc` 阶段位不变；True 时该阶段让位、在 `wih_js_intel` 之后运行 `wih_api_doc_unified` 子阶段——JS 发现文档当前任务内回流（§7.1 顺序） |
| 兼容/回滚 | `run_api_document_pipeline` | flag 关闭原样委托 legacy；True 时统一层整体异常回退 legacy 并计 `api_unified_fallback_total`（`API_UNIFIED_FALLBACK_ENABLE`）；Registry 挂载 `context.api_candidate_registry` 供第 8 批消费方取用 |
| 回归 | `ARL/test/test_api_candidate_registry.py` 19 项 | 注册表去重/聚合/状态机/Endpoint 资产、三通道回流各只获取一次、失败隔离、四预算闸、重投跳过、flag 开关输出 parity、profile 桶+镜像、`cross_bucket_hit` 转正锚、回退语义 |

验证：api 三件合跑 56 项全绿；`scripts/api-unified-golden.py --check` 无漂移；`test_task_finalizer` 26 项绿；
`test_discovery_context/test_wih_orchestrator/test_asset_wih_monitor/test_urlfinder_url_probe` 收集错误与
`shadow+web_info_intel` 配对污染均经 stash 基线对照确认与改动前一致（既有环境/污染问题，非本批引入）。
`asset_wih_monitor` 入口本批保持 legacy 调用（监控链路单站点，待第 8 批消费方接入统一切换）。

下一步为第 4 批：OpenAPI/Swagger 统一解析（JSON/YAML、servers/basePath、参数四位置、本地 `$ref`
有界解析与 unresolved 状态；验收下限＝`current_parser_baseline.json` 记录集合，上限＝
`unified_target_expectations.json`，补齐 G1/G3/G4/G7）。

### 第 4 批：OpenAPI/Swagger 统一解析（2026-09-05 完成）

| 交付 | 位置 | 说明 |
|---|---|---|
| 统一解析器 | `ARL/app/services/api_unified_parser.py` · `UnifiedOpenApiParser` | openapi3 + swagger2 双版本；servers/host/basePath/schemes 基址展开、越界 server→`domain` 候选（行为保留）、path 级参数与 operation 参数合并、`#/` 本地 `$ref` 有界解引用（预算 `max_ref_count`、循环显式 `cycle_ref`、未解析 `unresolved_ref`）、requestBody/responses Schema 摘要（深度 3、属性 50、截断标记）、securitySchemes/securityDefinitions→`auth_hint`（operation 覆盖 doc 级） |
| G1-G4/G7 缺口闭合 | 同上 | 模板端点 `{petId}` 保留原样进入端点/资产面（G1）；参数四位置+formData、schema/security 摘要（G3）；非法/深嵌套文档显式 `failed` diagnostics + error_type，不伪装"无 API"（G4）；端点携带 parent_document/base_url/api_version 追溯（G7） |
| 队列接线 | `api_candidate_registry.ApiDocumentQueue._parse_one` | 三级分发：unified（ok/degraded 桥接旧记录面 + 富资产直登记）→ skipped（postman/graphql 等未接管格式回 legacy）→ failed（显式失败，不回退）；解析器崩溃回退 legacy 并计 `api_unified_fallback_total`；新增指标 `api_document_unresolved_ref_total` |
| 桥接契约 | 附录A §4.8 | 统一输出为 legacy 记录面**超集**（只增不减）；模板 URL 抑制 `urlfinder_url` 记录（不可直接请求）；`AUTH_SCHEME_TYPE_TO_HINT` 增加顶层 `basic` 映射（§4.1 同步登记） |
| 回归 | `ARL/test/test_api_unified_parser.py` 22 项 | expectations 全量 must_include、swagger2/v3 端点集合一致、外部 ref 不获取、预算边界（大小/ref 数/深嵌套）、泄露守卫、队列桥接面 |

验证：api 四件合跑 79 项、九文件全组 122 项全绿；`api-unified-golden.py --check` 无漂移。
验收下限逐 fixture 断言（baseline 端点集 ⊆ 统一输出）；`unified_target_expectations.json`
的 openapi3/swagger2/external/invalid/deep 面全部满足，postman/graphql/wsdl 面属第 5-7 批。

下一步为第 5 批：Postman 统一解析（递归 item、`{{baseUrl}}` 变量解析策略、
`:id` 冒号变量、body 类型摘要、变量/环境地址脱敏）。

### 第 5 批：Postman 统一解析（2026-09-05 完成）

| 交付 | 位置 | 说明 |
|---|---|---|
| Postman 解析器 | `api_unified_parser.UnifiedPostmanParser` | 多层 `item` 递归（深度 10、条目 500 上限）；`raw` 字符串与 `protocol/host[]/path[]` 结构两种 URL 形态；集合变量解析策略按 expectations 冻结：可解析→候选 URL+置信度 70（降级），字面 URL→80，不可解析→保留 `{var}` 模板、置信度 30、不猜值 |
| G2 闭环 | 同上 | `{{baseUrl}}/users?limit=10` → `GET .../v1/users`（query 参数化为 `?{limit}` 模板进 path_template，URL 去 query）；`:id` 冒号端点保留原样进端点面并绕开会丢弃它的过滤器，同花括号模板抑制 `urlfinder_url`（`url_has_template` 扩展冒号段判定） |
| 参数与脱敏 | 同上 | header/query/path-variable/formData 参数只记名称+位置（`ParameterSpec` 无取值通道）；raw body 仅键名类型摘要且**敏感键名整体剔除**；变量值、body 值、示例值（`42`）经 `to_dict` 守卫双向断言禁止外流 |
| body 类型 | 同上 | `raw/urlencoded/formdata` 三模式摘要（expectations 口径为 Postman mode 名，非 MIME） |
| 队列分发 | `ApiDocumentQueue._parse_one` | 解析器链（openapi→postman），任一非 skipped 即接管；全 skipped 才回 legacy（graphql/wsdl 现状不变） |

验证：`test_api_unified_parser.py` 30 项（新增 Postman 面 7 项 + 队列链 1 项）、api 四件合跑 87 项、九文件全组 130 项全绿；golden `--check` 无漂移。`postman_collection.json` expectations 的 must_include、模板变量策略、body 类型三项断言全过。

下一步为第 6 批：GraphQL 能力补齐（请求事件统一、operation 提取、query hash、
可选 Schema 解析开关、Endpoint Registry 增 `api_type=graphql`）。

### 第 6 批：GraphQL 文档 Parser 完成，运行时事件接入未完成（2026-09-05 交付解析器；2026-09-06 用户决策 P0-05 选项二落盘范围）

| 交付 | 位置 | 说明 |
|---|---|---|
| GraphQL 解析器 | `api_unified_parser.UnifiedGraphqlParser`（`graphql_unified`） | 请求文档（`{url,method,request:{query,operationName,variables}}` 与裸 `{query}` 双形态）→ 每 operation 一个 `api_type=graphql` 端点（query/mutation/subscription 三类型、operationName、per-op `graphql_query_hash`、变量声明名称+类型）；`schema_available=False`；词法头+花括号配平，无第三方依赖 |
| SDL/introspection | 同上 | `GRAPHQL_SCHEMA_ENABLE`（默认 False→`skipped` 回 legacy）；SDL 行法摘要（types/enums/inputs/scalars、类型 500/字段 100 上限、`truncated`）；introspection 响应同预算；超 `GRAPHQL_SCHEMA_MAX_SIZE_BYTES` → `document_too_large` failed |
| 记录面 | 队列桥接 | `graphql "POST {url}"` 单条形态自本批起有唯一生产者（§二原为无生产者）；base 越界→`domain` 候选；variables 取值/嵌套键经守卫断言禁止外流 |
| 链分发 | `_parse_one` | 解析器链扩为 openapi→postman→graphql，全 skipped 才回 legacy |

范围收缩说明（如实记录；2026-09-06 用户决策 P0-05 选项二确认为范围裁定）：第 6 批
只交付 GraphQL 文档解析器，状态表述为"GraphQL 文档 Parser 完成，运行时事件接入未
完成"。浏览器运行时 body 的 operation 级拆解未在本批接入（`browser_intel_scan` 现有
`body_kind="graphql"` 分类点保留），按 §7.3 属 Endpoint Registry 消费方接入面，归
第 8 批复用本解析器完成；JS、页面来源的 GraphQL 请求事件接入同样顺延第 8 批；
JS/URLFinder 发现的 GraphQL URL 现状经 endpoint 候选→探测链消费，行为不变。

验证：`test_api_unified_parser.py` 39 项（GraphQL 面 9 项）、九文件全组 139 项全绿；golden 无漂移。

下一步为第 7 批：WSDL/SOAP 支持（安全 XML 解析：禁 XXE/外部实体/默认外部引用；
service/port/binding/portType/operation/message/soapAction 摘要；`api_type=soap`）。

### 第 7 批：WSDL/SOAP 支持（2026-09-05 完成）

| 交付 | 位置 | 说明 |
|---|---|---|
| WSDL 解析器 | `api_unified_parser.UnifiedWsdlParser`（`wsdl_unified`） | WSDL 1.1 `definitions/service/port/binding/portType/operation/message`（含 WSDL2.0 `endpoint/interface` 本地名兼容）；`soap:address@location`→URL、`soap:operation@soapAction`→`soap_action`、`wsdl:http@verb`→method（默认 POST）；端点携 `api_type=soap`/`wsdl_service`/`wsdl_port`/`operation_id`，input message part 名称摘要为 `ParameterSpec(body)` |
| G6 闭环 | 同上 | 基线无 soap 记录→统一层产出 2 个 soap 端点（getPet/listPets 同 location 不同 soapAction，富资产面并列、legacy 面 fnv 去重合一，超集语义）；`schema_available=False`（XSD 未解析不伪装完整） |
| XXE/SSRF 硬守卫 | 同上 `_looks_like_wsdl`/`_safe_fromstring` + `_DTD_FORBIDDEN_RE` | 含 `<!DOCTYPE`/`<!ENTITY` 文档**解析前**整体 `failed(dtd_forbidden)`、零网络（根除 XXE/billion-laughs 唯一载体）；过守卫后 expat 再关参数实体解析+拒外部实体引用兜底；大小受 `WSDL_MAX_SIZE_BYTES`（5MB）、operation/import/part 各 200/50/50 上限 |
| XSD 引用不获取 | 同上 `_collect_imports` | `xsd:import`/`include` 外部与同源引用只登记 `record_type=wsdl_xsd_import`（`content`/`resolved_url`/`namespace`/`same_origin`/`fetched=False`），计 `unresolved_ref_count`、状态 `degraded`（§6.4 外部引用默认不请求） |
| 链前置修复 | `UnifiedOpenApiParser.parse` | openapi 对 XML 标记形态由 `failed(not_object)` 改 `skipped(not_openapi_document)`，兑现"非 openapi/swagger 一律 skip"契约，避免 XML 在链首截断 wsdl 解析（postman/graphql 对 XML 本就 skip） |
| 队列分发 | `api_candidate_registry.ApiDocumentQueue._parse_one` | 解析器链扩为 openapi→postman→graphql→wsdl，全 skipped 才回 legacy；`_TYPE_HINT_KEYWORDS` 增 `wsdl` 分类（`.wsdl`/`?wsdl`）；越界 `soap:address`→`domain` 候选（端点为空仍保留候选与文档） |
| 回归 | `test/test_api_unified_parser.py` WSDL 面 14 项 | 2 soap 端点/soapAction/service/port、part 摘要、同源 XSD 登记不获取、越界 domain 候选、disabled/size skip、XXE dtd_forbidden 零端点+`xxe-probe`/`pe-probe` 零泄露、xsd 非 wsdl skip、openapi 对 XML skip、队列分发桥接 soap 记录、队列 XXE failed |

验证：`test_api_unified_parser.py` 53 项（WSDL 面 14 项）、api 四件合跑 110 项全绿；
`api-unified-golden.py --check` 无漂移（WSDL 为 legacy 之外新增面，基线不含 soap 记录，
验收下限为空、上限＝`unified_target_expectations.json` 的 wsdl_service/wsdl_xxe 面，全部满足）。
`WSDL_PARSE_ENABLE` 默认 True 但仅 `API_UNIFIED_ENABLE=True` 时经统一链生效，生产默认行为未切换。

下一步为第 8 批：Endpoint Registry 消费方接入（WIH endpoint probe / URL Probe 以 Registry
为唯一候选入口、浏览器运行时 operation 级拆解复用第 6 批 GraphQL 解析器、`asset_wih_monitor`
监控入口从 legacy 切换统一层、js/path/site 候选消费协议收口、新来源自动合并 `sources`）。

### 第 4-6 批 Review 整改轮 1（2026-09-06，P0-01 + P1-10，与第 7 批合并提交）

第 4-6 批提交后（commits `e81f0d36`/`02072a9d`）经独立 Review 判 **Request Changes**
（见 `docs/review/[Review已完成][整改待处理]计划6第4-6批API统一解析Review-20260905.md`）。
第 7 批 WSDL 继承了其中 P0-01，故按用户决策（Option A）先修第 7 批直接关联的两个安全/范围
阻断项，再与第 7 批合并为整改提交。两个并行整改子代理严格文件所有权隔离（P0-01 改
parser+registry，P1-10 改 models），编排者集成复跑。

| 项 | 处置 | 契约登记 |
|---|---|---|
| P0-01 越界 host 入 in-scope domain 资产 | 四解析器越界 host 候选 `domain`→`out_of_scope_domain` 证据类型；桥接 `_bridge_candidate`/`_bridge_out_of_scope_domain` 统一安全出口复用既有 host/Fld 校验，只计 `api_document_out_of_scope_domain_total`、绝不落 domain 记录；`wsdl_xsd_import`/未接线类型各自计数不静默丢弃 | 附录A §4.12 |
| P1-10 URL/source 自由文本脱敏盲区 | models 新增 `sanitize_url_secrets`/`sanitize_source_text`，构造与 `add_source`/merge 入口统一清洗 url/source/parent_url/parent_document/base_url/sources；`find_sensitive_keys` 守卫扩展检出敏感 query、残留令 `to_dict()` 抛错；干净 URL 逐字节 no-op | 附录A §4.12 |

验证：api 四件集成合跑 **126 项全绿**（parser 56 / registry 24 / models 38 / shadow 8）；
`api-unified-golden.py --check` exit 0（legacy 基线无漂移）；`py_compile` 与 `git diff --check` 通过。
**行为收窄**：统一路径对同-Fld 越界 host 也不再产 domain 记录（legacy 会产），"legacy 超集"
口径修订为"越界 domain 证据化是唯一允许缺失面"。**仍待后续整改轮**：P0-02（Postman 敏感变量
进 URL）、P0-03（GraphQL Schema 深度预算接线）、P0-04（Schema 摘要队列存储面）、P0-05（JS/页面/
浏览器事件接入 + G5 验收口径）、P1-06~P1-12、P2-13~P2-15——`API_UNIFIED_ENABLE` 在这些项
（尤其 P0-02 安全阻断）闭环前不得切换默认。

### 第 4-6 批 Review 整改轮 2 决策（2026-09-06，用户确认）

用户已就计划 6 Review 轮 2 的三项阻断决策拍板，连同范围修正一并落盘为本节及附录A
§4.13，作为后续代码实施（T1/T2/T3/T8 票）的冻结依据。P0-05 采纳选项二：第 6 批只交付
GraphQL 文档解析器，JS、页面、浏览器事件接入顺延第 8 批，第 8 批新增三来源同一 Registry
合并且敏感值不外流的独立门禁；P1-12 采纳 Endpoint 幂等键纳入 api_type（operation identity
由 input_signature 承载，无需历史数据迁移，契约冻结、代码待 T8 实施）；P0-04 采纳"当前批
不落 Mongo、Registry 延后第 8 批"，并将摘要承载表述修正为整数计数与有界诊断摘要双通道
（契约冻结、代码待 T3 实施）；范围修正：`wsdl_operation_total` 移出 GraphQL 整改票（T3 只
负责 GraphQL metrics），登记为第 8 批或独立 WSDL 可观测性票事项。本节仅为决策与契约记录，
不预告任何未完成的实现。（同日后续：T1/T2/T3 已于整改轮 2 实施完毕，见下一节；
P0-05 事件接入与 P1-12 仍维持"待 T8"。）

### 第 4-6 批 Review 整改轮 2 实施（2026-09-06，T1/T2/T3 + P1-08/P1-09 + P2-13）

按轮 2 决策冻结面实施代码。契约细则登记附录A §4.14；本节只记交付与验收口径。

| 票 | 项 | 交付 |
|---|---|---|
| T1 | P0-02 Postman 敏感变量进 URL | `UnifiedPostmanParser._substitute` 对敏感键名（`is_sensitive_key`）永不解析真实值：保留 `{{key}}` 模板并标 unresolved，走既有"不可解析→置信度 30、桥接抑制 urlfinder"链路；path/query/host/raw 四位置的泄露断言 + 桥接输出零原值 |
| T2 | P1-06/P1-07 GraphQL operation tokenizer | `_mask_literals`（`#` 注释、`"..."`、块字符串含转义，逐位等长掩码）+ 文档级深度 0 识别 operation header（可选 name/变量声明/指令括号配平）；未闭合→`unclosed`（无完整 operation 且非截断致因→`failed(malformed_query)`，否则 degraded 注记）；超 50 operation→`degraded(operation_limit_exceeded)` 禁静默切片；匿名 operation 变量兜底 = `$name` 引用 ∪ variables 键名（只取名称） |
| T3 | P0-03 Schema 预算/状态收口 | `GRAPHQL_SCHEMA_MAX_DEPTH` 经 `_parse_options` 真正注入并执行（depth 冻结为类型引用包装链层数：SDL `[`/`!` 计数、introspection `ofType` NON_NULL/LIST 链）；bytes/type/field/argument/depth 任一预算命中→`degraded + 首个预算名`，结构性错误→`failed`，永不假 `ok`；`_schema_failed` 显式化坏 introspection（missing/invalid/broken json） |
| T3 | P0-04 Schema 摘要双通道 | 生产侧 `_schema_summary_contract`（白名单键、canonical sha256 `schema_hash[:16]`、`summary_bytes`）；消费侧 `ApiCandidateRegistry.schema_diagnostics` 有界诊断面（驻留 16 条满则丢最旧、单条 `GRAPHQL_SCHEMA_SUMMARY_MAX_BYTES`=8192 超限裁剪为安全头部+`summary_dropped`、契约违规→failed+`schema_contract_violation` 不回显候选字段值）；metrics 整数计数 `graphql_schema_success/degraded/failed/skipped_total`、`graphql_request_total`（端点桥接逐条）、`api_document_schema_diagnostics_total`/`_dropped_total`；`graphql_schema_summary` 不再进 unbridged 观测锚（归零断言锁定）；不落 Mongo、不进 legacy 记录面 |
| T3 附带 | 链分发前置修复（真实队列端到端测试暴露） | openapi 对无 openapi/swagger 痕迹的 YAML 载入失败与非 dict 载入结果由 `failed` 改 `skipped(not_openapi_document)`；postman（JSON-only）载入失败一律 `skipped(not_postman_document)`——否则 GraphQL SDL 等文本在链首被截断、后继解析器经真实队列永不可达（第 7 批"XML→skip"同一契约方向）；`RecursionError`/`document_too_large` 维持显式 failed（G4/成本边界不受痕迹门控） |
| 队列 | P1-08 失败收口 | 空响应纳入 `parse_failed_count` + `api_document_parse_failed_total`；不变式"被消费文档必收敛 success/failed 之一"三路径（fetch 异常/空响应/Parser failed）分别断言 |
| 队列 | P1-09 fallback 开关单一语义 | 单文档 Parser 崩溃回退与 stage 级整体异常同受 `API_UNIFIED_FALLBACK_ENABLE` 约束：False 时不回退、不产生 fallback 事件，文档标 failed 入统一收口 |
| 测试卫生 | P2-13 | `test/_api_unified_bootstrap.py` 临时桩加载（带 `__path__` 桩包 + finally 槽位还原 + 空壳污染回归断言）；四件测试各自独立进程可运行 |

范围外（维持冻结待实施）：P0-05 事件接入与三来源合并门禁（T8/第 8 批）、P1-12 幂等键改形
（T8）、P1-11 的 `wsdl_operation_total`（轮 2 范围修正移出，归第 8 批或独立 WSDL 可观测性票）、
P2-15 解析器分文件重构（本轮仅按 Review 建议保持共享辅助函数，不强制拆分）。

验证（P2-14 口径修正：只登记可复现命令与实际计数）：四件独立进程
`PYTHONPATH=. python3 -m unittest test.test_api_unified_{parser,candidate_registry,models,shadow}`
= 86/39/38/8 全绿；api 四件合跑 **171 项全绿**（轮 1 基线 126 → +45）；
六件邻接合跑（+`test_task_finalizer`、`test_discovery_context`）212 项全绿；
`scripts/api-unified-golden.py --check` exit 0；`git diff --check`、`py_compile` 通过。

## 当前状态（2026-09-06 第 7 批 + 整改轮 1/轮 2 后）

- [已完成] 第 1 批接口/结果契约冻结、golden corpus、legacy adapter、脱敏约束和幂等键定义已完成。
- [已完成] 第 2 批 shadow metrics、ResponseRegistry 无副作用读取和 API 文档/Endpoint 探测观测接线已完成；该批不改变运行时输出。
- [已完成] 第 3 批候选注册表、文档队列、状态机、来源聚合、幂等领取（重投 covered 跳过）、四道预算闸与 JS 发现文档当前任务回流已实现；`API_UNIFIED_ENABLE` 默认 False，生产行为面未切换。
- [已完成] 第 4 批 OpenAPI/Swagger 统一解析：G1 模板端点、G3 参数/schema/security、G4 显式失败、G7 追溯字段落地，输出为 legacy 超集；外部 `$ref` 不获取、预算有界。
- [已完成] 第 5 批 Postman 统一解析：递归 item、变量解析策略（候选 URL 降置信度/模板保留不猜值）、`:id` 冒号变量、body 三模式摘要、敏感键名剔除与值禁外流双向断言（G2 闭环）。
- [已完成] 第 6 批 GraphQL 文档 Parser（请求/SDL/introspection 统一解析：operation、variables 名称、query hash、Schema 开关与预算；`graphql` 记录获得唯一生产者）。
- [未完成] 第 6 批运行时事件接入：JS、页面、浏览器 GraphQL 请求事件接入未完成，顺延第 8 批（2026-09-06 用户决策 P0-05 选项二；第 6 批状态表述冻结为"GraphQL 文档 Parser 完成，运行时事件接入未完成"）。
- [已完成] 第 7 批 WSDL/SOAP 统一解析（G6 闭环：definitions/service/port/binding/portType/operation/message/soapAction，`api_type=soap` 端点；XXE/DTD 解析前硬拒+expat 兜底、XSD 引用登记不获取、越界 address→`out_of_scope_domain` 证据候选；openapi 对 XML 改 skip 修复链首截断；队列链 openapi→postman→graphql→wsdl）。
- [已完成] 第 4-6 批 Review 整改轮 1（P0-01 越界 host 证据化不入 in-scope domain 资产 + P1-10 URL/source 脱敏边界，与第 7 批合并提交；api 四件 126 项、golden 无漂移）。
- [已完成] 第 4-6 批 Review 整改轮 2 决策落盘（2026-09-06 用户确认：P0-05/P1-12/P0-04 及范围修正，见上文决策节与附录A §4.13）。
- [已完成] 第 4-6 批 Review 整改轮 2 代码实施（2026-09-06：P0-02 敏感变量 URL 替换禁令、P0-03 Schema 预算/状态收口、P0-04 摘要双通道 + 真实队列端到端闭环、P1-06/P1-07 operation tokenizer、P1-08 统一失败收口、P1-09 fallback 开关单一语义、P1-11 GraphQL metrics、P2-13 测试 bootstrap 独立进程；附带链分发前置修复 openapi/postman 对非本格式文本 skip 不截断链；api 四件 171 项全绿）。
- [未完成] 第 4-6 批 Review 余留项：P0-05 事件接入（归第 8 批/T8）、P1-12（契约冻结，代码待 T8 实施）、P1-11 的 `wsdl_operation_total`（范围修正移出 GraphQL 票，归第 8 批或独立 WSDL 可观测性票）、P2-15 解析器分文件重构（后续批次评估）；`API_UNIFIED_ENABLE` 切换默认的前置门禁中 P0-02~P0-04 安全/语义阻断已闭环，余 P0-05 三来源合并门禁（第 8 批）与 P1-12（T8）。
- [未完成] Endpoint Registry 消费方接入含浏览器运行时 operation 拆解（第 8 批）、阶段调度与 WAF 隔离（第 9 批）、Rust 纯数据层（第 10 批）、全量回归与发布验收（第 11 批）尚未完成。
- [已完成] `api_document_cross_bucket_hit_total` 转正：单测锁定 api_doc 桶命中计数路径；真实环境的转正观测并入第 4 批起的容器联调口径。
- [未完成] `asset_wih_monitor` 监控入口仍走 legacy `run_api_doc_scan`，待第 8 批消费方接入时统一切换。
- [未完成] Rust 解析层、40/64 目标协同回归和双架构发布验收不得提前宣称完成。

当前判定：计划 6 第 1–7 批解析器面 [已完成]（OpenAPI/Postman/GraphQL/WSDL 文档解析全部接管，golden 无漂移；其中第 6 批为 GraphQL 文档 Parser 完成、运行时事件接入未完成，顺延第 8 批——2026-09-06 用户决策 P0-05 选项二）；第 4-6 批 Review 整改轮 1（P0-01/P1-10）[已完成]、整改轮 2 代码实施 [已完成]（P0-02/P0-03/P0-04 + P1-06~P1-09/P1-11 + P2-13，api 四件 171 项全绿、真实队列 Schema 端到端闭环）；余留 P0-05 事件接入与 P1-12 幂等键改形 [未完成]（均归第 8 批/T8）；第 8 批起运行时消费方接入与最终验收 [未完成]。`API_UNIFIED_ENABLE` 默认 False，生产默认行为未切换——"代码具备入口"与"默认生效"仍分别记账，**切换默认的前置门禁：轮 1/轮 2 的 P0 安全/语义阻断已全部闭环，剩余为第 8 批三来源合并门禁（P0-05）与 P1-12（T8）**。第 2/3 批 Review 的终态与候选 drain 前置已在 2026-09-05 终态修复轮闭环，第 3–7 批未新增绕过统一收尾的消费通道（残余候选保持开放态，finalizer 显影语义不变）。
