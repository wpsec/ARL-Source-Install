# 计划 6：统一 API 解析与 Endpoint Registry 重构

状态：第 1-3 批已实施（2026-09-05，见文末实施进度；第 4 批起未开始）。契约冻结面见 [06-附录A](<../completed/[已完成]06-附录A-API契约冻结清单.md>)。

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

Endpoint 幂等键：

```text
task_id + api_endpoint + canonical_url + method + request_signature
```

同一 URL 使用不同 Header、认证上下文或请求 profile 时，必须保留为不同的请求观察，不得错误合并。

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
- Endpoint Registry 按 canonical URL、method、api_type、operation_id 建索引；
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

## 当前状态（2026-09-05 第 3 批后）

- [已完成] 第 1 批接口/结果契约冻结、golden corpus、legacy adapter、脱敏约束和幂等键定义已完成。
- [已完成] 第 2 批 shadow metrics、ResponseRegistry 无副作用读取和 API 文档/Endpoint 探测观测接线已完成；该批不改变运行时输出。
- [已完成] 第 3 批候选注册表、文档队列、状态机、来源聚合、幂等领取（重投 covered 跳过）、四道预算闸与 JS 发现文档当前任务回流已实现；`API_UNIFIED_ENABLE` 默认 False，生产行为面未切换。
- [未完成] OpenAPI/Postman 的参数/schema/auth 完整统一、GraphQL Schema、WSDL/SOAP Operation 解析和统一 Endpoint 消费链路尚未完成。
- [已完成] `api_document_cross_bucket_hit_total` 转正：单测锁定 api_doc 桶命中计数路径；真实环境的转正观测并入第 4 批起的容器联调口径。
- [未完成] `asset_wih_monitor` 监控入口仍走 legacy `run_api_doc_scan`，待第 8 批消费方接入时统一切换。
- [未完成] Rust 解析层、40/64 目标协同回归和双架构发布验收不得提前宣称完成。

当前判定：计划 6 第 1–3 批 [已完成]；第 4 批及后续运行时接入 [未完成]。第 2/3 批 Review 的终态与候选 drain 前置已在 2026-09-05 终态修复轮闭环，第 3 批未新增绕过统一收尾的消费通道（残余候选保持开放态，finalizer 显影语义不变）。
