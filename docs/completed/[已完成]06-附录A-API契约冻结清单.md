# 06 附录A · API 契约冻结清单（计划 6 第 1 批）

- 冻结日期:2026-09-05。基线 rev:`6376e4ca` 之后的工作区(第 1 批未提交前)。
- 机器可验部分(现行解析记录基线)由 `python3 scripts/api-unified-golden.py` 生成至
  `ARL/test/fixtures/api_unified/expected/current_parser_baseline.json`,`--check` 模式做漂移检测;
  本文件其余为语义冻结说明,行号会漂移、锚点以函数名为准。
- 本清单是第 2-11 批的对照面:任何与本清单冲突的实现,须在计划 6 文档内显式修订并说明兼容影响。

## 一、WihRecord 序列化面冻结

`ARL/app/modules/wihRecord.py` · `WihRecord`:

| 字段(dump_json) | 构造参数 | 语义 |
|---|---|---|
| `record_type` | `record_type`(属性名 `recordType`) | 记录类型,小写字符串 |
| `content` | `content` | 记录内容,格式按类型冻结(见第二节) |
| `site` | `site` | `safe_site(url)` 产出的站点(协议+host,去 path) |
| `source` | `source` | 证据来源(URL 或生产者名) |
| `fnv_hash` | `fnv_hash` | 见下 |

- 去重哈希:`web_info_intel_utils.stable_hash(record_type, content, site)` =
  `int(md5("type|content|site").hexdigest()[:16], 16)`。**source 不参与去重**——
  同一记录不同来源合并为一条,来源信息丢失是现状缺陷;统一层的 `sources` 聚合(§七)是其替代,旧记录面不改。

## 二、API 相关记录类型面冻结(生产者与内容格式)

| record_type | content 格式 | source 语义 | 生产者(代码锚点) |
|---|---|---|---|
| `api_doc_url` | 文档 URL 原文 | 同 content(文档自身) | `api_doc_scan.ApiDocScanner._parse_swagger_like` / `_parse_postman` |
| `api_doc_endpoint` | `"{METHOD} {normalized_url}"`(单空格) | 父文档 URL | `ApiDocScanner._emit_endpoint` |
| `urlfinder_url` | `{normalized_url}` | 父文档/发现者 URL | `_emit_endpoint`、URLFinder 链路 |
| `domain` | 纯主机名(无协议) | 父文档 URL | `ApiDocScanner._emit_domain_records`(文档内越界 host、同 FLD 才记录) |
| `wih_endpoint` | WIH 主扫描端点 | Go 工具 payload | `infoHunter` payload `endpoints`/`records`(id/type 字段) |
| `graphql` | 现状**无独立生产者**;仅 `browser_intel_scan` 以 `body_kind="graphql"` 归类、`urlfinder_sensitive_scan` 关键字表含 `graphql` | — | 见 §五缺口 G5 |

- 归一化:`normalize_in_scope_url`(基于 `url_candidate_filter`),越界绝对 URL 转 `domain` 候选并丢弃端点。
- 方法集:`ApiDocScanner._HTTP_METHODS`(get/post/put/delete/patch/options/head);
  path item 无任何 method 键时兜底按 `GET` 输出(冻结为现状,统一层保留该行为以免结果减少)。

## 三、配置读取现状

- `api_doc_scan` 全部走 `getattr(Config, ...)`,**Config 中均未定义**,实际生效为默认值:
  `API_DOC_ENABLE=True`、`API_DOC_MAX_CANDIDATES=20`、`API_DOC_MAX_BODY_BYTES=786432`。
  超时硬编码 `(5, 12)`。
- 计划 6 §8.3 的 14 个 `API_UNIFIED_*`/`API_DOCUMENT_*`/`GRAPHQL_SCHEMA_*`/`WSDL_*` 键:
  第 1 批仅冻结于代码常量 `api_unified_models.UNIFIED_API_CONFIG_DEFAULTS`,**未写入 Config**;
  接线批次(第 3 批起)用 `getattr(Config, name, 常量默认)` 读取,默认值语义与本表一致。
- 后续批次增补的常量键(同一读取口径):`GRAPHQL_SCHEMA_SUMMARY_MAX_BYTES`(轮 2 P0-04)、
  `API_ENDPOINT_CLAIM_LEASE_SEC`(R6/T9 claim lease),见 §4.14/§4.17。

## 四、统一数据契约(第 1 批代码落地面)

模块:`ARL/app/services/api_unified_models.py`(纯 stdlib,不 import 网络/Mongo/Celery/AI;
URL 规范化与 `ResponseRegistry` 共用 `discovery_context.normalize_url`,口径一致)。

### 4.1 枚举(值集合与含义即契约,扩展视为变更)

- 文档候选状态:`discovered/queued/fetching/fetched/parsed/failed/skipped`
- Endpoint 状态:`discovered/queued/probed/covered/failed/degraded/pending/skipped`
- 类型:`type_hint=openapi|swagger|postman|graphql|wsdl|unknown`;`api_type=rest|graphql|soap`
- `auth_hint=none|basic|bearer|api_key|cookie|oauth2|mtls|unknown`;
  securitySchemes 类型映射表 `AUTH_SCHEME_TYPE_TO_HINT`(未识别一律 `unknown`)
- `graphql_operation=query|mutation|subscription|unknown`;参数位置 `path|query|header|cookie|formData|body`
- 请求 profile:`api_doc|api_endpoint_probe|graphql_schema_optional|soap_endpoint_observe|browser`
- 诊断状态:`ok|degraded|failed|skipped`

### 4.2 幂等键(三层,冻结拼接形态)

| 层 | 键 | 说明 |
|---|---|---|
| 文档候选 | `task_id\|api_doc\|canonical_url\|request_profile\|input_signature` | `ApiDocumentCandidate.idempotency_key` |
| Endpoint 资产 | `task_id\|api_endpoint\|canonical_url\|METHOD\|input_signature` | `UnifiedApiEndpoint.scoped_idempotency_key`;同 URL 不同 method 必为不同键 |
| 请求观察 | `api_observation\|canonical_url\|METHOD\|profile\|sha256(auth_profile)[:32]` | `probe_observation_key`;认证上下文/profile 不同不共享缓存响应(§8.1) |

`input_signature` 由生产方用 `compute_input_signature(*parts)`(sha256 前 32 位)生成,
文档正文 hash、请求上下文摘要都走该函数。

> **Endpoint 资产层键冻结变更(2026-09-06 用户决策,P1-12;已于第 8 批 T8-1 实施)**:
> Endpoint 幂等键纳入 `api_type`,冻结为
> `task_id + canonical_url + method + api_type + input_signature`,`input_signature`
> 必须已含协议内部 operation identity(细则见 §4.13);Registry 尚未切生产
> (`API_UNIFIED_ENABLE` 默认 False),改 key 无需历史数据迁移。上表保留的现行
> 代码拼接形态自 T8-1 起为历史形态,现实现见 §4.15。

### 4.3 Parser 契约

`parse(document_artifact, parse_options) → ParseResult{documents, endpoints, candidates, diagnostics}`,
diagnostics 字段:`parser, input_count, output_count, deduplicated_count, unresolved_ref_count, rejected_count, error_type, status`。
`ParseResult.to_dict()` 内置泄露守卫:输出含敏感键值时抛 `ValueError`(契约级缺陷即时暴露)。

### 4.4 脱敏策略(冻结)

- `ParameterSpec` **结构上无取值通道**(仅 name/in/type/required;不存在 value/example/default 属性)。
- `SecurityRequirementSummary` 仅 name+映射后的 type;凭据内容无字段可放。
- `is_sensitive_key`:authorization/cookie/set-cookie/x-api-key/api_key/secret/token/password/session_id/private_key 等形态(全匹配)。
- `find_sensitive_keys(obj)`:递归守卫;额外覆盖 `{name: <敏感名>, value: 非空}` 参数摘要形态;
  自由文本字段(`.value/.raw/.content`)含 `key: value` 赋值形态也命中。
- `redact_assignment_text`:把敏感赋值整段替换为 `key=<redacted>`(值段到 `,;` 或行尾,覆盖 `Bearer xxx` 双词形态)。
- 外部引用默认关闭(`ParseOptions.external_ref_enable=False`)、GraphQL Schema/introspection 默认关闭(`graphql_schema_enable=False`)、WSDL 解析默认开启——与 §8.3 默认一致。
- **改判指针(2026-09-06)**:本节把"URL query 凭据"列为脱敏对象的语义已被 §4.16 三层
  数据契约改判——URL 观测字段(含 query 值)原样保留,守卫仅作用于内容面字段;
  `sanitize_url_secrets`/`sanitize_source_text` 用途收窄至私有请求上下文字段。
  schema 示例/参数取值/赋值形态的守卫不受影响。

### 4.5 shadow 请求复用观测(第 2 批,只计数不改输出)

模块:`ARL/app/services/api_unified_shadow.py`;观测原语:
`ResponseRegistry.peek` / `DiscoveryContext.peek_response`(无副作用:不登记 consumer、
不动 LRU、不产生 cache_hit/miss 指标,返回不含 body 的快照)。指标随
`DiscoveryContext.metrics` 进入 `commonTask.observation_snapshot()` 诊断日志,不落 Mongo。

| 指标键(冻结) | 语义 |
|---|---|
| `api_document_fetch_total` / `_unique_total` / `_repeat_total` | 文档获取尝试总数/唯一 URL 数/重复尝试数(task 作用域) |
| `api_document_cache_hit_total` | 尝试前 `html_get` 桶已存在响应(现行真实复用面) |
| `api_document_cross_strategy_reuse_total` | 命中响应且 consumers 含非 `api_doc_scan` 来源 |
| `api_document_cross_bucket_hit_total` | 尝试前统一 `api_doc` 桶已有响应——**现状恒为 0**,第 3 批接管获取后应转正,作为切换生效证据锚 |
| `api_document_expected_network_total` | 两桶皆无、即将真实请求的尝试数 |
| `api_document_fetch_empty_total` | 获取返回空的尝试数 |
| `api_probe_total` / `_unique_total` / `_repeat_total` | Endpoint 探测尝试(键=URL+method+profile) |
| `api_probe_cache_hit_total` / `_cross_strategy_reuse_total` / `_expected_network_total` | 探测前对应 profile 桶状态 |
| `api_probe_failed_total` | 探测异常路径 |
| `api_shadow_error_total` | 观测自身异常(伴随既有 `degraded_count`);观测失败绝不阻断扫描 |

接线点:`api_doc_scan.run()` 文档 fetch 前后;`wih_endpoint_probe._probe_one()` profile
确定后、缓存解析前,及 except 路径。既有全局指标(`network_request_count`、
`cache_hit_count`、`actual_duplicate_request_count`、`cross_strategy_reuse_count`)口径不变,
本表是 API 类别的分解视图。WAF blocked/pending 分类计数按计划留待第 9 批。

### 4.7 第 3 批运行时接界面(2026-09-05 登记)

- 模块:`ARL/app/services/api_candidate_registry.py`(`ApiCandidateRegistry`/`ApiDocumentQueue`/
  `run_api_document_pipeline`)。`API_UNIFIED_ENABLE`(默认 False)关闭时委托 legacy
  `run_api_doc_scan`,行为与 §4.5 完全一致;开启时 `wih_api_doc` 阶段位让位,
  `wih_js_intel` 之后运行 `wih_api_doc_unified`(JS 回流当前任务)。
- 获取 profile:`fetch_text` 新增 `request_profile`(默认 `html_get`,既有调用零变化)与
  `mirror_html_get`。统一 `api_doc` 桶查询顺序:api_doc 桶→`html_get` 桶(命中回填
  api_doc 桶,不发请求)→真实抓取;真实抓取镜像登记 `html_get` 桶(直写 registry,
  不发布 `PageFetched`、不计 `actual_duplicate`),保持旧消费者复用面。
- 文档候选消费单元 = 规范化 URL;账本幂等键 = `context.idempotency_key("api_doc", url,
  "api_doc", "")`,`covered` 重投跳过(与 WIH 主扫描先例同窗口取舍);预算键读取口径 =
  `getattr(Config, name, UNIFIED_API_CONFIG_DEFAULTS[name])`,非正值回退默认。
- **URL 唯一契约(Review 20260905 一般项处置,2026-09-05 显式化)**:文档获取固定
  单一 profile=`api_doc`、GET、无认证上下文差异,任务窗口内以 URL 唯一、正文变化
  不强制重验为设计语义;正文漂移由新 task_id 的下一周期覆盖。该语义变更必须改用
  (profile, body-hash) 组合键并同步修订本节;由
  `test_api_candidate_registry.py::test_ledger_url_unique_contract_locked` 锁定。
  同 URL 不同 profile 的并列实例需求(如认证文档)属第 8 批 Endpoint 消费面,不改变
  文档获取面。
- 新增计数指标(随 `metrics_snapshot` 进诊断日志,不落 Mongo):
  `api_document_candidates_total`、`api_document_sources_merged_total`、
  `api_document_parse_success_total`、`api_document_parse_failed_total`、
  `api_document_pending_residual_total`、`api_document_budget_skipped_total`、
  `api_document_resumed_skip_total`、`api_endpoint_discovered_total`、
  `api_endpoint_deduplicated_total`、`api_unified_fallback_total`。
- 输出不变性:`API_UNIFIED_ENABLE` 开启时记录面集合与 legacy 逐字节一致(同一解析实现、
  同一 `_append_record` 去重),由 `test_api_candidate_registry.py` parity 用例锁定;
  Endpoint 资产登记面(`context.api_candidate_registry.snapshot_endpoints()`)为第 8 批
  消费方预留,本批不改变任何下游消费行为。
- 候选图镜像:统一注册表按 `candidate_type="api_doc"`、`request_profile="api_doc"` 镜像
  `ApiDocumentCandidateDiscovered` 事件,不与 `endpoint` 型候选混用;finalizer
  `pending_backlog|api|*` 显影只消费 `endpoint` 型,语义不变(残余开放候选仍按下一轮周期显影)。

### 4.1a AUTH_SCHEME_TYPE_TO_HINT 第 4 批扩展

- 增加顶层 `"basic"→basic` 映射(swagger2 `securityDefinitions.type: basic` 无
  `http:` 前缀形态);其余值集合不变(§4.1 冻结枚举的既有语义未改)。

### 4.6 兼容映射(§7.3 的 adapter 语义)

`UnifiedApiEndpoint.to_legacy_records()`:
- `rest`/`soap` → `api_doc_endpoint "{METHOD} {url}"` + `urlfinder_url {url}`,source=`parent_document`(缺失回退 source/url)——与第二节现行格式逐字节一致;
- `graphql` → `graphql "{METHOD} {url}"` 单条。
文档候选回写旧记录时 `api_doc_url content=url, source=url`。

### 4.8 第 4 批统一 OpenAPI/Swagger 解析面(2026-09-05 登记)

- 模块:`ARL/app/services/api_unified_parser.py` · `UnifiedOpenApiParser`
  (`parse(document_artifact, ParseOptions) → ParseResult`,实现 §4.3 契约)。
- **输出口径变更(取代 §4.7"逐字节一致"表述)**:`API_UNIFIED_ENABLE=True` 且文档
  为 openapi/swagger 形态时,统一 Parser 输出为 legacy 记录面**超集**(只增不减):
  增量面仅允许模板端点类补充记录;非 openapi 形态(skipped)与崩溃回退时仍为
  legacy 同一实现、逐字节一致。`test_output_floor_and_format_vs_legacy` 锁定。
- G1 模板端点:`{petId}` 类 URL 原样进入 `api_doc_endpoint` 与 Endpoint 资产面;
  **模板 URL 抑制 `urlfinder_url` 记录**(不可直接请求,不污染 URL 资产/探测链)。
- G4 失败可见:非法/超限/深嵌套文档 diagnostics `failed`+error_type,文档状态
  `failed`、计 `api_document_parse_failed_total`,不回退 legacy 静默成功。
- 引用解析:仅本地 `#/` ref;外部 ref 一律 `unresolved_ref` 标记并计数
  (`api_document_unresolved_ref_total`),零网络;预算 `max_ref_count` 耗尽→
  `degraded`;循环 `cycle_ref` 标记计入 `rejected_count` 不算 unresolved。
- Schema 摘要深度 3、属性 50、超限 `truncated:true`;`schema_available` 仅在
  摘要含有效解析结构时为 True(未解析引用不得伪装完整)。
- 鉴权:`operation.security` 覆盖 doc 级;`security:[]`→`auth_hint=none`;
  未识别 scheme→`unknown`。

### 4.9 第 5 批 Postman 统一解析面(2026-09-05 登记)

- 解析器:`api_unified_parser.UnifiedPostmanParser`(`postman_unified`);队列
  `_parse_one` 为解析器链(openapi→postman),任一非 skipped 即接管,全 skipped
  才回 legacy。识别口径:`item` 为 list(与 legacy `_parse_doc` 判定一致)。
- 变量策略(expectations 冻结):集合变量解析成功→候选 URL、confidence 70
  (字面 URL 80);不可解析→`{var}` 模板保留、confidence 30、不猜值。
  示例值(`variable[].value`)一律不进任何输出面。
- URL 形态:query 参数化为 `path_template` 的 `?{key}` 尾串,`url` 去 query
  (期望 content 为资源 URL);`raw` 缺失时由 `protocol/host[]/path[]` 组装。
- 冒号路径变量 `:id` 与花括号模板同口径:`url_has_template` 增加冒号段判定,
  桥接层同样抑制其 `urlfinder_url`,端点与资产面保留(§4.8 扩展)。
- 脱敏:header/query/path/formData 参数只记名称+位置;raw body 摘要仅键名+
  类型且 `is_sensitive_key` 命中键名整体剔除;urlencoded/formdata 条目仅名称。
  body 类型期望为 Postman mode 名(`raw/urlencoded/formdata`),非 MIME。
- 新增指标语义:`postman_unified` 诊断的 `unresolved_ref_count` 复用为
  未解析模板变量计数,`rejected_count` 为畸形请求条目数。

### 4.10 第 6 批 GraphQL 解析面(2026-09-05 登记)

- 解析器:`UnifiedGraphqlParser`(`graphql_unified`),队列链 openapi→postman→graphql。
- 请求文档双形态:`{url,method,request:{query,operationName,variables}}` 外壳与裸
  `{query,...}`;端点 base 取文档 `url`(缺失回退发现 URL),越界→`domain` 候选。
- §二 `graphql` 行更新:自第 6 批起唯一生产者为统一层(经队列桥接,
  content=`"POST {url}"`);legacy 通道继续无生产者,`urlfinder_url`/`api_doc_endpoint`
  不为 graphql 产生。
- variables 面:仅 operation 声明的 名称+类型(`ParameterSpec(location=body)`);
  请求体 `variables` 对象取值与嵌套键一律不进任何输出面(守卫测试双向断言)。
- Schema 面默认关闭(`GRAPHQL_SCHEMA_ENABLE=False`→`skipped` 回 legacy);开启时
  SDL/introspection 摘要进 `ParseResult.candidates`
  (`record_type=graphql_schema_summary`,含 `truncated`),不落 Mongo;预算
  `GRAPHQL_SCHEMA_MAX_SIZE_BYTES`(超限 failed)、类型 500、字段/类型 100。
- 范围说明:浏览器运行时 body 的 operation 级拆解归第 8 批消费面(复用本解析器);
  匿名/裸 body 查询产单条 `query` 端点。
- 状态口径(2026-09-06 用户决策 P0-05 选项二):第 6 批为"GraphQL 文档 Parser 完成,
  运行时事件接入未完成"。Schema 摘要存储面契约(双通道)按 §4.13 登记,已于整改轮 2
  实施(消费面形态见 §4.14)。

### 4.11 第 7 批 WSDL/SOAP 解析面(2026-09-05 登记)

- 解析器:`UnifiedWsdlParser`(`wsdl_unified`),队列链扩为 openapi→postman→graphql→wsdl,
  全 skipped 才回 legacy。**链前置修复**:`UnifiedOpenApiParser` 对 XML 标记形态
  (`<?xml`/`<标签`)由原 `failed(not_object)` 改为 `skipped(not_openapi_document)`,
  以兑现"非 openapi/swagger 形态一律 skipped"契约,避免 XML 在链首被误判 failed
  而截断后续 wsdl 解析(postman/graphql 对 XML 本就 skip,无需改)。
- WSDL 1.1 解析面:`definitions/service/port(+WSDL2.0 endpoint)/binding/portType
  (+interface)/operation/message`;`soap:address@location`→端点 URL、
  `soap:operation@soapAction`→`soap_action`、`wsdl:http@verb`→method(默认 POST);
  端点携 `api_type=soap`/`wsdl_service`/`wsdl_port`/`operation_id`,input message
  的 part 名称摘要为 `ParameterSpec(location=body, type=element/type 本地名)`。
- 安全边界(§6.4/§11.3,验收硬约束):含 `<!DOCTYPE`/`<!ENTITY` 的文档在**解析前**
  整体判 `failed(dtd_forbidden)`、零解析零网络(XXE/SSRF/billion-laughs 的唯一载体
  即 DTD,拒绝 DTD 即根除);通过守卫后再以 expat 关闭参数实体解析
  (`XML_PARAM_ENTITY_PARSING_NEVER`)并拒绝外部实体引用(`ExternalEntityRefHandler→False`)
  作兜底;大小受 `max_document_bytes`(`WSDL_MAX_SIZE_BYTES` 默认 5MB)约束;
  operation/import/part 各有上限(200/50/50);越界 `soap:address`→`domain` 候选(与
  openapi 越界 server 同口径,端点为空仍保留候选与文档,不静默丢弃)。
- `xsd:import`/`include` 的外部与同源 XSD **只登记观测候选、不获取**
  (`record_type=wsdl_xsd_import`,含 `content`/`resolved_url`/`namespace`/`same_origin`/
  `fetched=False`),计 `unresolved_ref_count` 且状态 `degraded`——不伪装完整 Schema
  (§4.3 未解析 WSDL 类型必须显式标记)。`schema_available=False`。
- 记录面(§4.6 映射):soap 端点经 `to_legacy_records()` 产 `api_doc_endpoint "{POST} {url}"`
  + `urlfinder_url {url}`(SOAP location 为可请求 URL,无模板抑制);同 location 多
  operation 的 legacy 面按 fnv 去重合一,统一层富资产面按 `soap_action`/`input_signature`
  保留为并列端点(超集语义)。`type_hint` 分类新增 `wsdl` 关键词(`.wsdl`/`?wsdl`)。
- 默认开启(`WSDL_PARSE_ENABLE=True`),但仅在 `API_UNIFIED_ENABLE=True` 时经统一链生效;
  关闭时 `skipped(wsdl_disabled)` 回 legacy(legacy 无 WSDL 面,等价零产出)。

### 4.12 第 4-6 批 Review 整改轮 1(2026-09-06 登记,P0-01 + P1-10)

针对 `docs/review/[Review已完成][整改已完成]计划6第4-6批API统一解析Review-20260905.md`
的两个安全/范围阻断项,与第 7 批 WSDL 合并整改(详见该 Review §9 轮 1)。

- **P0-01 越界 host 证据化(取代 §4.8/§4.10/§4.11 的 `domain` 候选口径)**:四解析器
  (openapi/postman/graphql/wsdl)对越界 host 不再产 `record_type=domain`,改产
  `out_of_scope_domain`(模块常量 `api_unified_parser.OUT_OF_SCOPE_DOMAIN_RECORD_TYPE`)。
  桥接层 `ApiDocumentQueue._bridge_candidate` 为统一安全出口:`out_of_scope_domain`
  (及防御性 `domain`)经 `_bridge_out_of_scope_domain` 复用 `extract_host`+`is_valid_domain`
  /`get_fld`+scanner `allowed_hosts/allowed_flds` 二次核验,**只计指标、绝不落 in-scope
  domain 记录**;`wsdl_xsd_import` 与未接线类型(`graphql_schema_summary`)各自计数,不静默
  丢弃。**契约变更**:统一路径对同-Fld 越界 host 也不再产 domain 资产(legacy 会产),
  `unified_target_expectations.json` 的"legacy 超集"口径据此修订为"越界 domain 证据化
  是唯一允许缺失面"(`test_output_floor_and_format_vs_legacy` 锁定唯一差异
  `{("domain","blue.example.com")}`)。
- **P1-10 URL/source 脱敏边界(扩展 §4.4 脱敏策略)**:models 新增 `sanitize_url_secrets`
  (敏感 query 值→`<redacted>`,不删 URL,干净 URL 逐字节 no-op、幂等)与 `sanitize_source_text`
  (赋值形态 + query 键互补);`ApiDocumentCandidate`/`UnifiedApiEndpoint` 的 `__post_init__`
  (url/source/parent_url/parent_document/base_url/sources)与 `add_source` 入口统一清洗,
  url 在 `endpoint_id` 派生前清洗(密钥不进任何键面);`find_sensitive_keys` 守卫扩展检出
  url/source/sources/parent_url/base_url/parent_document 的敏感 query,残留令
  `ParseResult.to_dict()` 抛错;registry merge 入口 `existing.parent_url=` 改经
  `sanitize_source_text`。**merge 语义变化**:`add_source` 现脱敏,仅密钥不同的同形 source
  (`?token=A` 与 `?token=B`)清洗后折叠为同一证据,`merged_source_count` 计数口径随之变化。
  (本条为轮 1 历史记录,不改写;其 URL/source 观测字段清洗与守卫语义已于 2026-09-06
  被 §4.16 三层数据契约改判撤销,merge 折叠口径同步恢复原文去重。)
- **新增指标(纳入 §4.5 观测面,待看板登记)**:`api_document_out_of_scope_domain_total`
  (越界 host 证据计数)、`api_document_wsdl_xsd_import_total`(XSD 引用登记不获取)、
  `api_document_unbridged_candidate_total`(未接线候选类型计数,P0-04 接线后应归零,
  可作观测锚)。
- 仍待后续轮次:P0-02(Postman 敏感变量替换进 URL)、P0-03(GraphQL Schema 深度预算接线)、
  P0-04(Schema 摘要队列存储面)、P0-05(JS/页面/浏览器事件接入 + G5 验收口径)、P1-06~P1-12、
  P2-13~P2-15。(本节为轮 1 历史登记,保留原问题不改写;其中 P0-04/P0-05/P1-12 的轮 2
  决策见 §4.13。)

### 4.13 第 4-6 批 Review 整改轮 2 决策(2026-09-06 用户决策,登记;P0-04/P0-05 口径已实施,实施面见 §4.14/§4.15)

针对 `docs/review/[Review已完成][整改已完成]计划6第4-6批API统一解析Review-20260905.md`
整改轮 2 的阻断决策,用户于 2026-09-06 拍板,本节登记为后续 T1-T8 代码实施的冻结依据。
§4.12 保留轮 1 原问题,不改写为已修复。轮 2 实施(同日)落地 P0-02/P0-03/P0-04 +
P1-06~P1-09/P1-11 + P2-13,并附带链分发前置修复;P0-05 事件接入与 P1-12 幂等键改形
仍待 T8(第 8 批),本节相应措辞按实施状态修正。

- **P0-05(采纳选项二)**:第 6 批只交付 GraphQL 文档解析器,JS、页面、浏览器事件接入
  顺延第 8 批;第 6 批状态表述改为"GraphQL 文档 Parser 完成,运行时事件接入未完成";
  全文"G5 闭环"类表述删除/修正(计划 6 第 6 批节标题与正文、当前状态索引第 6 批行、
  当前判定段,以及本清单 §五 G5 行、§七第 6 批完成判据)。第 8 批新增独立门禁(同步登记
  §七):JS、页面、浏览器三来源进入同一 Endpoint Registry 并按 sources 合并,不重复建
  资产;浏览器 query 值、变量值、敏感 header 不得外流。
- **P1-12(采纳)**:Endpoint 幂等键纳入 api_type,冻结为
  `task_id + canonical_url + method + api_type + input_signature`。`input_signature`
  必须已含协议内部 operation identity:GraphQL = operation type + operation name +
  query hash;SOAP = operation/soapAction;REST = 请求参数或 operation_id 摘要;无需再
  单独拼接 operation_id,由测试证明其稳定进入 `input_signature`。Registry 尚未切生产
  (`API_UNIFIED_ENABLE` 默认 False),本次改 key 无需历史数据迁移。同步面:计划 6 §4.3、
  §9.2 与本清单 §4.2。**已实施(第 8 批 T8-1,2026-09-06;实施面见 §4.15)**。
- **P0-04 GraphQL Schema 存储面(采纳"当前批不落 Mongo、Registry 延后第 8 批",并将
  "metrics 承载摘要"表述修正为双通道)**:
  - `context.metrics` 只放整数计数:`graphql_schema_success_total`、
    `graphql_schema_degraded_total`、`graphql_schema_failed_total`、
    `graphql_schema_skipped_total`、`graphql_request_total`;
  - context 内临时诊断摘要承载:`schema_hash`、`kind`、`types/enums/inputs/scalars`、
    `type_count/field_count`、`truncated`、`status`、`error_type`;摘要必须有明确字节
    上限(不得只依赖类型数/字段数上限);
  - 约束:不保存 Schema 原文、变量值、Token、Header;Schema 结构错误必须 failed、预算
    截断必须 degraded,不得标完整成功;`graphql_schema_summary` 经队列后进入 context
    诊断摘要,`api_document_unbridged_candidate_total` 对该类型归零;摘要丢失可重新解析,
    不作为持久化事实源;
  - 规范措辞:"Schema 摘要进入当前任务 context 的有界诊断面;stage metrics 仅记录状态与
    计数;第 8 批再决定是否纳入 Endpoint Registry 资产面。"**已实施(整改轮 2,消费面形态见 §4.14;
    诊断面挂载点为 `context.api_candidate_registry.schema_diagnostics`,属"当前任务 context 的
    有界诊断面"的具体承载)**。
- **范围修正**:`wsdl_operation_total` 移出 GraphQL 整改票(T3 只负责 GraphQL metrics),
  登记为"第 8 批或独立 WSDL 可观测性票"事项。

### 4.14 第 4-6 批 Review 整改轮 2 实施面(2026-09-06 登记,已实施)

实施 P0-02/P0-03/P0-04 + P1-06~P1-09/P1-11 + P2-13 后的新增冻结面。

- **P0-02 敏感变量 URL 替换禁令**(parser):`UnifiedPostmanParser._substitute` 命中
  `is_sensitive_key` 键名时永不解析真实值,保留 `{{key}}` 模板并标 unresolved,复用
  "不可解析变量→置信度 30、`url_has_template` 抑制 urlfinder"既有链路。敏感键名是唯一
  安全依据;`sanitize_url_secrets` 只兜 query 键位,path/host 位原值由本禁令在源头拦截。
- **P0-03 depth 定义与状态收口**(parser):`graphql_schema_max_depth` 冻结为**类型引用
  包装链展开深度**——SDL 字段/参数类型的 `[` 与 `!` 层数之和(`[[Int!]!]`=4)、
  introspection `ofType` 链上 NON_NULL/LIST 节点数(`_MAX_OF_TYPE_CHAIN`=1000 守卫伪造环)。
  预算命中(bytes/type/field/argument/depth)→`degraded + 首个命中预算名`,结构性错误→
  `failed`,**预算命中永不产出 ok**;配置经 `_parse_options` 注入,缺省走代码常量 20。
- **P1-06/P1-07 operation tokenizer**(parser):`_mask_literals` 将 `#` 行注释、`"..."`
  行字符串、`"""..."""` 块字符串(含 `\` 转义)替换为等长空白;operation header 只在
  掩码文本花括号深度 0 识别;匿名 operation 仅当首个非空白字符为 `{`。诊断语义:截断
  致因的未闭合 degraded(`query_truncated`/`unclosed_operation`),非截断且无任何完整
  operation→`failed(malformed_query)`;超 50 operation→`degraded(operation_limit_exceeded)`,
  禁止静默切片。匿名 operation 变量兜底 = 掩码文本 `$name` 引用 ∪ 请求体 variables 键名
  (仅名称,值无落点)。`hash_source` 取规范化前完整 operation 原文切片。
- **P0-04 Schema 摘要双通道消费面**(registry):生产侧契约键
  `{record_type,kind,status,error_type,schema_hash,types,enums,inputs,scalars,
  type_count,field_count,truncated,summary_bytes}`;`schema_hash` = sha256(canonical json
  of types/enums/inputs/scalars)[:16](sort_keys、紧凑分隔符、名单保发现序,确定性);
  `summary_bytes` = 契约 canonical json(不含自身键)UTF-8 字节数。消费侧白名单投影
  (契约外键一律不进诊断面,违规候选不回显任何字段值,只留 `error_type=
  schema_contract_violation` 归因);诊断面驻留 `SCHEMA_DIAGNOSTICS_MAX_ENTRIES`=16 条、
  满则丢最旧;单条超 `GRAPHQL_SCHEMA_SUMMARY_MAX_BYTES`(代码常量默认 8192,新增配置键,
  未写入 Config、读取口径同 §三)裁剪为安全头部 + `summary_dropped=true` + `truncated=true`。
  指标键新增:`graphql_schema_success/degraded/failed/skipped_total`、`graphql_request_total`
  (端点桥接逐条计数)、`api_document_schema_diagnostics_total`、
  `api_document_schema_diagnostics_dropped_total`;`graphql_schema_skipped_total` 为
  best-effort 弱证据(type_hint 关键词),真值语义待 T8 运行时事件接入补强。
  `api_document_unbridged_candidate_total` 对 `graphql_schema_summary` 归零(观测锚)。
- **链分发前置修复**(parser,轮 2 真实队列端到端测试暴露):openapi 对无
  openapi/swagger 痕迹文本的 YAML 载入失败、以及载入结果非 dict(YAML scalar/JSON 数组),
  由 `failed` 改 `skipped(not_openapi_document)`;postman(JSON-only)载入失败一律
  `skipped(not_postman_document)`。理由:解析器链"非本格式一律 skip"契约下,任意文本
  (GraphQL SDL 等)不得在链首被截断为 failed。`RecursionError`、`document_too_large`、
  带痕迹断裂文档(invalid_json→`load_error`)维持显式 failed(G4 与成本边界不受痕迹门控)。
- **P1-08 统一失败收口**(registry):凡被消费(fetch_count+1)的文档终态必落
  `parse_success_count` 或 `parse_failed_count` 之一;空响应(`error_type=empty_response`)
  与 fetch 异常、Parser 显式 failed 同计 `api_document_parse_failed_total`。三条失败路径
  error_type 词表保持区分。
- **P1-09 fallback 开关单一语义**(registry):`API_UNIFIED_FALLBACK_ENABLE` 同时覆盖
  stage 级整体异常与单文档统一 Parser 崩溃:True 两处都回退 legacy 并计
  `api_unified_fallback_total`;False 两处都不回退(stage 异常上抛;Parser 崩溃文档标
  failed、入统一收口、不产生 fallback 事件)。非崩溃单文档失败与回退开关无关。
- **P2-13 测试 bootstrap**(test):`test/_api_unified_bootstrap.py` 提供临时桩加载
  (桩包必须带 `__path__`;finally 还原 `app`/`app.services` 槽位;子模块缓存条目保留供
  运行期懒导入命中);`assert_no_shell_pollution` 回归空壳残留。四件 api 统一测试各自
  独立进程可运行,禁止依赖其它测试提前修改 `sys.modules`。

### 4.15 第 8 批消费方接入实施面(2026-09-06 登记,已实施;T8-1~T8-6)

- **P1-12 现形态**:`UnifiedApiEndpoint.idempotency_key` =
  `api_endpoint|url|method|api_type|input_signature`(`task_id` 由 Registry
  `scoped_idempotency_key` 前缀拼接);operation identity 进入 `input_signature`
  由 parser 测试与 `EndpointConsumerSurfaceTest.test_p1_12_api_type_assets_not_swallowed`
  证成。§4.2 表中形态为 T8-1 前历史形态。
- **Endpoint 状态机**:`_ENDPOINT_TRANSITIONS`(discovered→queued/pending/skipped,
  queued→probed/failed/skipped/pending,probed→covered/degraded/failed,终态不再迁移);
  `claim_endpoints_for_probe` 按 confidence 降序领取(低置信度显影 pending,不丢弃),
  `probe_report` 词表映射(probed/observed/error/skipped→资产终态,probed 链式收口
  covered);`mark_endpoint_observed` 非终态观察收口(discovered/queued/pending→
  covered),供浏览器/首轮运行期证据收口,终态不被回写。
- **Registry→候选图回流**:`register_endpoint` 新建时发布
  `EndpointCandidateDiscovered`(candidate=url, candidate_type=endpoint,
  `request_profile=api_endpoint_probe`,metadata 含 api_type/method)——与 wih
  来源(request_profile=default)图条目分离,不互相吞并;发布失败不阻断资产登记。
- **§7.3 消费协议**:统一管线挂载 `context.api_candidate_registry` 后,
  WIH endpoint 补探只消费 Registry(`_registry_endpoint_followup`:GET/HEAD 探测、
  POST/SOAP/GraphQL 标 skipped 不发无 body 请求、首轮已观察 (url,method) 回报
  observed、首轮结果双写 covered rest 资产);未挂载/异常回退
  `_legacy_endpoint_followup`(原候选图扫描逐字保留=显式 fallback)。URL Probe
  在 Registry 挂载时排除 Endpoint 资产 URL(同 URL 不在 html_get/page_fetch
  双桶各打一次)。`asset_wih_monitor` flag-on 走 `run_api_document_pipeline`
  且 js_intel 先于文档阶段(与 orchestrator 同序),flag-off 原顺序逐字不变。
- **P0-05 浏览器事件面**:GraphQL 请求在 `handle_response` 就地经
  `UnifiedGraphqlParser` 拆解(解析器 allowed_hosts 以请求 URL 自身 host 为界,
  任务范围过滤在摄取面按 `context.allowed_hosts`),端点对象走事件
  `_graphql_endpoints` 内存通道(不参与 JSON 序列化与去重键;本结果集因此不得
  整体入库),诊断字段 `graphql_diagnostics` 只含 status/error_type/operation_count;
  `ingest_browser_runtime_events` 逐条 register+observed 收口,越界 host 只计
  `api_endpoint_browser_out_of_scope_total`。三来源(js/page 经文档队列、browser
  经摄取面)同 operation 命中同一 `scoped_idempotency_key`,sources 合并
  (`register_endpoint` 合并面含入参完整 sources 集),不重复建资产。
  `browser_intel_scan._open_playwright` 为测试注入钩子(原 `@patch(sync_playwright)`
  目标属性不存在的脆弱点一并修复)。
- **文档候选分类扩展**:统一面 `_TYPE_HINT_KEYWORDS` 增 graphql/graphiql;
  `_collect_backflow` 通道 2 接受 urlfinder_url/page_link 记录按 URL 形态命中文档
  关键词升级为候选(证据优先级)。js `_is_api_doc_candidate`、
  `ApiDocScanner._DOC_KEYWORDS/_DOC_PATHS` 与 Rust 原生
  (`lib.rs is_api_doc_candidate`)维持不含 graphql 的历史口径——flag-off
  请求面零变化;Rust 对齐归第 10 批。
- **新指标**:`wsdl_operation_total`(桥接面逐 soap operation,§4.13 范围修正
  落地)、`api_endpoint_browser_ingested_total`、`api_endpoint_browser_out_of_scope_total`、
  `api_probe_total/api_probe_skipped_total/api_probe_failed_total`、
  `api_endpoint_by_type.<t>`、`api_endpoint_by_method.<m>`、
  `api_endpoint_sources_merged_total`。

### 4.16 三层数据契约(2026-09-06 用户裁定,紧急修复轮 T0 冻结;改判 §4.4/§4.12/§4.15 的 URL 脱敏语义)

依据 `docs/plan/[进行中]紧急修复-统一发现系统数据与状态边界收口.md` §二。历史小节(§4.4
脱敏策略、§4.12 P1-10、§4.15 相关行)保留原文不重写,其 **URL 观测字段语义以本节为准**;
内容面守卫(参数取值、schema 示例、自由文本赋值形态)不受本改判影响。

- **公开观测面**:`observed_url`、URL path/query(含 `token=` 类参数值)、页面来源、
  `source`/`sources`/`parent_url`/`parent_target`/`parent_document` 一律原样保存。
  `token=abc123` 是业务参数还是凭据不由资产层判定,不得偷偷修改用户看到的资产;
  可选的 query 参数 classification 标记(`unknown|business|credential_like`)为展示/
  请求策略辅助,登记为后续增强,不构成对观测值的改写。
- **规范资产面**:`url` 字段语义收窄为**非破坏性规范化 URL**(scheme/host 小写、默认
  端口折叠等,`discovery_context.normalize_url` 现口径,不删除/不替换 query 值),用于
  比较、排序、去重;`endpoint_key`(`scoped_idempotency_key`,§4.2/§4.15)与
  `input_signature` 独立推导。合并资产关系时只并 `sources`/证据,不得覆盖或丢弃
  原始观测值(快照必须同时可见 observed 与 normalized)。
- **请求上下文层**:Cookie/Authorization/浏览器登录态/Postman 私有变量/重放配置不进入
  普通 Endpoint Registry;是否保存与是否用于主动验证由独立的权限、生命周期、审计规则
  决定,**不通过篡改资产 URL 实现凭据保护**。P0-02 的 Postman 敏感变量模板禁令
  (§4.14)不在此改判范围:变量展开是把凭据存储的值"生成"进 URL,不是公开观测值。
- **`sanitize_url_secrets`/`sanitize_source_text` 用途收窄**:仅可用于明确标记为私有
  凭据的字段(请求上下文层),对观测/资产/证据面的 URL 与来源字段不得调用;
  `find_sensitive_keys` 守卫的字段范围=内容面(`.value/.raw/.content` 与
  `{name:敏感名, value:非空}` 参数形态),URL 观测字段不属于守卫对象。
- **生产方规则**(§2.3 冻结):URLFinder/公开页面/公开 JS/公开 API 文档发现的 URL
  原样进入观测面;GraphQL operation 身份与请求 URL 进 Registry,完整 query 是否保存
  按观测/认证分层另行处理;`parent_target` 是来源关系字段,不列为脱敏问题
  (第 8 批独立复审 P1-05 撤销)。
- **legacy 兼容口径**:旧记录面 content/source 本就承载未脱敏的规范化 URL(legacy 无
  sanitize),统一层观测面改造后与 legacy 口径一致而非收紧,`current_parser_baseline`
  与 `--check` 不受影响;`to_legacy_records` 继续输出 normalized `url`。

### 4.17 第 9 批阶段调度与 WAF 隔离实施面(2026-09-06 登记,已实施;提交 `d8ce750a`)

- **流量类别扩展**:`TRAFFIC_CLASSES = normal/crawler/wih/directory/browser/
  **api_doc**(并发 6)/**endpoint_probe**(并发 8)`;§8.1 请求 profile→类别映射
  冻结:`api_doc`/`graphql_schema_optional`→api_doc,`api_endpoint_probe`/
  `soap_endpoint_observe`→endpoint_probe,`browser`→browser(Playwright 自有
  网络栈=外部边界,单列 `external_network_browser_intel`,不经调度器)。
  `traffic_class_for_module` 判定顺序:directory/crawler/browser 词根→
  `endpoint`→endpoint_probe→`api_doc`→api_doc→泛 wih 词根→wih→normal;
  `wih_endpoint_probe`/`api_doc_scan` 不再归 wih 类。
- **互不连坐契约(§8.2)**:类别熔断只暂停对应流量类别(`WafPolicy` 本就按
  (host,class) 隔离,本批接入新类别);`WafPolicy.is_host_blocked` 为查询接口,
  类别信号不得升级为主机级。熔断归因词表:文档=`failed/waf_blocked` +
  `api_document_waf_blocked_total`;探测 legacy 面 `verification_status=skipped`
  (词汇不变,UI/入库兼容)+ item 携带 `degraded_reason=host_waf_blocked` 时
  Registry 资产经 `queued→degraded` 合法边收口 `degraded`(终态,本任务内不再探)。
- **fetch_text `block_signal` 出参**:调用方传 dict 时 blocked 路径写
  `waf_blocked=True`;默认 None 既有调用零变化;空串返回不再把"被熔断"与
  "抓到空"混同(§8.2"解析失败不能伪装无 API"的 WAF 维度延伸)。
- **阶段计时指标(§十二)**:`api_stage_wall_time`/`api_stage_cpu_time`/
  `api_stage_network_wait_time`(毫秒 int,queue run 收口 flush,record_metric
  加法跨多次 run 累计;network_wait 只计真实 fetch 挂钟,不含解析/排队);
  `api_probe_pending_total`(低置信度 pending 队列)、`api_probe_waf_blocked_total`、
  `api_probe_host_waf_blocked_total`。
- **配置键增补(§三 14 键之外)**:`API_ENDPOINT_CLAIM_LEASE_SEC`(默认 900s,
  R6 claim lease 回收;`config_lease_sec` 读取口径同 §三);Endpoint 状态机
  `queued→degraded` 新合法边(R6 前枚举 frozen 于 §4.1,本条为增量修订)。

### 4.18 第 10 批 Rust 纯数据层实施面(2026-09-06 登记,已实施)

- **文档关键词三面同口径**:`lib.rs::is_api_doc_candidate` 与
  `js_intel_scan._is_api_doc_candidate` 关键词集合 = `_TYPE_HINT_KEYWORDS`
  keywords 全集 `{postman, openapi, swagger, api-docs, wsdl, graphql,
  graphiql}`(源码钉 `test_rust_accel.TestApiDocKeywordAlignment` 断言三面
  集合相等)。变化面 = `api_doc_url` 记录发射(JS/页面发现的 graphql/wsdl
  形态 URL 双记录 api_doc_url+urlfinder_url);**不变面** =
  `ApiDocScanner._DOC_KEYWORDS`(四 token,legacy 文档扫描请求面)与 js 静态
  关键字表(第 8 批 P0-05 决策维持)。`urlfinder_url` 等既有 record_type 的
  WihRecord 字段结构与 source 聚合语义不变(§一/§二口径)。
- **Rust unified 批量函数语义契约**:native 四函数仅在 Python adapter
  安全子集内被生产消费(`unified_normalize_urls` 输入 = 小写 http(s)+纯 ASCII
  netloc、无方括号、无 \t\r\n、无 C0 控制字符;hint/method = 纯可打印
  ASCII;IPv6/非 ASCII/大写 scheme/控制字符恒走 Python 基线)——跨 CPython
  版本 urlsplit 边缘行为(控制字符剥离、WHATWG lstrip、bracketed IPv6 校验、
  Unicode case mapping)不在 Rust 复刻范围,子集外 native 直调属测试面。
  输出逐字节等于 `discovery_context.normalize_url` /
  `api_candidate_registry.document_type_hint` /
  `api_unified_models.canonical_method` / `merge_endpoint_records`,golden
  事实源 `test/data/api_unified_rust_corpus.json`(`--run-native
  --strict-order` 编译钉,python:3.10.20=生产版本实测)。
- **配置键(§三 14 键之外的性能层键,getattr 软读)**:
  `RUST_ACCEL_API_UNIFIED_MODE`(off|shadow|rust,默认 shadow;非法值收敛
  shadow)。shadow=双跑、输出恒为 Python 基线、mismatch 显影;rust 模式
  启用前置条件:shadow 观察 mismatch 恒 0 + corpus 编译钉过 + 本函数 CPU
  闸达标(normalize/method 达标,hint/dedupe 按 2026-09-06 aarch64 基准
  **不达标不得升级**)。
- **观测指标(§十二增补)**:`api_unified_hint_batch_total`/
  `api_unified_hint_input_total`(queue 收口 flush)、
  `api_unified_hint_mismatch_total`/`api_unified_hint_fallback_total`
  (逐批事件计数);进程内 `rust_accel.get_stats()` 新增
  `unified_{normalize,hint,method,dedupe}_calls/_fallbacks` 与
  `unified_shadow_mismatches`。
- **比较器契约扩展(corpus kind)**:`unified_normalize/unified_hint/
  unified_method`(逐元素,重复输出值合法)、`unified_dedupe`(聚合分组);
  既有 extract/html/js_endpoint/rank kind 的去重语义门禁不变。

## 五、现状缺口清单(目标期望与基线的差异面,即第 4-7 批验收项)

golden 基线(`current_parser_baseline.json`,record 数:openapi3 json/yaml 各 9、swagger2 8、postman 9)
相对 `expected/unified_target_expectations.json` 的下述缺口为**已知、预期由统一层补齐**:

| 编号 | 缺口 | 证据 |
|---|---|---|
| G1 | `{petId}` 花括号模板端点被丢弃(`/pets/{petId}` GET+DELETE 不在基线) | openapi3 基线 4 endpoint vs 目标 6 |
| G2 | Postman `{{baseUrl}}` 模板整体跳过、`:id` 冒号变量端点被丢弃 | postman 基线无 ListUsers/GetUserById |
| G3 | 参数、requestBody、响应 Schema、securitySchemes、$ref 全不解析 | 基线无任何 parameter 痕迹 |
| G4 | 非法/异常文档静默零记录,无 failed/degraded 语义(解析失败伪装成"无 API") | invalid_json 无记录、无 diagnostics |
| G5 | GraphQL 无统一记录形态(浏览器仅 body_kind、URLFinder 仅关键字)——**第 6 批 GraphQL 文档 Parser 完成,运行时事件接入未完成**(2026-09-06 用户决策 P0-05 选项二,顺延第 8 批),见 §4.10/§4.13 | 第二节 `graphql` 行 |
| G6 | WSDL/SOAP 完全不支持——**第 7 批闭环**,见 §4.11 | 基线无 soap 记录 |
| G7 | 越界 server 只产 `domain` 候选、范围内多 server 全展开(行为本身保留,但无父子文档/置信度追溯) | openapi3 `blue.example.com` |
| G8 | 文档来源(source)不参与去重,多来源证据丢失 | 第一节 fnv_hash 语义 |

## 六、golden corpus 清单与再生方式

目录 `ARL/test/fixtures/api_unified/`(全 example.com 保留域,无真实目标):

| 文件 | 用途 |
|---|---|
| `openapi3_petstore.json` / `.yaml` | OpenAPI 3 JSON/YAML 等价镜像;servers×2、参数四位置、循环引用(Pet↔Owner)、未解析引用(Missing) |
| `swagger2_petstore.json` | host/basePath/schemes 组合与 formData/basic auth |
| `postman_collection.json` | 多层 item、变量、raw/urlencoded/formdata、含泄露样本 `POSTMANLEAKTOKEN123/POSTMANLEAKPASS456` |
| `graphql_request.json` | query/mutation/subscription 三操作、变量含泄露样本 `GRAPHQLLEAKPASS789` |
| `graphql_schema.sdl` | SDL:type/enum/input/scalar/argument |
| `wsdl_service.wsdl` + `types.xsd` | service/port/binding/portType/operation×2/soapAction、同源 import |
| `wsdl_xxe.xml` | 外部实体+参数实体声明,必须解析失败且无网络探测(端口 9 不可达即探针) |
| `external_ref_openapi.json` | 远程 `$ref`,默认不获取、标 unresolved |
| `invalid_json.json` / `deep_nesting.json` | 非法 JSON、400 层嵌套 |
| `expected/current_parser_baseline.json` | 现行 ApiDocScanner 基线(脚本生成,禁手改) |
| `expected/unified_target_expectations.json` | 统一层目标结果语义 + 泄露禁流列表 |

再生:`python3 scripts/api-unified-golden.py`(写基线);`--check`(漂移检测,corpus/解析器变更后必须重跑)。
泄露约束:三个 `*LEAK*` 字面量与 `xxe-probe/pe-probe` 禁止出现在任何基线、模型序列化与(后续)Parser 输出中,
由 `test_api_unified_models.py` 与生成脚本双向检查。

## 七、验收挂点

- 第 1 批完成判据:本文件 + `api_unified_models.py` + corpus + `test/test_api_unified_models.py` 29 项全绿(2026-09-05 本地通过)。
- 第 2 批完成判据:`api_unified_shadow.py` + `peek_response` + 两接线点 + `test/test_api_unified_shadow.py` 8 项,
  含"同一文档跨 Scanner 实例只发一次网络请求、记录集合与单次运行一致"的输出不变性验证;
  全量本地套件下 `test_api_unified*` 零失败(collection-error 集合与改动前基线一致)。
- 第 3 批完成判据:`api_candidate_registry.py` + `fetch_text` profile/镜像改造 +
  `wih_orchestrator` 接线 + `test/test_api_candidate_registry.py` 19 项,含 flag 开关
  输出 parity 与 `cross_bucket_hit` 转正锚(2026-09-05 本地通过;golden `--check` 无漂移)。
- 第 2 批起不得修改本清单第一、二节冻结面(旧记录兼容);§4 契约扩展须同批更新本文件并过 corpus 回归。
- 第 4-7 批 Parser 验收下限 = `current_parser_baseline.json` 记录集合;目标上限 = `unified_target_expectations.json`。
- 第 4 批完成判据:`api_unified_parser.py` + 队列三级分发 + §4.8 契约登记 +
  `test/test_api_unified_parser.py` 22 项 + registry parity 口径改超集(2026-09-05
  本地全组 122 项通过;golden `--check` 无漂移)。G1/G3/G4/G7 就此闭环。
- 第 5 批完成判据:`UnifiedPostmanParser` + §4.9 契约登记 +
  `test/test_api_unified_parser.py` Postman 面 8 项(2026-09-05 api 四件 87 项、
  全组 130 项通过;golden 无漂移)。G2 闭环。
- 第 6 批完成判据:`UnifiedGraphqlParser` + §4.10 契约登记 +
  `test/test_api_unified_parser.py` GraphQL 面 9 项(2026-09-05 全组 139 项通过;
  golden 无漂移)。G5 文档 Parser 面就此闭环,运行时事件接入未完成、顺延第 8 批
  (2026-09-06 用户决策 P0-05 选项二,见 §4.13);G6 由第 7 批接管,G8 已由第 3 批注册表聚合替代
  (旧记录面不改)。
- 第 7 批完成判据:`UnifiedWsdlParser` + openapi XML skip 链前置修复 + 队列链
  openapi→postman→graphql→wsdl + §4.11 契约登记 + `test/test_api_unified_parser.py`
  WSDL 面 14 项(2 soap 端点/soapAction/service/port、part 摘要、同源 XSD 登记不获取、
  越界 domain 候选、disabled/size skip、XXE dtd_forbidden 零端点零泄露、xsd 非 wsdl skip、
  openapi 对 XML skip、队列分发 wsdl 桥接 soap 记录与 XXE failed;2026-09-05 api 四件
  110 项通过;golden `--check` 无漂移)。G6 闭环。`unified_target_expectations.json`
  的 wsdl_service/wsdl_xxe 面全部满足;`WSDL_PARSE_ENABLE` 默认 True 但仅
  `API_UNIFIED_ENABLE=True` 时经统一链生效,生产默认行为未切换。
- 第 8 批独立门禁(2026-09-06 用户决策,P0-05 选项二,见 §4.13):JS、页面、浏览器三来源
  进入同一 Endpoint Registry 并按 sources 合并,不重复建资产;浏览器 query 值、变量值、
  敏感 header 不得外流。第 6 批只交付文档 Parser 面,本门禁不向前追溯判定第 6 批。
  **已实施(第 8 批 T8-1~T8-6,门禁证据见下方完成判据)。**
- 整改轮 2 完成判据(2026-09-06,§4.14):P0-02 敏感变量替换禁令 + P0-03 预算/深度收口 +
  P0-04 摘要双通道(含 `QueueGraphqlSchemaChainTest` 真实队列端到端:SDL/introspection
  成功落诊断面与计数、failed 文档不标 parsed/covered)+ P1-06/P1-07 tokenizer +
  P1-08 失败收口 + P1-09 开关单一语义 + P1-11 GraphQL metrics + P2-13 bootstrap +
  openapi/postman 链分发前置修复。可复现证据:四件独立进程
  `PYTHONPATH=. python3 -m unittest test.test_api_unified_{parser,candidate_registry,models,shadow}`
  = 86/39/38/8;api 四件合跑 171 项全绿;六件邻接合跑(+finalizer/discovery_context)
  212 项全绿;golden `--check` exit 0。P1-11 的 `wsdl_operation_total` 按 §4.13 范围修正
  移出本判据(归第 8 批或独立 WSDL 可观测性票);P2-15 分文件重构不属本判据。
  `API_UNIFIED_ENABLE` 切换默认的前置门禁余 P0-05 三来源合并(第 8 批)与 P1-12(T8)。
- 第 8 批完成判据(2026-09-06,§4.15):P1-12 键改形 + Registry Endpoint 状态机/
  领取/回报/观察收口 + 候选图回流;`asset_wih_monitor` 统一层切换;
  `_registry_endpoint_followup`/`_legacy_endpoint_followup` 双通道;浏览器
  operation 级拆解与 `ingest_browser_runtime_events`(P0-05 三来源合一 +
  零泄露门禁);urlfinder_url/page_link 文档形态回流;URL Probe 统一候选排除;
  `wsdl_operation_total` 落地。可复现证据:九件独立进程 parser 86/registry 51/
  models 39/shadow 8/browser 5/orchestrator 10/finalizer 26/url_probe 8 全绿,
  九件合跑(含 discovery_context)248 项;golden `--check` exit 0。
  `test_wih_orchestrator`/`test_browser_intel_scan`/`test_urlfinder_url_probe`
  由既有收集错误恢复为可运行(P2-13 口径扩展)。切换默认的代码前置门禁就此全部
  闭环,余为发布流程决策。
- 第 9 批完成判据(2026-09-06,§4.17,提交 `d8ce750a`):api_doc/endpoint_probe
  独立流量类别与并发额度、`traffic_class_for_module` 词根拆分、文档
  `failed/waf_blocked` 归因(与 empty_response 区分、仍入 P1-08 收口)、探测
  主机级 `degraded/host_waf_blocked` 资产收口(legacy 词汇不变)、
  `api_stage_wall/cpu/network_wait_time` 与 pending/外部边界指标。可复现证据:
  九件合跑 **261 项**全绿、独立进程 parser 86/registry 62/models 38/shadow 8/
  browser 5/orchestrator 11/finalizer 26/url_probe 8、golden `--check` exit 0、
  隔离 pycache compileall、`git diff --check` 干净;probe_cache/web_info_intel
  合跑顺序污染经 stash 基线对照确认既有(probe_cache 单跑 skip 属环境依赖)。
