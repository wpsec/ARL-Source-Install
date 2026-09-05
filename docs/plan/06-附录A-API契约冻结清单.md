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

### 4.5 兼容映射(§7.3 的 adapter 语义)

`UnifiedApiEndpoint.to_legacy_records()`:
- `rest`/`soap` → `api_doc_endpoint "{METHOD} {url}"` + `urlfinder_url {url}`,source=`parent_document`(缺失回退 source/url)——与第二节现行格式逐字节一致;
- `graphql` → `graphql "{METHOD} {url}"` 单条。
文档候选回写旧记录时 `api_doc_url content=url, source=url`。

## 五、现状缺口清单(目标期望与基线的差异面,即第 4-7 批验收项)

golden 基线(`current_parser_baseline.json`,record 数:openapi3 json/yaml 各 9、swagger2 8、postman 9)
相对 `expected/unified_target_expectations.json` 的下述缺口为**已知、预期由统一层补齐**:

| 编号 | 缺口 | 证据 |
|---|---|---|
| G1 | `{petId}` 花括号模板端点被丢弃(`/pets/{petId}` GET+DELETE 不在基线) | openapi3 基线 4 endpoint vs 目标 6 |
| G2 | Postman `{{baseUrl}}` 模板整体跳过、`:id` 冒号变量端点被丢弃 | postman 基线无 ListUsers/GetUserById |
| G3 | 参数、requestBody、响应 Schema、securitySchemes、$ref 全不解析 | 基线无任何 parameter 痕迹 |
| G4 | 非法/异常文档静默零记录,无 failed/degraded 语义(解析失败伪装成"无 API") | invalid_json 无记录、无 diagnostics |
| G5 | GraphQL 无统一记录形态(浏览器仅 body_kind、URLFinder 仅关键字) | 第二节 `graphql` 行 |
| G6 | WSDL/SOAP 完全不支持 | 基线无 soap 记录 |
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
- 第 2 批起不得修改本清单第一、二节冻结面(旧记录兼容);§4 契约扩展须同批更新本文件并过 corpus 回归。
- 第 4-7 批 Parser 验收下限 = `current_parser_baseline.json` 记录集合;目标上限 = `unified_target_expectations.json`。
