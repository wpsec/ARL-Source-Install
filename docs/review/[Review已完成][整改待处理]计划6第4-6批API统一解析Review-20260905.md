# 计划 6 第 4–6 批 API 统一解析 Review（2026-09-05）

## 1. Review 信息

- Review 状态：**Request Changes（整改后再验收）**
- 整改状态：进行中（轮 1 已完成 P0-01、P1-10，与第 7 批 WSDL 合并整改提交，见 §9；P0-02~P0-05、P1-06~P1-12、P2 仍待后续轮次，故文件名 `整改待处理` 标签维持）。
- 审查范围：计划 6 第 4 批 OpenAPI/Swagger、第 5 批 Postman、第 6 批 GraphQL 的当前实现、测试、冻结契约和计划文档；代码基线为 `e81f0d36`，进度文档基线为 `02072a9d`。第 7 批 WSDL/SOAP 在本报告形成后实施，继承并同轮修复了 P0-01。
- 重点链路：`ApiDocumentQueue` → Parser chain → `ParseResult` → legacy adapter / Endpoint Registry；同时检查 JS、页面、浏览器事件是否真的进入统一链路。
- 审查方式：只读代码审查、CodeGraph 依赖/调用关系检查、边界探针、定向测试和 golden 校验。
- 工作区说明：审查期间用户已将相关实现提交；本报告按最后一次复核快照形成。Review 只新增本报告，不修改业务代码，不提交、不推送、不读取或输出运行期敏感配置。

## 2. 总体结论

当前实现已经具备可复用的 Parser/Registry 基础：OpenAPI、Postman 和 GraphQL 请求的直接解析器均存在，GraphQL 的 `api_type`、操作类型、operation name、query hash 也已接入模型；Schema 默认关闭的安全默认值正确保留。

但当前不能接受“第 6 批 G5 已闭环”的结论，也不建议打开 `API_UNIFIED_ENABLE`。原因不是单测数量不足，而是关键不变量在真实队列和跨来源链路中没有成立：

1. 统一层把越界 domain candidate 直接桥接到旧记录面，范围边界没有在统一出口重新校验。
2. Postman 可解析变量会被原样替换进 URL；敏感变量一旦被 URL 引用，现有 body/字段脱敏守卫无法阻止泄露。
3. GraphQL Schema 的 `GRAPHQL_SCHEMA_MAX_DEPTH` 没有传入或执行；截断结果仍可能标记为 `ok`，解析失败/不完整状态不能可靠到达队列外部。
4. Schema 摘要只存在于 Parser 的临时 `ParseResult.candidates`，队列桥接只处理 `domain`，因此 Schema 结果和成功/失败证据被丢弃。
5. 计划 6 原定的 JS、页面、浏览器 GraphQL 事件统一没有在本批接入；当前文档把它顺延到第 8 批，但仍将第 6 批标成 G5 完成，存在验收口径漂移。

因此建议将当前状态改为：**第 4–6 批实现部分完成，整改项未完成；第 6 批不放行，先修安全边界、预算状态和队列闭环，再决定是否将浏览器接入作为明确的第 8 批前置。**

## 3. 当前实现状态

| 批次 | 当前判断 | 已有能力 | 不能验收的原因 |
|---|---|---|---|
| 第 4 批 OpenAPI/Swagger | 部分完成 | v2/v3、参数、security、局部 `$ref`、模板 URL、显式诊断 | 越界 domain candidate 进入桥接记录面；统一出口缺少范围/Fld 校验；测试仍有模块顺序依赖 |
| 第 5 批 Postman | 部分完成 | item 递归、变量 URL、`:id`、body 摘要、参数和 auth hint | 敏感变量被引用进 URL 时原值外流；递归/条目预算截断没有进入 diagnostics |
| 第 6 批 GraphQL | 部分完成 | 请求文档、三类 operation、operation name、变量声明名/类型、hash、SDL/introspection 初步摘要 | Schema 深度预算未执行、Schema 结果被队列丢弃、解析边界有误报、JS/页面/浏览器事件未接通 |

## 4. 发现项

### P0-01 [阻断/安全] 越界 domain candidate 未经过统一范围校验

- 位置：`ARL/app/services/api_unified_parser.py:189-264,344-352,947-953`；`ARL/app/services/api_candidate_registry.py:569-599`。
- 现象：OpenAPI 和 GraphQL 对越界 host 产生 `record_type=domain` candidate；队列桥接对 candidate 只判断 `record_type`，直接调用 `_append_record("domain", ...)`。`allowed_flds` 在这些路径中没有实际约束。
- 证据：使用 `allowed_hosts={api.example.com}`、`allowed_flds={example.com}` 的越界 OpenAPI 输入，统一 Parser 仍返回越界 host 的 domain candidate；桥接层没有二次过滤。GraphQL 越界 base 也采用相同语义。
- 影响：不可信文档中的 server/base URL 可以把不在当前目标范围内的 host 写入旧 domain 资产面，后续候选图、站点发现或探测消费方可能将其视为任务资产。`API_UNIFIED_ENABLE` 当前默认关闭只能降低当前生产暴露面，不能替代代码边界。
- 最小修复：保留“越界证据”与“可消费 domain 资产”两个概念。统一出口必须复用现有 host/FQDN/Fld 校验；越界信息如需保留，应使用独立的 `out_of_scope_domain` 证据类型或只进入 diagnostics/metrics，禁止直接进入 in-scope `domain` 记录。
- 必补测试：同 Fld 越界、跨 Fld 越界、非法 host、模板 host、OpenAPI/GraphQL 两条路径分别验证“有证据但不入范围资产”。

### P0-02 [阻断/安全] Postman 敏感变量可被替换进 Endpoint URL

- 位置：`ARL/app/services/api_unified_parser.py:633-644,646-704`。
- 现象：集合变量统一放入 `variables`，`_substitute()` 对 URL 中的每个变量无条件替换；只有未解析变量会保留模板。敏感键没有在 URL substitution 处被拒绝、模板化或摘要化。
- 证据：构造一个 URL 引用敏感变量的最小 Collection，Parser 输出的 Endpoint URL 仍包含变量原值；当前测试只验证 fixture 中未被 URL 引用的敏感变量没有出现在输出，因此没有覆盖真正的泄露路径。
- 影响：原值会进入 `UnifiedApiEndpoint.url`、Endpoint Registry、legacy 记录和后续日志/导出链。`ParseResult.to_dict()` 的敏感键守卫不能识别 URL 字符串中的普通值。
- 最小修复：对变量 substitution 建立显式策略：敏感变量永不解析为真实值，统一保留安全模板或 `<redacted>`；同时对 URL query、source、parent URL 和记录 content 做最终脱敏。不要用“变量名不敏感”作为安全依据。
- 必补测试：敏感变量出现在 path、query、host、raw URL 四种位置时，所有 Parser 输出、legacy 记录、Registry snapshot 和日志摘要均不得包含原值。

### P0-03 [阻断/预算] GraphQL Schema 深度预算未接线，截断仍报告 `ok`

- 位置：`ARL/app/services/api_candidate_registry.py:468-479`；`ARL/app/services/api_unified_models.py:579-595`；`ARL/app/services/api_unified_parser.py:846-849,1051-1129`。
- 现象：`ParseOptions` 有 `graphql_schema_max_depth`，但 `_parse_options()` 没有从配置传入该值，GraphQL Parser 也没有读取它。SDL/introspection 只执行了类型数、部分字段数和字节数限制；触达限制时只写 `summary["truncated"]`，诊断状态仍为 `ok`。
- 证据：同一 SDL 分别使用 depth=1 和 depth=20 解析，结果完全相同；字段超限和 introspection 类型超限都可以返回 `ok` + `truncated=true`。
- 影响：调用方无法区分“Schema 完整”“Schema 被预算截断”“Schema 解析异常”；在计划要求“解析失败显式状态、不伪装无 Schema”的前提下，`covered`/`parsed` 语义不可信，深层输入也缺少有效的成本上界。
- 最小修复：明确 depth 的定义（类型引用展开深度或选择集深度），把配置完整注入 `ParseOptions`，在 tokenizer/摘要遍历中执行；预算命中统一返回 `degraded`，结构异常返回 `failed`，并在 diagnostics 中记录具体预算类型和计数。introspection 同样执行 depth、type、field、argument 上限。
- 必补测试：depth=1/20 差异、类型/字段/参数/operation 上限、未闭合定义、截断后的 `status/error_type` 和队列最终状态。

### P0-04 [阻断/闭环] Schema 摘要在队列桥接处被丢弃

- 位置：`ARL/app/services/api_unified_parser.py:1093-1125`；`ARL/app/services/api_candidate_registry.py:569-599`。
- 现象：SDL/introspection 返回 `record_type=graphql_schema_summary` candidate，但 `_bridge_parse_result()` 只处理 `domain` candidate；`graphql_schema_summary` 不会进入记录面、Registry、stage metrics 或其他可查询结果。
- 证据：开启 Schema 解析后，通过队列输入 SDL，Parser 可生成临时 summary，但队列结果没有 Schema summary，Endpoint Registry 也没有相应 Schema 状态；当前 queue 测试只验证 GraphQL 请求记录，不验证 Schema 队列闭环。
- 影响：即使 Schema 被截断或解析失败，队列仍可能按普通 Parser 成功路径标记文档 `parsed/covered`，外部无法知道 Schema 是否成功。与“解析失败显式状态”和 `graphql_schema_success_total` 验收要求冲突。
- 最小修复：先冻结存储策略：如果坚持“不落 Mongo”，至少要把安全摘要、diagnostics、success/degraded/failed 状态和指标传到当前任务上下文；如果需要被第 8 批消费，则将摘要挂到 Registry 的文档/Endpoint 资产。桥接层不能静默丢弃未知 candidate 类型。
- 必补测试：SDL/introspection 经真实 `ApiDocumentQueue` 运行后的 summary、状态、指标和重投幂等；Schema 失败不能被记为 `covered`。

### P0-05 [阻断/验收口径] JS、页面、浏览器 GraphQL 事件未进入同一 Registry

- 位置：`ARL/app/services/js_intel_scan.py:164-180`；`ARL/app/services/browser_intel_scan.py:149-175,271-314,450-515`；`ARL/app/services/asset_wih_monitor.py:122-130`；`ARL/app/services/wih_orchestrator.py:285-340`。
- 现象：JS 文档候选关键字只覆盖 swagger/openapi/api-docs/postman；浏览器虽能把请求标成 `body_kind="graphql"`，但 `_build_template_object()` 将 query 内容替换为 `<value>`，结果只停留在浏览器返回字典，没有 Parser/Registry adapter。资产监控仍直接调用 legacy `run_api_doc_scan`，没有统一队列接线。
- 影响：计划 6 原始范围要求“JS/页面/浏览器事件统一”和“浏览器发现的 GraphQL 请求进入同一 Endpoint Registry”无法成立；同一 GraphQL 请求可能只留下 body_kind，丢失 operation、name、hash。
- 最小修复：二选一并同步文档：
  - 继续将事件接入作为第 6 批：浏览器只传安全的 query 结构摘要/operation 信息给统一 adapter，JS/URLFinder 发现的 GraphQL URL 进入 `ApiDocumentCandidate`，统一注册 Endpoint；
  - 明确第 6 批只交付 GraphQL 文档 Parser，把浏览器/JS/页面接入从 G5 验收条件中移出，改为第 8 批独立门禁；在第 6 批完成前不得使用“G5 闭环”表述。
- 必补测试：JS URL、page record、browser runtime event 三个来源产生同一 Endpoint 时，Registry 只保留一条资产并合并 sources；浏览器 query、变量值和敏感 header 不得外流。

### P1-06 [重要/正确性] GraphQL operation 提取会产生嵌套字段误报，匿名变量兜底未实现

- 位置：`ARL/app/services/api_unified_parser.py:840-843,957-1029`。
- 现象：`_OP_RE` 全文搜索 `query|mutation|subscription`，没有要求 operation header 位于文档级深度 0；嵌套 selection 中名为 `query` 的字段会被误判为第二个 operation。匿名 `{ ... }` 只生成一个无变量 endpoint，代码注释承诺的 variables 对象键名兜底没有实现。
- 证据：`query { viewer { query { id } } }` 得到 2 个 operation；匿名请求引用变量但 variables 对象只提供名称时，输出变量名集合为空。
- 影响：Endpoint 数量、operation hash 和 Registry 幂等键会被污染；匿名请求的变量资产缺失，和 Parser 自身注释及“variables 名称”语义不一致。
- 最小修复：用轻量 tokenizer 跳过 string/comment，并只在文档级深度 0 识别 operation header；对匿名 query 明确是否从 `$name` 引用和 variables 键名生成名称摘要，不能保留未实现注释。
- 必补测试：嵌套字段名、注释中的关键字、字符串中的花括号、多个 operation、匿名 query、未闭合花括号和超过 operation 上限。

### P1-07 [重要/正确性] 花括号配平不是安全 tokenizer，异常边界会被当作正常结果

- 位置：`ARL/app/services/api_unified_parser.py:1010-1047`。
- 现象：`_match_brace()` 对字符串和注释中的 `{`/`}` 也计数；找不到闭合花括号时仍用剩余文本生成 operation，并未把 diagnostics 标为 degraded/failed。超过 50 个 operation 时直接切片，也没有截断状态。
- 影响：query hash 可能对应错误文本；错误/不完整请求仍可能生成 `ok` endpoint，导致“未发现”与“解析成功但结果不完整”无法区分。
- 最小修复：tokenizer 维护 string、escape、comment 和 brace depth；未闭合、operation 上限、query 上限分别记录 diagnostics，至少为 `degraded`，不可静默截断。

### P1-08 [重要/正确性] 空响应标记失败但不计入失败计数和指标

- 位置：`ARL/app/services/api_candidate_registry.py:655-671`。
- 现象：`fetch_fn()` 返回空文本时，文档被标为 `failed/empty_response`，但没有增加 `parse_failed_count`，也没有记录 `api_document_parse_failed_total`。
- 证据：队列空响应探针得到 `fetch_count=1`、`parse_failed_count=0`。
- 影响：阶段日志中的失败数、文档状态和 metrics 不一致；当前 GraphQL queue 测试对非目标 seed 返回空文本，却断言失败数为 0，掩盖了该问题。
- 最小修复：将空响应纳入统一失败收口，增加 counter/metric，并补充“异常、空响应、Parser failed”三种路径各自的断言。

### P1-09 [重要/配置语义] Parser 崩溃路径没有遵守 `API_UNIFIED_FALLBACK_ENABLE`

- 位置：`ARL/app/services/api_candidate_registry.py:481-536,712-766`。
- 现象：整个队列异常时会检查 `API_UNIFIED_FALLBACK_ENABLE`；但单个 Parser 构造或调用抛异常时，`_parse_one()` 无条件计 fallback 并继续 legacy。
- 影响：配置关闭时，队列级崩溃会抛出，单文档 Parser 崩溃却静默回退，调用方无法按配置选择“严格失败”或“兼容回退”。
- 最小修复：冻结开关作用域：若开关覆盖单文档，按同一配置决定抛出/失败/legacy；若只覆盖 stage 级异常，改名并在契约中明确，不要让同名开关有两套语义。

### P1-10 [重要/安全守卫] 统一模型的最终脱敏没有覆盖 source 和 URL 自由文本

- 位置：`ARL/app/services/api_unified_models.py:140-179,321-355,451-512,635-647`。
- 现象：`find_sensitive_keys()` 主要检查敏感键名和部分 `.value/.raw/.content` 赋值形态；`ApiDocumentCandidate`/`UnifiedApiEndpoint` 的初始 `source`、`sources`、`url` 在构造时可保留原文。URL query 中的 token 或 source detail 不一定命中守卫。
- 影响：即便 parameters 和 body 摘要不保存值，带凭据的发现 URL、来源 URL 或记录 content 仍可能进入 Registry、Mongo、日志和导出。
- 最小修复：把 URL/source 定义为独立的安全边界：解析时去除敏感 query/value，构造和 merge 入口统一清洗；最终守卫加入 URL、source、sources 的敏感 query 检查。测试必须覆盖初始 source 和后续 add_source 两条路径。

### P1-11 [重要/指标缺口] GraphQL 专用 metrics 没有实现

- 位置：计划文档 `docs/plan/[进行中]06-计划6-统一API解析与Endpoint Registry重构.md:578-608`；当前统一 Parser/Queue 仅能看到通用 `api_document_*`、`api_endpoint_*` 指标路径。
- 现象：没有发现 `graphql_request_total`、`graphql_schema_success_total` 和按 GraphQL operation/type 的实际记录点；GraphQL 请求是否来自 JS、浏览器、文档以及 Schema 是否成功无法从 stage metrics 复算。
- 影响：无法证明 G5 请求识别、Schema 预算和跨来源合并的真实运行效果，也无法区分“没有 GraphQL”与“GraphQL 被解析器/队列丢弃”。
- 最小修复：在统一 adapter/Registry 入口按事件来源、operation type、Schema status 记录有界计数；指标不能带 query 正文、变量值或 token。

### P1-12 [重要/Registry 前置决策] Endpoint 幂等键是否区分 `api_type` 需要在第 8 批前冻结

- 位置：`ARL/app/services/api_unified_models.py:470-485`；`ARL/app/services/api_candidate_registry.py:242-253`。
- 现象：当前 endpoint key 使用 URL、method、`input_signature`，不直接包含 `api_type`。当前 GraphQL operation 通常通过 signature 区分，但同 URL/method/signature 的 REST 与 GraphQL 资产仍可能合并。
- 影响：第 8 批消费方接入后，Registry 的去重结果可能与计划中“按 URL/method/api_type/operation 识别资产”的预期不一致。
- 最小修复：在第 8 批前明确 key 的规范。若 `api_type` 和 operation 是资产身份的一部分，纳入 key 并更新冻结清单；若刻意共用 URL 资产，则将协议类型放进独立 observation/variant 字段并补跨类型回归。

### P2-13 [一般/测试卫生] 新 Parser 测试不能独立运行

- 位置：`ARL/test/test_api_unified_parser.py:24-36`。
- 现象：测试只注入 `app` package，没有隔离 `app.services`；单独执行 `PYTHONPATH=. python3 -m unittest -v test.test_api_unified_parser` 会因 `app.services.__init__` 导入缺失的 `xing` 而失败。与模型/其他测试按特定顺序运行时，前置模块注入掩盖了这个问题。
- 影响：测试结果依赖模块加载顺序，无法确认新测试在标准入口和独立进程中都可复现；后续新增 GraphQL 测试容易继续扩大假绿范围。
- 最小修复：用项目标准测试 bootstrap/conftest 隔离依赖，或在测试中使用可恢复的 patch；每个测试文件独立进程可导入、可运行，禁止依赖其他测试提前修改 `sys.modules`。

### P2-14 [一般/文档一致性] 实施状态与测试计数存在冲突

- 位置：`docs/plan/[进行中]06-计划6-统一API解析与Endpoint Registry重构.md:3,731-763`；`docs/completed/[已完成]06-附录A-API契约冻结清单.md:201-216,273-276`；`ARL/test/test_api_unified_parser.py:1-10,308-310`。
- 现象：计划文档一处称第 1–6 批已实施/完成，文末又称第 4 批及后续未完成；第 6 批记录声称九文件 139 项全绿，而本轮可复现的明确命令为 4 个 API 测试模块、96 项通过。新测试文件顶部和旧 skipped test 仍描述 GraphQL 尚未接管。
- 影响：实施状态、验收数量和测试意图无法由文档复现，后续修复可能基于错误基线判断完成度。
- 最小修复：修复完成后只保留一套可执行命令和实际计数；区分“直接 Parser 测试通过”“队列/跨来源集成通过”“标准容器全量通过”，不要用未提供命令的总数宣称完成。

### P2-15 [一般/可维护性] Parser 文件已经同时承担三类格式职责

- 位置：`ARL/app/services/api_unified_parser.py`，当前 1148 行。
- 现象：OpenAPI、Postman、GraphQL 三套格式解析、边界策略和桥接辅助函数集中在一个文件，GraphQL 增量继续修改同一模块。
- 影响：格式识别、预算和脱敏策略容易互相影响；解析器链对 `skipped/failed` 的语义变更需要同时回归多种格式。
- 最小修复：本轮不要求立即拆分；先抽取共享的安全范围校验、diagnostics/预算结果和文本 tokenizer 辅助层。第 7/8 批前评估按 parser 分文件，保持统一接口不变。

## 5. 已确认的正向结果

- `UnifiedGraphqlParser` 已提供请求 JSON 的嵌套/裸形态识别，支持 query、mutation、subscription 三类 operation，并生成 per-operation query hash。
- GraphQL 请求 Endpoint 的 legacy 适配形态为单条 `graphql` 记录，未额外生成 `urlfinder_url`；这是与冻结契约一致的增量方向。
- GraphQL variables 当前只从 operation 声明读取名称和类型，fixture 中的变量值没有进入 Endpoint parameters；Schema/introspection 默认关闭。
- OpenAPI/Swagger 的 `$ref`、参数、security、模板 URL 和显式失败语义已有独立测试；Postman 的 URL/body/参数摘要也有直接测试。
- 未引入第三方 GraphQL 依赖，符合本批零第三方依赖约束；query hash 的空白折叠规则已在模型测试中锁定。
- 本轮 AST 解析通过，`git diff --check` 通过，`python3 scripts/api-unified-golden.py --check` 通过。

这些结果只能证明代码面和部分直接 Parser 行为可运行，不能覆盖上节列出的安全边界和队列闭环。

## 6. 下一轮建议修复顺序

1. 先建立统一安全出口：范围/Fld 校验、越界证据类型、URL/source/query 脱敏；补 OpenAPI、Postman、GraphQL 三种来源测试。
2. 修复 Postman 敏感变量 substitution，先使“敏感变量引用到 URL 永不原样落出”成为硬断言。
3. 冻结 GraphQL Schema contract：`schema_available`、summary 是否只进 context/metrics 还是进入 Registry、Schema hash/error/truncated 的结构和状态。
4. 接线并执行所有 GraphQL 预算：bytes、depth、types、fields、arguments、operations；预算命中不得返回假 `ok`。
5. 替换 GraphQL operation 的正则/配平边界：只识别文档级 operation header，处理 string/comment/escape，显式处理 malformed/truncated。
6. 修复队列失败收口：空响应计数、Parser crash fallback 开关语义、Schema summary/diagnostics 不丢失；补 SDL/introspection 的真实队列测试。
7. 根据产品决策接通 JS/page/browser；若暂缓到第 8 批，必须把 G5 状态改为“文档 Parser 完成、运行时事件未完成”，不能同时写“G5 闭环”。
8. 清理测试 bootstrap，使 Parser 测试独立进程可运行，再重新生成实际测试总数和 golden 证据。
9. 第 8 批开始前冻结 Endpoint Registry key 是否包含 `api_type`/operation，并同步附录 A。

## 7. 下一轮验收门禁

### 7.1 安全与范围

- OpenAPI/Swagger/GraphQL 越界 host 不进入 in-scope domain 资产；同 Fld 和跨 Fld 均有断言。
- Postman 敏感变量出现在 URL path/query/host 时不落原值；Registry、legacy record、source 和日志摘要都无原值。
- 浏览器 headers 至少覆盖 `authorization`、cookie、CSRF、API key 类字段；只保留类型或 `<redacted>`。
- Parser 输出和最终桥接输出都通过敏感值检查，不把 URL/source 当作守卫盲区。

### 7.2 GraphQL 直接解析

- 三类 operation、命名/匿名 operation、operationName、变量声明名/类型、空白归一化 hash。
- 嵌套字段关键字、注释、字符串花括号、转义字符、未闭合 operation、超过上限。
- SDL 的 type/enum/input/scalar/field/argument/relationship 摘要；introspection 的同等摘要。
- bytes/depth/type/field/argument/operation 各预算的 `ok/degraded/failed` 状态和计数。
- Schema 默认关闭时是明确 `skipped`；开启后成功、截断和失败均可被外部观测。

### 7.3 队列与跨来源

- SDL/introspection 通过真实 `ApiDocumentQueue` 后，summary、diagnostics、metrics 和最终文档状态可验证。
- GraphQL 请求通过队列后只生成约定的 `graphql` legacy record，并进入同一 Endpoint Registry。
- JS、page、browser 三来源的相同 GraphQL Endpoint 合并 sources，不重复建资产。
- 空响应、网络异常、Parser failed、Schema degraded 四种状态分别计数，不能出现状态与 counter 不一致。

### 7.4 测试与发布前置

- `cd ARL && PYTHONPATH=. python3 -m unittest -v test.test_api_unified_parser` 独立通过。
- API 定向套件使用明确的文件列表和实际总数；本轮基线为 `test_api_unified_models`、`test_api_unified_shadow`、`test_api_candidate_registry`、`test_api_unified_parser` 共 96 项通过，不把它表述为九文件 139 项。
- `python3 scripts/api-unified-golden.py --check`、`git diff --check`、AST/标准容器回归均重新取证。
- 容器、40/64 目标、双架构和生产部署仍是后续独立门禁，本报告不以本机定向测试替代。

## 8. 最终判定

**Request Changes。**

第 4/5 批和 GraphQL 直接 Parser 可以继续增量开发，但当前不满足统一 API 生产启用条件，也不满足“第 6 批 G5 闭环”验收条件。优先修复 P0-01 至 P0-05；其中 P0-01、P0-02 是安全阻断，P0-03、P0-04 是 Schema 语义/队列阻断，P0-05 是原计划范围与当前实现状态的阻断。

第 4–6 批代码已经提交，但当前提交不等于验收通过；后续继续开发前，建议按本报告建立独立修复提交边界。禁止自动执行 `git push`；修复完成后再按项目提交规范生成本地提交。

## 9. 整改记录

### 轮 1（2026-09-06，P0-01 + P1-10 安全/范围阻断项）

按用户决策（Option A）优先修复第 7 批 WSDL 直接继承的两个安全/范围项，与第 7 批 WSDL/SOAP 解析器合并为整改提交。P0-02~P0-05、P1-06~P1-12、P2-13~P2-15 仍待后续轮次。

| 问题项 | 处置 | 证据 |
|---|---|---|
| P0-01 越界 domain candidate 未经统一范围校验 | 四解析器（openapi/postman/graphql/wsdl）越界 host 候选 `record_type` 由 `domain` 改为 `out_of_scope_domain` 证据类型；桥接层新增统一安全出口 `_bridge_candidate`/`_bridge_out_of_scope_domain`：复用既有 `extract_host`+`utils.is_valid_domain`/`get_fld`+scanner `allowed_hosts`/`allowed_flds` 二次核验（与 legacy `_emit_domain_records` 同口径），一律只计 `api_document_out_of_scope_domain_total`，绝不 `_append_record("domain",...)`；核验意外通过仅 debug 留痕。桥接对 `wsdl_xsd_import`、未接线类型（`graphql_schema_summary`）分别计 `api_document_wsdl_xsd_import_total`/`api_document_unbridged_candidate_total`，不静默丢弃（顺带覆盖 P0-04 "桥接不得静默丢弃"口径） | `test_api_unified_parser.py::OutOfScopeEvidenceTest`（同Fld/跨Fld/非法host/模板host × openapi+graphql+wsdl 三路径）、三既有越界用例改名 `test_out_of_scope_{server,base,address}_yields_evidence_not_domain`（断言证据存在+无 domain 候选+endpoints 排除越界+经真实队列桥接后无 `("domain",...)` 记录）、`test_api_candidate_registry.py::OutOfScopeDomainBridgeTest`（端到端不入资产+指标计数+`_append_record("domain")` 零触发 mock 验证） |
| P1-10 统一模型最终脱敏未覆盖 source/URL | models 新增 `sanitize_url_secrets`（仅把敏感 query 值替换为 `<redacted>`、不删整条 URL、干净 URL 逐字节 no-op、幂等）与 `sanitize_source_text`（赋值形态 `redact_assignment_text` + query 键 `sanitize_url_secrets` 互补）；接线 `ApiDocumentCandidate`/`UnifiedApiEndpoint` 的 `__post_init__`（url/source/parent_url/parent_document/base_url/sources，url 在 endpoint_id 派生前清洗）与 `add_source`；`find_sensitive_keys` 守卫扩展检出 url/source/sources/parent_url/base_url/parent_document 的敏感 query，残留令 `ParseResult.to_dict()` 抛 ValueError；registry merge 入口 `existing.parent_url=` 改经 `sanitize_source_text`（堵构造期外的直接赋值） | `test_api_unified_models.py::UrlSourceBoundaryTest` 9 项（URL 敏感 query 构造期脱敏、source 初始+`add_source` 两路径、ApiDocumentCandidate 与 UnifiedApiEndpoint 双模型、干净 URL 与 path 段 `token` 不误报） |

轮 1 验证：api 四件本地合跑 **126 项全绿**（parser 56 / registry 24 / models 38 / shadow 8）；`scripts/api-unified-golden.py --check` exit 0（legacy 基线无漂移）；`py_compile` 与 `git diff --check` 通过。

行为收窄登记：统一路径现对同-Fld 越界 host 也不再产 domain 记录（legacy 会产）——这是 P0-01 的有意安全收窄；若产品需同-Fld host 回流资产面，必须走独立的、经范围校验的显影通道，而非解析器桥接。`unified_target_expectations.json` 的"legacy 超集"口径据此修订为"越界 domain 证据化是唯一允许缺失面"（`test_output_floor_and_format_vs_legacy` 已锁定该唯一差异）。

仍待后续轮次：P0-02（Postman 敏感变量替换进 URL）、P0-03（GraphQL Schema 深度预算接线）、P0-04（Schema 摘要队列存储面）、P0-05（JS/页面/浏览器事件接入 + G5 验收口径）、P1-06~P1-12、P2-13~P2-15。新增指标 `api_document_out_of_scope_domain_total`/`api_document_wsdl_xsd_import_total`/`api_document_unbridged_candidate_total` 待纳入看板；`unbridged` 计数在 P0-04 接线 `graphql_schema_summary` 存储面后应归零，可作该整改观测锚。
