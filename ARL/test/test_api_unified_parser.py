"""计划 6 第 4 批：UnifiedOpenApiParser 回归。

验收面（unified_target_expectations.json + 附录A §五）：
- openapi3：G1 模板端点保留、参数四位置、auth_hint、循环/未解析引用标记、
  越界 server → out_of_scope_domain 证据候选（Review P0-01：绝不落 in-scope
  domain 资产）、诊断 degraded≠failed；
- swagger2：同范围内端点集合与 openapi3 一致、formData、basic auth；
- external_ref：外部 $ref 不获取、unresolved 计数、状态非 ok；
- invalid/deep_nesting：显式 failed 且零端点（G4 不伪装"无 API"）；
- 格式外（postman/graphql）：skipped 交回 legacy；
- 下限：baseline 记录集 ⊆ 统一输出（含队列桥接面）。
"""

import hashlib
import json
import sys
import unittest
from pathlib import Path

ARL_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ARL_ROOT / "test" / "fixtures" / "api_unified"

if str(ARL_ROOT) not in sys.path:
    sys.path.insert(0, str(ARL_ROOT))

from test._api_unified_bootstrap import load_unified_modules  # noqa: E402

# bootstrap 在临时桩窗口内加载子模块（绕过 app.services 真实 __init__ 的 NPoC 等
# 重依赖），完成后还原 app / app.services 槽位，不留空壳桩。桥接用例
# （_bridge_via_queue 等）与 api_unified_parser 函数体内部的懒导入均为子模块
# 直接形式，命中此处预载并保留的缓存条目，不再触发包 __init__。
_captured = load_unified_modules()

UnifiedOpenApiParser = _captured["app.services.api_unified_parser"].UnifiedOpenApiParser
ParseOptions = _captured["app.services.api_unified_models"].ParseOptions

DOC_URL = "https://api.example.com/v3/api-docs"
ALLOWED = {"api.example.com"}
BASELINE = json.loads(
    (FIXTURES / "expected" / "current_parser_baseline.json").read_text(encoding="utf-8")
)["fixtures"]
FORBIDDEN = json.loads(
    (FIXTURES / "expected" / "unified_target_expectations.json").read_text(encoding="utf-8")
)["forbidden_substrings"]


def _parse(name, allowed=ALLOWED, doc_url=DOC_URL, **option_kw):
    text = (FIXTURES / name).read_text(encoding="utf-8")
    parser = UnifiedOpenApiParser(
        task_id="b4", doc_url=doc_url, allowed_hosts=set(allowed),
        allowed_flds={"example.com"},
    )
    return parser.parse(text, ParseOptions(**option_kw))


def _endpoint_contents(result):
    return {"{} {}".format(e.method, e.url) for e in result.endpoints}


def _baseline_endpoints(name):
    return {
        str(item.get("content") or "")
        for item in BASELINE[name]["records"]
        if item.get("record_type") == "api_doc_endpoint"
    }


def _record_pair(record):
    return (
        str(getattr(record, "recordType", "") or getattr(record, "record_type", "")),
        str(getattr(record, "content", "") or ""),
    )


def _assert_queue_failure_convergence(case, queue):
    """P1-08 统一失败收口不变式（同 registry test_per_document_failure_isolation 口径）。

    被消费文档终态必落 success/failed 之一，fetch 异常/空响应/Parser failed
    全部计入 parse_failed_count。旧断言把"非目标 seed 空响应不计量"固化为
    parse_failed_count==0/1 的绝对值期望，属被 Review 证伪的口径，改用不变式
    + 目标文档自身状态精确断言，队列不再依赖 fetch_count 的绝对期望。
    """

    case.assertEqual(
        queue.parse_failed_count, queue.fetch_count - queue.parse_success_count,
        "P1-08：每个被消费文档必须收敛到 success/failed 之一（空响应同样计入失败收口）")


def _bridge_via_queue(text, task_id, sites, match="api-docs"):
    """经真实 ApiDocumentQueue 跑解析器链 + 桥接层，返回旧记录面。

    P0-01 桥接断言入口：验证越界 host 候选在桥接后不落 in-scope domain 记录
    （指标计数断言在 test_api_candidate_registry.py，需要 DiscoveryContext）。
    """

    from app.services.api_doc_scan import ApiDocScanner
    from app.services.api_candidate_registry import (
        ApiCandidateRegistry,
        ApiDocumentQueue,
    )
    from app.services.api_unified_models import UNIFIED_API_CONFIG_DEFAULTS

    config = dict(UNIFIED_API_CONFIG_DEFAULTS)
    config["API_UNIFIED_ENABLE"] = True
    scanner = ApiDocScanner(sites=list(sites), wih_records=[])
    registry = ApiCandidateRegistry(task_id=task_id)
    queue = ApiDocumentQueue(
        scanner=scanner, registry=registry, context=None, config=config,
        fetch_fn=lambda doc: text if (match is None or match in doc.url) else "",
    )
    return queue.run()


class OpenApi3Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = _parse("openapi3_petstore.json")

    def test_g1_template_endpoints_kept(self):
        contents = _endpoint_contents(self.result)
        expected = {
            "GET https://api.example.com/v1/pets",
            "POST https://api.example.com/v1/pets",
            "GET https://api.example.com/v1/pets/{petId}",
            "DELETE https://api.example.com/v1/pets/{petId}",
            "GET https://api.example.com/v1/legacy/only-parameters",
            "GET https://api.example.com/v1/broken/ref",
        }
        self.assertTrue(
            expected.issubset(contents),
            "缺: {}".format(sorted(expected - contents)),
        )

    def test_parameter_positions_and_ref_merge(self):
        by_key = {
            "{} {}".format(e.method, e.url): e for e in self.result.endpoints
        }
        pets = by_key["GET https://api.example.com/v1/pets"]
        params = {(p.name, p.location) for p in pets.parameters}
        self.assertIn(("X-Tenant", "header"), params, "path 级参数必须并入")
        self.assertIn(("limit", "query"), params)
        self.assertIn(("sessionId", "cookie"), params)
        petid = by_key["GET https://api.example.com/v1/pets/{petId}"]
        self.assertIn(
            ("petId", "path"), {(p.name, p.location) for p in petid.parameters},
            "#/components/parameters $ref 必须解引用",
        )

    def test_auth_hint_operation_overrides_document(self):
        by_key = {
            "{} {}".format(e.method, e.url): e for e in self.result.endpoints
        }
        get_pets = by_key["GET https://api.example.com/v1/pets"]
        post_pets = by_key["POST https://api.example.com/v1/pets"]
        self.assertEqual(get_pets.auth_hint, "api_key")
        self.assertEqual(post_pets.auth_hint, "bearer", "operation.security 覆盖 doc 级")
        self.assertEqual(
            [(s.name, s.type) for s in post_pets.security_requirements],
            [("BearerAuth", "bearer")],
        )

    def test_request_body_summary_bounded_and_circular(self):
        by_key = {
            "{} {}".format(e.method, e.url): e for e in self.result.endpoints
        }
        post = by_key["POST https://api.example.com/v1/pets"]
        self.assertEqual(post.request_body_type, "application/json")
        self.assertEqual(post.request_body_schema.get("type"), "object")
        self.assertTrue(post.schema_available)
        dumped = json.dumps(post.response_schema or {}, ensure_ascii=False) \
            + json.dumps(post.request_body_schema, ensure_ascii=False)
        self.assertNotIn("RecursionError", dumped)

    def test_unresolved_marks_schema_unavailable(self):
        by_key = {
            "{} {}".format(e.method, e.url): e for e in self.result.endpoints
        }
        broken = by_key["GET https://api.example.com/v1/broken/ref"]
        self.assertFalse(broken.schema_available, "Missing $ref 不得伪装 Schema 完整")
        self.assertGreaterEqual(self.result.diagnostics.unresolved_ref_count, 1)

    def test_out_of_scope_server_yields_evidence_not_domain(self):
        # Review P0-01：同-Fld 越界 server 只产 out_of_scope_domain 证据候选，
        # 桥接后绝不落 in-scope domain 记录。
        evidence = {
            item.get("content") for item in self.result.candidates
            if item.get("record_type") == "out_of_scope_domain"
        }
        self.assertIn("blue.example.com", evidence)
        self.assertFalse(
            [c for c in self.result.candidates if c.get("record_type") == "domain"],
            "解析器不得再产出可消费的 domain 候选")
        self.assertTrue(all(
            e.url.startswith("https://api.example.com") for e in self.result.endpoints),
            "endpoints 必须排除越界 host")
        text = (FIXTURES / "openapi3_petstore.json").read_text(encoding="utf-8")
        records = _bridge_via_queue(text, "b4p01", ["https://api.example.com"],
                                    match="v3/api-docs")
        self.assertFalse(
            [p for p in map(_record_pair, records) if p[0] == "domain"],
            "桥接后越界 host 不得落 in-scope domain 记录")

    def test_diagnostics_and_document(self):
        self.assertIn(self.result.diagnostics.status, ("ok", "degraded"))
        self.assertEqual(len(self.result.documents), 1)
        doc = self.result.documents[0]
        self.assertEqual(doc.type_hint, "openapi")
        self.assertEqual(doc.task_id, "b4")
        self.assertTrue(doc.input_signature)

    def test_output_leak_guard(self):
        payload = json.dumps(self.result.to_dict(), ensure_ascii=False)
        for token in FORBIDDEN:
            self.assertNotIn(token, payload)

    def test_baseline_floor_endpoints(self):
        self.assertTrue(
            _baseline_endpoints("openapi3_petstore.json").issubset(
                _endpoint_contents(self.result)))


class YamlMirrorTest(unittest.TestCase):
    def test_yaml_endpoint_set_equals_json(self):
        json_result = _parse("openapi3_petstore.json")
        yaml_result = _parse("openapi3_petstore.yaml")
        self.assertEqual(
            _endpoint_contents(json_result), _endpoint_contents(yaml_result))


class Swagger2Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = _parse("swagger2_petstore.json",
                            doc_url="https://api.example.com/v2/api-docs")
        cls.v3 = _parse("openapi3_petstore.json")

    def test_in_scope_endpoint_set_equals_openapi3(self):
        self.assertEqual(
            _endpoint_contents(self.v3), _endpoint_contents(self.result))

    def test_formdata_location_and_body_type(self):
        by_key = {
            "{} {}".format(e.method, e.url): e for e in self.result.endpoints
        }
        post = by_key["POST https://api.example.com/v1/pets"]
        self.assertIn(
            ("name", "formData"), {(p.name, p.location) for p in post.parameters})
        self.assertEqual(post.request_body_type, "application/x-www-form-urlencoded")

    def test_basic_auth_hint(self):
        by_key = {
            "{} {}".format(e.method, e.url): e for e in self.result.endpoints
        }
        self.assertEqual(
            by_key["POST https://api.example.com/v1/pets"].auth_hint, "basic")

    def test_baseline_floor_endpoints(self):
        self.assertTrue(
            _baseline_endpoints("swagger2_petstore.json").issubset(
                _endpoint_contents(self.result)))


class SafetyBoundaryTest(unittest.TestCase):
    def test_external_ref_not_fetched_but_degraded(self):
        result = _parse("external_ref_openapi.json")
        contents = _endpoint_contents(result)
        self.assertIn("GET https://api.example.com/xref/probe", contents)
        self.assertIn("GET https://api.example.com/xref/local", contents)
        self.assertGreaterEqual(result.diagnostics.unresolved_ref_count, 1)
        self.assertNotEqual(result.diagnostics.status, "ok")
        dumped = json.dumps(result.to_dict(), ensure_ascii=False)
        self.assertNotIn("xxe-probe", dumped)

    def test_invalid_json_explicit_failed(self):
        result = _parse("invalid_json.json")
        self.assertIn(result.diagnostics.status, ("failed", "degraded"))
        self.assertEqual(len(result.endpoints), 0)
        self.assertTrue(result.diagnostics.error_type,
                        "G4：失败必须显式，不得表现为静默空结果")

    def test_deep_nesting_bounded(self):
        result = _parse("deep_nesting.json")
        self.assertIn(result.diagnostics.status, ("skipped", "failed", "degraded"))
        self.assertEqual(len(result.endpoints), 0)

    def test_size_budget_rejects(self):
        result = _parse("openapi3_petstore.json", max_document_bytes=1024)
        self.assertEqual(result.diagnostics.status, "failed")
        self.assertEqual(result.diagnostics.error_type, "document_too_large")

    def test_ref_budget_exhausted_degrades_not_crash(self):
        result = _parse("openapi3_petstore.json", max_ref_count=1)
        self.assertIn(result.diagnostics.status, ("degraded", "failed"))


class PostmanTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from app.services.api_unified_parser import UnifiedPostmanParser

        text = (FIXTURES / "postman_collection.json").read_text(encoding="utf-8")
        cls.result = UnifiedPostmanParser(
            task_id="b5",
            doc_url="https://api.example.com/postman.json",
            allowed_hosts=set(ALLOWED),
            allowed_flds={"example.com"},
        ).parse(text, ParseOptions())
        cls.by_key = {"{} {}".format(e.method, e.url): e for e in cls.result.endpoints}

    def test_baseline_floor_and_must_include(self):
        contents = set(self.by_key)
        for expected in (
            "HEAD https://api.example.com/v1/health",
            "POST https://api.example.com/v1/users",
            "PUT https://api.example.com/v1/users/7",
            "POST https://api.example.com/v1/users/7/avatar",
        ):
            self.assertIn(expected, contents)
        self.assertTrue(
            _baseline_endpoints("postman_collection.json").issubset(contents))

    def test_g2_variable_endpoints_recovered(self):
        # ListUsers：{{baseUrl}} 解析、query 参数化为 {limit} 模板、URL 去 query。
        list_users = self.by_key.get("GET https://api.example.com/v1/users")
        self.assertIsNotNone(list_users, "G2：{{baseUrl}} 端点不再整体跳过")
        self.assertIn("{limit}", list_users.path_template)
        get_by_id = self.by_key.get("GET https://api.example.com/v1/users/:id")
        self.assertIsNotNone(get_by_id, "G2：:id 冒号变量端点不再丢弃")
        self.assertIn(":id", get_by_id.path_template)

    def test_body_type_expectations(self):
        self.assertEqual(self.by_key["POST https://api.example.com/v1/users"].request_body_type, "raw")
        self.assertEqual(self.by_key["PUT https://api.example.com/v1/users/7"].request_body_type, "urlencoded")
        self.assertEqual(self.by_key["POST https://api.example.com/v1/users/7/avatar"].request_body_type, "formdata")

    def test_leak_values_absent_and_guard_passes(self):
        payload = json.dumps(self.result.to_dict(), ensure_ascii=False)
        for token in ("POSTMANLEAKTOKEN123", "POSTMANLEAKPASS456"):
            self.assertNotIn(token, payload, "变量值/body 值禁止外流（to_dict 守卫必须通过）")
        # 路径变量示例值 42 不得进入资产 URL（不猜值策略）。
        self.assertNotIn("42", self.by_key["GET https://api.example.com/v1/users/:id"].url)
        create = self.by_key["POST https://api.example.com/v1/users"]
        props = create.request_body_schema.get("properties", {})
        self.assertNotIn("token", props, "敏感键名摘要必须整体剔除")
        self.assertIn("name", props)

    def test_parameters_and_auth_hint(self):
        list_users = self.by_key["GET https://api.example.com/v1/users"]
        pairs = {(p.name, p.location) for p in list_users.parameters}
        self.assertIn(("Authorization", "header"), pairs)
        self.assertIn(("limit", "query"), pairs)
        self.assertEqual(list_users.auth_hint, "bearer", "Authorization 头部推导 auth_hint")
        get_by_id = self.by_key["GET https://api.example.com/v1/users/:id"]
        self.assertIn(
            ("id", "path"), {(p.name, p.location) for p in get_by_id.parameters})

    def test_variable_resolution_confidence_policy(self):
        resolved = self.by_key["GET https://api.example.com/v1/users"]
        literal = self.by_key["HEAD https://api.example.com/v1/health"]
        self.assertLess(resolved.confidence, literal.confidence, "变量解析结果置信度降级")


class PostmanSensitiveVariableTest(unittest.TestCase):
    """Review P0-02：敏感变量永不解析为真实值进入端点输出面。

    四个泄露位置各一条回归（raw URL 文本、结构化 host 拼装、query 段、
    path 变量段），敏感变量真值只允许虚构值；修复前该组测试以
    assertNotIn 失败复现泄露（修复前红证据见提交说明），修复后要求
    统一走"不可解析变量→保留 {{key}} 模板、置信度 30"路径。
    """

    DOC_URL = "https://api.example.com/postman.json"

    def _parse(self, variables, url):
        from app.services.api_unified_parser import UnifiedPostmanParser

        doc = {
            "info": {"name": "t1-p0-02",
                     "schema": "https://schema.postman.com/collection/v2.1.0/schema.json"},
            "variable": [{"key": k, "value": v} for k, v in variables.items()],
            "item": [{"name": "req", "request": {"method": "GET", "url": url}}],
        }
        return UnifiedPostmanParser(
            task_id="t1p02", doc_url=self.DOC_URL,
            allowed_hosts={"api.example.com"}, allowed_flds={"example.com"},
        ).parse(doc, ParseOptions())

    def _assert_secret_absent(self, result, secret):
        # 泄露面全覆盖：to_dict（endpoints/documents/candidates/diagnostics）与
        # 端点属性直读，任一位置出现原值即失败。
        payload = json.dumps(result.to_dict(), ensure_ascii=False, default=str)
        self.assertNotIn(secret, payload)
        for endpoint in result.endpoints:
            surface = "{} {} {} {}".format(
                endpoint.url, endpoint.base_url, endpoint.path_template,
                " ".join(p.name for p in endpoint.parameters))
            self.assertNotIn(secret, surface)
        for candidate in result.candidates:
            self.assertNotIn(secret, json.dumps(candidate, ensure_ascii=False, default=str))

    def test_l1_raw_url_path_variable_never_resolved(self):
        secret = "SECRETVALUE-NOTREAL-123"
        result = self._parse({"api_token": secret},
                             "https://api.example.com/files/{{api_token}}")
        self._assert_secret_absent(result, secret)
        self.assertEqual(len(result.endpoints), 1, "模板 URL 仍产出端点（不抛异常、不造新记录类型）")
        endpoint = result.endpoints[0]
        self.assertIn("{{api_token}}", endpoint.url, "敏感变量必须保留 {{key}} 模板形态")
        self.assertEqual(endpoint.confidence, 30)
        self.assertEqual(result.diagnostics.unresolved_ref_count, 1)
        self.assertEqual(result.diagnostics.status, "degraded")

    def test_l2_structured_host_variable_never_resolved(self):
        secret = "internal-vault.example.net"
        result = self._parse({"authTokenHost": secret}, {
            "protocol": "https", "host": ["{{authTokenHost}}"], "path": ["v1", "ping"]})
        self._assert_secret_absent(result, secret)
        # host 位为模板：不得因替换后的真值生成越界证据，走模板保留路径。
        for candidate in result.candidates:
            self.assertNotEqual(candidate.get("content"), secret)
        self.assertEqual(len(result.endpoints), 1)
        # 模板保留即可；端点构造期 URL 规范化会把 host 段小写（既有行为）。
        self.assertIn("{{authtokenhost}}", result.endpoints[0].url.lower())
        self.assertEqual(result.endpoints[0].confidence, 30)

    def test_l3_query_segment_variable_never_resolved(self):
        secret = "SECRETKEYVALUE-NOTREAL-456"
        result = self._parse({"api_key": secret},
                             "https://api.example.com/search?{{api_key}}=1")
        self._assert_secret_absent(result, secret)
        # 修复前泄露面：真值经 query 键名进入 parameters 名称。
        self.assertEqual(len(result.endpoints), 1)
        endpoint = result.endpoints[0]
        self.assertNotIn(secret, [p.name for p in endpoint.parameters])
        self.assertEqual(endpoint.confidence, 30)

    def test_l4_structured_path_variable_never_resolved(self):
        secret = "PRIVKEYVALUE-NOTREAL-789"
        result = self._parse({"privateKey": secret}, {
            "protocol": "https", "host": ["api.example.com"],
            "path": ["keys", "{{privateKey}}", "meta"]})
        self._assert_secret_absent(result, secret)
        self.assertEqual(len(result.endpoints), 1)
        self.assertIn("{{privateKey}}", result.endpoints[0].url)
        self.assertEqual(result.endpoints[0].confidence, 30)

    def test_nonsensitive_variable_resolution_unchanged(self):
        # 干净非敏感变量的既有解析行为必须不变（含值替换与置信度 70）。
        result = self._parse({"env": "prod"}, "https://api.example.com/{{env}}/status")
        self.assertEqual(len(result.endpoints), 1)
        self.assertEqual(result.endpoints[0].url, "https://api.example.com/prod/status")
        self.assertEqual(result.endpoints[0].confidence, 70)

    def test_variables_not_leaked_via_collection_definition_only(self):
        # 敏感变量存在但未被 URL 引用：值不得进入任何输出（既有守卫面不回归）。
        secret = "SESSIONIDVALUE-NOTREAL-321"
        result = self._parse({"session_id": secret}, "https://api.example.com/v1/health")
        self._assert_secret_absent(result, secret)
        self.assertEqual(result.endpoints[0].confidence, 80, "无变量 URL 保持字面量高置信")

    def test_bridge_output_carries_no_sensitive_value(self):
        # 桥接产物在 parser 单文件层面验证：经队列桥接后任一记录不得含原值。
        secret = "SECRETVALUE-NOTREAL-123"
        doc = {
            "info": {"name": "t1-p0-02",
                     "schema": "https://schema.postman.com/collection/v2.1.0/schema.json"},
            "variable": [{"key": "api_token", "value": secret}],
            "item": [{"name": "req", "request": {
                "method": "GET",
                "url": "https://api.example.com/files/{{api_token}}"}}],
        }
        records = _bridge_via_queue(json.dumps(doc), "t1p02b",
                                    [self.DOC_URL], match="postman")
        self.assertTrue(records, "postman 文档应经队列产出桥接记录")
        for record in records:
            blob = json.dumps(vars(record), ensure_ascii=False, default=str)
            self.assertNotIn(secret, blob, "桥接记录禁止携带敏感变量原值")


class SkippedFormatsTest(unittest.TestCase):
    def test_graphql_still_returns_skipped(self):
        # 第 6 批接管前：graphql 请求文档仍回 legacy；openapi 解析器对它 skip。
        result = _parse("graphql_request.json", doc_url="https://api.example.com/any")
        self.assertEqual(result.diagnostics.status, "skipped")
        self.assertEqual(result.diagnostics.error_type, "not_openapi_document")

    def test_openapi_parser_skips_postman_chain_handoff(self):
        # openapi 解析器对 postman 文档必须 skip（由队列链转 postman 解析器）。
        from app.services.api_unified_parser import UnifiedOpenApiParser

        text = (FIXTURES / "postman_collection.json").read_text(encoding="utf-8")
        result = UnifiedOpenApiParser(
            task_id="b5", doc_url="https://api.example.com/postman.json",
            allowed_hosts=set(ALLOWED)).parse(text)
        self.assertEqual(result.diagnostics.status, "skipped")


class QueueBridgeTest(unittest.TestCase):
    def test_queue_bridges_unified_output_with_template_suppression(self):
        from app.services.api_doc_scan import ApiDocScanner
        from app.services.api_candidate_registry import (
            ApiCandidateRegistry,
            ApiDocumentQueue,
        )
        from app.services.api_unified_models import UNIFIED_API_CONFIG_DEFAULTS

        text = (FIXTURES / "openapi3_petstore.json").read_text(encoding="utf-8")
        config = dict(UNIFIED_API_CONFIG_DEFAULTS)
        config["API_UNIFIED_ENABLE"] = True
        scanner = ApiDocScanner(sites=["https://api.example.com"], wih_records=[])
        registry = ApiCandidateRegistry(task_id="b4q")
        queue = ApiDocumentQueue(
            scanner=scanner, registry=registry, context=None, config=config,
            fetch_fn=lambda doc: text if "v3/api-docs" in doc.url else "",
        )
        records = queue.run()
        pairs = {
            (str(getattr(r, "recordType", "") or getattr(r, "record_type", "")),
             str(getattr(r, "content", "") or ""))
            for r in records
        }
        templates = {p for p in pairs if p[0] == "api_doc_endpoint" and "{" in p[1]}
        self.assertTrue(templates, "G1 模板端点必须出现在 api_doc_endpoint 面")
        self.assertFalse(
            [p for p in pairs if p[0] == "urlfinder_url" and "{" in p[1]],
            "模板 URL 不得流入 urlfinder_url 资产面",
        )
        self.assertTrue(
            _baseline_endpoints("openapi3_petstore.json").issubset(
                {c for t, c in pairs if t == "api_doc_endpoint"}))
        rich = [
            e for e in registry.snapshot_endpoints()
            if e["method"] == "POST" and e["url"].endswith("/pets")
        ]
        self.assertEqual(len(rich), 1)
        self.assertEqual(rich[0]["auth_hint"], "bearer", "富资产端点必须带 auth 语义")
        self.assertTrue(rich[0]["parameters"])

    def test_invalid_document_fails_visibly_in_queue(self):
        from app.services.api_doc_scan import ApiDocScanner
        from app.services.api_candidate_registry import (
            ApiCandidateRegistry,
            ApiDocumentQueue,
        )
        from app.services.api_unified_models import UNIFIED_API_CONFIG_DEFAULTS

        bad_url = "https://api.example.com/v3/api-docs"
        text = (FIXTURES / "invalid_json.json").read_text(encoding="utf-8")
        config = dict(UNIFIED_API_CONFIG_DEFAULTS)
        config["API_UNIFIED_ENABLE"] = True
        scanner = ApiDocScanner(sites=["https://api.example.com"], wih_records=[])
        registry = ApiCandidateRegistry(task_id="b4q2")
        queue = ApiDocumentQueue(
            scanner=scanner, registry=registry, context=None, config=config,
            fetch_fn=lambda doc: text if bad_url in doc.url else "",
        )
        queue.run()
        doc = registry.document(bad_url)
        self.assertEqual(doc.status, "failed")
        # 目标文档失败原因精确断言：openapi 解析器对断裂 JSON 标 load_error。
        self.assertEqual(doc.error_type, "load_error")
        # 旧口径 parse_failed_count==1 固化了"非目标 seed 空响应不计数"的
        # 被证伪语义（P1-08），改为不变式 + success 分母零产出断言。
        self.assertEqual(queue.parse_success_count, 0,
                         "断裂 JSON 不得计入成功收口")
        _assert_queue_failure_convergence(self, queue)


class QueuePostmanChainTest(unittest.TestCase):
    def test_queue_dispatches_postman_document_to_unified_parser(self):
        from app.services.api_doc_scan import ApiDocScanner
        from app.services.api_candidate_registry import (
            ApiCandidateRegistry,
            ApiDocumentQueue,
        )
        from app.services.api_unified_models import UNIFIED_API_CONFIG_DEFAULTS

        text = (FIXTURES / "postman_collection.json").read_text(encoding="utf-8")
        config = dict(UNIFIED_API_CONFIG_DEFAULTS)
        config["API_UNIFIED_ENABLE"] = True
        scanner = ApiDocScanner(sites=["https://api.example.com"], wih_records=[])
        registry = ApiCandidateRegistry(task_id="b5q")
        consumed = []

        def fetch_fn(doc):
            if "postman" in doc.url:
                consumed.append(doc.url)
                return text
            return ""

        queue = ApiDocumentQueue(
            scanner=scanner, registry=registry, context=None, config=config,
            fetch_fn=fetch_fn,
        )
        records = queue.run()
        contents = {
            str(getattr(r, "content", "") or "") for r in records
        }
        self.assertTrue(
            _baseline_endpoints("postman_collection.json").issubset(
                {c for c in contents if " " in c and c.split(" ", 1)[0].isalpha()}),
            "unified 链必须覆盖 legacy 全部 postman 端点",
        )
        self.assertIn("GET https://api.example.com/v1/users/:id", contents)
        for record in records:
            blob = "{}|{}|{}".format(
                getattr(record, "content", ""), getattr(record, "source", ""),
                getattr(record, "site", ""))
            self.assertNotIn("POSTMANLEAKTOKEN123", blob)
            self.assertNotIn("POSTMANLEAKPASS456", blob)
        # P1-08：目标 postman 文档必须真实 parsed；其余 seed 空响应计入失败
        # 收口属预期语义，绝对值断言改为不变式（见 helper 注释）。
        self.assertTrue(consumed, "目标 postman 文档必须被队列消费")
        self.assertEqual(registry.document(consumed[0]).status, "parsed")
        self.assertGreaterEqual(queue.parse_success_count, 1)
        _assert_queue_failure_convergence(self, queue)


def _parse_graphql(name, enabled=False, **kw):
    from app.services.api_unified_parser import UnifiedGraphqlParser

    text = (FIXTURES / name).read_text(encoding="utf-8")
    parser = UnifiedGraphqlParser(
        task_id="b6",
        doc_url=kw.pop("found_url", "https://api.example.com/intel/graphql-payload.json"),
        allowed_hosts=set(kw.pop("allowed", ALLOWED)),
        allowed_flds={"example.com"},
        **kw,
    )
    return parser.parse(text, ParseOptions(graphql_schema_enable=enabled))


class GraphqlRequestTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = _parse_graphql("graphql_request.json")
        cls.by_op = {
            (e.graphql_operation, e.graphql_operation_name): e for e in cls.result.endpoints
        }

    def test_endpoint_base_and_operations(self):
        self.assertTrue(self.by_op, "请求文档必须产出 graphql 端点")
        for e in self.result.endpoints:
            self.assertEqual(e.api_type, "graphql")
            self.assertEqual(e.url, "https://api.example.com/graphql")
            self.assertEqual(e.method, "POST")
            self.assertFalse(e.schema_available)
            self.assertEqual(len(e.graphql_query_hash), 64)
        for op, name in (("query", "GetPet"), ("mutation", "AdoptPet"),
                         ("subscription", "OnPetAdopted")):
            self.assertIn((op, name), self.by_op)

    def test_variable_names_only_and_leak_guard(self):
        union = {p.name for e in self.result.endpoints for p in e.parameters}
        self.assertEqual(union, {"petId", "input"})
        get_pet = self.by_op[("query", "GetPet")]
        self.assertEqual(
            {(p.name, p.type_summary) for p in get_pet.parameters},
            {("petId", "ID!")},
        )
        payload = json.dumps(self.result.to_dict(), ensure_ascii=False)
        for token in ("GRAPHQLLEAKPASS789", "pet-1", "Rex", "password"):
            self.assertNotIn(token, payload, "variables 取值/嵌套键禁止外流")

    def test_out_of_scope_base_yields_evidence_not_domain(self):
        # Review P0-01：越界 base 只产 out_of_scope_domain 证据候选。
        result = _parse_graphql("graphql_request.json", allowed={"other.example.com"})
        self.assertEqual(result.endpoints, [], "endpoints 必须排除越界 host")
        evidence = {c.get("content") for c in result.candidates
                    if c.get("record_type") == "out_of_scope_domain"}
        self.assertIn("api.example.com", evidence)
        self.assertFalse(
            [c for c in result.candidates if c.get("record_type") == "domain"],
            "解析器不得再产出可消费的 domain 候选")
        text = (FIXTURES / "graphql_request.json").read_text(encoding="utf-8")
        records = _bridge_via_queue(text, "b6p01", ["https://other.example.com"])
        self.assertFalse(
            [p for p in map(_record_pair, records) if p[0] == "domain"],
            "桥接后越界 host 不得落 in-scope domain 记录")

    def test_queue_bridge_graphql_record_first_producer(self):
        from app.services.api_doc_scan import ApiDocScanner
        from app.services.api_candidate_registry import (
            ApiCandidateRegistry,
            ApiDocumentQueue,
        )
        from app.services.api_unified_models import UNIFIED_API_CONFIG_DEFAULTS

        text = (FIXTURES / "graphql_request.json").read_text(encoding="utf-8")
        config = dict(UNIFIED_API_CONFIG_DEFAULTS)
        config["API_UNIFIED_ENABLE"] = True
        scanner = ApiDocScanner(sites=["https://api.example.com"], wih_records=[])
        registry = ApiCandidateRegistry(task_id="b6q")
        consumed = []

        def fetch_fn(doc):
            if "api-docs" in doc.url:
                consumed.append(doc.url)
                return text
            return ""

        queue = ApiDocumentQueue(
            scanner=scanner, registry=registry, context=None, config=config,
            fetch_fn=fetch_fn,
        )
        records = queue.run()
        pairs = {
            (str(getattr(r, "recordType", "") or getattr(r, "record_type", "")),
             str(getattr(r, "content", "") or ""))
            for r in records
        }
        self.assertIn(
            ("graphql", "POST https://api.example.com/graphql"), pairs,
            "§二：graphql 记录形态自第 6 批起由统一层产出",
        )
        self.assertFalse([p for p in pairs if p[0] == "urlfinder_url"])
        # P1-08：目标 graphql 文档真实 parsed + 统一失败收口不变式，
        # 旧 parse_failed_count==0 断言已随空响应计量语义修正。
        self.assertTrue(consumed, "目标 graphql 文档必须被队列消费")
        self.assertEqual(registry.document(consumed[0]).status, "parsed")
        _assert_queue_failure_convergence(self, queue)
        self.assertGreaterEqual(registry.endpoint_created_count, 1)


class GraphqlSchemaTest(unittest.TestCase):
    def test_sdl_disabled_returns_skipped(self):
        result = _parse_graphql("graphql_schema.sdl", enabled=False)
        self.assertEqual(result.diagnostics.status, "skipped")
        self.assertEqual(result.diagnostics.error_type, "graphql_schema_disabled")

    def test_sdl_enabled_summary(self):
        result = _parse_graphql("graphql_schema.sdl", enabled=True)
        self.assertEqual(result.diagnostics.status, "ok")
        summary = next(c for c in result.candidates
                       if c.get("record_type") == "graphql_schema_summary")
        self.assertEqual(summary["kind"], "sdl")
        self.assertEqual(set(summary["types"]),
                         {"Owner", "Pet", "Query", "Mutation", "Subscription"})
        self.assertEqual(summary["enums"], ["PetStatus"])
        self.assertEqual(summary["inputs"], ["PetInput"])
        self.assertEqual(summary["scalars"], ["DateTime"])
        self.assertFalse(summary["truncated"])
        self.assertEqual(result.documents[0].type_hint, "graphql")

    def test_introspection_default_disabled(self):
        from app.services.api_unified_parser import UnifiedGraphqlParser

        payload = json.dumps({"data": {"__schema": {"types": [
            {"name": "Pet", "kind": "OBJECT"}, {"name": "PetStatus", "kind": "ENUM"}]}}})
        parser = UnifiedGraphqlParser(task_id="b6", doc_url="https://api.example.com/graphql")
        disabled = parser.parse(payload, ParseOptions(graphql_schema_enable=False))
        self.assertEqual(disabled.diagnostics.status, "skipped")
        enabled = parser.parse(payload, ParseOptions(graphql_schema_enable=True))
        summary = enabled.candidates[0]
        self.assertEqual(summary["kind"], "introspection")
        self.assertEqual(summary["types"], ["Pet"])
        self.assertEqual(summary["enums"], ["PetStatus"])

    def test_schema_size_budget(self):
        big = ("type BigType {\n" + "  f: Int\n" * 500 + "}\n") * 8
        from app.services.api_unified_parser import UnifiedGraphqlParser

        parser = UnifiedGraphqlParser(
            task_id="b6", doc_url="https://api.example.com/sdl",
            allowed_hosts=set(ALLOWED), schema_max_bytes=4096)
        result = parser.parse(big, ParseOptions(graphql_schema_enable=True))
        self.assertEqual(result.diagnostics.status, "failed")
        self.assertEqual(result.diagnostics.error_type, "document_too_large")

    def test_field_budget_marks_truncated(self):
        from app.services.api_unified_parser import UnifiedGraphqlParser

        big = "type Wide {\n" + "".join("  f{}: Int\n".format(i) for i in range(150)) + "}\n"
        parser = UnifiedGraphqlParser(
            task_id="b6", doc_url="https://api.example.com/sdl",
            allowed_hosts=set(ALLOWED))
        result = parser.parse(big, ParseOptions(graphql_schema_enable=True))
        summary = result.candidates[0]
        self.assertTrue(summary["truncated"])


# ---------------------------------------------------------------------------
# T2+T3（合并票）：P1-06/P1-07 operation tokenizer + P0-03 Schema 预算（Parser 半边）
# ---------------------------------------------------------------------------

# 附录A §4.13 冻结的 graphql_schema_summary 生产侧契约键集合（消费侧
# api_candidate_registry._SCHEMA_SUMMARY_PROJECTION_KEYS 同名单）。
_SCHEMA_CONTRACT_KEYS = {
    "record_type", "kind", "status", "error_type", "schema_hash",
    "types", "enums", "inputs", "scalars",
    "type_count", "field_count", "truncated", "summary_bytes",
}


def _parse_gql_query(query, variables=None, operation_name=None, options=None):
    from app.services.api_unified_parser import UnifiedGraphqlParser

    request = {"query": query}
    if operation_name is not None:
        request["operationName"] = operation_name
    if variables is not None:
        request["variables"] = variables
    doc = json.dumps({"url": "https://api.example.com/graphql", "request": request})
    parser = UnifiedGraphqlParser(
        task_id="t23", doc_url="https://api.example.com/graphql",
        allowed_hosts=set(ALLOWED), allowed_flds={"example.com"},
    )
    return parser.parse(doc, options or ParseOptions())


def _parse_sdl_text(text, max_depth=20, enabled=True,
                    doc_url="https://api.example.com/sdl"):
    from app.services.api_unified_parser import UnifiedGraphqlParser

    parser = UnifiedGraphqlParser(
        task_id="t23", doc_url=doc_url,
        allowed_hosts=set(ALLOWED), allowed_flds={"example.com"},
    )
    return parser.parse(text, ParseOptions(
        graphql_schema_enable=enabled, graphql_schema_max_depth=max_depth))


def _schema_candidate(result):
    return next(c for c in result.candidates
                if c.get("record_type") == "graphql_schema_summary")


def _of_type_chain(inner, wrappers):
    node = dict(inner)
    for _ in range(wrappers):
        node = {"kind": "NON_NULL", "name": None, "ofType": node}
    return node


class GraphqlOperationTokenizerTest(unittest.TestCase):
    """P1-06/P1-07：operation 识别必须是深度 0 词法 tokenizer，不是全文正则。

    Review 判定的误报根因：`_OP_RE` 全文搜索 + `_match_brace` 裸计数会把嵌套
    selection 字段名（`{ viewer { query {...} } }`）、`#` 注释、行字符串与块
    字符串里的关键字/花括号当成 operation。
    """

    def test_nested_field_keywords_are_not_operations(self):
        result = _parse_gql_query(
            "query { viewer { query { id } mutation { x } subscription { y } } }")
        self.assertEqual(len(result.endpoints), 1,
                         "P1-06：嵌套 selection 字段名不得各自成 operation")
        endpoint = result.endpoints[0]
        self.assertEqual(endpoint.graphql_operation, "query")
        self.assertEqual(endpoint.graphql_operation_name, "")
        self.assertEqual(endpoint.api_type, "graphql")
        self.assertEqual(len(endpoint.graphql_query_hash), 64)
        self.assertEqual(result.diagnostics.status, "ok")

    def test_brace_first_anonymous_operation(self):
        # 票面冻结：匿名 query（文档以 `{` 开头）产出无名 operation；
        # 前导注释行不影响匿名判定（掩码后首个非空白字符仍是 `{`）。
        result = _parse_gql_query("# leading comment\n{ viewer { id } }")
        self.assertEqual(len(result.endpoints), 1)
        endpoint = result.endpoints[0]
        self.assertEqual(endpoint.graphql_operation, "query")
        self.assertEqual(endpoint.graphql_operation_name, "")
        self.assertEqual(result.diagnostics.status, "ok")

    def test_comment_and_line_string_keywords_skipped(self):
        query = ('# mutation Sneaky { id }\n'
                 'query Get {\n'
                 '  a(reason: "query { fake }")\n'
                 '  b: "{ mutation nope }"\n'
                 '}\n')
        result = _parse_gql_query(query)
        self.assertEqual(len(result.endpoints), 1,
                         "P1-07：注释与字符串中的关键字/花括号不得成 operation")
        self.assertEqual(result.endpoints[0].graphql_operation_name, "Get")
        self.assertEqual(result.diagnostics.status, "ok")

    def test_block_string_content_skipped(self):
        query = ('query Get {\n'
                 '  field(desc: """\n'
                 '    mutation InBlock { x }\n'
                 '  """)\n'
                 '}\n')
        result = _parse_gql_query(query)
        self.assertEqual(len(result.endpoints), 1, "块字符串内容必须整体跳过")
        self.assertEqual(result.endpoints[0].graphql_operation_name, "Get")

    def test_multiple_operations_each_emitted(self):
        query = ("query A {x} mutation B($v: Int!) {y(y: $v)} subscription C {z}")
        result = _parse_gql_query(query)
        by_op = {(e.graphql_operation, e.graphql_operation_name)
                 for e in result.endpoints}
        self.assertEqual(by_op, {("query", "A"), ("mutation", "B"),
                                 ("subscription", "C")})
        self.assertEqual(result.diagnostics.status, "ok")
        adopt = next(e for e in result.endpoints
                     if e.graphql_operation_name == "B")
        self.assertEqual({(p.name, p.type_summary) for p in adopt.parameters},
                         {("v", "Int!")})

    def test_anonymous_query_variable_names_union_values_never(self):
        secret1 = "SECRETVALUE-NOTREAL-123"
        secret2 = "SUBSECRET-NOTREAL-456"
        query = "query { viewer(id: $userId, org: $orgId) { name } }"
        variables = {"userId": secret1, "nested": {"token": secret2},
                     "unusedKey": True}
        result = _parse_gql_query(query, variables=variables)
        self.assertEqual(len(result.endpoints), 1)
        endpoint = result.endpoints[0]
        # 名称来源 = 查询文本 $name 引用 ∪ 请求体 variables 键名（只取名称）。
        self.assertEqual({p.name for p in endpoint.parameters},
                         {"userId", "orgId", "nested", "unusedKey"})
        self.assertEqual(result.diagnostics.status, "ok")
        payload = json.dumps(result.to_dict(), ensure_ascii=False)
        self.assertNotIn(secret1, payload, "variables 取值绝不外流")
        self.assertNotIn(secret2, payload)

    def test_unclosed_operation_degrades_with_complete_ops(self):
        result = _parse_gql_query("query A { x } mutation B { y")
        self.assertEqual(len(result.endpoints), 1,
                         "未闭合的尾部 operation 不得用剩余文本产出")
        self.assertEqual(result.endpoints[0].graphql_operation_name, "A")
        self.assertEqual(result.diagnostics.status, "degraded")
        self.assertEqual(result.diagnostics.error_type, "unclosed_operation")

    def test_unclosed_only_fails_malformed(self):
        result = _parse_gql_query("query B { y")
        self.assertEqual(len(result.endpoints), 0)
        self.assertEqual(result.diagnostics.status, "failed")
        self.assertEqual(result.diagnostics.error_type, "malformed_query")

    def test_operation_limit_degrades_not_silent(self):
        query = "".join("query Q{} {{ f{} }}\n".format(i, i) for i in range(51))
        result = _parse_gql_query(query)
        self.assertEqual(len(result.endpoints), UnifiedOpLimitProbe.LIMIT)
        self.assertEqual(result.diagnostics.status, "degraded")
        self.assertEqual(result.diagnostics.error_type, "operation_limit_exceeded")

    def test_query_truncated_stays_degraded(self):
        # "field\n" 6 字节 ×12000 + 头部 12 字节 = 72012 > _MAX_QUERY_BYTES(65536)。
        query = "query Big {\n" + ("field\n" * 12000)
        result = _parse_gql_query(query)
        self.assertEqual(result.diagnostics.status, "degraded")
        self.assertEqual(result.diagnostics.error_type, "query_truncated")


class UnifiedOpLimitProbe:
    """operation 上限常量镜像（沿用既有 50，禁止测试端漂移）。"""

    LIMIT = 50


class GraphqlSchemaBudgetTest(unittest.TestCase):
    """P0-03（Parser 半边）：Schema 预算命中不得伪装 ok；契约键名/取值域冻结。

    depth 定义冻结（附录A §4.13）：类型引用包装链展开深度——SDL 字段类型
    `!`/`[...]` 嵌套层数、introspection `ofType` 链层数。
    """

    def test_depth_budget_distinguishes_max_depth_option(self):
        sdl = "type Deep {\n  f: [[[Int!]!]!]!\n  g: Int\n}\n"
        strict = _parse_sdl_text(sdl, max_depth=1)
        loose = _parse_sdl_text(sdl, max_depth=20)
        self.assertEqual(strict.diagnostics.status, "degraded",
                         "同一深嵌套输入 depth=1 必须命中预算并 degraded")
        self.assertEqual(loose.diagnostics.status, "ok")
        self.assertEqual(strict.diagnostics.error_type, "schema_depth_exceeded")
        self.assertEqual(loose.diagnostics.error_type, "")
        strict_summary = _schema_candidate(strict)
        loose_summary = _schema_candidate(loose)
        self.assertTrue(strict_summary["truncated"])
        self.assertFalse(loose_summary["truncated"])
        self.assertEqual(strict_summary["status"], "degraded")
        self.assertEqual(strict_summary["error_type"], "schema_depth_exceeded")
        self.assertEqual(loose_summary["status"], "ok")

    def test_introspection_of_type_chain_depth_budget(self):
        payload = json.dumps({"data": {"__schema": {"types": [
            {"name": "Query", "kind": "OBJECT", "fields": [
                {"name": "f", "args": [],
                 "type": _of_type_chain({"kind": "SCALAR", "name": "Int",
                                         "ofType": None}, 4)},
            ]},
        ]}}})
        strict = _parse_sdl_text(payload, max_depth=2,
                                 doc_url="https://api.example.com/graphql")
        loose = _parse_sdl_text(payload, max_depth=20,
                                doc_url="https://api.example.com/graphql")
        self.assertEqual(strict.diagnostics.status, "degraded")
        self.assertEqual(strict.diagnostics.error_type, "schema_depth_exceeded")
        self.assertEqual(loose.diagnostics.status, "ok")
        strict_summary = _schema_candidate(strict)
        self.assertTrue(strict_summary["truncated"])
        self.assertEqual(strict_summary["kind"], "introspection")
        self.assertEqual(strict_summary["status"], "degraded")
        self.assertEqual(_schema_candidate(loose)["status"], "ok")
        self.assertEqual(_schema_candidate(loose)["field_count"], 1)

    def test_type_limit_degrades_with_error_type(self):
        sdl = "".join("scalar S{}\n".format(i) for i in range(501))
        result = _parse_sdl_text(sdl)
        summary = _schema_candidate(result)
        self.assertTrue(summary["truncated"])
        self.assertEqual(summary["status"], "degraded")
        self.assertEqual(summary["error_type"], "schema_type_limit")
        self.assertEqual(len(summary["scalars"]), 500)
        self.assertEqual(result.diagnostics.status, "degraded")
        self.assertEqual(result.diagnostics.error_type, "schema_type_limit")

    def test_field_limit_error_type_surfaced(self):
        big = "type Wide {\n" + "".join(
            "  f{}: Int\n".format(i) for i in range(150)) + "}\n"
        result = _parse_sdl_text(big)
        summary = _schema_candidate(result)
        self.assertTrue(summary["truncated"])
        self.assertEqual(result.diagnostics.status, "degraded")
        self.assertEqual(result.diagnostics.error_type, "schema_field_limit")
        self.assertEqual(summary["error_type"], "schema_field_limit")

    def test_argument_depth_budget(self):
        sdl = "type Q {\n  f(id: [[[[[Int!]!]!]!]!]!): Int\n}\n"
        strict = _parse_sdl_text(sdl, max_depth=3)
        self.assertEqual(strict.diagnostics.status, "degraded")
        self.assertEqual(strict.diagnostics.error_type, "schema_depth_exceeded")
        loose = _parse_sdl_text(sdl, max_depth=20)
        self.assertEqual(loose.diagnostics.status, "ok")

    def test_invalid_sdl_header_fails(self):
        result = _parse_sdl_text("type {\n  x: Int\n}\n")
        self.assertEqual(result.diagnostics.status, "failed")
        self.assertEqual(result.diagnostics.error_type, "sdl_invalid_header")
        summary = _schema_candidate(result)
        self.assertEqual(summary["status"], "failed")
        self.assertEqual(summary["error_type"], "sdl_invalid_header")

    def test_invalid_introspection_fails(self):
        broken_types = json.dumps({"data": {"__schema": {"types": "oops"}}})
        result = _parse_sdl_text(broken_types,
                                 doc_url="https://api.example.com/graphql")
        self.assertEqual(result.diagnostics.status, "failed")
        self.assertEqual(result.diagnostics.error_type,
                         "introspection_types_invalid")
        self.assertEqual(_schema_candidate(result)["status"], "failed")

        missing_schema = json.dumps({"data": {"__schema": None}})
        result2 = _parse_sdl_text(missing_schema,
                                  doc_url="https://api.example.com/graphql")
        self.assertEqual(result2.diagnostics.status, "failed")
        self.assertEqual(result2.diagnostics.error_type,
                         "introspection_schema_missing")

        broken_json = '{"data": {"__schema": {"types": ['
        result3 = _parse_sdl_text(broken_json,
                                  doc_url="https://api.example.com/graphql")
        self.assertEqual(result3.diagnostics.status, "failed")
        self.assertEqual(result3.diagnostics.error_type,
                         "introspection_json_broken")

    def test_schema_default_disabled_still_skipped(self):
        result = _parse_sdl_text("type A {\n  x: Int\n}\n",
                                 max_depth=1, enabled=False)
        self.assertEqual(result.diagnostics.status, "skipped")
        self.assertEqual(result.diagnostics.error_type, "graphql_schema_disabled")
        payload = json.dumps({"data": {"__schema": {"types": "oops"}}})
        result2 = _parse_sdl_text(payload, max_depth=1, enabled=False,
                                  doc_url="https://api.example.com/graphql")
        self.assertEqual(result2.diagnostics.status, "skipped")
        self.assertEqual(result2.diagnostics.error_type, "graphql_schema_disabled")

    def test_contract_keys_domain_and_hash_determinism(self):
        text = (FIXTURES / "graphql_schema.sdl").read_text(encoding="utf-8")
        first = _schema_candidate(_parse_sdl_text(text))
        second = _schema_candidate(_parse_sdl_text(text))
        self.assertEqual(set(first.keys()), _SCHEMA_CONTRACT_KEYS)
        self.assertEqual(first["record_type"], "graphql_schema_summary")
        self.assertEqual(first["kind"], "sdl")
        self.assertEqual(first["status"], "ok")
        self.assertEqual(first["error_type"], "")
        self.assertIsInstance(first["truncated"], bool)
        for key in ("types", "enums", "inputs", "scalars"):
            self.assertIsInstance(first[key], list)
            self.assertTrue(all(isinstance(item, str) for item in first[key]))
        for key in ("type_count", "field_count", "summary_bytes"):
            self.assertIsInstance(first[key], int)
            self.assertNotIsInstance(first[key], bool)
        # 旧字段保留兼容：types/enums/inputs/scalars/truncated 语义不变。
        self.assertEqual(set(first["types"]),
                         {"Owner", "Pet", "Query", "Mutation", "Subscription"})
        self.assertEqual(first["enums"], ["PetStatus"])
        self.assertEqual(first["inputs"], ["PetInput"])
        self.assertEqual(first["scalars"], ["DateTime"])
        self.assertFalse(first["truncated"])
        self.assertEqual(first["type_count"], 8)
        self.assertEqual(first["field_count"], 14)
        self.assertRegex(first["schema_hash"], r"^[0-9a-f]{16}$")
        self.assertEqual(first["schema_hash"], second["schema_hash"],
                         "同一输入两次解析 schema_hash 必须相等（确定性）")
        canonical = json.dumps(
            {k: first[k] for k in ("types", "enums", "inputs", "scalars")},
            ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        self.assertEqual(first["schema_hash"],
                         hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16],
                         "schema_hash = sha256(canonical json)[:16]")
        self.assertGreater(first["summary_bytes"], 0)
        body = {k: v for k, v in first.items() if k != "summary_bytes"}
        self.assertEqual(first["summary_bytes"],
                         len(json.dumps(body, ensure_ascii=False, sort_keys=True,
                                        separators=(",", ":")).encode("utf-8")),
                         "summary_bytes = 契约 json（不含自身键）utf-8 字节数")

    def test_schema_raw_text_and_secret_never_persisted(self):
        secret = "SCHEMARAWSECRET-NOTREAL-999"
        text = ('""" archived doc ' + secret + ' """\n'
                'type T {\n  superSecretField: Int\n}\n')
        result = _parse_sdl_text(text)
        blob = json.dumps({
            "candidates": result.candidates,
            "documents": [d.to_dict() for d in result.documents],
            "diagnostics": result.diagnostics.to_dict(),
        }, ensure_ascii=False)
        self.assertNotIn(secret, blob, "Schema 原文不得进入任何输出面")
        self.assertNotIn("superSecretField", blob, "字段名明细不在冻结契约中")


def _parse_wsdl(name, enabled=True, **kw):
    from app.services.api_unified_parser import UnifiedWsdlParser

    text = (FIXTURES / name).read_text(encoding="utf-8")
    doc_url = kw.pop("doc_url", "https://api.example.com/soap/PetService.wsdl")
    allowed = kw.pop("allowed", ALLOWED)
    option_kw = kw.pop("options", {})
    parser = UnifiedWsdlParser(
        task_id="b7", doc_url=doc_url,
        allowed_hosts=set(allowed), allowed_flds={"example.com"}, **kw,
    )
    return parser.parse(text, ParseOptions(wsdl_parse_enable=enabled, **option_kw))


class WsdlTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = _parse_wsdl("wsdl_service.wsdl")
        cls.by_action = {e.soap_action: e for e in cls.result.endpoints}

    def test_soap_endpoints_match_expectations(self):
        # expectations.wsdl_service.wsdl.soap_endpoints 两个 operation 全命中。
        self.assertEqual(len(self.result.endpoints), 2)
        for e in self.result.endpoints:
            self.assertEqual(e.api_type, "soap")
            self.assertEqual(e.method, "POST")
            self.assertEqual(e.url, "https://api.example.com/soap/PetService")
            self.assertEqual(e.wsdl_service, "PetService")
            self.assertEqual(e.wsdl_port, "PetPort")
            self.assertFalse(e.schema_available, "XSD 未获取，不得伪装完整 Schema")
        get_pet = self.by_action["http://api.example.com/soap/pet/getPet"]
        self.assertEqual(get_pet.operation_id, "getPet")
        list_pets = self.by_action["http://api.example.com/soap/pet/listPets"]
        self.assertEqual(list_pets.operation_id, "listPets")

    def test_input_message_part_summary(self):
        get_pet = self.by_action["http://api.example.com/soap/pet/getPet"]
        params = {(p.name, p.location) for p in get_pet.parameters}
        self.assertIn(("parameters", "body"), params, "input message part 名称摘要")

    def test_same_origin_xsd_import_recorded_not_fetched(self):
        imports = [c for c in self.result.candidates
                   if c.get("record_type") == "wsdl_xsd_import"]
        self.assertTrue(imports, "xsd:import 必须登记为观测候选")
        types_import = next(c for c in imports if c.get("content") == "types.xsd")
        self.assertTrue(types_import["same_origin"])
        self.assertFalse(types_import["fetched"], "§6.4：外部/同源 XSD 默认不请求")
        self.assertGreaterEqual(self.result.diagnostics.unresolved_ref_count, 1)

    def test_diagnostics_degraded_and_document(self):
        self.assertEqual(self.result.diagnostics.status, "degraded")
        self.assertEqual(len(self.result.documents), 1)
        self.assertEqual(self.result.documents[0].type_hint, "wsdl")
        self.assertTrue(self.result.documents[0].input_signature)

    def test_out_of_scope_address_yields_evidence_not_domain(self):
        # Review P0-01：越界 soap:address 只产 out_of_scope_domain 证据候选。
        result = _parse_wsdl("wsdl_service.wsdl", allowed={"other.example.com"})
        self.assertEqual(result.endpoints, [], "endpoints 必须排除越界 host")
        evidence = {c.get("content") for c in result.candidates
                    if c.get("record_type") == "out_of_scope_domain"}
        self.assertIn("api.example.com", evidence)
        self.assertFalse(
            [c for c in result.candidates if c.get("record_type") == "domain"],
            "解析器不得再产出可消费的 domain 候选")
        text = (FIXTURES / "wsdl_service.wsdl").read_text(encoding="utf-8")
        records = _bridge_via_queue(text, "b7p01", ["https://other.example.com"])
        self.assertFalse(
            [p for p in map(_record_pair, records) if p[0] == "domain"],
            "桥接后越界 host 不得落 in-scope domain 记录")

    def test_disabled_returns_skipped(self):
        result = _parse_wsdl("wsdl_service.wsdl", enabled=False)
        self.assertEqual(result.diagnostics.status, "skipped")
        self.assertEqual(result.diagnostics.error_type, "wsdl_disabled")

    def test_size_budget_rejects(self):
        result = _parse_wsdl("wsdl_service.wsdl", options={"max_document_bytes": 1024})
        self.assertEqual(result.diagnostics.status, "failed")
        self.assertEqual(result.diagnostics.error_type, "document_too_large")

    def test_leak_guard(self):
        payload = json.dumps(self.result.to_dict(), ensure_ascii=False)
        for token in FORBIDDEN:
            self.assertNotIn(token, payload)


class WsdlXxeTest(unittest.TestCase):
    def test_dtd_forbidden_no_endpoints_no_network(self):
        result = _parse_wsdl("wsdl_xxe.xml")
        self.assertIn(result.diagnostics.status, ("failed", "degraded"))
        self.assertEqual(result.diagnostics.error_type, "dtd_forbidden")
        self.assertEqual(len(result.endpoints), 0)

    def test_xxe_entity_content_never_leaks(self):
        result = _parse_wsdl("wsdl_xxe.xml")
        payload = json.dumps(result.to_dict(), ensure_ascii=False)
        # 外部实体探测串绝不进入输出（DTD 在解析前即被拒，实体从未展开）。
        self.assertNotIn("xxe-probe", payload)
        self.assertNotIn("pe-probe", payload)


class WsdlHandoffTest(unittest.TestCase):
    def test_xsd_is_not_wsdl_skipped(self):
        result = _parse_wsdl("types.xsd")
        self.assertEqual(result.diagnostics.status, "skipped")
        self.assertEqual(result.diagnostics.error_type, "not_wsdl_document")

    def test_openapi_parser_skips_xml_for_wsdl_chain(self):
        # 链式分发前置修复：openapi 解析器对 XML 必须 skip（不得 failed 截断链）。
        from app.services.api_unified_parser import UnifiedOpenApiParser

        text = (FIXTURES / "wsdl_service.wsdl").read_text(encoding="utf-8")
        result = UnifiedOpenApiParser(
            task_id="b7", doc_url="https://api.example.com/soap/PetService.wsdl",
            allowed_hosts=set(ALLOWED)).parse(text)
        self.assertEqual(result.diagnostics.status, "skipped")


class QueueWsdlChainTest(unittest.TestCase):
    def test_queue_dispatches_wsdl_and_bridges_soap_records(self):
        from app.services.api_doc_scan import ApiDocScanner
        from app.services.api_candidate_registry import (
            ApiCandidateRegistry,
            ApiDocumentQueue,
        )
        from app.services.api_unified_models import UNIFIED_API_CONFIG_DEFAULTS

        text = (FIXTURES / "wsdl_service.wsdl").read_text(encoding="utf-8")
        config = dict(UNIFIED_API_CONFIG_DEFAULTS)
        config["API_UNIFIED_ENABLE"] = True
        scanner = ApiDocScanner(sites=["https://api.example.com"], wih_records=[])
        registry = ApiCandidateRegistry(task_id="b7q")
        wsdl_url = "https://api.example.com/soap/PetService.wsdl"
        registry.register_document(wsdl_url, source="seed", type_hint="wsdl")
        queue = ApiDocumentQueue(
            scanner=scanner, registry=registry, context=None, config=config,
            fetch_fn=lambda doc: text if "PetService.wsdl" in doc.url else "",
        )
        queue.run()
        soap = [e for e in registry.snapshot_endpoints() if e["api_type"] == "soap"]
        self.assertEqual(len(soap), 2)
        self.assertEqual(
            {e["soap_action"] for e in soap},
            {"http://api.example.com/soap/pet/getPet",
             "http://api.example.com/soap/pet/listPets"})
        contents = {str(getattr(r, "content", "") or "") for r in scanner.records}
        self.assertIn("POST https://api.example.com/soap/PetService", contents)
        # P1-08：目标 wsdl 文档真实 parsed + 统一失败收口不变式（同 graphql/postman 用例）。
        self.assertEqual(registry.document(wsdl_url).status, "parsed")
        self.assertGreaterEqual(queue.parse_success_count, 1)
        _assert_queue_failure_convergence(self, queue)

    def test_queue_marks_xxe_document_failed(self):
        from app.services.api_doc_scan import ApiDocScanner
        from app.services.api_candidate_registry import (
            ApiCandidateRegistry,
            ApiDocumentQueue,
        )
        from app.services.api_unified_models import UNIFIED_API_CONFIG_DEFAULTS

        text = (FIXTURES / "wsdl_xxe.xml").read_text(encoding="utf-8")
        config = dict(UNIFIED_API_CONFIG_DEFAULTS)
        config["API_UNIFIED_ENABLE"] = True
        scanner = ApiDocScanner(sites=["https://api.example.com"], wih_records=[])
        registry = ApiCandidateRegistry(task_id="b7x")
        xxe_url = "https://api.example.com/soap/Xxe.wsdl"
        registry.register_document(xxe_url, source="seed", type_hint="wsdl")
        queue = ApiDocumentQueue(
            scanner=scanner, registry=registry, context=None, config=config,
            fetch_fn=lambda doc: text if "Xxe.wsdl" in doc.url else "",
        )
        queue.run()
        doc = registry.document(xxe_url)
        self.assertEqual(doc.status, "failed")
        self.assertEqual(doc.error_type, "dtd_forbidden")
        self.assertEqual([e for e in registry.snapshot_endpoints()], [])
        for record in scanner.records:
            self.assertNotIn("xxe-probe", str(getattr(record, "content", "") or ""))


class QueueGraphqlSchemaChainTest(unittest.TestCase):
    """P0-04 必补测试（Review 轮 2 / §7.3）：Schema 面经真实 ApiDocumentQueue 闭环。

    直接 Parser 测试只冻结生产侧形态；本类锁定消费侧接线——
    - SDL/introspection 开启 Schema 后经队列：摘要进 registry 有界诊断面、
      状态计数进 context metrics、`api_document_unbridged_candidate_total`
      对该类型归零（轮 1 登记的观测锚）；
    - 结构性 Schema 失败：文档终态 failed（绝不被标 parsed/covered 伪装成功）、
      计入统一失败收口（P1-08 口径）、诊断面零驻留（failed 不桥接候选）、
      记录面零产出。
    重投幂等由账本 covered 跳过承载（格式无关，test_api_candidate_registry
    ::test_ledger_covered_resumed_skip 已锁语义），此处不重复。
    """

    def _run_queue(self, text, task_id, schema_enable, context=None, match="schema"):
        from app.services.api_doc_scan import ApiDocScanner
        from app.services.api_candidate_registry import (
            ApiCandidateRegistry,
            ApiDocumentQueue,
        )
        from app.services.api_unified_models import UNIFIED_API_CONFIG_DEFAULTS

        config = dict(UNIFIED_API_CONFIG_DEFAULTS)
        config["API_UNIFIED_ENABLE"] = True
        config["GRAPHQL_SCHEMA_ENABLE"] = schema_enable
        scanner = ApiDocScanner(sites=["https://api.example.com"], wih_records=[])
        registry = ApiCandidateRegistry(task_id=task_id)
        schema_url = "https://api.example.com/graphql/schema.sdl"
        registry.register_document(schema_url, source="seed", type_hint="graphql")
        queue = ApiDocumentQueue(
            scanner=scanner, registry=registry, context=context, config=config,
            fetch_fn=lambda doc: text if match in doc.url else "",
        )
        queue.run()
        return queue, registry, schema_url

    def test_sdl_through_real_queue_populates_diagnostics_channel(self):
        from app.services.discovery_context import DiscoveryContext

        text = (FIXTURES / "graphql_schema.sdl").read_text(encoding="utf-8")
        context = DiscoveryContext(task_id="b8schema1")
        queue, registry, schema_url = self._run_queue(
            text, "b8schema1", schema_enable=True, context=context, match="schema.sdl")
        self.assertEqual(registry.document(schema_url).status, "parsed")
        entries = registry.schema_diagnostics
        self.assertEqual(len(entries), 1, "真实解析链的 Schema 摘要必须落诊断面")
        entry = entries[0]
        self.assertEqual(entry["kind"], "sdl")
        self.assertEqual(entry["status"], "ok")
        self.assertEqual(
            set(entry["types"]), {"Owner", "Pet", "Query", "Mutation", "Subscription"})
        self.assertGreaterEqual(entry["summary_bytes"], 1)
        self.assertEqual(
            int(context.metrics.get("graphql_schema_success_total", 0) or 0), 1)
        self.assertEqual(
            int(context.metrics.get("api_document_schema_diagnostics_total", 0) or 0), 1,
            "metrics 只放整数计数，摘要本体不外摆")
        self.assertEqual(
            int(context.metrics.get("api_document_unbridged_candidate_total", 0) or 0), 0,
            "轮 1 观测锚：graphql_schema_summary 接管后 unbridged 归零")
        self.assertEqual(queue.parse_failed_count, queue.fetch_count - queue.parse_success_count)

    def test_introspection_through_real_queue_populates_diagnostics_channel(self):
        from app.services.discovery_context import DiscoveryContext

        payload = json.dumps({"data": {"__schema": {"types": [
            {"name": "Pet", "kind": "OBJECT", "fields": [{"name": "id", "type": {"kind": "SCALAR"}}]},
            {"name": "PetStatus", "kind": "ENUM"}]}}})
        context = DiscoveryContext(task_id="b8schema2")
        _queue, registry, _url = self._run_queue(
            payload, "b8schema2", schema_enable=True, context=context, match="schema.sdl")
        entries = [e for e in registry.schema_diagnostics if e["kind"] == "introspection"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["status"], "ok")
        self.assertEqual(entries[0]["types"], ["Pet"])
        self.assertEqual(entries[0]["enums"], ["PetStatus"])
        self.assertEqual(
            int(context.metrics.get("graphql_schema_success_total", 0) or 0), 1)
        self.assertEqual(
            int(context.metrics.get("api_document_unbridged_candidate_total", 0) or 0), 0)

    def test_broken_sdl_fails_document_and_never_marks_success(self):
        text = "type {\n  leaked: Int\n}\n"
        queue, registry, schema_url = self._run_queue(
            text, "b8schema3", schema_enable=True, match="schema.sdl")
        doc = registry.document(schema_url)
        self.assertEqual(doc.status, "failed", "结构性 Schema 失败不得伪装 parsed/covered")
        self.assertEqual(doc.error_type, "sdl_invalid_header")
        self.assertEqual(registry.schema_diagnostics, [], "failed 不桥接候选，诊断面零驻留")
        self.assertEqual(registry.snapshot_endpoints(), [])
        self.assertFalse(queue.scanner.records, "failed 文档不得产出旧记录面")
        self.assertGreaterEqual(queue.parse_failed_count, 1, "P1-08 统一失败收口含本路径")


def _evidence_openapi_doc(server_url):
    return json.dumps({
        "openapi": "3.0.0",
        "info": {"title": "scope", "version": "1.0"},
        "servers": [{"url": server_url}],
        "paths": {"/pets": {"get": {"responses": {"200": {"description": "ok"}}}}},
    })


def _evidence_graphql_doc(base_url):
    return json.dumps({"url": base_url, "query": "query GetPet { pet { id } }"})


_EVIDENCE_WSDL_TMPL = """<?xml version="1.0" encoding="UTF-8"?>
<definitions name="Svc" xmlns="http://schemas.xmlsoap.org/wsdl/"
             xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
             xmlns:tns="http://api.example.com/tns"
             targetNamespace="http://api.example.com/tns">
  <portType name="SvcPortType"><operation name="ping"/></portType>
  <binding name="SvcBinding" type="tns:SvcPortType">
    <soap:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>
    <operation name="ping"><soap:operation soapAction="urn:ping"/></operation>
  </binding>
  <service name="SvcService">
    <port name="SvcPort" binding="tns:SvcBinding">
      <soap:address location="{location}"/>
    </port>
  </service>
</definitions>"""


class OutOfScopeEvidenceTest(unittest.TestCase):
    """Review P0-01 必补测试：越界 host 有证据但不入 in-scope domain 资产。

    同-Fld（blue.example.com）/ 跨-Fld（evil.com）/ 非法 host / 模板 host
    四种形态分别过 openapi + graphql + wsdl 三条解析路径；统一断言口径：
    - 仅产 out_of_scope_domain 证据候选（content=host、source=doc_url 追溯）；
    - 绝不产 record_type=domain 候选；
    - endpoints 为零（越界 host 不产生任何端点资产）。
    桥接后"无 in-scope domain 记录 + 指标计数"由三个 *_yields_evidence_not_domain
    用例与 test_api_candidate_registry.py 的 OutOfScopeDomainBridgeTest 覆盖。
    """

    CASES = (
        ("same_fld", "https://blue.example.com", "blue.example.com"),
        ("cross_fld", "https://evil.com", "evil.com"),
        ("invalid_host", "https://in valid.example.com", "in valid.example.com"),
        ("template_host", "https://{env}.example.com", "{env}.example.com"),
    )

    def _assert_evidence_only(self, result, expected_host):
        evidence = [c for c in result.candidates
                    if c.get("record_type") == "out_of_scope_domain"]
        self.assertEqual({c.get("content") for c in evidence}, {expected_host},
                         "越界 host 必须保留为证据（不静默丢弃发现线索）")
        for item in evidence:
            self.assertTrue(item.get("source"), "证据候选必须带 source=doc_url 追溯")
        self.assertFalse(
            [c for c in result.candidates if c.get("record_type") == "domain"],
            "不得产出可消费的 domain 候选（P0-01）")
        self.assertEqual(result.endpoints, [], "越界 host 不得产生端点资产")

    def test_openapi_out_of_scope_evidence(self):
        from app.services.api_unified_parser import UnifiedOpenApiParser

        for name, base, expected_host in self.CASES:
            with self.subTest(case=name):
                parser = UnifiedOpenApiParser(
                    task_id="p01", doc_url=DOC_URL,
                    allowed_hosts=set(ALLOWED), allowed_flds={"example.com"})
                result = parser.parse(
                    _evidence_openapi_doc(base + "/v1"), ParseOptions())
                self._assert_evidence_only(result, expected_host)

    def test_graphql_out_of_scope_evidence(self):
        from app.services.api_unified_parser import UnifiedGraphqlParser

        for name, base, expected_host in self.CASES:
            with self.subTest(case=name):
                parser = UnifiedGraphqlParser(
                    task_id="p01", doc_url=DOC_URL,
                    allowed_hosts=set(ALLOWED), allowed_flds={"example.com"})
                result = parser.parse(
                    _evidence_graphql_doc(base + "/graphql"), ParseOptions())
                self._assert_evidence_only(result, expected_host)

    def test_wsdl_out_of_scope_evidence(self):
        from app.services.api_unified_parser import UnifiedWsdlParser

        for name, base, expected_host in self.CASES:
            with self.subTest(case=name):
                parser = UnifiedWsdlParser(
                    task_id="p01", doc_url="https://api.example.com/soap/Svc.wsdl",
                    allowed_hosts=set(ALLOWED), allowed_flds={"example.com"})
                result = parser.parse(
                    _EVIDENCE_WSDL_TMPL.format(location=base + "/soap"),
                    ParseOptions(wsdl_parse_enable=True))
                self._assert_evidence_only(result, expected_host)


if __name__ == "__main__":
    unittest.main()
