"""计划 6 第 4 批：UnifiedOpenApiParser 回归。

验收面（unified_target_expectations.json + 附录A §五）：
- openapi3：G1 模板端点保留、参数四位置、auth_hint、循环/未解析引用标记、
  越界 server → domain 候选、诊断 degraded≠failed；
- swagger2：同范围内端点集合与 openapi3 一致、formData、basic auth；
- external_ref：外部 $ref 不获取、unresolved 计数、状态非 ok；
- invalid/deep_nesting：显式 failed 且零端点（G4 不伪装"无 API"）；
- 格式外（postman/graphql）：skipped 交回 legacy；
- 下限：baseline 记录集 ⊆ 统一输出（含队列桥接面）。
"""

import json
import sys
import types
import unittest
from pathlib import Path

ARL_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ARL_ROOT / "test" / "fixtures" / "api_unified"

if str(ARL_ROOT) not in sys.path:
    sys.path.insert(0, str(ARL_ROOT))


def _ensure_app_package():
    app = sys.modules.get("app")
    if app is None or not hasattr(app, "__path__"):
        app = types.ModuleType("app")
        app.__path__ = [str(ARL_ROOT / "app")]
        sys.modules["app"] = app


_ensure_app_package()

from app.services.api_unified_parser import UnifiedOpenApiParser  # noqa: E402
from app.services.api_unified_models import ParseOptions  # noqa: E402

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

    def test_out_of_scope_server_yields_domain_candidate(self):
        domains = {
            item.get("content") for item in self.result.candidates
            if item.get("record_type") == "domain"
        }
        self.assertIn("blue.example.com", domains)
        self.assertTrue(all(
            e.url.startswith("https://api.example.com") for e in self.result.endpoints))

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
        self.assertTrue(doc.error_type)
        self.assertEqual(queue.parse_failed_count, 1)


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
        queue = ApiDocumentQueue(
            scanner=scanner, registry=registry, context=None, config=config,
            fetch_fn=lambda doc: text if "postman" in doc.url else "",
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
        self.assertEqual(queue.parse_failed_count, 0)


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

    def test_out_of_scope_base_yields_domain_candidate(self):
        result = _parse_graphql("graphql_request.json", allowed={"other.example.com"})
        self.assertEqual(result.endpoints, [])
        domains = {c.get("content") for c in result.candidates
                   if c.get("record_type") == "domain"}
        self.assertIn("api.example.com", domains)

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
        queue = ApiDocumentQueue(
            scanner=scanner, registry=registry, context=None, config=config,
            fetch_fn=lambda doc: text if "api-docs" in doc.url else "",
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
        self.assertEqual(queue.parse_failed_count, 0)
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


if __name__ == "__main__":
    unittest.main()
