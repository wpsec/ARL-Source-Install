"""计划 6 第 1 批：统一 API 数据契约与 golden corpus 回归测试。

覆盖四类不变量：
- schema 字段面与冻结枚举一致（含配置默认值）；
- 幂等键语义（文档候选、Endpoint 资产、请求观察）；
- 脱敏不变量（敏感键守卫、ParseResult 输出守卫、corpus 泄露样本隔离）；
- golden corpus 结构与现行 ApiDocScanner 基线不漂移。
"""

import json
import sys
import types
import unittest
import xml.etree.ElementTree as ET
from collections import deque
from dataclasses import fields
from pathlib import Path

ARL_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ARL_ROOT / "test" / "fixtures" / "api_unified"
EXPECTED = FIXTURES / "expected"

if str(ARL_ROOT) not in sys.path:
    sys.path.insert(0, str(ARL_ROOT))


def _stub_packages():
    """绕过 app.services 包级 __init__（NPoC 等重依赖），只加载纯 stdlib 子模块。

    已有真实包时保持不动；桩包的 __path__ 指向真实目录，后续子模块导入可正常解析。
    """

    app = sys.modules.get("app")
    if app is None or not hasattr(app, "__path__"):
        app = types.ModuleType("app")
        app.__path__ = [str(ARL_ROOT / "app")]
        sys.modules["app"] = app
    services = sys.modules.get("app.services")
    if services is None:
        services = types.ModuleType("app.services")
        services.__path__ = [str(ARL_ROOT / "app" / "services")]
        sys.modules["app.services"] = services


_stub_packages()

from app.services import api_unified_models as m  # noqa: E402


def _fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _make_scanner():
    from app.services.api_doc_scan import ApiDocScanner

    scanner = ApiDocScanner(
        sites=["https://api.example.com"],
        wih_records=[],
        waf_guard=None,
        discovery_context=None,
    )
    scanner.allowed_hosts = {"api.example.com"}
    scanner.allowed_flds = {"example.com"}
    return scanner


def _scanner_records(scanner):
    return sorted(
        (
            {
                "record_type": record.recordType,
                "content": record.content,
                "source": record.source,
                "site": record.site,
                "fnv_hash": str(record.fnv_hash),
            }
            for record in scanner.records
        ),
        key=lambda item: (item["record_type"], item["content"], item["source"]),
    )


class SchemaFreezeTest(unittest.TestCase):
    def test_endpoint_schema_fields(self):
        actual = sorted(f.name for f in fields(m.UnifiedApiEndpoint))
        self.assertEqual(actual, sorted(m.API_ENDPOINT_SCHEMA_FIELDS))
        # to_dict 输出顺序即冻结的语义顺序（计划6 §4.3）。
        self.assertEqual(
            list(m.UnifiedApiEndpoint(url="https://api.example.com/pets").to_dict().keys()),
            list(m.API_ENDPOINT_SCHEMA_FIELDS),
        )

    def test_document_candidate_schema_fields(self):
        actual = sorted(f.name for f in fields(m.ApiDocumentCandidate))
        self.assertEqual(actual, sorted(m.API_DOCUMENT_SCHEMA_FIELDS))
        candidate = m.ApiDocumentCandidate(task_id="t1", url="https://api.example.com/v3/api-docs")
        self.assertEqual(list(candidate.to_dict().keys()), list(m.API_DOCUMENT_SCHEMA_FIELDS))

    def test_diagnostics_and_result_shape(self):
        diagnostics = m.ParseDiagnostics(parser="openapi")
        self.assertEqual(
            list(diagnostics.to_dict().keys()), list(m.PARSE_DIAGNOSTICS_FIELDS)
        )
        result = m.ParseResult(parser="openapi")
        self.assertEqual(list(result.to_dict().keys()), list(m.PARSE_RESULT_OUTPUT_KEYS))

    def test_config_defaults_match_plan(self):
        self.assertFalse(m.UNIFIED_API_CONFIG_DEFAULTS["API_UNIFIED_ENABLE"])
        self.assertTrue(m.UNIFIED_API_CONFIG_DEFAULTS["API_UNIFIED_FALLBACK_ENABLE"])
        self.assertFalse(m.UNIFIED_API_CONFIG_DEFAULTS["API_EXTERNAL_REF_ENABLE"])
        self.assertFalse(m.UNIFIED_API_CONFIG_DEFAULTS["GRAPHQL_SCHEMA_ENABLE"])
        self.assertTrue(m.UNIFIED_API_CONFIG_DEFAULTS["WSDL_PARSE_ENABLE"])
        self.assertEqual(m.UNIFIED_API_CONFIG_DEFAULTS["API_DOCUMENT_MAX_DEPTH"], 3)
        self.assertEqual(m.UNIFIED_API_CONFIG_DEFAULTS["API_DOCUMENT_MAX_SIZE_BYTES"], 5242880)
        options = m.ParseOptions()
        self.assertFalse(options.external_ref_enable)
        self.assertFalse(options.graphql_schema_enable)

    def test_status_enums(self):
        for status in m.API_DOCUMENT_STATUSES:
            m.ApiDocumentCandidate(
                task_id="t", url="https://api.example.com/x", status=status
            )
        for status in m.API_ENDPOINT_STATUSES:
            m.UnifiedApiEndpoint(url="https://api.example.com/x", status=status)
        with self.assertRaises(ValueError):
            m.ApiDocumentCandidate(task_id="t", url="https://api.example.com/x", status="probed")
        with self.assertRaises(ValueError):
            m.UnifiedApiEndpoint(url="https://api.example.com/x", status="parsed")


class IdempotencyKeyTest(unittest.TestCase):
    def test_document_key_normalizes_url_and_separates_profile(self):
        base = m.ApiDocumentCandidate(
            task_id="t1",
            url="HTTPS://API.Example.COM:443/v3/api-docs?x=1#frag",
            input_signature="sig-a",
            request_profile="api_doc",
        )
        twin = m.ApiDocumentCandidate(
            task_id="t1",
            url="https://api.example.com/v3/api-docs?x=1",
            input_signature="sig-a",
            request_profile="api_doc",
        )
        other_profile = m.ApiDocumentCandidate(
            task_id="t1",
            url="https://api.example.com/v3/api-docs?x=1",
            input_signature="sig-a",
        )
        other_profile.request_profile = "browser"
        self.assertEqual(base.idempotency_key, twin.idempotency_key)
        self.assertNotEqual(base.idempotency_key, other_profile.idempotency_key)

    def test_endpoint_keys_separate_method_and_task(self):
        get_ep = m.UnifiedApiEndpoint(url="https://api.example.com/pets", method="GET")
        post_ep = m.UnifiedApiEndpoint(url="https://api.example.com/pets", method="POST")
        self.assertNotEqual(get_ep.idempotency_key, post_ep.idempotency_key)
        self.assertNotEqual(
            get_ep.scoped_idempotency_key("task-a"), get_ep.scoped_idempotency_key("task-b")
        )

    def test_auth_context_not_merged_in_observation(self):
        ep = m.UnifiedApiEndpoint(url="https://api.example.com/pets", method="GET")
        first = ep.probe_observation_key(auth_profile="user-a")
        second = ep.probe_observation_key(auth_profile="user-b")
        third = ep.probe_observation_key(
            request_profile="api_doc", auth_profile="user-a"
        )
        self.assertEqual(len({first, second, third}), 3)

    def test_add_source_merges_without_duplicate(self):
        ep = m.UnifiedApiEndpoint(url="https://api.example.com/pets", source="page_intel")
        self.assertTrue(ep.add_source("js_intel"))
        self.assertFalse(ep.add_source("js_intel"))
        self.assertEqual(ep.sources, {"page_intel", "js_intel"})


class RedactionTest(unittest.TestCase):
    def test_parameter_spec_has_no_value_channel(self):
        parameter = m.ParameterSpec(name="sessionId", location="cookie", type_summary="string")
        self.assertNotIn("value", parameter.to_dict())
        self.assertNotIn("example", parameter.to_dict())
        for attribute in ("value", "example", "default"):
            self.assertFalse(hasattr(parameter, attribute))

    def test_security_summary_maps_scheme_type(self):
        summary = m.SecurityRequirementSummary(name="BearerAuth", type="http:bearer")
        self.assertEqual(summary.to_dict(), {"name": "BearerAuth", "type": "bearer"})
        unknown = m.SecurityRequirementSummary(name="X", type="weird")
        self.assertEqual(unknown.type, "unknown")

    def test_find_sensitive_keys_detects_nested_leaks(self):
        payload = {
            "request_body_schema": {"example": {"Authorization": "Bearer abc"}},
            "parameters": [{"name": "token", "value": "x"}],
        }
        hits = m.find_sensitive_keys(payload)
        self.assertTrue(any("Authorization" in path for path in hits))
        self.assertTrue(any("token" in path for path in hits))
        self.assertEqual(m.find_sensitive_keys({"cookie": "", "nested": {"apikey": None}}), [])

    def test_redact_assignment_text(self):
        redacted = m.redact_assignment_text(
            "Cookie: session=abc123 ; Authorization=Bearer-xyz"
        )
        self.assertNotIn("abc123", redacted)
        self.assertNotIn("Bearer-xyz", redacted)
        self.assertIn("<redacted>", redacted)

    def test_parse_result_guard_raises_on_leak(self):
        endpoint = m.UnifiedApiEndpoint(
            url="https://api.example.com/pets",
            response_schema={"example": {"Authorization": "Bearer leak"}},
        )
        result = m.ParseResult(parser="openapi", endpoints=[endpoint])
        with self.assertRaises(ValueError):
            result.to_dict()

    def test_endpoint_from_corpus_inputs_serializes_clean(self):
        # 用 corpus 中出现的敏感字面量构造，模型序列化必须不含原值。
        endpoint = m.UnifiedApiEndpoint(
            url="https://api.example.com/v1/users",
            method="GET",
            parent_document="https://api.example.com/postman.json",
            source=m.redact_assignment_text("Authorization: Bearer POSTMANLEAKTOKEN123"),
            security_requirements=[m.SecurityRequirementSummary(name="Authorization", type="http:basic")],
        )
        payload = json.dumps(endpoint.to_dict())
        self.assertNotIn("POSTMANLEAKTOKEN123", payload)
        self.assertEqual(m.find_sensitive_keys(endpoint.to_dict()), [])


class LegacyCompatTest(unittest.TestCase):
    def test_rest_record_shape_matches_api_doc_scan(self):
        endpoint = m.UnifiedApiEndpoint(
            url="https://api.example.com/v1/pets",
            method="GET",
            parent_document="https://api.example.com/v3/api-docs",
        )
        records = endpoint.to_legacy_records()
        contents = {item["record_type"]: item["content"] for item in records}
        self.assertEqual(contents["api_doc_endpoint"], "GET https://api.example.com/v1/pets")
        self.assertEqual(contents["urlfinder_url"], "https://api.example.com/v1/pets")
        for item in records:
            self.assertEqual(item["source"], "https://api.example.com/v3/api-docs")

    def test_graphql_record_shape(self):
        records = m.UnifiedApiEndpoint(
            url="https://api.example.com/graphql",
            method="POST",
            api_type="graphql",
            graphql_operation="query",
            graphql_operation_name="GetPet",
        ).to_legacy_records()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["record_type"], "graphql")
        self.assertEqual(records[0]["content"], "POST https://api.example.com/graphql")

    def test_soap_uses_endpoint_record(self):
        records = m.UnifiedApiEndpoint(
            url="https://api.example.com/soap/PetService",
            method="POST",
            api_type="soap",
            soap_action="http://api.example.com/soap/pet/getPet",
        ).to_legacy_records()
        self.assertIn("api_doc_endpoint", {item["record_type"] for item in records})


class CorpusStructureTest(unittest.TestCase):
    def test_json_fixtures_load(self):
        for name in (
            "openapi3_petstore.json",
            "swagger2_petstore.json",
            "postman_collection.json",
            "graphql_request.json",
            "external_ref_openapi.json",
            "expected/current_parser_baseline.json",
            "expected/unified_target_expectations.json",
        ):
            json.loads(_fixture_text(name))

    def test_yaml_mirror_equals_json(self):
        import yaml

        self.assertEqual(
            json.loads(_fixture_text("openapi3_petstore.json")),
            yaml.safe_load(_fixture_text("openapi3_petstore.yaml")),
        )

    def test_wsdl_parses_and_has_operations(self):
        root = ET.fromstring(_fixture_text("wsdl_service.wsdl"))
        names = {element.tag.rpartition("}")[2] for element in root.iter()}
        self.assertIn("definitions", names)
        self.assertIn("binding", names)
        self.assertIn("service", names)
        ET.fromstring(_fixture_text("types.xsd"))

    def test_xxe_fixture_fails_entity_free_parsing(self):
        # 标准库不解析外部实体：未定义实体必须直接报错，统一 Parser 映射 failed/degraded。
        with self.assertRaises(ET.ParseError):
            ET.fromstring(_fixture_text("wsdl_xxe.xml"))

    def test_invalid_json_and_deep_nesting_parse_behavior(self):
        with self.assertRaises(ValueError):
            json.loads(_fixture_text("invalid_json.json"))
        payload = json.loads(_fixture_text("deep_nesting.json"))
        depth = 0
        while isinstance(payload, dict) and "nested" in payload:
            payload = payload["nested"]
            depth += 1
        self.assertGreaterEqual(depth, 300)


class CurrentParserBaselineTest(unittest.TestCase):
    """现行 ApiDocScanner 基线漂移检测：corpus 或现行解析变更后须重跑生成脚本。"""

    DOC_URLS = {
        "openapi3_petstore.json": "https://api.example.com/v3/api-docs",
        "openapi3_petstore.yaml": "https://api.example.com/openapi3_petstore.yaml",
        "swagger2_petstore.json": "https://api.example.com/v2/api-docs",
        "postman_collection.json": "https://api.example.com/postman.json",
    }

    def test_baseline_matches_recomputation(self):
        committed = json.loads(_fixture_text("expected/current_parser_baseline.json"))
        for name, doc_url in self.DOC_URLS.items():
            scanner = _make_scanner()
            scanner._parse_doc(doc_url, _fixture_text(name), deque())
            with self.subTest(fixture=name):
                self.assertEqual(
                    _scanner_records(scanner),
                    committed["fixtures"][name]["records"],
                    "baseline drift: rerun scripts/api-unified-golden.py",
                )

    def test_baseline_free_of_leak_literals(self):
        committed = json.loads(_fixture_text("expected/current_parser_baseline.json"))
        expectations = json.loads(_fixture_text("expected/unified_target_expectations.json"))
        forbidden = expectations["forbidden_substrings"]
        serialized = json.dumps(committed)
        for token in forbidden:
            self.assertNotIn(token, serialized)

    def test_known_gaps_documented_in_expectations(self):
        # 现行解析丢弃 {petId}/:id 模板端点：基线不含、目标期望含，差异面即第 4/5 批验收项。
        committed = json.loads(_fixture_text("expected/current_parser_baseline.json"))
        baseline_contents = {
            item["content"] for item in committed["fixtures"]["openapi3_petstore.json"]["records"]
        }
        expectations = json.loads(_fixture_text("expected/unified_target_expectations.json"))
        must_include = expectations["fixtures"]["openapi3_petstore.json"]["must_include_endpoints"]
        for endpoint in must_include:
            if "{" in endpoint:
                self.assertNotIn(endpoint, baseline_contents)
                continue
            self.assertIn(endpoint, baseline_contents)

    def test_servers_and_swagger_in_scope_endpoint_equivalence(self):
        # 计划6 §6.1：servers 与 host/basePath/schemes 组合在范围内主机上结果一致。
        committed = json.loads(_fixture_text("expected/current_parser_baseline.json"))
        openapi = {
            item["content"]
            for item in committed["fixtures"]["openapi3_petstore.json"]["records"]
            if item["record_type"] == "api_doc_endpoint"
        }
        swagger = {
            item["content"]
            for item in committed["fixtures"]["swagger2_petstore.json"]["records"]
            if item["record_type"] == "api_doc_endpoint"
        }
        self.assertEqual(openapi, swagger)


class GraphQLHashTest(unittest.TestCase):
    def test_query_hash_stable_under_whitespace(self):
        request = json.loads(_fixture_text("graphql_request.json"))
        first = m.graphql_query_hash(request["request"]["query"])
        second = m.graphql_query_hash(
            "  ".join(str(request["request"]["query"]).split())
        )
        self.assertEqual(first, second)
        self.assertEqual(len(first), 64)

    def test_operation_enum_rejects_unknown_words(self):
        with self.assertRaises(ValueError):
            m.UnifiedApiEndpoint(
                url="https://api.example.com/graphql",
                api_type="graphql",
                graphql_operation="resolve",
            )


if __name__ == "__main__":
    unittest.main()
