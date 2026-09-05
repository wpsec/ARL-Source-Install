"""计划 6 第 1 批：统一 API 数据契约与 golden corpus 回归测试。

覆盖四类不变量：
- schema 字段面与冻结枚举一致（含配置默认值）；
- 幂等键语义（文档候选、Endpoint 资产、请求观察）；
- 脱敏不变量（敏感键守卫、ParseResult 输出守卫、corpus 泄露样本隔离）；
- golden corpus 结构与现行 ApiDocScanner 基线不漂移。
"""

import contextlib
import json
import sys
import unittest
import xml.etree.ElementTree as ET
from collections import deque
from dataclasses import fields
from pathlib import Path
from unittest import mock

ARL_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ARL_ROOT / "test" / "fixtures" / "api_unified"
EXPECTED = FIXTURES / "expected"

if str(ARL_ROOT) not in sys.path:
    sys.path.insert(0, str(ARL_ROOT))

from test._api_unified_bootstrap import (  # noqa: E402
    assert_no_shell_pollution,
    load_unified_modules,
)

# 模块级捕获真实引用:既有用例可能在 collection/运行期注入 fake app.utils/app.services
# 且不还原(本地环境尤为明显),运行期再 import 会取到被污染的模块。
# bootstrap 在临时桩窗口内完成子模块加载,随后还原 app / app.services 槽位,
# 不留空壳桩污染同进程既有用例(Review P2-13)。
_captured = load_unified_modules()
assert_no_shell_pollution()

_app_utils = _captured["app.utils"]
_api_doc_module = _captured["app.services.api_doc_scan"]
m = _captured["app.services.api_unified_models"]


@contextlib.contextmanager
def _safe_domain_fns():
    """app.utils.is_valid_domain/get_fld 内部按模块名重导入,受他用例假模块污染。

    这里在被污染的函数被调用前,直接在真实模块对象上替换实现,与网络无关、可还原。
    """

    with mock.patch.object(
        _app_utils, "is_valid_domain", lambda value: "." in str(value or "")
    ), mock.patch.object(_app_utils, "get_fld", lambda host: "example.com"):
        yield


def _fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _make_scanner():
    with _safe_domain_fns():
        scanner = _api_doc_module.ApiDocScanner(
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

    def test_endpoint_key_includes_api_type(self):
        # P1-12（附录A §4.13/§4.14，T8 实施）：同 URL+method+signature 的
        # rest/graphql/soap 资产不得互相吞并；api_type 真实进入键拼接形态。
        same = "a" * 32
        rest = m.UnifiedApiEndpoint(
            url="https://api.example.com/gql", method="POST",
            api_type="rest", input_signature=same)
        graphql = m.UnifiedApiEndpoint(
            url="https://api.example.com/gql", method="POST",
            api_type="graphql", input_signature=same)
        soap = m.UnifiedApiEndpoint(
            url="https://api.example.com/gql", method="POST",
            api_type="soap", input_signature=same)
        self.assertNotEqual(rest.idempotency_key, graphql.idempotency_key)
        self.assertNotEqual(graphql.idempotency_key, soap.idempotency_key)
        self.assertIn("|graphql|", graphql.idempotency_key)
        twin = m.UnifiedApiEndpoint(
            url="https://api.example.com/gql", method="POST",
            api_type="graphql", input_signature=same)
        self.assertEqual(
            graphql.scoped_idempotency_key("t1"), twin.scoped_idempotency_key("t1"))

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


class UrlSourceBoundaryTest(unittest.TestCase):
    """三层数据契约（附录A §4.16，2026-09-06 用户裁定，替代原 P1-10 语义）：

    公开观测值（url 的 query/path、source、parent_url/parent_target/
    parent_document/base_url）原样保留，资产层不改写；normalize 只做非破坏性
    规范化供比较去重；守卫仅作用于内容面（参数取值/schema/赋值形态自由文本）。
    """

    def test_document_url_query_preserved_as_observed(self):
        candidate = m.ApiDocumentCandidate(
            task_id="t1", url="https://api.example.com/x?token=abc123")
        # 观测值原样：query 参数与值不删、不改写、不折叠。
        self.assertEqual(candidate.observed_url, "https://api.example.com/x?token=abc123")
        self.assertIn("token=abc123", candidate.url)
        self.assertEqual(m.find_sensitive_keys(candidate.to_dict()), [])
        payload = json.dumps(m.ParseResult(parser="openapi", documents=[candidate]).to_dict())
        self.assertIn("token=abc123", payload)

    def test_endpoint_url_query_preserved_key_from_normalized(self):
        endpoint = m.UnifiedApiEndpoint(url="https://api.example.com/x?api_key=K1")
        self.assertIn("api_key=K1", endpoint.url)
        self.assertEqual(endpoint.observed_url, "https://api.example.com/x?api_key=K1")
        self.assertEqual(m.find_sensitive_keys(endpoint.to_dict()), [])
        # 去重键派生自 normalized url：不同 query 值是两个资产（不折叠、不改写）。
        twin = m.UnifiedApiEndpoint(url="https://api.example.com/x?api_key=K2")
        self.assertNotEqual(endpoint.idempotency_key, twin.idempotency_key)
        same = m.UnifiedApiEndpoint(url="https://api.example.com/x?api_key=K1")
        self.assertEqual(endpoint.idempotency_key, same.idempotency_key)

    def test_parent_target_and_source_fields_preserved_verbatim(self):
        endpoint = m.UnifiedApiEndpoint(
            url="https://api.example.com/x",
            parent_target="https://portal.example.com/page?token=PT",
            parent_document="https://ref.example.com/d?api_key=PD",
            base_url="https://api.example.com?access_key=BU")
        payload = endpoint.to_dict()
        self.assertIn("token=PT", payload["parent_target"])
        self.assertIn("api_key=PD", payload["parent_document"])
        self.assertIn("access_key=BU", payload["base_url"])
        self.assertEqual(m.find_sensitive_keys(payload), [])
        doc = m.ApiDocumentCandidate(
            task_id="t1", url="https://api.example.com/v3/api-docs",
            parent_url="https://app.example.com/home?api_key=PURL",
            source="https://ref.example.com/openapi.json?api_key=KEY")
        self.assertIn("api_key=PURL", doc.to_dict()["parent_url"])
        self.assertIn("api_key=KEY", doc.source)
        self.assertEqual(m.find_sensitive_keys(doc.to_dict()), [])

    def test_add_source_dedupes_verbatim_without_folding(self):
        # §4.16 撤销 P1-10 的 merge 折叠口径：仅键值不同的两个来源串是不同证据。
        candidate = m.ApiDocumentCandidate(task_id="t1", url="https://api.example.com/x")
        self.assertTrue(candidate.add_source("https://ref.example.com/d?token=A"))
        self.assertTrue(candidate.add_source("https://ref.example.com/d?token=B"))
        self.assertFalse(candidate.add_source("https://ref.example.com/d?token=A"))
        self.assertEqual(len(candidate.sources), 2)
        self.assertIn("token=A", " ".join(candidate.sources))

    def test_clean_urls_and_normalized_still_byte_identical(self):
        # 非破坏性规范化的 no-op 面：干净 URL、path 段名为 token、含参 query。
        for url in (
            "https://api.example.com/v1/pets",
            "https://api.example.com/token/refresh",
            "https://api.example.com/v3/api-docs?x=1",
        ):
            with self.subTest(url=url):
                self.assertEqual(
                    m.ApiDocumentCandidate(task_id="t1", url=url).url, url)
                self.assertEqual(m.UnifiedApiEndpoint(url=url).url, url)
        # 大小写 host/scheme 的非破坏性归一仍生效（比较面），observed 保留原样。
        mixed = m.UnifiedApiEndpoint(url="HTTPS://API.Example.COM/V1?a=B")
        self.assertEqual(mixed.url, "https://api.example.com/V1?a=B")
        self.assertEqual(mixed.observed_url, "HTTPS://API.Example.COM/V1?a=B")

    def test_guard_covers_content_fields_not_url_observations(self):
        # 守卫范围=内容面：参数取值、schema 赋值形态仍 raise；URL 观测字段放行。
        self.assertEqual(
            m.find_sensitive_keys({"url": "https://x/y?token=SECRET"}), [])
        self.assertEqual(
            m.find_sensitive_keys({"sources": ["https://x/d?api_key=KEY"]}), [])
        self.assertEqual(
            m.find_sensitive_keys({"parent_url": "https://x/y?Authorization=a"}), [])
        leaked = m.UnifiedApiEndpoint(
            url="https://api.example.com/x",
            response_schema={"example": {"Authorization": "Bearer leak"}})
        self.assertTrue(m.find_sensitive_keys(leaked.to_dict()))
        with self.assertRaises(ValueError):
            m.ParseResult(parser="openapi", endpoints=[leaked]).to_dict()
        param_shape = m.UnifiedApiEndpoint(
            url="https://api.example.com/x",
            parameters=[m.ParameterSpec(name="token", type_summary="string")])
        # ParameterSpec 无取值通道：仅名称命中不构成泄露。
        self.assertEqual(m.find_sensitive_keys(param_shape.to_dict()), [])

    def test_observed_url_explicit_input_wins(self):
        ep = m.UnifiedApiEndpoint(
            url="https://api.example.com/x?a=1",
            observed_url="https://api.example.com/x?a=1&from=scan")
        self.assertEqual(ep.observed_url, "https://api.example.com/x?a=1&from=scan")
        self.assertIn("a=1", ep.url)


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
            with _safe_domain_fns():
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
