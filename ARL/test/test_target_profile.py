"""计划 7 第一批目标画像契约测试。"""

import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "app" / "services" / "target_profile.py"
SPEC = importlib.util.spec_from_file_location("plan7_target_profile", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class TargetProfileResolverTest(unittest.TestCase):
    def setUp(self):
        self.resolver = MODULE.TargetProfileResolver()

    def test_empty_input_is_low_cost_unknown(self):
        profile = self.resolver.resolve()

        self.assertEqual(profile.profile, MODULE.PROFILE_UNKNOWN)
        self.assertEqual(profile.confidence, MODULE.CONFIDENCE_LOW)
        self.assertEqual(profile.recommended_collectors, (MODULE.COLLECTOR_HTTP,))
        self.assertIn(MODULE.COLLECTOR_BROWSER_RUNTIME, profile.skipped_collectors)

    def test_spa_markers_enable_runtime_as_optional_only(self):
        profile = self.resolver.resolve(
            pages=[
                {
                    "content_type": "text/html",
                    "body": '<div id="root"></div><script type="module" src="main.js"></script>',
                }
            ]
        )

        self.assertEqual(profile.profile, MODULE.PROFILE_SPA)
        self.assertIn(MODULE.COLLECTOR_BROWSER_RUNTIME, profile.optional_collectors)
        self.assertNotIn(MODULE.COLLECTOR_BROWSER_RUNTIME, profile.recommended_collectors)
        self.assertIn("html:spa_marker", profile.evidence)

    def test_server_rendered_form_is_traditional_mvc(self):
        profile = self.resolver.resolve(
            pages=[
                {
                    "content_type": "text/html; charset=utf-8",
                    "body": '<html><body><form action="/login"><input name="user"></form></body></html>',
                }
            ]
        )

        self.assertEqual(profile.profile, MODULE.PROFILE_TRADITIONAL_MVC)
        self.assertIn("html:form", profile.evidence)

    def test_ssr_marker_has_no_browser_default(self):
        profile = self.resolver.resolve(
            pages=[
                {
                    "content_type": "text/html",
                    "body": '<html data-server-rendered="true"><body>content</body></html>',
                }
            ]
        )

        self.assertEqual(profile.profile, MODULE.PROFILE_SSR)
        self.assertIn(MODULE.COLLECTOR_BROWSER_RUNTIME, profile.skipped_collectors)

    def test_openapi_document_is_document_first(self):
        profile = self.resolver.resolve(
            pages=[
                {
                    "content_type": "application/json",
                    "url": "/api-docs",
                    "body": '{"openapi":"3.0.0","paths":{}}',
                }
            ]
        )

        self.assertEqual(profile.profile, MODULE.PROFILE_DOCUMENT_FIRST)
        self.assertEqual(
            profile.recommended_collectors,
            (MODULE.COLLECTOR_HTTP, MODULE.COLLECTOR_API_DOCUMENT),
        )

    def test_api_only_uses_json_and_api_path_evidence(self):
        profile = self.resolver.resolve(
            pages=[
                {
                    "content_type": "application/json",
                    "url": "/api/items",
                    "body": '{"items":[]}',
                }
            ]
        )

        self.assertEqual(profile.profile, MODULE.PROFILE_API_ONLY)
        self.assertIn("response:json", profile.evidence)
        self.assertIn("url:api_path", profile.evidence)

    def test_evidence_is_capped_and_does_not_emit_url_or_body(self):
        secret_marker = "do-not-persist-this-value"
        pages = [
            {
                "content_type": "text/html",
                "url": "opaque-target-path?secret=" + secret_marker,
                "body": '<div id="root"></div>' + (" x" * 100000),
            }
        ]

        profile = self.resolver.resolve(pages=pages, scripts=[{"body": "react vue angular vite"}])
        output = str(profile.to_dict())

        self.assertLessEqual(len(profile.evidence), 16)
        self.assertNotIn(secret_marker, output)
        self.assertNotIn("opaque-target-path", output)

    def test_mapping_and_scalar_inputs_are_safe(self):
        profile = self.resolver.resolve(pages={"content_type": "application/json", "body": "{}"})
        self.assertEqual(profile.profile, MODULE.PROFILE_API_ONLY)
        self.assertEqual(self.resolver.resolve(pages=42).profile, MODULE.PROFILE_UNKNOWN)

    def test_existing_records_are_weak_hints_without_promoting_script_to_spa(self):
        record = type("Record", (), {"recordType": "js", "content": "main.js"})()
        profile = self.resolver.resolve_records([record])

        self.assertEqual(profile.profile, MODULE.PROFILE_UNKNOWN)
        self.assertIn("source:script", profile.evidence)

    def test_existing_document_record_selects_document_first(self):
        record = {"record_type": "api_doc", "content": "openapi.json"}
        profile = self.resolver.resolve_records([record])

        self.assertEqual(profile.profile, MODULE.PROFILE_DOCUMENT_FIRST)

    def test_response_metadata_can_supply_api_only_signal_without_body(self):
        profile = self.resolver.resolve_records(
            response_metadata=[
                {
                    "normalized_url": "/api/items",
                    "content_type": "application/json",
                    "status_code": 200,
                }
            ]
        )

        self.assertEqual(profile.profile, MODULE.PROFILE_API_ONLY)

    def test_protocol_signals_get_specialized_profiles_without_network(self):
        graphql = self.resolver.resolve(
            pages=[{"content_type": "application/json", "url": "/graphql", "body": '{"data": {}}'}],
            scripts=[{"body": "graphql query operationName"}],
        )
        self.assertEqual(MODULE.PROFILE_GRAPHQL, graphql.profile)
        self.assertIn(MODULE.COLLECTOR_PROTOCOL, graphql.recommended_collectors)

        soap = self.resolver.resolve(
            pages=[{"content_type": "text/xml", "url": "/service?wsdl", "body": "<wsdl:definitions><soap:binding/></wsdl:definitions>"}],
        )
        self.assertEqual(MODULE.PROFILE_SOAP, soap.profile)

        websocket = self.resolver.resolve(
            runtime_events=[{"url": "wss://example.test/socket", "content_type": "application/octet-stream"}],
        )
        self.assertEqual(MODULE.PROFILE_WEBSOCKET, websocket.profile)

    def test_micro_frontend_signal_is_an_optional_profile(self):
        profile = self.resolver.resolve(
            pages=[{"content_type": "text/html", "body": '<div id="micro-app"></div>'}],
            scripts=[{"body": "qiankun registerMicroApps"}],
        )
        self.assertEqual(MODULE.PROFILE_MICRO_FRONTEND, profile.profile)
        self.assertIn(MODULE.COLLECTOR_BROWSER_RUNTIME, profile.optional_collectors)

    def test_micro_frontend_adapter_is_explicit_and_read_only(self):
        observed = []

        def adapter(**kwargs):
            observed.append(kwargs)
            return [{"application": "bsc", "entry": "https://example.test/bsc/"}]

        resolver = MODULE.TargetProfileResolver(resource_adapter=adapter)
        profile = resolver.resolve(
            pages=[{"content_type": "text/html", "body": "<div id=\"micro-app\"></div>"}],
            base_url="https://example.test/",
            allowed_hosts={"example.test"},
        )
        self.assertEqual(MODULE.PROFILE_MICRO_FRONTEND, profile.profile)
        self.assertEqual(1, len(resolver.last_micro_frontend_resources))
        self.assertEqual(1, len(observed))
        self.assertEqual("https://example.test/", observed[0]["base_url"])
        self.assertEqual({"example.test"}, observed[0]["allowed_hosts"])


if __name__ == "__main__":
    unittest.main()
