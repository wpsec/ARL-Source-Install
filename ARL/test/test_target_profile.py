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


if __name__ == "__main__":
    unittest.main()
