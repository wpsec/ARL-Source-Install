"""计划 7 HAR 导入与敏感信息边界测试。"""

import json
import sys
import unittest
from pathlib import Path


ARL_ROOT = Path(__file__).resolve().parents[1]
if str(ARL_ROOT) not in sys.path:
    sys.path.insert(0, str(ARL_ROOT))

from test._api_unified_bootstrap import load_modules  # noqa: E402


_MODULES = load_modules(
    "app.services.discovery_context",
    "app.services.api_unified_models",
    "app.services.api_candidate_registry",
    "app.services.wih_har_import",
)
MODULE = _MODULES["app.services.wih_har_import"]


class HarImportTest(unittest.TestCase):
    def test_imports_observed_endpoint_without_retaining_secret_values(self):
        payload = {
            "log": {
                "version": "1.2",
                "entries": [{
                    "request": {
                        "method": "POST",
                        "url": "https://api.example.test/graphql?token=secret&view=full",
                        "headers": [{"name": "Authorization", "value": "Bearer secret"}],
                        "postData": {
                            "mimeType": "application/json",
                            "text": '{"query":"query User { user { id } }","token":"secret"}',
                        },
                    },
                }],
            },
        }

        result = MODULE.import_har(payload, allowed_hosts={"api.example.test"})

        self.assertEqual(1, result.imported_count)
        endpoint = result.endpoints[0]
        self.assertEqual("graphql", endpoint.api_type)
        self.assertEqual("covered", endpoint.status)
        self.assertEqual("bearer", endpoint.auth_hint)
        self.assertIn("token=<redacted>", endpoint.url)
        self.assertNotIn("secret", json.dumps(result.to_dict(), ensure_ascii=False))

    def test_rejects_out_of_scope_and_userinfo_urls(self):
        entries = [
            {"request": {"method": "GET", "url": "https://other.example.test/a"}},
            {"request": {"method": "GET", "url": "https://user:password@example.test/a"}},
            {"request": {"method": "GET", "url": "https://example.test:invalid/a"}},
        ]
        result = MODULE.import_har(
            {"log": {"version": "1.2", "entries": entries}},
            allowed_hosts={"example.test"},
        )

        self.assertEqual(0, result.imported_count)
        self.assertEqual(3, result.rejected_count)

    def test_duplicate_observations_are_merged_by_endpoint_identity(self):
        entry = {"request": {"method": "GET", "url": "https://example.test/a?item=1"}}
        result = MODULE.import_har(
            {"log": {"version": "1.2", "entries": [entry, entry]}},
            allowed_hosts={"example.test"},
        )

        self.assertEqual(1, result.imported_count)
        self.assertEqual(1, result.merged_count)

    def test_registry_receives_covered_endpoint_and_keeps_scope(self):
        registry_type = _MODULES["app.services.api_candidate_registry"].ApiCandidateRegistry
        registry = registry_type("har-task")
        registry.set_endpoint_scope({"example.test"})
        result = MODULE.import_har(
            {
                "log": {
                    "version": "1.2",
                    "entries": [{
                        "request": {
                            "method": "GET",
                            "url": "https://example.test/observed",
                        },
                    }],
                },
            },
            registry=registry,
        )

        self.assertEqual(1, result.imported_count)
        self.assertEqual("covered", registry.snapshot_endpoints()[0]["status"])

    def test_imports_standardized_proxy_event_without_values(self):
        result = MODULE.import_proxy_events(
            [{
                "request": {
                    "method": "POST",
                    "url": "https://example.test/v1/items?token=secret&limit=10",
                    "headers": {"Authorization": "Bearer secret", "X-Trace": "abc"},
                    "query": {"token": "secret", "limit": "10"},
                    "contentType": "application/json",
                    "body": '{"token":"secret","name":"demo"}',
                },
            }],
            allowed_hosts={"example.test"},
        )

        self.assertEqual(1, result.imported_count)
        endpoint = result.endpoints[0]
        self.assertEqual("POST", endpoint.method)
        self.assertEqual("bearer", endpoint.auth_hint)
        self.assertIn("limit", [item.name for item in endpoint.parameters])
        self.assertNotIn("secret", json.dumps(result.to_dict(), ensure_ascii=False))

    def test_proxy_import_bounds_invalid_and_out_of_scope_events(self):
        result = MODULE.import_proxy_events(
            [
                {"url": "https://other.example.test/a"},
                {"request": {"url": ""}},
                "not-an-event",
            ],
            allowed_hosts={"example.test"},
            max_events=2,
        )

        self.assertEqual(0, result.imported_count)
        self.assertGreaterEqual(result.rejected_count, 2)
        self.assertEqual(1, result.truncated_count)


if __name__ == "__main__":
    unittest.main()
