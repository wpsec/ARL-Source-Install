"""计划 7 微前端资源图适配器测试。"""

import json
import sys
import unittest
from pathlib import Path


ARL_ROOT = Path(__file__).resolve().parents[1]
if str(ARL_ROOT) not in sys.path:
    sys.path.insert(0, str(ARL_ROOT))

from test._api_unified_bootstrap import load_modules  # noqa: E402


MODULE = load_modules(
    "app.services.api_unified_models",
    "app.services.wih_micro_frontend",
)["app.services.wih_micro_frontend"]


class WihMicroFrontendTest(unittest.TestCase):
    def test_qiankun_resource_graph_is_bounded_and_normalized(self):
        resources = MODULE.extract_micro_frontend_resources(
            scripts=[{
                "url": "https://example.test/assets/main.js",
                "body": (
                    "registerMicroApps([{name:'bsc', entry:'/bsc/', "
                    "activeRule:'/bsc', container:'#sub'}])"
                ),
            }],
            base_url="https://example.test/",
            allowed_hosts={"example.test"},
        )
        self.assertEqual(1, len(resources))
        self.assertEqual("bsc", resources[0]["application"])
        self.assertEqual("/bsc", resources[0]["route"])
        self.assertEqual("https://example.test/bsc/", resources[0]["entry"])
        self.assertEqual("qiankun", resources[0]["framework"])

    def test_out_of_scope_and_sensitive_entry_are_safe(self):
        resources = MODULE.extract_micro_frontend_resources(
            pages=[{
                "url": "https://example.test/",
                "body": (
                    '<micro-app name="admin" '
                    'url="https://evil.test/app.js?token=secret"></micro-app>'
                ),
            }],
            allowed_hosts={"example.test"},
        )
        self.assertEqual([], resources)
        self.assertNotIn("secret", json.dumps(resources, ensure_ascii=False))

    def test_duplicate_observations_merge(self):
        item = {
            "body": "registerMicroApps([{name:'app',entry:'/entry.js'}])",
            "url": "https://example.test/index",
        }
        resources = MODULE.extract_micro_frontend_resources(
            pages=[item, item], allowed_hosts={"example.test"})
        self.assertEqual(1, len(resources))

    def test_rejects_non_http_entry_and_invalid_confidence(self):
        resource = MODULE.MicroFrontendResource(
            application="shell",
            entry="javascript:alert(1)",
            confidence="invalid",
        )

        self.assertEqual("", resource.entry)
        self.assertEqual(0, resource.confidence)

    def test_entry_drops_userinfo_and_fragment(self):
        resource = MODULE.MicroFrontendResource(
            application="shell",
            entry="https://user:password@example.test/app.js?token=secret#fragment-secret",
        )
        self.assertEqual("", resource.entry)

    def test_empty_scope_rejects_external_entry(self):
        resources = MODULE.extract_micro_frontend_resources(
            pages=[{
                "body": '<micro-app name="admin" url="https://example.test/app.js"></micro-app>',
                "url": "https://example.test/",
            }],
            allowed_hosts=set(),
        )

        self.assertEqual([], resources)


if __name__ == "__main__":
    unittest.main()
