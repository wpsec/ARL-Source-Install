"""枚举路由而不逐项调用业务处理器，避免合同检查产生持久化副作用。"""

import re
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from app import utils
from app.config import Config
from app.main import arl_app

from scripts.generate_test_inventory import route_inventory

PUBLIC_OPERATIONS = {
    ("POST", "/api/user/login"),
    ("GET", "/api/user/logout"),
}


def _sample_path(path):
    values = {"int": "1", "float": "1.0", "path": "fixture", "string": "fixture"}

    def replace(match):
        converter = match.group(1) or "string"
        return values.get(converter, "fixture")

    return re.sub(r"<(?:(\w+):)?[^<>]+>", replace, path)


class ApiRouteContractInventoryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.namespace_count, cls.operations = route_inventory()
        cls.client = arl_app.test_client()
        cls.original_auth = Config.AUTH
        Config.AUTH = True

    @classmethod
    def tearDownClass(cls):
        Config.AUTH = cls.original_auth

    def test_registered_api_operations_match_source_inventory(self):
        expected = {
            (item["path"], item["method"])
            for item in self.operations
        }
        actual = {
            (rule.rule, method)
            for rule in arl_app.url_map.iter_rules()
            if rule.rule.startswith("/api/")
            and rule.rule not in {"/api/doc", "/api/swagger.json"}
            for method in rule.methods
            if method in {"GET", "POST", "PUT", "PATCH", "DELETE"}
        }
        self.assertEqual(expected, actual)
        self.assertGreaterEqual(self.namespace_count, 1)

    def test_only_explicit_login_and_logout_operations_are_public(self):
        actual_public = {
            (item["method"], item["path"])
            for item in self.operations
            if not item["authenticated"]
        }
        self.assertEqual(PUBLIC_OPERATIONS, actual_public)

    def test_each_protected_operation_rejects_a_missing_token(self):
        protected = [item for item in self.operations if item["authenticated"]]
        self.assertTrue(protected, "路由清单未识别到受保护操作")

        for item in protected:
            with self.subTest(method=item["method"], path=item["path"]):
                response = self.client.open(
                    _sample_path(item["path"]),
                    method=item["method"],
                    json={},
                )
                self.assertEqual(200, response.status_code)
                payload = response.get_json()
                self.assertIsInstance(payload, dict)
                self.assertEqual(401, payload.get("code"))
                self.assertIn("message", payload)
                self.assertIn("data", payload)

    def test_public_logout_keeps_the_documented_success_envelope(self):
        public = [item for item in self.operations if not item["authenticated"]]
        self.assertEqual(PUBLIC_OPERATIONS, {
            (item["method"], item["path"]) for item in public
        })

        with patch.object(utils, "user_logout") as logout:
            response = self.client.get("/api/user/logout")

        self.assertEqual(200, response.status_code)
        body = response.get_json()
        self.assertEqual(200, body["code"])
        self.assertEqual("success", body["message"])
        self.assertEqual({}, body["data"])
        logout.assert_called_once_with(None)


if __name__ == "__main__":
    unittest.main()
