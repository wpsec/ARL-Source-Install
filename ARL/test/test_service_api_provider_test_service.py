"""Provider 测试服务回归测试。"""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app.services.service_api_provider_test_service import ServiceApiProviderTestService


class _Response(object):
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self.payload = payload

    def json(self):
        return self.payload


class _Utils(object):
    @staticmethod
    def is_valid_domain(value):
        return value == "example.com"

    @staticmethod
    def http_req(*args, **kwargs):
        return _Response(200, {"login": "operator"})

    @staticmethod
    def load_query_plugins(_path):
        return []


class _ConfigApi(object):
    def merge(self, config, service_api):
        config["QUERY_PLUGIN"] = {}
        return config


class TestServiceApiProviderTestService(unittest.TestCase):
    def _service(self):
        return ServiceApiProviderTestService(
            config=SimpleNamespace(dns_query_plugin_path="/tmp/plugins"),
            service_api_config_service=_ConfigApi(),
            utils_module=_Utils,
        )

    def test_target_normalization_and_configured_provider_selection(self):
        service = self._service()
        self.assertEqual("example.com", service.normalize_target("invalid"))
        providers = service.configured_providers(
            {"fofa_email": "operator@example.invalid", "fofa_key": "placeholder"}
        )
        self.assertEqual(["fofa"], [item["provider"] for item in providers])

    def test_github_test_returns_normalized_result_without_persisting_config(self):
        service = self._service()
        result = service.test_provider("github", {"github_token": "placeholder"}, "example.com")
        self.assertTrue(result["ok"])
        self.assertEqual("github", result["provider"])
        self.assertEqual("operator", result["detail"]["login"])

    def test_provider_exception_is_reported_as_failure(self):
        service = self._service()
        with patch.object(_Utils, "http_req", side_effect=RuntimeError("connection failed")):
            result = service.test_provider("github", {"github_token": "placeholder"}, "example.com")
        self.assertFalse(result["ok"])
        self.assertIn("测试失败", result["message"])


if __name__ == "__main__":
    unittest.main()
