"""第三方服务 API 配置域服务测试。"""

import unittest
from unittest.mock import patch

from app.config import Config
from app.services.service_api_config_service import ServiceApiConfigService


class TestServiceApiConfigService(unittest.TestCase):
    def test_merge_and_extract_keep_legacy_sections(self):
        service = ServiceApiConfigService()
        config = {}

        service.merge(
            config,
            {
                "fofa_url": "https://fofa.example",
                "fofa_email": "operator@example.invalid",
                "fofa_key": "configured-value",
                "hunter_api_key": "configured-value",
                "hunter_enable": False,
                "passivetotal_email": "risk@example.invalid",
                "passivetotal_key": "configured-value",
                "github_token": "configured-value",
            },
        )

        extracted = service.extract(config)
        self.assertEqual("https://fofa.example", extracted["fofa_url"])
        self.assertEqual("operator@example.invalid", extracted["fofa_email"])
        self.assertEqual("configured-value", extracted["fofa_key"])
        self.assertFalse(extracted["hunter_enable"])
        self.assertEqual("risk@example.invalid", config["RISKIQ"]["EMAIL"])
        self.assertEqual("configured-value", config["GITHUB"]["TOKEN"])

    def test_sanitize_and_fill_missing_sensitive_fields(self):
        service = ServiceApiConfigService()
        config = {"FOFA": {"KEY": "configured-value"}}
        current = service.extract(config)

        safe, configured = service.sanitize(current)
        self.assertEqual("", safe["fofa_key"])
        self.assertTrue(configured["fofa_key"])

        submitted = service.fill_missing_sensitive({"fofa_url": "https://fofa.example"}, config)
        self.assertEqual("configured-value", submitted["fofa_key"])

    def test_extract_uses_runtime_fofa_key_fallback(self):
        service = ServiceApiConfigService()
        with patch.object(Config, "FOFA_KEY", "runtime-value"):
            self.assertEqual("runtime-value", service.extract({})["fofa_key"])


if __name__ == "__main__":
    unittest.main()
