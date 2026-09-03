"""扫描配置域服务测试。"""

import tempfile
import unittest
import importlib.util
from pathlib import Path


_MODULE_PATH = Path(__file__).resolve().parents[1] / "app" / "services" / "scan_config_service.py"
_SPEC = importlib.util.spec_from_file_location("scan_config_service_test_module", _MODULE_PATH)
_MODULE = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
_SPEC.loader.exec_module(_MODULE)
ScanConfigService = _MODULE.ScanConfigService


class TestScanConfigService(unittest.TestCase):
    def test_profile_alias_and_field_mapping(self):
        service = ScanConfigService()
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            domain_dict = root / "domain.txt"
            file_leak_dict = root / "file-leak.txt"
            domain_dict.write_text("api\n", encoding="utf-8")
            file_leak_dict.write_text(".env\n", encoding="utf-8")

            config = service.merge(
                {"ARL": {"unchanged": True}},
                {
                    "scan_profile_id": "4c4g5m",
                    "domain_dict": str(domain_dict),
                    "file_leak_dict": str(file_leak_dict),
                    "black_ips": ["127.0.0.1"],
                    "dns_resolvers": ["8.8.8.8"],
                },
            )

            self.assertTrue(config["ARL"]["unchanged"])
            self.assertEqual("medium_performance", service.extract(config)["scan_profile_id"])
            self.assertEqual(96, config["ARL"]["DOMAIN_BRUTE_CONCURRENT"])
            self.assertEqual(str(domain_dict), config["ARL"]["DOMAIN_DICT"])

    def test_invalid_dictionary_is_rejected_before_mutation(self):
        service = ScanConfigService()
        config = {"ARL": {"DOMAIN_DICT": "before"}}

        with self.assertRaises(ValueError):
            service.merge(
                config,
                {
                    "domain_dict": "/path/that/does/not/exist",
                    "file_leak_dict": "/path/that/does/not/exist",
                    "black_ips": ["127.0.0.1"],
                },
            )

        self.assertEqual("before", config["ARL"]["DOMAIN_DICT"])


if __name__ == "__main__":
    unittest.main()
