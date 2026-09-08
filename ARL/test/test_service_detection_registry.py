"""计划 5 服务识别结果统一映射测试。"""

import unittest
from pathlib import Path
from unittest import mock

from test._api_unified_bootstrap import load_modules


_captured = load_modules(
    "app.services.service_fingerprint_registry",
    "app.services.service_detection",
)
SERVICE = _captured["app.services.service_fingerprint_registry"]
DETECTION = _captured["app.services.service_detection"]


class ServiceDetectionRegistryTest(unittest.TestCase):
    def test_nmap_product_is_a_real_evidence_source(self):
        registry = SERVICE.ServiceFingerprintRegistry(
            str(Path(__file__).resolve().parents[1]
                / "app" / "dicts" / "service_fingerprints.json.gz")
        )
        with mock.patch.object(
            SERVICE, "get_service_registry", return_value=registry
        ):
            result = DETECTION.resolve_service_result(product="mysql", port=3306)

        self.assertEqual("mysql", result["service"])
        self.assertEqual(80, result["confidence"])
        self.assertEqual(["nmap_product_version"], result["sources"])


if __name__ == "__main__":
    unittest.main()
