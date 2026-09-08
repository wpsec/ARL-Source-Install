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

    def test_low_confidence_service_is_not_confirmed_when_registry_fallback_runs(self):
        with mock.patch.object(
            DETECTION, "normalize_scheme", side_effect=lambda value, use_registry=False: value
        ):
            result = DETECTION.resolve_service_result(
                service_name="unknown", use_registry=False
            )

        self.assertEqual("", result["service"])
        self.assertFalse(result["confirmed"])
        self.assertEqual(0, result["confidence"])
        self.assertEqual([], result["sources"])

    def test_low_confidence_npoc_result_is_not_written_back(self):
        task = type("Task", (), {
            "ip_info_list": [{
                "ip": "192.0.2.10",
                "port_info": [{"port_id": 443, "service_name": "unknown", "product": ""}],
            }],
        })()
        updated = DETECTION.apply_npoc_service_result(
            task,
            [{"host": "192.0.2.10", "port": "443", "scheme": "unknown"}],
            use_registry=False,
        )

        port_info = task.ip_info_list[0]["port_info"][0]
        self.assertEqual(0, updated)
        self.assertEqual("unknown", port_info["service_name"])
        self.assertEqual("", port_info["product"])


if __name__ == "__main__":
    unittest.main()
