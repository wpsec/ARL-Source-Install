"""Nuclei 阶段批次状态和 fallback 指标回归测试。"""

import unittest
from unittest.mock import patch

from app.services.nuclei_scan import NucleiScan, NucleiScanResult


class TestNucleiStageMetrics(unittest.TestCase):
    def test_auto_scan_falls_back_once_and_returns_command_result(self):
        scanner = NucleiScan(["https://example.test"], scan_profile={})
        scanner._gen_target_file = lambda *_args: None
        scanner._build_base_command = lambda **_kwargs: ["nuclei"]
        scanner._run_nuclei_command = lambda **kwargs: {
            "returncode": 1 if kwargs["stage"] == "auto-scan" else 0,
            "stdout": "",
            "stderr": "auto scan failed" if kwargs["stage"] == "auto-scan" else "",
            "result_size": 0,
        }

        result = scanner.exec_nuclei(
            {
                "targets": ["https://example.test"],
                "tags": "cve",
                "auto_scan": True,
                "batch_type": "fallback",
            },
            index=1,
        )

        self.assertEqual(0, result["returncode"])
        self.assertEqual(1, scanner.scan_metrics["fallback_count"])
        self.assertEqual(1, scanner.scan_metrics["degraded_count"])

    def test_run_returns_list_compatible_metrics(self):
        scanner = NucleiScan(["https://example.test"])
        with patch.object(scanner, "check_have_nuclei", return_value=False):
            with patch("app.services.nuclei_scan.utils.check_dns_policy_for_url", return_value=(True, {})):
                result = scanner.run()

        self.assertIsInstance(result, NucleiScanResult)
        self.assertEqual([], result)
        self.assertEqual("skipped", result.metrics["status"])
        self.assertEqual("binary_not_found", result.metrics["end_reason"])


if __name__ == "__main__":
    unittest.main()
