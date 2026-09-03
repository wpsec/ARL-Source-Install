"""WIH 基线聚合工具回归测试。"""
import unittest
import importlib.util
from pathlib import Path


_MODULE_PATH = Path(__file__).resolve().parents[1] / "app" / "tools" / "collect_wih_baseline.py"
_SPEC = importlib.util.spec_from_file_location("collect_wih_baseline_test_module", _MODULE_PATH)
_MODULE = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
_SPEC.loader.exec_module(_MODULE)
build_baseline = _MODULE.build_baseline


class TestCollectWihBaseline(unittest.TestCase):
    def test_excludes_aggregate_stage_from_execution_summary(self):
        baseline = build_baseline(
            [
                {
                    "_id": "task-1",
                    "service": [
                        {
                            "name": "web_info_hunter",
                            "elapsed": 12,
                            "stage_kind": "aggregate",
                        },
                        {
                            "name": "wih_primary_scan",
                            "elapsed": 10.5,
                            "status": "partial",
                            "end_reason": "budget_exhausted",
                            "input_count": 64,
                            "output_count": 18,
                            "metrics": {
                                "cpu_elapsed_sec": 4.5,
                                "non_cpu_elapsed_sec": 6,
                                "rss_peak_mb": 128,
                            },
                        },
                    ],
                },
                {
                    "_id": "task-2",
                    "service": [
                        {
                            "name": "wih_primary_scan",
                            "elapsed": 8,
                            "status": "success",
                            "end_reason": "completed",
                            "input_count": 64,
                            "output_count": 23,
                            "metrics": {
                                "cpu_elapsed_sec": 5,
                                "non_cpu_elapsed_sec": 3,
                                "rss_peak_mb": 140,
                            },
                        },
                    ],
                },
            ]
        )

        self.assertEqual(2, baseline["task_count"])
        self.assertEqual([64, 64], baseline["target_count_distribution"])
        summary = baseline["stage_summary"]["wih_primary_scan"]
        self.assertEqual(2, summary["sample_count"])
        self.assertEqual(10.5, summary["p95_elapsed_sec"])
        self.assertEqual(5, summary["p95_cpu_elapsed_sec"])
        self.assertEqual(140, summary["max_rss_peak_mb"])
        self.assertNotIn("web_info_hunter", baseline["stage_summary"])


if __name__ == "__main__":
    unittest.main()
