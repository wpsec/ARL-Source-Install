"""WIH 基线门禁校验回归测试。"""
import importlib.util
import unittest
from pathlib import Path


_MODULE_PATH = Path(__file__).resolve().parents[1] / "app" / "tools" / "validate_wih_baseline.py"
_SPEC = importlib.util.spec_from_file_location("validate_wih_baseline_test_module", _MODULE_PATH)
_MODULE = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
_SPEC.loader.exec_module(_MODULE)
validate_baseline = _MODULE.validate_baseline


def _stage(name):
    return {
        "name": name,
        "budget_sec": 2700 if name == "wih_primary_scan" else 1800,
        "status": "success",
        "end_reason": "completed",
    }


def _baseline(run_modes):
    return {
        "schema_version": 1,
        "stage_summary": {
            name: {
                "p95_elapsed_sec": 10,
                "p95_cpu_elapsed_sec": 5,
                "p95_non_cpu_elapsed_sec": 5,
                "max_rss_peak_mb": 128,
                "status_counts": {"success": 2},
                "end_reason_counts": {"completed": 2},
            }
            for name in ("wih_primary_scan", "wih_urlfinder_sensitive")
        },
        "tasks": [
            {
                "task_id": "task-{}".format(index),
                "run_mode": mode,
                "target_count": 64,
                "stages": [_stage("wih_primary_scan"), _stage("wih_urlfinder_sensitive")],
            }
            for index, mode in enumerate(run_modes)
        ],
    }


class TestValidateWihBaseline(unittest.TestCase):
    def test_accepts_cold_and_hot_runs(self):
        result = validate_baseline(_baseline(("cold", "hot")))

        self.assertTrue(result["ok"])
        self.assertEqual(2, result["actual_runs"])
        self.assertEqual([], result["errors"])

    def test_rejects_incomplete_target_runs(self):
        result = validate_baseline(_baseline(("cold",)), min_runs=2)

        self.assertFalse(result["ok"])
        self.assertIn("至少 2 轮", result["errors"][0])


if __name__ == "__main__":
    unittest.main()
