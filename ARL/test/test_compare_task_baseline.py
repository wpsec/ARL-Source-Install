"""Python/Rust 任务基线比较测试。"""

import importlib.util
import unittest
from pathlib import Path


_MODULE_PATH = Path(__file__).resolve().parents[1] / "app" / "tools" / "compare_task_baseline.py"
_SPEC = importlib.util.spec_from_file_location("compare_task_baseline_test_module", _MODULE_PATH)
_MODULE = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
_SPEC.loader.exec_module(_MODULE)
compare_baselines = _MODULE.compare_baselines


def _baseline(cpu, elapsed, output, mode):
    stage = {
        "name": "wih_urlfinder_extract",
        "elapsed_sec": elapsed,
        "cpu_elapsed_sec": cpu,
        "status": "success",
        "end_reason": "completed",
        "input_count": 100,
        "output_count": output,
        "metrics": {"cpu_elapsed_sec": cpu},
    }
    return {
        "schema_version": 1,
        "tasks": [
            {
                "task_id": "task-{}".format(mode),
                "target_count": 64,
                "task_elapsed_sec": elapsed,
                "stages": [stage],
            },
            {
                "task_id": "task-{}-2".format(mode),
                "target_count": 64,
                "task_elapsed_sec": elapsed,
                "stages": [stage],
            },
        ],
        "stage_summary": {
            "wih_urlfinder_extract": {
                "sample_count": 2,
                "p95_elapsed_sec": elapsed,
                "p95_cpu_elapsed_sec": cpu,
                "input_count_total": 200,
                "output_count_total": output * 2,
            },
        },
    }


class TestCompareTaskBaseline(unittest.TestCase):
    def test_accepts_cpu_gate_without_result_loss(self):
        result = compare_baselines(
            _baseline(10, 100, 20, "python"),
            _baseline(6, 102, 20, "rust"),
            stages=("wih_urlfinder_extract",),
        )

        self.assertTrue(result["ok"])
        self.assertTrue(result["stages"][0]["hotspot_gate"])
        self.assertLessEqual(result["task_elapsed_change"], 0.05)

    def test_rejects_result_reduction(self):
        result = compare_baselines(
            _baseline(10, 100, 20, "python"),
            _baseline(6, 100, 19, "rust"),
            stages=("wih_urlfinder_extract",),
        )

        self.assertFalse(result["ok"])
        self.assertFalse(result["stages"][0]["result_not_reduced"])


if __name__ == "__main__":
    unittest.main()
