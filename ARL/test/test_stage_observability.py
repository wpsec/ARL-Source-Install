"""阶段统计字段回归测试。"""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

try:
    import app.services.baseUpdateTask as base_update_task_module
    BaseUpdateTask = base_update_task_module.BaseUpdateTask
except Exception:
    base_update_task_module = None
    BaseUpdateTask = None


@unittest.skipIf(BaseUpdateTask is None, "运行依赖未安装，跳过阶段统计回归")
class TestStageObservability(unittest.TestCase):
    def test_apply_stage_metadata_preserves_subsecond_elapsed_and_budget(self):
        payload = {"name": "wih_primary_scan", "elapsed": 0.734}

        BaseUpdateTask._apply_stage_metadata(
            payload,
            {
                "started_at": 100.12345,
                "finished_at": 100.85789,
                "status": "partial",
                "end_reason": "budget_exhausted",
                "input_count": 64,
                "output_count": 18,
                "budget_sec": 2700,
                "stage_kind": "execution",
                "metrics": {"timeout_count": 2},
            },
        )

        self.assertEqual(100.123, payload["started_at"])
        self.assertEqual(100.858, payload["finished_at"])
        self.assertEqual("partial", payload["status"])
        self.assertEqual("budget_exhausted", payload["end_reason"])
        self.assertEqual(64, payload["input_count"])
        self.assertEqual(18, payload["output_count"])
        self.assertEqual(2700.0, payload["budget_sec"])
        self.assertEqual({"timeout_count": 2}, payload["metrics"])

    def test_finish_stage_writes_structured_service_item(self):
        updater = BaseUpdateTask("507f1f77bcf86cd799439011")
        updates = []
        updater._safe_update_task = lambda query, update, action: updates.append(update)
        context = {
            "name": "wih_urlfinder_sensitive",
            "started_at": 100.0,
            "started_monotonic": 10.0,
            "input_count": 300,
            "budget_sec": 1800,
            "stage_kind": "execution",
        }

        with patch.object(base_update_task_module.time, "monotonic", return_value=10.734):
            with patch.object(base_update_task_module.time, "time", return_value=101.0):
                updater.finish_stage(
                    context,
                    status="partial",
                    end_reason="no_gain",
                    output_count=7,
                    metrics={"duplicate_record_count": 4},
                )

        service_item = updates[0]["$push"]["service"]
        self.assertEqual("wih_urlfinder_sensitive", service_item["name"])
        self.assertEqual(0.734, service_item["elapsed"])
        self.assertEqual(100.0, service_item["started_at"])
        self.assertEqual(101.0, service_item["finished_at"])
        self.assertEqual("partial", service_item["status"])
        self.assertEqual("no_gain", service_item["end_reason"])
        self.assertEqual(300, service_item["input_count"])
        self.assertEqual(7, service_item["output_count"])
        self.assertEqual(1800.0, service_item["budget_sec"])
        self.assertEqual(4, service_item["metrics"]["duplicate_record_count"])
        self.assertIn("cpu_elapsed_sec", service_item["metrics"])
        self.assertIn("non_cpu_elapsed_sec", service_item["metrics"])
        self.assertIn("rss_peak_mb", service_item["metrics"])
        self.assertEqual("process_lifetime_max", service_item["metrics"]["rss_scope"])

    def test_rss_unit_conversion_matches_platform(self):
        usage = SimpleNamespace(ru_maxrss=2 * 1024 * 1024)
        with patch.object(base_update_task_module.resource, "getrusage", return_value=usage):
            with patch.object(base_update_task_module.sys, "platform", "linux"):
                self.assertEqual(2048.0, BaseUpdateTask._process_rss_mb())
            with patch.object(base_update_task_module.sys, "platform", "darwin"):
                self.assertEqual(2.0, BaseUpdateTask._process_rss_mb())


if __name__ == "__main__":
    unittest.main()
