"""统一 StageMetric 事件格式测试。"""

import unittest
from unittest.mock import patch

from app.services.stage_metrics import StageMetric


class TestStageMetricSchema(unittest.TestCase):
    def test_finish_contains_independent_batch_metrics(self):
        metric = StageMetric(
            task_id="task-1",
            stage="port_scan",
            batch="2/4",
            target_count=3,
            port_count=1000,
            provider="",
            started_at=100.0,
            started_monotonic=10.0,
            cpu_started_sec=2.0,
        )
        with patch("app.services.stage_metrics.time.time", return_value=101.5):
            with patch("app.services.stage_metrics.time.monotonic", return_value=11.5):
                event = metric.finish(
                    status="partial",
                    end_reason="batch_failed",
                    input_count=5,
                    output_count=2,
                    metrics={
                        "dedup_count": 1,
                        "filtered_count": 2,
                        "queued_count": 4,
                        "success_count": 2,
                        "timeout_count": 1,
                        "retry_count": 1,
                        "failed_count": 1,
                        "degraded_count": 1,
                        "rust_execution_count": 1,
                        "fallback_count": 1,
                        "network_wait_sec": 0.8,
                        "batch_error_type": "TimeoutError",
                    },
                    cpu_finished_sec=2.4,
                )

        self.assertEqual("task-1", event["task_id"])
        self.assertEqual("2/4", event["batch"])
        self.assertEqual(1.5, event["wall_clock_sec"])
        self.assertEqual(0.4, event["cpu_time_sec"])
        self.assertEqual(0.8, event["network_wait_sec"])
        self.assertEqual("partial", event["status"])
        self.assertEqual(1, event["fallback_count"])
        self.assertEqual("TimeoutError", event["batch_error_type"])


if __name__ == "__main__":
    unittest.main()
