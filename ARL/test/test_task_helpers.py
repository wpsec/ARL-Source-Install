"""任务重启辅助函数的状态重置与缺失任务边界。"""

import unittest
from copy import deepcopy
from unittest.mock import patch

from app.helpers.task import restart_task


class TestTaskHelpers(unittest.TestCase):
    def test_restart_task_reports_missing_task_id(self):
        with patch("app.helpers.task.get_task_data", return_value=None):
            with self.assertRaisesRegex(Exception, "fixture-task-id"):
                restart_task("fixture-task-id")

    def test_restart_task_resets_runtime_fields_before_submit(self):
        task = {
            "_id": "fixture-id",
            "name": "fixture task",
            "target": "fixture-target",
            "status": "failed",
            "type": "ip",
            "task_tag": "task",
            "options": {},
            "start_time": "old-start",
            "end_time": "old-end",
            "service": ["stale"],
            "celery_id": "stale-celery-id",
            "last_error": "stale-error",
        }
        with patch("app.helpers.task.get_task_data", return_value=deepcopy(task)), \
                patch("app.helpers.task.submit_task", side_effect=lambda data: data) as submit:
            result = restart_task("fixture-task-id")

        self.assertEqual("重新运行-fixture task", result["name"])
        self.assertEqual("waiting", result["status"])
        self.assertEqual("-", result["start_time"])
        self.assertEqual("-", result["end_time"])
        self.assertEqual([], result["service"])
        self.assertEqual("", result["celery_id"])
        self.assertNotIn("last_error", result)
        submit.assert_called_once_with(result)


if __name__ == "__main__":
    unittest.main()
