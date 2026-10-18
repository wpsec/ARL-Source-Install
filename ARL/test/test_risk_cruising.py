"""风险巡航任务构造测试不投递 Celery，也不执行扫描。"""

import unittest

from app.helpers.task import build_task_data
from app.modules import TaskStatus, TaskTag, TaskType


class TestRiskCruisingTaskData(unittest.TestCase):
    def test_build_task_data_keeps_explicit_empty_poc_selection(self):
        task = build_task_data(
            "fixture risk task",
            ["https://target.fixture.invalid"],
            TaskType.RISK_CRUISING,
            TaskTag.RISK_CRUISING,
            {"poc_config": [], "npoc_poc_scan": None},
        )

        self.assertEqual(TaskStatus.WAITING, task["status"])
        self.assertEqual("目标：1， PoC：0", task["target"])
        self.assertFalse(task["options"]["npoc_poc_scan"])
        self.assertEqual([], task["options"]["poc_config"])


if __name__ == "__main__":
    unittest.main()
