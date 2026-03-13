import unittest

from app.routes.task_schedule import normalize_task_schedule_query_args


class TestTaskScheduleQueryArgs(unittest.TestCase):
    """计划任务查询参数规范化测试。"""

    def test_schedule_status_should_map_to_status(self):
        args = {
            "name": "demo",
            "schedule_status": "scheduled",
            "status": None
        }
        data = normalize_task_schedule_query_args(args)

        self.assertEqual(data.get("status"), "scheduled")
        self.assertNotIn("schedule_status", data)

    def test_status_should_keep_when_schedule_status_missing(self):
        args = {
            "name": "demo",
            "status": "stop"
        }
        data = normalize_task_schedule_query_args(args)
        self.assertEqual(data.get("status"), "stop")

    def test_empty_status_should_be_removed(self):
        args = {
            "schedule_status": "   ",
            "status": ""
        }
        data = normalize_task_schedule_query_args(args)
        self.assertNotIn("status", data)


if __name__ == "__main__":
    unittest.main()
