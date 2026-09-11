"""普通任务 NPoC 配置和同步行为回归测试。"""

import unittest
from unittest.mock import MagicMock, patch

from app.helpers.task import build_task_data, normalize_task_poc_config
from app.modules import TaskTag, TaskType
from app.services.npoc import NPoC


class TestTaskPocConfig(unittest.TestCase):
    def test_normalize_task_poc_config_validates_database_plugin_and_deduplicates(self):
        collection = MagicMock()
        collection.find_one.return_value = {
            "plugin_name": "Demo_POC",
            "plugin_type": "poc",
            "vul_name": "Demo 漏洞",
        }

        with patch("app.helpers.task.utils.conn_db", return_value=collection):
            result = normalize_task_poc_config([
                {"plugin_name": "Demo_POC", "enable": True},
                {"plugin_name": "Demo_POC", "enable": True},
            ])

        self.assertEqual(
            [{"plugin_name": "Demo_POC", "vul_name": "Demo 漏洞", "enable": True}],
            result,
        )
        collection.find_one.assert_called_once_with(
            {"plugin_name": "Demo_POC", "plugin_type": "poc"}
        )

    def test_normalize_task_poc_config_rejects_unknown_plugin(self):
        collection = MagicMock()
        collection.find_one.return_value = None

        with patch("app.helpers.task.utils.conn_db", return_value=collection):
            with self.assertRaisesRegex(Exception, "没有找到"):
                normalize_task_poc_config([
                    {"plugin_name": "Unknown_POC", "enable": True},
                ])

    def test_ip_task_keeps_measurement_plugin_enabled(self):
        collection = MagicMock()
        collection.find_one.return_value = {
            "plugin_name": "Demo_POC",
            "plugin_type": "poc",
            "vul_name": "Demo 漏洞",
        }

        with patch("app.helpers.task.utils.conn_db", return_value=collection):
            task_data = build_task_data(
                "ip-task",
                "203.0.113.10",
                TaskType.IP,
                TaskTag.TASK,
                {
                    "dns_query_plugin": True,
                    "poc_config": [{"plugin_name": "Demo_POC", "enable": True}],
                },
            )

        self.assertTrue(task_data["options"]["dns_query_plugin"])
        self.assertEqual(
            [{"plugin_name": "Demo_POC", "vul_name": "Demo 漏洞", "enable": True}],
            task_data["options"]["poc_config"],
        )


class TestNPoCSync(unittest.TestCase):
    def test_sync_to_db_upserts_every_plugin(self):
        collection = MagicMock()
        instance = NPoC.__new__(NPoC)
        instance._poc_info_list = [
            {
                "plugin_name": "Demo_POC",
                "plugin_type": "poc",
                "vul_name": "Demo 漏洞",
            },
        ]
        instance._plugin_name_list = None
        instance.plugin_name_set = set()

        with patch("app.services.npoc.utils.conn_db", return_value=collection), \
                patch("app.services.npoc.utils.curr_date", return_value="now"):
            self.assertTrue(instance.sync_to_db())

        collection.update_one.assert_called_once()
        args, kwargs = collection.update_one.call_args
        self.assertEqual({"plugin_name": "Demo_POC"}, args[0])
        self.assertTrue(kwargs["upsert"])
        self.assertEqual("Demo 漏洞", args[1]["$set"]["vul_name"])
        collection.insert_one.assert_not_called()


if __name__ == "__main__":
    unittest.main()
