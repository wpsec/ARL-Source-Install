"""资产站点监控的范围校验与任务投递边界。"""

import unittest
from unittest.mock import patch

import app.services.asset_site_monitor as site_monitor
from app.helpers.asset_site_monitor import submit_asset_site_monitor_job
from app.modules import TaskStatus, TaskType
from app.services.asset_site_monitor import asset_site_monitor


class TestAssetSiteMonitor(unittest.TestCase):
    def test_scope_not_found_is_reported(self):
        with patch.object(site_monitor, "get_scope_by_scope_id", return_value=None):
            with self.assertRaisesRegex(Exception, "没有找到资产组"):
                asset_site_monitor(scope_id="fixture-scope")

    def test_monitor_with_no_changes_does_not_send_notification(self):
        with patch.object(
            site_monitor, "get_scope_by_scope_id", return_value={"name": "fixture scope"}
        ), patch.object(site_monitor, "AssetSiteCompare") as compare, \
                patch.object(site_monitor, "push_email") as email, \
                patch.object(site_monitor, "push_dingding") as dingding:
            compare.return_value.run.return_value = {}
            asset_site_monitor(scope_id="fixture-scope")

        compare.assert_called_once_with(scope_id="fixture-scope")
        email.assert_not_called()
        dingding.assert_not_called()

    def test_monitor_job_submits_task_data(self):
        with patch("app.helpers.task.submit_task") as submit:
            submit_asset_site_monitor_job(
                scope_id="fixture-scope",
                name="fixture monitor",
                scheduler_id="fixture-scheduler",
            )

        task_data = submit.call_args.args[0]
        self.assertEqual(TaskStatus.WAITING, task_data["status"])
        self.assertEqual(TaskType.ASSET_SITE_UPDATE, task_data["type"])
        self.assertEqual("fixture-scope", task_data["options"]["scope_id"])
        self.assertEqual("fixture-scheduler", task_data["options"]["scheduler_id"])


if __name__ == "__main__":
    unittest.main()
