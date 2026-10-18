"""资产 WIH Celery 任务 wrapper 的生命周期状态写入。"""

import unittest
from unittest.mock import Mock, patch

import app.tasks.asset_wih as asset_wih_task
from app.modules import TaskStatus


class TestAssetWihTask(unittest.TestCase):
    def test_wrapper_updates_scheduler_and_task_lifecycle(self):
        task = Mock()
        dates = iter(["fixture-start", "fixture-end"])
        with patch.object(asset_wih_task, "AssetWihUpdateTask", return_value=task), \
                patch("app.scheduler.update_job_run") as update_job_run, \
                patch.object(asset_wih_task.utils, "curr_date", side_effect=lambda: next(dates)):
            asset_wih_task.asset_wih_update_task(
                task_id="fixture-task",
                scope_id="fixture-scope",
                scheduler_id="fixture-scheduler",
            )

        update_job_run.assert_called_once_with(job_id="fixture-scheduler")
        task.run.assert_called_once_with()
        task.base_update_task.update_task_field.assert_any_call("start_time", "fixture-start")
        task.base_update_task.update_task_field.assert_any_call("status", TaskStatus.DONE)
        task.base_update_task.update_task_field.assert_any_call("end_time", "fixture-end")


if __name__ == "__main__":
    unittest.main()
