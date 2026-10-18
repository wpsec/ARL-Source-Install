"""资产站点更新任务只校验阶段顺序，不连接 Mongo 或触发网络请求。"""

import unittest
from unittest.mock import patch

from app.modules import TaskStatus
from app.tasks.asset_site import AssetSiteUpdateTask


class TestAssetSiteUpdateTask(unittest.TestCase):
    def test_run_orders_lifecycle_stages(self):
        calls = []
        base_task = AssetSiteUpdateTask.__bases__[0]
        with patch.object(base_task, "__init__", return_value=None):
            task = AssetSiteUpdateTask("fixture-task", "fixture-scope")

        task.set_start_time = lambda: calls.append("start")
        task.monitor = lambda: calls.append("monitor")
        task.insert_task_stat = lambda: calls.append("stats")
        task.update_status = lambda status: calls.append(("status", status))
        task.set_end_time = lambda: calls.append("end")

        task.run()

        self.assertEqual(
            ["start", "monitor", "stats", ("status", TaskStatus.DONE), "end"],
            calls,
        )


if __name__ == "__main__":
    unittest.main()
