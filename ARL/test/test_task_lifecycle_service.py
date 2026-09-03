"""任务生命周期服务回归测试。"""

import unittest
from unittest.mock import patch

from app.services.task_lifecycle_service import TaskLifecycleService


class _Task(object):
    def __init__(self, options=None):
        self.task_id = "507f1f77bcf86cd799439011"
        self.options = options or {}


class TestTaskLifecycleService(unittest.TestCase):
    def test_finalize_keeps_statistics_before_asset_sync(self):
        service = TaskLifecycleService(_Task())
        calls = []

        with patch.object(service, "insert_finger_stat", side_effect=lambda: calls.append("finger")), \
                patch.object(service, "insert_cip_stat", side_effect=lambda: calls.append("cip")), \
                patch.object(service, "insert_task_stat", side_effect=lambda: calls.append("task")), \
                patch.object(service, "sync_asset", side_effect=lambda: calls.append("asset")):
            service.finalize()

        self.assertEqual(["finger", "cip", "task", "asset"], calls)

    def test_run_finalize_uses_task_internal_stage_when_available(self):
        task = _Task()
        task.calls = []

        def run_internal_stage(name, func):
            task.calls.append(name)
            return func()

        task._run_internal_stage = run_internal_stage
        service = TaskLifecycleService(task)
        with patch.object(service, "finalize") as finalize:
            service.run_finalize(sync_asset=False)

        self.assertEqual(["task_finalize"], task.calls)
        finalize.assert_called_once_with(sync_asset=False)

    def test_sync_asset_requires_valid_scope_id(self):
        task = _Task({"related_scope_id": "too-short"})
        service = TaskLifecycleService(task)

        with patch("app.services.task_lifecycle_service.services.sync_asset") as sync_asset:
            service.sync_asset()

        sync_asset.assert_not_called()

    def test_sync_asset_delegates_valid_scope_id(self):
        scope_id = "507f1f77bcf86cd799439011"
        task = _Task({"related_scope_id": scope_id})
        service = TaskLifecycleService(task)

        with patch("app.services.task_lifecycle_service.services.sync_asset") as sync_asset:
            service.sync_asset()

        sync_asset.assert_called_once_with(task_id=task.task_id, scope_id=scope_id)


if __name__ == "__main__":
    unittest.main()
