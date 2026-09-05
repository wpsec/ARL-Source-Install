"""任务终态兼容映射一致性测试(Review 20260905 §4 重要项1)。

done 家族(done/done_pending/done_degraded)分散在 app.modules.TaskStatus、
task_finalizer 决策值、app.utils 字面量镜像与 collection 查询兼容层四处，
必须单源一致；本文件用纯断言锁定映射，不依赖 Mongo/Celery。
"""

import unittest

from app.modules import TaskStatus
from app.services import task_finalizer as tf_mod
from app.utils import TASK_DONE_FAMILY, TASK_TERMINAL_STATUSES
from app.services.collection_query_service import normalize_task_status_query


class TerminalLiteralConsistencyTest(unittest.TestCase):
    def test_finalizer_terminal_values_are_task_status_members(self):
        self.assertEqual(tf_mod.TERMINAL_DONE, TaskStatus.DONE)
        self.assertEqual(tf_mod.TERMINAL_DONE_PENDING, TaskStatus.DONE_PENDING)
        self.assertEqual(tf_mod.TERMINAL_DONE_DEGRADED, TaskStatus.DONE_DEGRADED)
        for value in (
            tf_mod.TERMINAL_DONE,
            tf_mod.TERMINAL_DONE_PENDING,
            tf_mod.TERMINAL_DONE_DEGRADED,
        ):
            self.assertTrue(TaskStatus.is_done_like(value))
            self.assertTrue(TaskStatus.is_terminal(value))

    def test_utils_mirror_matches_task_status(self):
        # app.utils 与 app.modules 存在导入环，只能镜像字面量；漂移即失败。
        self.assertEqual(set(TASK_DONE_FAMILY), set(TaskStatus.DONE_FAMILY))
        self.assertEqual(set(TASK_TERMINAL_STATUSES), set(TaskStatus.TERMINAL))

    def test_helpers_semantics(self):
        self.assertTrue(TaskStatus.is_clean_done("done"))
        self.assertFalse(TaskStatus.is_clean_done("done_pending"))
        self.assertFalse(TaskStatus.is_clean_done("done_degraded"))
        self.assertTrue(TaskStatus.is_done_like("done_degraded"))
        self.assertTrue(TaskStatus.is_done_like("  DONE_PENDING "))
        self.assertFalse(TaskStatus.is_done_like("waiting"))
        self.assertFalse(TaskStatus.is_terminal("wih"))
        self.assertTrue(TaskStatus.is_terminal("error"))
        self.assertTrue(TaskStatus.is_terminal("stop"))


class CollectionStatusFilterTest(unittest.TestCase):
    def test_done_filter_covers_family(self):
        query = normalize_task_status_query(
            "task", {"status": "done"}, {"status": "done"}
        )
        self.assertEqual(query["status"], {"$in": list(TaskStatus.DONE_FAMILY)})

    def test_running_filter_excludes_family(self):
        query = normalize_task_status_query(
            "task", {"status": "running"}, {"status": "running"}
        )
        # 家族成员必须在 $nin 中，否则积压任务永远显示"运行中"。
        for value in TaskStatus.DONE_FAMILY:
            self.assertIn(value, query["status"]["$nin"])

    def test_exact_filters_unchanged(self):
        query = normalize_task_status_query(
            "task", {"status": "error"}, {"status": "error"}
        )
        self.assertEqual(query["status"], "error")


if __name__ == "__main__":
    unittest.main()
