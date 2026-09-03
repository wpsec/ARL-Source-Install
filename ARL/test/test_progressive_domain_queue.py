"""渐进式深度消息的持久化、恢复和幂等回归测试。"""

import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

try:
    import app.celerytask as celerytask_module
except Exception:
    celerytask_module = None


class _FakeCollection(object):
    def __init__(self, documents=None, modified_count=1):
        self.documents = list(documents or [])
        self.modified_count = modified_count
        self.update_calls = []

    def find_one(self, query, projection=None):
        if self.documents:
            return self.documents[0]
        return None

    def find(self, query, projection=None):
        return iter(self.documents)

    def update_one(self, query, update):
        self.update_calls.append((query, update))
        return SimpleNamespace(modified_count=self.modified_count)


@unittest.skipIf(celerytask_module is None, "运行依赖未安装，跳过渐进式队列测试")
class TestProgressiveDomainQueue(unittest.TestCase):
    TASK_ID = "507f1f77bcf86cd799439011"

    def test_claim_only_allows_one_consumer(self):
        collection = _FakeCollection(modified_count=1)
        with patch.object(celerytask_module.utils, "conn_db", return_value=collection):
            self.assertTrue(celerytask_module._claim_domain_deep_task(self.TASK_ID, "celery-1"))

        query, update = collection.update_calls[0]
        self.assertEqual("deep_scan_pending", query["status"])
        self.assertEqual("queued", query["deep_scan.status"])
        self.assertEqual("deep_scan_running", update["$set"]["status"])
        self.assertEqual("celery-1", update["$set"]["deep_scan.celery_id"])

        collection = _FakeCollection(modified_count=0)
        with patch.object(celerytask_module.utils, "conn_db", return_value=collection):
            self.assertFalse(celerytask_module._claim_domain_deep_task(self.TASK_ID, "celery-2"))

    def test_enqueue_records_dispatch_and_celery_id(self):
        collection = _FakeCollection(
            documents=[{"status": "deep_scan_pending", "deep_scan": {}}],
            modified_count=1,
        )
        async_result = SimpleNamespace(id="celery-deep-1")
        with patch.object(celerytask_module.utils, "conn_db", return_value=collection):
            with patch.object(celerytask_module.arl_task_heavy, "apply_async", return_value=async_result):
                self.assertTrue(
                    celerytask_module.enqueue_domain_deep_task(
                        self.TASK_ID,
                        "example.com",
                        {"port_scan": True},
                    )
                )

        self.assertGreaterEqual(len(collection.update_calls), 2)
        ready_update = collection.update_calls[0][1]
        self.assertEqual("queued", ready_update["$set"]["deep_scan"]["status"])
        id_update = collection.update_calls[-1][1]
        self.assertEqual("celery-deep-1", id_update["$set"]["deep_scan.celery_id"])

    def test_recovery_requeues_stale_deep_message(self):
        stale_ts = int(time.time()) - 120
        collection = _FakeCollection(
            documents=[
                {
                    "_id": self.TASK_ID,
                    "status": "deep_scan_pending",
                    "target": "example.com",
                    "options": {"port_scan": True},
                    "deep_scan": {
                        "status": "queued",
                        "dispatch_ts": stale_ts,
                        "celery_id": "missing-celery-id",
                    },
                }
            ],
            modified_count=1,
        )
        with patch.object(
            celerytask_module,
            "_collect_live_task_recovery_guard",
            return_value={"trusted": True, "task_id_set": set()},
        ):
            with patch.object(
                celerytask_module,
                "_get_broker_queue_message_counts",
                return_value=({"arlheavy": 0}, True),
            ):
                with patch.object(celerytask_module.utils, "conn_db", return_value=collection):
                    with patch.object(
                        celerytask_module,
                        "enqueue_domain_deep_task",
                        return_value=True,
                    ) as enqueue:
                        result = celerytask_module.recover_orphan_domain_deep_tasks_on_worker_start(
                            grace_sec=30
                        )

        self.assertEqual(1, result["requeued"])
        enqueue.assert_called_once_with(
            self.TASK_ID,
            "example.com",
            {"port_scan": True},
        )

    def test_enqueue_does_not_publish_duplicate_queued_message(self):
        collection = _FakeCollection(
            documents=[
                {
                    "status": "deep_scan_pending",
                    "deep_scan": {"status": "queued", "celery_id": "celery-1"},
                }
            ],
            modified_count=1,
        )
        with patch.object(celerytask_module.utils, "conn_db", return_value=collection):
            with patch.object(celerytask_module.arl_task_heavy, "apply_async") as apply_async:
                self.assertTrue(
                    celerytask_module.enqueue_domain_deep_task(
                        self.TASK_ID,
                        "example.com",
                        {"port_scan": True},
                    )
                )

        apply_async.assert_not_called()
        self.assertEqual([], collection.update_calls)


if __name__ == "__main__":
    unittest.main()
