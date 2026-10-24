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

    def test_wih_is_scheduled_before_poc(self):
        stage_order = celerytask_module._DOMAIN_DEEP_STAGE_ORDER
        self.assertLess(stage_order.index("wih"), stage_order.index("poc"))
        self.assertEqual("poc", celerytask_module._next_domain_deep_stage("wih"))
        self.assertEqual("wih", celerytask_module._next_domain_deep_stage("poc", stage_order_version=1))
        self.assertEqual("finalize", celerytask_module._next_domain_deep_stage("poc", stage_order_version=2))

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
            with patch.object(
                celerytask_module,
                "_resolve_domain_deep_dispatch_queue",
                return_value=("arlheavy", "progressive_domain_deep"),
            ):
                with patch.object(
                    celerytask_module.arl_task_heavy,
                    "apply_async",
                    return_value=async_result,
                ):
                    self.assertTrue(
                        celerytask_module.enqueue_domain_deep_task(
                            self.TASK_ID,
                            "example.com",
                            {"port_scan": True},
                        )
                    )

        self.assertGreaterEqual(len(collection.update_calls), 2)
        ready_update = collection.update_calls[0][1]
        self.assertEqual("queued", ready_update["$set"]["deep_scan.status"])
        self.assertEqual("arlheavy", ready_update["$set"]["deep_scan.queue"])
        self.assertEqual(
            2,
            ready_update["$set"]["deep_scan.stage_order_version"],
        )
        id_update = collection.update_calls[-1][1]
        self.assertEqual("celery-deep-1", id_update["$set"]["deep_scan.celery_id"])

    def test_legacy_stage_keeps_legacy_order_version(self):
        collection = _FakeCollection(
            documents=[
                {
                    "status": "deep_scan_pending",
                    "deep_scan": {"stage": "poc"},
                }
            ],
            modified_count=1,
        )
        async_result = SimpleNamespace(id="celery-legacy-deep-1")
        with patch.object(celerytask_module.utils, "conn_db", return_value=collection):
            with patch.object(
                celerytask_module,
                "_resolve_domain_deep_dispatch_queue",
                return_value=("arlheavy", "progressive_domain_deep"),
            ):
                with patch.object(
                    celerytask_module.arl_task_heavy,
                    "apply_async",
                    return_value=async_result,
                ):
                    self.assertTrue(
                        celerytask_module.enqueue_domain_deep_task(
                            self.TASK_ID,
                            "example.com",
                            {"port_scan": True},
                        )
                    )

        ready_update = collection.update_calls[0][1]
        self.assertEqual(
            1,
            ready_update["$set"]["deep_scan.stage_order_version"],
        )

    def test_enqueue_falls_back_to_main_queue_when_heavy_consumer_unavailable(self):
        collection = _FakeCollection(
            documents=[{"status": "deep_scan_pending", "deep_scan": {}}],
            modified_count=1,
        )
        async_result = SimpleNamespace(id="celery-main-deep-1")
        with patch.object(celerytask_module.utils, "conn_db", return_value=collection):
            with patch.object(
                celerytask_module,
                "_resolve_domain_deep_dispatch_queue",
                return_value=(
                    "arltask",
                    "progressive_domain_deep:fallback=arlheavy_unavailable",
                ),
            ):
                with patch.object(
                    celerytask_module.arl_task,
                    "apply_async",
                    return_value=async_result,
                ) as publish:
                    self.assertTrue(
                        celerytask_module.enqueue_domain_deep_task(
                            self.TASK_ID,
                            "example.com",
                            {"port_scan": True},
                        )
                    )

        ready_update = collection.update_calls[0][1]
        self.assertEqual("arltask", ready_update["$set"]["deep_scan.queue"])
        self.assertEqual("arltask", ready_update["$set"]["dispatch_queue"])
        self.assertEqual(
            "progressive_domain_deep:fallback=arlheavy_unavailable",
            ready_update["$set"]["dispatch_queue_reason"],
        )
        publish.assert_called_once()
        self.assertEqual("arltask", publish.call_args.kwargs["queue"])
        self.assertEqual("arltask", publish.call_args.args[0][0]["data"]["dispatch_queue"])

    def test_recovery_requeues_stale_deep_message(self):
        stale_ts = int(time.time()) - 120
        collection = _FakeCollection(
            documents=[
                {
                    "_id": self.TASK_ID,
                    "status": "wih_urlfinder_sensitive",
                    "target": "example.com",
                    "options": {"port_scan": True},
                    "deep_scan": {
                        "status": "queued",
                        "stage": "site",
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
        recovery_query, recovery_update = collection.update_calls[0]
        self.assertNotIn("wih_urlfinder_sensitive", recovery_query["status"]["$nin"])
        self.assertIn("stop", recovery_query["status"]["$nin"])
        self.assertEqual("queued", recovery_query["deep_scan.status"])
        self.assertEqual("site", recovery_query["deep_scan.stage"])
        self.assertEqual(1, recovery_update["$inc"]["deep_scan.recovery_attempts"])
        enqueue.assert_called_once_with(
            self.TASK_ID,
            "example.com",
            {"port_scan": True},
        )

    def test_recovery_skips_when_worker_inspection_is_untrusted(self):
        collection = _FakeCollection(
            documents=[
                {
                    "_id": self.TASK_ID,
                    "status": "wih_primary_scan",
                    "deep_scan": {"status": "running", "stage": "site"},
                }
            ]
        )
        with patch.object(
            celerytask_module,
            "_collect_live_task_recovery_guard",
            return_value={"trusted": False, "task_id_set": set()},
        ):
            with patch.object(
                celerytask_module,
                "_get_broker_queue_message_counts",
            ) as queue_counts:
                with patch.object(celerytask_module.utils, "conn_db", return_value=collection):
                    result = celerytask_module.recover_orphan_domain_deep_tasks_on_worker_start()

        self.assertEqual({"requeued": 0, "skipped": 0, "failed": 0}, result)
        self.assertEqual([], collection.update_calls)
        queue_counts.assert_not_called()

    def test_recovery_skips_when_broker_inspection_fails(self):
        collection = _FakeCollection(
            documents=[
                {
                    "_id": self.TASK_ID,
                    "status": "wih_primary_scan",
                    "deep_scan": {"status": "running", "stage": "site"},
                }
            ]
        )
        with patch.object(
            celerytask_module,
            "_collect_live_task_recovery_guard",
            return_value={"trusted": True, "task_id_set": set()},
        ):
            with patch.object(
                celerytask_module,
                "_get_broker_queue_message_counts",
                return_value=({}, False),
            ):
                with patch.object(celerytask_module.utils, "conn_db", return_value=collection):
                    result = celerytask_module.recover_orphan_domain_deep_tasks_on_worker_start()

        self.assertEqual({"requeued": 0, "skipped": 0, "failed": 0}, result)
        self.assertEqual([], collection.update_calls)

    def test_recovery_skips_live_celery_task_and_queued_broker_message(self):
        stale_ts = int(time.time()) - 120
        live_collection = _FakeCollection(
            documents=[
                {
                    "_id": self.TASK_ID,
                    "status": "wih_primary_scan",
                    "deep_scan": {
                        "status": "running",
                        "stage": "site",
                        "dispatch_ts": stale_ts,
                        "celery_id": "active-deep-celery-id",
                    },
                }
            ]
        )
        with patch.object(
            celerytask_module,
            "_collect_live_task_recovery_guard",
            return_value={"trusted": True, "task_id_set": {"active-deep-celery-id"}},
        ):
            with patch.object(
                celerytask_module,
                "_get_broker_queue_message_counts",
                return_value=({"arlheavy": 0}, True),
            ):
                with patch.object(celerytask_module.utils, "conn_db", return_value=live_collection):
                    result = celerytask_module.recover_orphan_domain_deep_tasks_on_worker_start(
                        grace_sec=30
                    )

        self.assertEqual(1, result["skipped"])
        self.assertEqual([], live_collection.update_calls)

        queued_collection = _FakeCollection(
            documents=[
                {
                    "_id": self.TASK_ID,
                    "status": "wih_primary_scan",
                    "deep_scan": {
                        "status": "queued",
                        "stage": "site",
                        "dispatch_ts": stale_ts,
                        "celery_id": "missing-deep-celery-id",
                        "queue": "arlheavy",
                    },
                }
            ]
        )
        with patch.object(
            celerytask_module,
            "_collect_live_task_recovery_guard",
            return_value={"trusted": True, "task_id_set": set()},
        ):
            with patch.object(
                celerytask_module,
                "_get_broker_queue_message_counts",
                return_value=({"arlheavy": 1}, True),
            ):
                with patch.object(celerytask_module.utils, "conn_db", return_value=queued_collection):
                    result = celerytask_module.recover_orphan_domain_deep_tasks_on_worker_start(
                        grace_sec=30
                    )

        self.assertEqual(1, result["skipped"])
        self.assertEqual([], queued_collection.update_calls)

    def test_recovery_marks_task_failed_after_three_lost_retries(self):
        stale_ts = int(time.time()) - 120
        collection = _FakeCollection(
            documents=[
                {
                    "_id": self.TASK_ID,
                    "status": "wih_primary_scan",
                    "target": "example.com",
                    "options": {"port_scan": True},
                    "deep_scan": {
                        "status": "running",
                        "stage": "site",
                        "dispatch_ts": stale_ts,
                        "celery_id": "missing-celery-id",
                        "recovery_attempts": 3,
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
                    ) as enqueue:
                        result = celerytask_module.recover_orphan_domain_deep_tasks_on_worker_start(
                            grace_sec=30
                        )

        self.assertEqual(1, result["failed"])
        self.assertEqual("error", collection.update_calls[0][1]["$set"]["status"])
        self.assertEqual(
            "recovery_attempts_exhausted",
            collection.update_calls[0][1]["$set"]["deep_scan.end_reason"],
        )
        enqueue.assert_not_called()

    def test_manual_reconciliation_dry_run_does_not_write(self):
        stale_ts = int(time.time()) - 120
        collection = _FakeCollection(
            documents=[
                {
                    "_id": self.TASK_ID,
                    "status": "wih_primary_scan",
                    "celery_id": "old-root-celery-id",
                    "deep_scan": {
                        "status": "running",
                        "stage": "site",
                        "dispatch_ts": stale_ts,
                        "celery_id": "old-deep-celery-id",
                        "queue": "arlheavy",
                    },
                }
            ]
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
                    result = celerytask_module.reconcile_stale_domain_deep_tasks(
                        [self.TASK_ID],
                        apply=False,
                    )

        self.assertTrue(result["dry_run"])
        self.assertEqual("would_mark_interrupted", result["items"][0]["status"])
        self.assertEqual([], collection.update_calls)

    def test_manual_reconciliation_apply_preserves_results_and_terminalizes_only_target(self):
        stale_ts = int(time.time()) - 120
        collection = _FakeCollection(
            documents=[
                {
                    "_id": self.TASK_ID,
                    "status": "wih_primary_scan",
                    "deep_scan": {
                        "status": "running",
                        "stage": "site",
                        "dispatch_ts": stale_ts,
                        "celery_id": "old-deep-celery-id",
                        "queue": "arlheavy",
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
                    result = celerytask_module.reconcile_stale_domain_deep_tasks(
                        [self.TASK_ID],
                        apply=True,
                    )

        self.assertFalse(result["dry_run"])
        self.assertEqual("marked_interrupted", result["items"][0]["status"])
        query, update = collection.update_calls[0]
        self.assertEqual(self.TASK_ID, str(query["_id"]))
        self.assertIn("stop", query["status"]["$nin"])
        self.assertEqual("error", update["$set"]["status"])
        self.assertEqual("failed", update["$set"]["deep_scan.status"])
        self.assertNotIn("$unset", update)

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
