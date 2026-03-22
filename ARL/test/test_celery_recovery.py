import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from app.celerytask import (
    celery,
    recover_orphan_waiting_tasks_on_worker_start,
    requeue_orphan_waiting_tasks_on_worker_start,
)
from app.utils import recover_interrupted_tasks_on_worker_start


class TestCeleryRecovery(unittest.TestCase):
    def test_celery_uses_early_ack_for_long_running_tasks(self):
        self.assertFalse(celery.conf.task_acks_late)

    def test_celery_sets_explicit_broker_heartbeat_defaults(self):
        self.assertEqual(int(celery.conf.broker_heartbeat), 120)
        self.assertEqual(float(celery.conf.broker_heartbeat_checkrate), 2.0)

    @patch("app.utils.get_logger")
    @patch("app.utils.curr_date", return_value="2026-03-19 17:00:00")
    @patch("app.utils.conn_db")
    def test_recover_interrupted_tasks_marks_running_tasks_as_error(
        self,
        mock_conn_db,
        _mock_curr_date,
        mock_get_logger,
    ):
        logger = MagicMock()
        mock_get_logger.return_value = logger

        task_collection = MagicMock()
        task_collection.update_many.return_value = SimpleNamespace(modified_count=2)
        github_collection = MagicMock()
        github_collection.update_many.return_value = SimpleNamespace(modified_count=1)

        def fake_conn_db(name):
            if name == "task":
                return task_collection
            if name == "github_task":
                return github_collection
            raise AssertionError("unexpected collection {}".format(name))

        mock_conn_db.side_effect = fake_conn_db

        result = recover_interrupted_tasks_on_worker_start(reason="worker restarted")

        expected_query = {
            "status": {"$nin": ["waiting", "done", "stop", "error"]},
            "start_time": {"$nin": ["", "-"]},
        }

        task_collection.update_many.assert_called_once()
        github_collection.update_many.assert_called_once()

        task_query, task_update = task_collection.update_many.call_args[0]
        self.assertEqual(task_query, expected_query)
        self.assertEqual(task_update["$set"]["status"], "error")
        self.assertEqual(task_update["$set"]["end_time"], "2026-03-19 17:00:00")
        self.assertEqual(task_update["$set"]["stop_reason"], "worker restarted")
        self.assertTrue(task_update["$set"]["interrupted"])

        self.assertEqual(result, {"task": 2, "github_task": 1})
        logger.warning.assert_called()

    @patch("app.celerytask._get_broker_queue_message_counts")
    @patch("app.celerytask._collect_live_celery_task_ids")
    @patch("app.celerytask.utils.curr_date", return_value="2026-03-19 18:00:00")
    @patch("app.celerytask.time.time", return_value=2000)
    @patch("app.celerytask.utils.conn_db")
    @patch("app.celerytask.arl_github.delay", return_value="new-github-celery-id")
    @patch("app.celerytask.arl_task.delay", return_value="new-task-celery-id")
    def test_requeue_orphan_waiting_tasks_re_dispatches_safe_waiting_tasks(
        self,
        _mock_task_delay,
        _mock_github_delay,
        mock_conn_db,
        _mock_time,
        _mock_curr_date,
        mock_collect_live,
        mock_queue_counts,
    ):
        mock_collect_live.return_value = (set(), True)
        mock_queue_counts.return_value = (
            {"arltask": 0, "arlheavy": 0, "arlweb": 0, "arlgithub": 0},
            True,
        )

        task_collection = MagicMock()
        task_collection.find.return_value = [
            {
                "_id": "task-orphan",
                "celery_id": "lost-task-id",
                "dispatch_queue": "arltask",
                "dispatch_ts": 1000,
                "type": "domain",
                "task_tag": "task",
                "target": "example.com",
                "name": "demo-task",
                "options": {},
            },
        ]
        task_collection.update_one.return_value = SimpleNamespace(modified_count=1)

        github_collection = MagicMock()
        github_collection.find.return_value = [
            {
                "_id": "github-orphan",
                "celery_id": "lost-github-id",
                "dispatch_queue": "arlgithub",
                "dispatch_ts": 1000,
                "task_tag": "monitor",
                "target": "keyword",
                "name": "demo-github",
            },
        ]
        github_collection.update_one.return_value = SimpleNamespace(modified_count=1)

        def fake_conn_db(name):
            if name == "task":
                return task_collection
            if name == "github_task":
                return github_collection
            raise AssertionError("unexpected collection {}".format(name))

        mock_conn_db.side_effect = fake_conn_db

        result = requeue_orphan_waiting_tasks_on_worker_start(reason="worker restarted")

        task_update_query, task_update_doc = task_collection.update_one.call_args[0]
        github_update_query, github_update_doc = github_collection.update_one.call_args[0]
        self.assertEqual(task_update_query["celery_id"], "lost-task-id")
        self.assertEqual(task_update_doc["$set"]["celery_id"], "new-task-celery-id")
        self.assertEqual(task_update_doc["$set"]["dispatch_queue_reason"], "worker_start_requeue_waiting")
        self.assertEqual(github_update_query["celery_id"], "lost-github-id")
        self.assertEqual(github_update_doc["$set"]["celery_id"], "new-github-celery-id")
        self.assertEqual(result, {"task": 1, "github_task": 1})

    @patch("app.celerytask._get_broker_queue_message_counts")
    @patch("app.celerytask._collect_live_celery_task_ids")
    @patch("app.celerytask.utils.curr_date", return_value="2026-03-19 18:00:00")
    @patch("app.celerytask.time.time", return_value=2000)
    @patch("app.celerytask.utils.conn_db")
    def test_recover_orphan_waiting_tasks_marks_only_high_confidence_orphans(
        self,
        mock_conn_db,
        _mock_time,
        _mock_curr_date,
        mock_collect_live,
        mock_queue_counts,
    ):
        mock_collect_live.return_value = ({"live-task-id"}, True)
        mock_queue_counts.return_value = (
            {"arltask": 0, "arlheavy": 3, "arlweb": 2, "arlgithub": 0},
            True,
        )

        task_collection = MagicMock()
        task_collection.find.return_value = [
            {
                "_id": "task-orphan",
                "celery_id": "lost-task-id",
                "dispatch_queue": "arltask",
                "dispatch_ts": 1000,
            },
            {
                "_id": "task-live",
                "celery_id": "live-task-id",
                "dispatch_queue": "arltask",
                "dispatch_ts": 1000,
            },
            {
                "_id": "task-queued",
                "celery_id": "queued-heavy-id",
                "dispatch_queue": "arlheavy",
                "dispatch_ts": 1000,
            },
            {
                "_id": "task-web-queued",
                "celery_id": "queued-web-id",
                "dispatch_queue": "arlweb",
                "dispatch_ts": 1000,
            },
        ]
        task_collection.update_many.return_value = SimpleNamespace(modified_count=1)

        github_collection = MagicMock()
        github_collection.find.return_value = [
            {
                "_id": "github-orphan",
                "celery_id": "lost-github-id",
                "dispatch_queue": "arlgithub",
                "dispatch_ts": 1000,
            }
        ]
        github_collection.update_many.return_value = SimpleNamespace(modified_count=1)

        def fake_conn_db(name):
            if name == "task":
                return task_collection
            if name == "github_task":
                return github_collection
            raise AssertionError("unexpected collection {}".format(name))

        mock_conn_db.side_effect = fake_conn_db

        result = recover_orphan_waiting_tasks_on_worker_start(reason="worker restarted")

        task_update_query = task_collection.update_many.call_args[0][0]
        github_update_query = github_collection.update_many.call_args[0][0]
        self.assertEqual(task_update_query["_id"]["$in"], ["task-orphan"])
        self.assertEqual(github_update_query["_id"]["$in"], ["github-orphan"])
        self.assertEqual(result, {"task": 1, "github_task": 1})


if __name__ == "__main__":
    unittest.main()
