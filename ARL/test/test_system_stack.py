"""用隔离 Compose 服务验证消息、状态和存储协作，避免连入部署环境。"""

import json
import os
import secrets
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone
from unittest.mock import patch
import urllib.error
import urllib.request
from urllib.parse import urlencode
import uuid

from bson import ObjectId
from pymongo import MongoClient
import redis
from kombu.exceptions import OperationalError

from app.celerytask import celery
from app.config import Config
from app.main import arl_app
from app.routes import task as task_route
from app.utils.user import gen_md5, salt
from test import system_test_tasks
from test.system_test_tasks import persist_marker


SYSTEM_TESTS_ENABLED = os.environ.get("ARL_RUN_SYSTEM_TESTS") == "1"
ARL_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKER_MODULE = "test.system_test_tasks"


@unittest.skipUnless(SYSTEM_TESTS_ENABLED, "需要隔离 Compose 服务的系统测试")
class SystemStackTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mongo = MongoClient(Config.MONGO_URL, serverSelectionTimeoutMS=3000)
        cls.collection = cls.mongo[Config.MONGO_DB].system_test_markers
        cls.tasks = cls.mongo[Config.MONGO_DB].task
        cls.users = cls.mongo[Config.MONGO_DB].user
        cls.api_url = os.environ["ARL_SYSTEM_TEST_API_URL"].rstrip("/")
        cls.redis_client = redis.Redis.from_url(
            os.environ["ARL_SYSTEM_TEST_REDIS_URL"], socket_connect_timeout=3
        )
        cls.worker = None
        cls.worker_log = None
        cls.worker_name = "arl-system-test-{}@%h".format(os.getpid())

    @classmethod
    def tearDownClass(cls):
        cls._stop_worker()
        if hasattr(cls, "redis_client"):
            cls.redis_client.close()
        if hasattr(cls, "mongo"):
            cls.mongo.close()

    @classmethod
    def _start_worker(cls):
        if cls.worker and cls.worker.poll() is None:
            return
        cls.worker_log = tempfile.TemporaryFile(mode="w+b")
        command = [
            sys.executable,
            "-m",
            "celery",
            "-A",
            "app.celerytask.celery",
            "worker",
            "--loglevel=WARNING",
            "--pool=solo",
            "--concurrency=1",
            "--queues=arl-system-test",
            "--include={}".format(WORKER_MODULE),
            "--hostname={}".format(cls.worker_name),
        ]
        cls.worker = subprocess.Popen(
            command,
            cwd=ARL_ROOT,
            env=os.environ.copy(),
            stdin=subprocess.DEVNULL,
            stdout=cls.worker_log,
            stderr=subprocess.STDOUT,
            start_new_session=(os.name == "posix"),
        )
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            if cls.worker.poll() is not None:
                raise AssertionError("隔离 Celery worker 未能启动")
            try:
                replies = celery.control.inspect(timeout=0.5).ping() or []
                if any(cls.worker_name.split("@")[0] in reply for reply in replies):
                    return
            except Exception:
                time.sleep(0.25)
        cls._stop_worker()
        raise AssertionError("隔离 Celery worker 未在限定时间内就绪")

    @classmethod
    def _stop_worker(cls):
        worker = getattr(cls, "worker", None)
        if worker is not None and worker.poll() is None:
            if os.name == "posix":
                os.killpg(worker.pid, signal.SIGTERM)
            else:
                worker.terminate()
            try:
                worker.wait(timeout=10)
            except subprocess.TimeoutExpired:
                if os.name == "posix":
                    os.killpg(worker.pid, signal.SIGKILL)
                else:
                    worker.kill()
                worker.wait(timeout=5)
        cls.worker = None
        log = getattr(cls, "worker_log", None)
        if log is not None:
            log.close()
            cls.worker_log = None

    def _wait_for_marker(self, marker_id, timeout=20):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            document = self.collection.find_one({"_id": marker_id})
            if document:
                return document
            time.sleep(0.2)
        self.fail("Celery 消息未在限定时间内写入隔离 MongoDB")

    def _request_json(self, url, method="GET", payload=None, token=None):
        headers = {}
        body = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if token:
            headers["Token"] = token
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))

    def test_http_auth_and_fixture_target_are_reachable(self):
        api_url = os.environ["ARL_SYSTEM_TEST_API_URL"].rstrip("/") + "/api/task/"
        with urllib.request.urlopen(api_url, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
            self.assertEqual(200, response.status)
            self.assertEqual(401, payload.get("code"))

        target_url = os.environ["ARL_SYSTEM_TEST_TARGET_URL"].rstrip("/") + "/"
        with urllib.request.urlopen(target_url, timeout=5) as response:
            body = response.read().decode("utf-8")
            self.assertEqual(200, response.status)
            self.assertIn("ARL isolated test target", body)

    def test_redis_uses_isolated_database(self):
        key = "arl-system-test:{}".format(uuid.uuid4().hex)
        try:
            self.assertTrue(self.redis_client.set(key, "fixture", ex=30))
            self.assertEqual(b"fixture", self.redis_client.get(key))
        finally:
            self.redis_client.delete(key)

    def test_rabbit_delivery_retry_mongo_write_and_worker_restart(self):
        retry_marker = "retry-" + uuid.uuid4().hex
        queued_marker = "queued-" + uuid.uuid4().hex
        try:
            self._start_worker()
            persist_marker.apply_async(
                args=(retry_marker, "retry fixture"),
                kwargs={"retry_once": True},
                queue="arl-system-test",
            )
            retry_result = self._wait_for_marker(retry_marker)
            self.assertEqual(2, retry_result["attempts"])

            self._stop_worker()
            persist_marker.apply_async(
                args=(queued_marker, "restart fixture"),
                queue="arl-system-test",
            )
            time.sleep(1)
            self.assertIsNone(self.collection.find_one({"_id": queued_marker}))

            self._start_worker()
            queued_result = self._wait_for_marker(queued_marker)
            self.assertEqual("restart fixture", queued_result["value"])
            self.assertEqual(1, queued_result["attempts"])
        finally:
            self._stop_worker()
            self.collection.delete_many({"_id": {"$in": [retry_marker, queued_marker]}})

    def test_rabbit_publish_failure_does_not_persist_success_and_recovers(self):
        marker_id = "broker-recovery-" + uuid.uuid4().hex
        self._start_worker()
        unavailable_connection = celery.connection_for_write(
            url="amqp://guest:guest@127.0.0.1:1/"
        )
        unavailable_connection.connect_timeout = 1
        try:
            producer = celery.amqp.Producer(unavailable_connection)
            with self.assertRaises(OperationalError):
                persist_marker.apply_async(
                    args=(marker_id, "recovered"),
                    queue="arl-system-test",
                    producer=producer,
                    retry=False,
                )
            self.assertIsNone(self.collection.find_one({"_id": marker_id}))
        finally:
            unavailable_connection.release()

        persist_marker.apply_async(
            args=(marker_id, "recovered"), queue="arl-system-test"
        )
        saved = self._wait_for_marker(marker_id)
        self.assertEqual("recovered", saved["value"])
        self.collection.delete_one({"_id": marker_id})

    def test_mongo_unavailable_task_is_reported_failed_then_can_be_retried(self):
        marker_id = "mongo-recovery-" + uuid.uuid4().hex
        outcome_key = "arl-system-test:outcome:" + marker_id
        self._start_worker()
        persist_marker.apply_async(
            args=(marker_id, "after-recovery"),
            kwargs={
                "mongo_url": "mongodb://127.0.0.1:1/arl_system_test",
                "outcome_key": outcome_key,
            },
            queue="arl-system-test",
        )
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.redis_client.get(outcome_key) == b"failed":
                break
            time.sleep(0.2)
        self.assertEqual(b"failed", self.redis_client.get(outcome_key))
        self.assertIsNone(self.collection.find_one({"_id": marker_id}))

        persist_marker.apply_async(
            args=(marker_id, "after-recovery"),
            kwargs={"outcome_key": outcome_key},
            queue="arl-system-test",
        )
        saved = self._wait_for_marker(marker_id)
        self.assertEqual("after-recovery", saved["value"])
        self.assertEqual(b"done", self.redis_client.get(outcome_key))
        self.collection.delete_one({"_id": marker_id})
        self.redis_client.delete(outcome_key)

    def test_duplicate_delivery_updates_one_idempotent_record(self):
        marker_id = "duplicate-delivery-" + uuid.uuid4().hex
        celery_task_id = "duplicate-celery-" + uuid.uuid4().hex
        self._start_worker()
        persist_marker.apply_async(
            args=(marker_id, "first"),
            queue="arl-system-test",
            task_id=celery_task_id,
        )
        persist_marker.apply_async(
            args=(marker_id, "second"),
            queue="arl-system-test",
            task_id=celery_task_id,
        )

        deadline = time.monotonic() + 20
        saved = None
        while time.monotonic() < deadline:
            saved = self.collection.find_one({"_id": marker_id})
            if saved and saved.get("deliveries") == 2:
                break
            time.sleep(0.2)

        self.assertIsNotNone(saved)
        self.assertEqual(2, saved.get("deliveries"))
        self.assertEqual("first", saved.get("value"))
        self.assertEqual(1, saved.get("attempts"))
        self.collection.delete_one({"_id": marker_id})

    def test_task_create_worker_persistence_and_http_query(self):
        username = "arl_system_test_" + uuid.uuid4().hex
        password = secrets.token_urlsafe(32)
        task_id = None
        self.users.insert_one({
            "username": username,
            "password": gen_md5(salt + password),
            "token": None,
        })
        try:
            login = self._request_json(
                self.api_url + "/api/user/login",
                method="POST",
                payload={"username": username, "password": password},
            )
            self.assertEqual(200, login.get("code"))
            token = login["data"]["token"]
            self._start_worker()

            def enqueue_deterministic_task(target, name, options, owner_username):
                task_document = {
                    "_id": ObjectId(),
                    "name": name,
                    "target": target,
                    "type": "domain",
                    "task_tag": "task",
                    "status": "waiting",
                    "progress": 0,
                    "owner_username": owner_username,
                    "options": options,
                    "create_time": datetime.now(timezone.utc),
                }
                self.tasks.insert_one(task_document)
                system_test_tasks.complete_task.apply_async(
                    args=(str(task_document["_id"]), "fixed-result"),
                    queue="arl-system-test",
                )
                return [{
                    "_id": str(task_document["_id"]),
                    "name": name,
                    "target": target,
                }]

            app_config = arl_app.config
            previous_testing = app_config.get("TESTING")
            app_config["TESTING"] = True
            self.addCleanup(app_config.__setitem__, "TESTING", previous_testing)
            with patch.object(
                task_route,
                "submit_task_task",
                side_effect=enqueue_deterministic_task,
            ):
                response = arl_app.test_client().post(
                    "/api/task/",
                    json={
                        "name": "deterministic-" + uuid.uuid4().hex,
                        "target": "fixture.invalid",
                        "port_scan": False,
                        "domain_brute": False,
                        "npoc_service_detection": False,
                    },
                    headers={"Token": token},
                )

            self.assertEqual(200, response.status_code)
            response_payload = response.get_json()
            self.assertEqual(200, response_payload.get("code"))
            task_id = response_payload["items"][0]["_id"]

            deadline = time.monotonic() + 20
            completed_task = None
            while time.monotonic() < deadline:
                completed_task = self.tasks.find_one({"_id": ObjectId(task_id)})
                if completed_task and completed_task.get("status") == "done":
                    break
                time.sleep(0.2)
            self.assertIsNotNone(completed_task)
            self.assertEqual("done", completed_task.get("status"))
            self.assertEqual(100, completed_task.get("progress"))
            self.assertEqual("fixed-result", completed_task.get("system_test_result"))
            self.assertEqual(username, completed_task.get("owner_username"))

            query = urlencode({"_id": task_id, "page": 1, "size": 10})
            payload = self._request_json(
                self.api_url + "/api/task/?" + query,
                token=token,
            )
            self.assertEqual(200, payload.get("code"))
            visible_task = next(
                item for item in payload.get("items", [])
                if item.get("_id") == task_id
            )
            self.assertEqual("done", visible_task.get("status"))
            self.assertEqual("fixed-result", visible_task.get("system_test_result"))
        finally:
            if task_id:
                self.tasks.delete_one({"_id": ObjectId(task_id)})
            self.users.delete_one({"username": username})

    def test_stop_api_revokes_delayed_deterministic_task(self):
        username = "arl_cancel_test_" + uuid.uuid4().hex
        password = secrets.token_urlsafe(32)
        task_id = ObjectId()
        marker_id = "cancel-" + uuid.uuid4().hex
        self.users.insert_one({
            "username": username,
            "password": gen_md5(salt + password),
            "token": None,
        })
        try:
            login = self._request_json(
                self.api_url + "/api/user/login",
                method="POST",
                payload={"username": username, "password": password},
            )
            token = login["data"]["token"]
            self._start_worker()
            async_result = system_test_tasks.cancel_marker.apply_async(
                args=(marker_id,),
                countdown=45,
                expires=20,
                queue="arl-system-test",
            )
            self.tasks.insert_one({
                "_id": task_id,
                "name": "cancel-fixture",
                "target": "fixture.invalid",
                "type": "domain",
                "status": "waiting",
                "progress": 0,
                "owner_username": username,
                "celery_id": async_result.id,
            })

            deadline = time.monotonic() + 10
            scheduled = False
            while time.monotonic() < deadline:
                scheduled_tasks = celery.control.inspect(timeout=0.5).scheduled() or {}
                scheduled = any(
                    entry.get("request", {}).get("id") == async_result.id
                    for entries in scheduled_tasks.values()
                    for entry in entries
                )
                if scheduled:
                    break
                time.sleep(0.2)
            self.assertTrue(scheduled, "worker 未接收可撤销的延迟消息")

            stopped = self._request_json(
                self.api_url + "/api/task/stop/{}".format(task_id),
                token=token,
            )
            self.assertEqual(200, stopped.get("code"))
            self.assertEqual("stop", self.tasks.find_one({"_id": task_id})["status"])
            revoked = celery.control.inspect(timeout=1).revoked() or {}
            self.assertTrue(
                any(async_result.id in task_ids for task_ids in revoked.values()),
                "worker 未登记任务撤销状态",
            )
            time.sleep(0.5)
            self.assertIsNone(self.collection.find_one({"_id": marker_id}))
        finally:
            self.tasks.delete_one({"_id": task_id})
            self.collection.delete_one({"_id": marker_id})
            self.users.delete_one({"username": username})

    def test_retry_exhaustion_persists_error_terminal_state(self):
        task_id = ObjectId()
        self.tasks.insert_one({
            "_id": task_id,
            "name": "failure-recovery-fixture",
            "target": "fixture.invalid",
            "status": "waiting",
            "progress": 0,
        })
        try:
            self._start_worker()
            system_test_tasks.fail_task.apply_async(
                args=(str(task_id),), queue="arl-system-test"
            )

            deadline = time.monotonic() + 20
            task_document = None
            while time.monotonic() < deadline:
                task_document = self.tasks.find_one({"_id": task_id})
                if task_document and task_document.get("status") == "error":
                    break
                time.sleep(0.2)

            self.assertIsNotNone(task_document)
            self.assertEqual("error", task_document.get("status"))
            self.assertEqual(2, task_document.get("retry_count"))
            self.assertEqual(
                "deterministic system-test failure", task_document.get("error")
            )
        finally:
            self.tasks.delete_one({"_id": task_id})


if __name__ == "__main__":
    unittest.main()
