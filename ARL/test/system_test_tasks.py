"""隔离队列回归复用确定性任务，避免触发真实扫描流程。"""

from datetime import datetime, timezone
import os

from bson import ObjectId
from pymongo import MongoClient
import redis

from app.celerytask import celery
from app.config import Config


@celery.task(bind=True, name="arl.system_test.persist_marker", max_retries=1)
def persist_marker(self, marker_id, value, retry_once=False, mongo_url=None, outcome_key=None):
    if retry_once and self.request.retries == 0:
        raise self.retry(countdown=0)

    client = MongoClient(mongo_url or Config.MONGO_URL, serverSelectionTimeoutMS=3000)
    try:
        try:
            client[Config.MONGO_DB].system_test_markers.update_one(
                {"_id": marker_id},
                {
                    "$inc": {"deliveries": 1},
                    "$setOnInsert": {
                        "value": value,
                        "attempts": self.request.retries + 1,
                    },
                },
                upsert=True,
            )
        except Exception:
            if outcome_key:
                _write_outcome(outcome_key, "failed")
            raise
        if outcome_key:
            _write_outcome(outcome_key, "done")
    finally:
        client.close()
    return marker_id


def _write_outcome(outcome_key, value):
    client = redis.Redis.from_url(os.environ["ARL_SYSTEM_TEST_REDIS_URL"])
    try:
        client.set(outcome_key, value, ex=60)
    finally:
        client.close()


@celery.task(bind=True, name="arl.system_test.complete_task", max_retries=0)
def complete_task(self, task_id, result_summary):
    """只更新测试任务文档，验证 Celery 到 API 的持久化链路。"""
    client = MongoClient(Config.MONGO_URL, serverSelectionTimeoutMS=3000)
    try:
        task_collection = client[Config.MONGO_DB].task
        task_object_id = ObjectId(task_id)
        task_collection.update_one(
            {"_id": task_object_id},
            {"$set": {
                "status": "running",
                "progress": 50,
                "current_stage": "system-test",
            }},
        )
        result = task_collection.update_one(
            {"_id": task_object_id},
            {"$set": {
                "status": "done",
                "progress": 100,
                "current_stage": "completed",
                "system_test_result": result_summary,
                "end_time": datetime.now(timezone.utc),
            }},
        )
        if result.matched_count != 1:
            raise LookupError("隔离测试任务不存在")
    finally:
        client.close()
    return task_id


@celery.task(bind=True, name="arl.system_test.cancel_marker", max_retries=0)
def cancel_marker(self, marker_id):
    """若撤销失败会写入标记，便于验证取消消息是否到达 worker。"""
    client = MongoClient(Config.MONGO_URL, serverSelectionTimeoutMS=3000)
    try:
        client[Config.MONGO_DB].system_test_markers.insert_one({
            "_id": marker_id,
            "value": "unexpectedly-executed",
        })
    finally:
        client.close()
    return marker_id


@celery.task(bind=True, name="arl.system_test.fail_task", max_retries=1)
def fail_task(self, task_id):
    """重试耗尽后持久化确定性错误终态，避免依赖生产扫描器。"""
    if self.request.retries == 0:
        raise self.retry(countdown=0)

    client = MongoClient(Config.MONGO_URL, serverSelectionTimeoutMS=3000)
    try:
        result = client[Config.MONGO_DB].task.update_one(
            {"_id": ObjectId(task_id)},
            {"$set": {
                "status": "error",
                "error": "deterministic system-test failure",
                "retry_count": self.request.retries + 1,
                "end_time": datetime.now(timezone.utc),
            }},
        )
        if result.matched_count != 1:
            raise LookupError("隔离测试任务不存在")
    finally:
        client.close()
    raise RuntimeError("deterministic system-test failure")
