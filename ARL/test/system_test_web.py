"""只在隔离 Compose API 中用确定性任务替代生产扫描入队函数。"""

from datetime import datetime, timezone

from bson import ObjectId
from pymongo import MongoClient

from app.config import Config
from app.main import arl_app
from app.routes import task as task_route
from test.system_test_tasks import complete_task, fail_task


def enqueue_deterministic_task(target, name, options, owner_username):
    task_id = ObjectId()
    task_document = {
        "_id": task_id,
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
    client = MongoClient(Config.MONGO_URL, serverSelectionTimeoutMS=3000)
    try:
        client[Config.MONGO_DB].task.insert_one(task_document)
    finally:
        client.close()

    if target == "fixture-failure.invalid":
        fail_task.apply_async(args=(str(task_id),), queue="arl-system-test")
    else:
        complete_task.apply_async(
            args=(str(task_id), "fixed-browser-result"),
            queue="arl-system-test",
        )
    return [{"_id": str(task_id), "name": name, "target": target}]


task_route.submit_task_task = enqueue_deterministic_task
