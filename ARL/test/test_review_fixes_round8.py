"""第八轮 Review 整改回归：PoC 同步改为后台任务。"""

import unittest
from types import SimpleNamespace
from unittest.mock import patch


class _Collection(object):
    def __init__(self):
        self.documents = []
        self.updates = []

    def insert_one(self, document):
        document = dict(document)
        document["_id"] = "507f1f77bcf86cd799439011"
        self.documents.append(document)
        return SimpleNamespace(inserted_id=document["_id"])

    def update_one(self, query, update):
        self.updates.append((query, update))
        return SimpleNamespace(modified_count=1)

    def find_one(self, query, _projection=None):
        if "status" in query and query["status"] == {"$in": ["queued", "running"]}:
            return None
        if query.get("_id") != "507f1f77bcf86cd799439011":
            return None
        if query.get("requested_by") and query["requested_by"] != "user":
            return None
        return {
            "_id": query["_id"],
            "status": "done",
            "plugin_cnt": 4,
            "updated_at": "2026-09-15 12:00:00",
        }


class TestReviewFixesRound8(unittest.TestCase):
    def test_poc_sync_submits_background_job(self):
        from flask import Flask
        from app.routes import poc as poc_module

        app = Flask(__name__)
        collection = _Collection()
        with patch.object(poc_module.utils, "conn_db", return_value=collection), \
                patch.object(poc_module.utils, "current_principal", return_value={
                    "type": "login", "username": "user",
                }), \
                patch.object(poc_module.celerytask.arl_task_web, "delay", return_value="celery-1") as delay:
            with app.test_request_context("/poc/sync/", method="POST"):
                response = poc_module.ARLPoCSync.post.__wrapped__(poc_module.ARLPoCSync())

        self.assertEqual(202, response[1])
        self.assertEqual("queued", response[0]["data"]["status"])
        self.assertEqual("celery-1", response[0]["data"]["celery_id"])
        delay.assert_called_once()
        self.assertEqual("queued", collection.documents[0]["status"])

    def test_poc_sync_worker_claims_and_finishes_job(self):
        from app import celerytask

        collection = _Collection()
        fake_npoc = SimpleNamespace(
            plugin_name_list=["one", "two"],
            sync_to_db=lambda: True,
            delete_db=lambda: True,
        )
        with patch.object(celerytask.utils, "conn_db", return_value=collection), \
                patch("app.services.npoc.NPoC", return_value=fake_npoc):
            result = celerytask.poc_sync_task({
                "data": {"sync_job_id": "507f1f77bcf86cd799439011"},
            })

        self.assertTrue(result)
        self.assertEqual(2, len(collection.updates))
        self.assertEqual("running", collection.updates[0][1]["$set"]["status"])
        self.assertEqual("done", collection.updates[1][1]["$set"]["status"])
        self.assertEqual(2, collection.updates[1][1]["$set"]["plugin_cnt"])


if __name__ == "__main__":
    unittest.main()
