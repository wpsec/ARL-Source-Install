"""第五轮 Review 整改回归：授权、跨消息响应缓存和安全错误摘要。"""

import unittest
from types import SimpleNamespace
from unittest.mock import patch


class _ResponseCollection(object):
    def __init__(self):
        self.docs = {}

    def create_index(self, *args, **kwargs):
        return "index"

    def find_one(self, query, projection=None):
        for doc in self.docs.values():
            if doc.get("task_id") != query.get("task_id"):
                continue
            if doc.get("key") != query.get("key"):
                continue
            if doc.get("expires_at", 0) <= query.get("expires_at", {}).get("$gt", 0):
                continue
            return dict(doc)
        return None

    def update_one(self, query, update, upsert=False):
        key = (query.get("task_id"), query.get("key"))
        document = dict(update.get("$set") or {})
        document.update({"task_id": key[0], "key": key[1]})
        self.docs[key] = document
        return SimpleNamespace(modified_count=1)


class _ResponseUtils(object):
    def __init__(self, collection):
        self.collection = collection

    def conn_db(self, _name):
        return self.collection


class TestReviewFixesRound5(unittest.TestCase):
    def test_response_cache_survives_new_context(self):
        from app.services.discovery_context import DiscoveryContext
        from app.services.discovery_ledger_store import MongoResponseBackend

        collection = _ResponseCollection()
        utils_module = _ResponseUtils(collection)
        first = DiscoveryContext(
            "task-1",
            response_backend=MongoResponseBackend("task-1", utils_module=utils_module),
        )
        first.put_response(
            "https://example.test/api",
            status_code=200,
            headers={"Content-Type": "text/plain"},
            body=b"bounded body",
            source="unit",
        )

        second = DiscoveryContext(
            "task-1",
            response_backend=MongoResponseBackend("task-1", utils_module=utils_module),
        )
        record = second.get_response("https://example.test/api", consumer="deep")
        self.assertIsNotNone(record)
        self.assertEqual(b"bounded body", record.body)
        self.assertEqual(1, second.metrics_snapshot()["cache_hit_count"])

    def test_scope_guard_does_not_join_same_name_tasks(self):
        from app.services import task_scope_guard as guard_mod

        task_id = "507f1f77bcf86cd799439011"
        class FakeCollection(object):
            def __init__(self, name):
                self.name = name

            def find_one(self, query, projection=None, **kwargs):
                if self.name == "task":
                    return {"name": "same", "target": "main.example.test"}
                return None

            def distinct(self, field, query, **kwargs):
                if self.name == "site":
                    return ["https://main.example.test"]
                if self.name == "domain":
                    return ["main.example.test"]
                return []

        def conn_db(name):
            return FakeCollection(name)

        with patch.object(guard_mod.utils, "conn_db", side_effect=conn_db):
            context = guard_mod.load_task_scope_context(task_id)
        self.assertIn("main.example.test", context["allowed_hosts"])
        self.assertNotIn("other.example.test", context["allowed_hosts"])
        self.assertEqual([task_id], context["task_ids"])

    def test_safe_error_text_redacts_path_and_query_secret(self):
        from app.utils.log_safety import safe_error_text

        text = safe_error_text(
            "open /Users/example/project/config.yaml failed "
            "https://example.test/?token=secret-value"
        )
        self.assertNotIn("/Users/example/project", text)
        self.assertNotIn("secret-value", text)
        self.assertIn("[PATH]", text)
        self.assertIn("[REDACTED]", text)


if __name__ == "__main__":
    unittest.main()
