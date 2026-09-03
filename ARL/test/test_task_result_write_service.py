"""任务结果写回服务回归测试。"""

import unittest
from unittest.mock import patch

from app.services.task_result_write_service import TaskResultWriteService


class _Collection(object):
    def __init__(self):
        self.calls = []

    def insert_one(self, document):
        self.calls.append(("insert_one", document))

    def bulk_write(self, operations, ordered=False):
        self.calls.append(("bulk_write", operations, ordered))

    def update_one(self, query, update, upsert=False):
        self.calls.append(("update_one", query, update, upsert))

    def replace_one(self, query, document, upsert=False):
        self.calls.append(("replace_one", query, document, upsert))

    def delete_many(self, query):
        self.calls.append(("delete_many", query))


class TestTaskResultWriteService(unittest.TestCase):
    def test_write_methods_keep_collection_and_upsert_semantics(self):
        collection = _Collection()
        service = TaskResultWriteService("task-demo")

        with patch(
            "app.services.task_result_write_service.utils.conn_db",
            return_value=collection,
        ) as conn_db:
            service.insert_one("site", {"task_id": "task-demo"})
            service.bulk_write("url", ["operation"], ordered=False)
            service.update_one("wih", {"fnv_hash": "hash"}, {"$set": {"x": 1}}, upsert=True)
            service.replace_one("wih_endpoint", {"fnv_hash": "hash"}, {"x": 1}, upsert=True)
            service.delete_many("url", {"task_id": "task-demo"})

        self.assertEqual(
            [
                "insert_one",
                "bulk_write",
                "update_one",
                "replace_one",
                "delete_many",
            ],
            [item[0] for item in collection.calls],
        )
        self.assertTrue(collection.calls[2][3])
        self.assertTrue(collection.calls[3][3])
        self.assertEqual(
            ["site", "url", "wih", "wih_endpoint", "url"],
            [call.args[0] for call in conn_db.call_args_list],
        )


if __name__ == "__main__":
    unittest.main()
