"""单用户部署历史资源归属迁移回归测试。"""

import unittest
from types import SimpleNamespace
from unittest.mock import patch


class _Collection(object):
    def __init__(self, documents):
        self.documents = list(documents)
        self.update_calls = []

    def find(self, _query, _projection=None):
        return list(self.documents)

    def update_many(self, query, update):
        self.update_calls.append((query, update))
        return SimpleNamespace(modified_count=2)


class _CountCollection(object):
    def __init__(self, count):
        self.count = count

    def count_documents(self, _query):
        return self.count


class TestLegacyOwnerMigration(unittest.TestCase):
    def test_single_user_migrates_unowned_tasks_and_export_jobs(self):
        from app.utils import arlupdate

        user_collection = _Collection([{"username": "admin"}])
        task_collection = _Collection([{"_id": "task-1"}])
        export_job_collection = _Collection([{"_id": "job-1"}])

        def conn_db(collection_name):
            return {
                "user": user_collection,
                "task": task_collection,
                "export_job": export_job_collection,
            }[collection_name]

        with patch.object(arlupdate, "conn_db", side_effect=conn_db):
            result = arlupdate.migrate_legacy_resource_owners()

        self.assertEqual({"task": 2, "export_job": 2, "skipped": False}, result)
        for collection in (task_collection, export_job_collection):
            self.assertEqual(1, len(collection.update_calls))
            query, update = collection.update_calls[0]
            self.assertIn("$or", query)
            self.assertEqual({"$set": {"owner_username": "admin"}}, update)

    def test_multiple_users_do_not_claim_unowned_resources(self):
        from app.utils import arlupdate

        user_collection = _Collection([
            {"username": "admin"},
            {"username": "operator"},
        ])
        task_collection = _Collection([{"_id": "task-1"}])
        export_job_collection = _Collection([{"_id": "job-1"}])

        def conn_db(collection_name):
            return {
                "user": user_collection,
                "task": task_collection,
                "export_job": export_job_collection,
            }[collection_name]

        with patch.object(arlupdate, "conn_db", side_effect=conn_db):
            result = arlupdate.migrate_legacy_resource_owners()

        self.assertEqual({"task": 0, "export_job": 0, "skipped": True}, result)
        self.assertEqual([], task_collection.update_calls)
        self.assertEqual([], export_job_collection.update_calls)

    def test_single_user_can_access_unowned_legacy_resource(self):
        from app.utils import user as user_module

        principal = {"type": "login", "username": "admin"}
        with patch.object(user_module.Config, "AUTH", True), \
                patch.object(user_module, "conn_db", return_value=_CountCollection(1)):
            self.assertTrue(user_module.can_access_owned_resource("", principal=principal))

    def test_legacy_resource_stays_blocked_for_multiple_users(self):
        from app.utils import user as user_module

        principal = {"type": "login", "username": "admin"}
        with patch.object(user_module.Config, "AUTH", True), \
                patch.object(user_module, "conn_db", return_value=_CountCollection(2)):
            self.assertFalse(user_module.can_access_owned_resource("", principal=principal))


if __name__ == "__main__":
    unittest.main()
