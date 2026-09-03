"""导出仓储回归测试。"""

import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


_MODULE_PATH = Path(__file__).resolve().parents[1] / "app" / "repositories" / "export_repository.py"
_SPEC = importlib.util.spec_from_file_location("export_repository_test_module", _MODULE_PATH)
_MODULE = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader

_saved_modules = {name: sys.modules.get(name) for name in ("app", "app.utils", "bson")}
try:
    fake_utils = types.ModuleType("app.utils")
    fake_utils.conn_db = None
    fake_app = types.ModuleType("app")
    fake_app.utils = fake_utils
    sys.modules["app"] = fake_app
    sys.modules["app.utils"] = fake_utils
    try:
        from bson import ObjectId  # noqa: F401
    except ImportError:
        fake_bson = types.ModuleType("bson")

        class ObjectId(object):
            def __init__(self, value):
                self.value = str(value)

            def __repr__(self):
                return "ObjectId({!r})".format(self.value)

        fake_bson.ObjectId = ObjectId
        sys.modules["bson"] = fake_bson
    _SPEC.loader.exec_module(_MODULE)
finally:
    for name, module in _saved_modules.items():
        if module is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = module

ExportRepository = _MODULE.ExportRepository


class _Cursor(object):
    def __init__(self):
        self.batch_sizes = []

    def batch_size(self, value):
        self.batch_sizes.append(value)
        return self


class _Collection(object):
    def __init__(self):
        self.calls = []
        self.cursor = _Cursor()

    def find(self, *args, **kwargs):
        self.calls.append(("find", args, kwargs))
        return self.cursor

    def find_one(self, *args, **kwargs):
        self.calls.append(("find_one", args, kwargs))
        return {"_id": args[0]["_id"]}

    def insert_one(self, document):
        self.calls.append(("insert_one", document))
        return types.SimpleNamespace(inserted_id="job-id")

    def update_one(self, *args):
        self.calls.append(("update_one", args))
        return "updated"

    def create_index(self, *args, **kwargs):
        self.calls.append(("create_index", args, kwargs))


class TestExportRepository(unittest.TestCase):
    def test_task_scoped_query_is_batched(self):
        collection = _Collection()
        with patch.object(_MODULE.utils, "conn_db", return_value=collection):
            cursor = ExportRepository.find_by_task_id("site", "task-1", batch_size=500)

        self.assertIs(collection.cursor, cursor)
        self.assertEqual({"task_id": "task-1"}, collection.calls[0][1][0])
        self.assertEqual([500], collection.cursor.batch_sizes)

    def test_job_operations_use_object_id(self):
        collection = _Collection()
        with patch.object(_MODULE.utils, "conn_db", return_value=collection):
            ExportRepository.find_job("65f000000000000000000001")
            ExportRepository.update_job("65f000000000000000000001", {"$set": {"status": "done"}})
            inserted = ExportRepository.insert_job({"status": "queued"})
            ExportRepository.ensure_job_indexes()

        self.assertEqual("job-id", inserted.inserted_id)
        find_call = collection.calls[0]
        update_call = collection.calls[1]
        self.assertIn("_id", find_call[1][0])
        self.assertIn("_id", update_call[1][0])
        self.assertEqual(3, len([item for item in collection.calls if item[0] == "create_index"]))


if __name__ == "__main__":
    unittest.main()
