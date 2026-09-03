"""任务仓储回归测试。"""

import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


_MODULE_PATH = Path(__file__).resolve().parents[1] / "app" / "repositories" / "task_repository.py"
_SPEC = importlib.util.spec_from_file_location("task_repository_test_module", _MODULE_PATH)
_MODULE = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader

# 仓储单元测试不需要启动完整 Flask 应用；这样在最小 Python 环境中也能验证查询边界。
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
TaskRepository = _MODULE.TaskRepository


class _Collection(object):
    def __init__(self):
        self.calls = []

    def find_one(self, *args):
        self.calls.append(("find_one", args))
        return {"_id": args[0]["_id"]}

    def update_one(self, *args):
        self.calls.append(("update_one", args))
        return "updated"

    def find_one_and_replace(self, *args):
        self.calls.append(("find_one_and_replace", args))
        return "replaced"

    def delete_many(self, *args):
        self.calls.append(("delete_many", args))
        return type("DeleteResult", (), {"deleted_count": 1})()


class TestTaskRepository(unittest.TestCase):
    def test_task_operations_use_task_collection_and_object_id(self):
        collection = _Collection()
        with patch.object(_MODULE.utils, "conn_db", return_value=collection) as conn_db:
            task = TaskRepository.find_by_id("65f000000000000000000001")
            updated = TaskRepository.update_by_id("65f000000000000000000001", {"$set": {"status": "stop"}})
            replaced = TaskRepository.replace_by_id("65f000000000000000000001", {"_id": "x"})
            deleted = TaskRepository.delete_by_id("65f000000000000000000001")

        self.assertEqual("task", conn_db.call_args_list[0].args[0])
        self.assertEqual("updated", updated)
        self.assertEqual("replaced", replaced)
        self.assertEqual(1, deleted.deleted_count)
        self.assertEqual(4, len(collection.calls))
        for _name, args in collection.calls:
            self.assertEqual("ObjectId('65f000000000000000000001')", repr(args[0]["_id"]))
        self.assertTrue(task)

    def test_delete_related_data_keeps_asset_delete_scope_explicit(self):
        collections = {}

        def get_collection(name):
            collections.setdefault(name, _Collection())
            return collections[name]

        with patch.object(_MODULE.utils, "conn_db", side_effect=get_collection):
            deleted = TaskRepository.delete_related_data("task-1", delete_asset_data=False)

        # 执行账本属恢复元数据：不随资产开关，任务删除即清理。
        self.assertEqual({"ai_denoise_result", "task_stage_ledger"}, set(collections))
        self.assertEqual(1, deleted["ai_denoise_result"])

        collections.clear()
        with patch.object(_MODULE.utils, "conn_db", side_effect=get_collection):
            deleted = TaskRepository.delete_related_data("task-1", delete_asset_data=True)

        self.assertEqual(
            {"ai_denoise_result", "task_stage_ledger"}.union(TaskRepository.RELATED_COLLECTIONS),
            set(collections),
        )
        self.assertTrue(all(value == 1 for value in deleted.values()))


if __name__ == "__main__":
    unittest.main()
