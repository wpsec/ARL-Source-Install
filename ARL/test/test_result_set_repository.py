"""结果集仓储回归测试。"""

import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


_MODULE_PATH = Path(__file__).resolve().parents[1] / "app" / "repositories" / "result_set_repository.py"
_SPEC = importlib.util.spec_from_file_location("result_set_repository_test_module", _MODULE_PATH)
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


ResultSetRepository = _MODULE.ResultSetRepository


class _Collection(object):
    def __init__(self):
        self.calls = []

    def find_one(self, *args):
        self.calls.append(args)
        return {"total": 12}


class TestResultSetRepository(unittest.TestCase):
    def test_find_total_by_id_uses_result_set_collection(self):
        collection = _Collection()
        with patch.object(_MODULE.utils, "conn_db", return_value=collection) as conn_db:
            result = ResultSetRepository.find_total_by_id("65f000000000000000000001")

        self.assertEqual({"total": 12}, result)
        conn_db.assert_called_once_with("result_set")
        self.assertEqual("ObjectId('65f000000000000000000001')", repr(collection.calls[0][0]["_id"]))
        self.assertEqual({"total": 1}, collection.calls[0][1])


if __name__ == "__main__":
    unittest.main()
