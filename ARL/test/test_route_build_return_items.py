import importlib.util
import json
import pathlib
import sys
import types
import unittest
from datetime import datetime


class _FakeObjectId(object):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value


def _load_routes_base_module():
    module_name = "app.routes.base_route_test_module"
    if module_name in sys.modules:
        return sys.modules[module_name]

    app_module = types.ModuleType("app")
    app_module.__path__ = []
    utils_module = types.ModuleType("app.utils")
    cache_module = types.ModuleType("app.utils.cache")
    config_module = types.ModuleType("app.config")
    modules_module = types.ModuleType("app.modules")
    # routes/__init__ 头部 import collection_query_service；本文件不驱动其语义，给空壳即可。
    services_module = types.ModuleType("app.services")
    services_module.__path__ = []
    query_service_module = types.ModuleType("app.services.collection_query_service")
    for _fn_name in (
        "build_collection_data",
        "build_db_query",
        "get_default_field",
        "normalize_task_status_query",
        "parse_refresh_flag",
    ):
        setattr(query_service_module, _fn_name, lambda *args, **kwargs: None)
    services_module.collection_query_service = query_service_module
    bson_module = types.ModuleType("bson")
    bson_objectid_module = types.ModuleType("bson.objectid")
    flask_restx_module = types.ModuleType("flask_restx")
    flask_module = types.ModuleType("flask")

    class _Resource(object):
        pass

    class _RequestParser(object):
        def __init__(self, *args, **kwargs):
            return None

        def add_argument(self, *args, **kwargs):
            return None

        def parse_args(self):
            return {}

    class _Fields(object):
        @staticmethod
        def Integer(**kwargs):
            return types.SimpleNamespace(
                required=kwargs.get("required", False),
                format=int,
                description=kwargs.get("description", ""),
            )

        @staticmethod
        def String(**kwargs):
            return types.SimpleNamespace(
                required=kwargs.get("required", False),
                format=str,
                description=kwargs.get("description", ""),
            )

    utils_module.conn_db = lambda _name: None
    cache_module.build_cache_key = lambda *args, **kwargs: "cache-key"
    cache_module.cached_call = lambda _key, func, expire=0, force_refresh=False: func()
    config_module.Config = types.SimpleNamespace(API_USE_ESTIMATED_COUNT=False, API_LIST_CACHE_EXPIRE=0)
    modules_module.CollectSource = types.SimpleNamespace(BATCH="batch")
    bson_objectid_module.ObjectId = _FakeObjectId
    flask_restx_module.Resource = _Resource
    flask_restx_module.reqparse = types.SimpleNamespace(RequestParser=_RequestParser)
    flask_restx_module.fields = _Fields
    flask_module.make_response = lambda value: value

    sys.modules["app"] = app_module
    sys.modules["app.utils"] = utils_module
    sys.modules["app.utils.cache"] = cache_module
    sys.modules["app.config"] = config_module
    sys.modules["app.modules"] = modules_module
    sys.modules["app.services"] = services_module
    sys.modules["app.services.collection_query_service"] = query_service_module
    sys.modules["bson"] = bson_module
    sys.modules["bson.objectid"] = bson_objectid_module
    sys.modules["flask_restx"] = flask_restx_module
    sys.modules["flask"] = flask_module

    route_path = pathlib.Path(__file__).resolve().parents[1] / "app" / "routes" / "__init__.py"
    source = route_path.read_text(encoding="utf-8")
    source = source.split("# ==================== 导入所有路由命名空间 ====================", 1)[0]

    module = types.ModuleType(module_name)
    module.__file__ = str(route_path)
    sys.modules[module_name] = module
    exec(compile(source, str(route_path), "exec"), module.__dict__)
    return module


routes_base_module = None


def setUpModule():
    global routes_base_module, _ORIGINAL_SYS_MODULES
    _ORIGINAL_SYS_MODULES = dict(sys.modules)
    routes_base_module = _load_routes_base_module()


def tearDownModule():
    # 替身环境只服务本文件的字符串 patch；退出时全量还原 sys.modules，
    # 避免合跑进程中污染其它测试对真实 app 包的解析。
    original_modules = globals().get("_ORIGINAL_SYS_MODULES")
    if original_modules is not None:
        sys.modules.clear()
        sys.modules.update(original_modules)





class TestRouteBuildReturnItems(unittest.TestCase):
    def test_build_return_items_serializes_nested_datetime_and_object_id(self):
        resource = routes_base_module.ARLResource()
        items = resource.build_return_items(
            [
                {
                    "_id": _FakeObjectId("task-1"),
                    "kb_push_time": datetime(2026, 7, 13, 9, 54, 41),
                    "service": [
                        {"name": "web_info_hunter", "elapsed": 1.2},
                        {"name": "wih_probe", "elapsed": 0.8},
                    ],
                    "nested": {
                        "created_at": datetime(2026, 7, 13, 9, 55, 0),
                        "task_id": _FakeObjectId("sub-task-1"),
                    },
                    "history": [
                        datetime(2026, 7, 13, 10, 0, 0),
                        {"node_id": _FakeObjectId("node-1")},
                    ],
                }
            ]
        )

        first_item = items[0]
        self.assertEqual("task-1", first_item["_id"])
        self.assertEqual("2026-07-13 09:54:41", first_item["kb_push_time"])
        self.assertEqual("2026-07-13 09:55:00", first_item["nested"]["created_at"])
        self.assertEqual("sub-task-1", first_item["nested"]["task_id"])
        self.assertEqual("2026-07-13 10:00:00", first_item["history"][0])
        self.assertEqual("node-1", first_item["history"][1]["node_id"])
        self.assertIn("service_summary", first_item)

        payload = json.dumps({"items": items}, ensure_ascii=False)
        self.assertIn("2026-07-13 09:54:41", payload)


if __name__ == "__main__":
    unittest.main()
