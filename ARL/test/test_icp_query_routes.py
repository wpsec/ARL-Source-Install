"""ICP 查询路由的认证、边界和错误响应回归测试。"""

import functools
import pathlib
import sys
import types
import unittest
from unittest.mock import patch


ROOT_DIR = pathlib.Path(__file__).resolve().parents[1]
ROUTE_PATH = ROOT_DIR / "app" / "routes" / "icp_query.py"


def _load_route_module():
    """用最小依赖桩加载路由，避免测试连接真实 Mongo 或 broker。"""
    original_modules = dict(sys.modules)
    app_module = types.ModuleType("app")
    app_module.__path__ = []
    utils_module = types.ModuleType("app.utils")
    config_module = types.ModuleType("app.config")
    services_module = types.ModuleType("app.services")
    services_module.__path__ = []
    icp_module = types.ModuleType("app.services.icp_query")
    flask_module = types.ModuleType("flask")
    flask_restx_module = types.ModuleType("flask_restx")

    class IcpQueryError(Exception):
        pass

    class FakeNamespace(object):
        def __init__(self, *args, **kwargs):
            return None

        def route(self, _path):
            return lambda resource: resource

    class FakeResource(object):
        pass

    def auth(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)

        wrapper._is_auth = True
        return wrapper

    logger = types.SimpleNamespace(error=lambda *args, **kwargs: None)
    icp_module.ICP_QUERY_TYPES = {
        "web": {"label": "网站备案", "service_type": 1, "black": False},
    }
    icp_module.IcpQueryError = IcpQueryError
    icp_module.logger = logger
    icp_module._config_int = lambda _name, default, minimum=1, maximum=None: default
    icp_module._redact_text = lambda value, max_length=600: str(value)[:max_length]
    icp_module.get_task = lambda _task_id: None

    config_module.Config = types.SimpleNamespace(
        ICP_QUERY_ENABLE=True,
        ICP_QUERY_MAX_ITEMS=200,
        ICP_QUERY_PAGE_SIZE=26,
    )
    utils_module.auth = auth
    utils_module.build_ret = lambda status, data: {
        "code": status["code"],
        "message": status["message"],
        "data": data,
    }
    app_module.utils = utils_module
    app_module.celerytask = types.SimpleNamespace(
        celery=types.SimpleNamespace(
            control=types.SimpleNamespace(revoke=lambda *args, **kwargs: None),
        ),
    )
    services_module.icp_query = icp_module
    flask_module.request = types.SimpleNamespace(
        args={},
        get_json=lambda silent=False: {},
    )
    flask_restx_module.Namespace = FakeNamespace
    flask_restx_module.Resource = FakeResource

    sys.modules.update({
        "app": app_module,
        "app.utils": utils_module,
        "app.config": config_module,
        "app.services": services_module,
        "app.services.icp_query": icp_module,
        "flask": flask_module,
        "flask_restx": flask_restx_module,
    })
    module = types.ModuleType("icp_query_routes_test_module")
    module.__file__ = str(ROUTE_PATH)
    try:
        exec(compile(ROUTE_PATH.read_text(encoding="utf-8"), str(ROUTE_PATH), "exec"), module.__dict__)
    except Exception:
        sys.modules.clear()
        sys.modules.update(original_modules)
        raise
    return module, original_modules


MODULE = None
ORIGINAL_MODULES = None


def setUpModule():
    global MODULE, ORIGINAL_MODULES
    MODULE, ORIGINAL_MODULES = _load_route_module()


def tearDownModule():
    if ORIGINAL_MODULES is not None:
        sys.modules.clear()
        sys.modules.update(ORIGINAL_MODULES)


class TestIcpQueryRoutes(unittest.TestCase):
    def test_resource_methods_are_auth_protected(self):
        resource_types = [
            value for name, value in vars(MODULE).items()
            if name.startswith("Icp") and isinstance(value, type)
        ]

        self.assertGreaterEqual(len(resource_types), 10)
        for resource_type in resource_types:
            for method_name in ("get", "post", "delete"):
                method = getattr(resource_type, method_name, None)
                if method is not None:
                    self.assertTrue(
                        getattr(method, "_is_auth", False),
                        "{}.{} 未挂载 auth".format(resource_type.__name__, method_name),
                    )

    def test_single_route_rejects_batch_task(self):
        with patch.object(MODULE.icp_query, "get_task", return_value={"task_kind": "batch"}):
            task, error = MODULE._single_task_or_404("batch-task")

        self.assertIsNone(task)
        self.assertEqual(404, error["code"])
        self.assertEqual("单次查询任务不存在", error["message"])

    def test_disabled_feature_exposes_state_but_rejects_actions(self):
        MODULE.Config.ICP_QUERY_ENABLE = False
        try:
            meta = MODULE.IcpMeta().get()
            disabled_action = MODULE.IcpQueryCreate().post()
        finally:
            MODULE.Config.ICP_QUERY_ENABLE = True

        self.assertEqual(200, meta["code"])
        self.assertIs(meta["data"]["enabled"], False)
        self.assertEqual(503, disabled_action["code"])

    def test_internal_route_error_is_redacted_to_generic_response(self):
        with patch.object(MODULE.icp_query, "get_task", side_effect=RuntimeError("mongo credential=secret")):
            response = MODULE.IcpQueryStatus().get("task-1")

        self.assertEqual(500, response["code"])
        self.assertEqual("ICP 任务状态暂时不可用，请稍后重试", response["message"])
        self.assertNotIn("secret", str(response))


if __name__ == "__main__":
    unittest.main()
