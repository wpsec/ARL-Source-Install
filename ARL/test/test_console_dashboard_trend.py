import importlib.util
import pathlib
import sys
import types
import unittest
from datetime import datetime, timedelta


def _build_logger():
    return types.SimpleNamespace(
        debug=lambda *args, **kwargs: None,
        info=lambda *args, **kwargs: None,
        warning=lambda *args, **kwargs: None,
        error=lambda *args, **kwargs: None,
    )


def _load_console_module():
    module_name = "app.routes.console_dashboard_test_module"
    if module_name in sys.modules:
        return sys.modules[module_name]

    class _Namespace:
        def __init__(self, *args, **kwargs):
            pass

        def route(self, *args, **kwargs):
            def _decorator(cls):
                return cls

            return _decorator

    flask_module = types.ModuleType("flask")
    flask_module.request = types.SimpleNamespace(args={})

    flask_restx_module = types.ModuleType("flask_restx")
    flask_restx_module.Namespace = _Namespace

    class _ObjectId:
        @staticmethod
        def from_datetime(value):
            return value

    bson_module = types.ModuleType("bson")
    bson_module.ObjectId = _ObjectId

    app_module = types.ModuleType("app")
    app_module.__path__ = []
    utils_module = types.ModuleType("app.utils")
    utils_module.get_logger = _build_logger
    utils_module.auth = lambda fn: fn
    utils_module.device_info = lambda: {}
    utils_module.build_ret = lambda code, data: {"code": code, "data": data}

    utils_device_module = types.ModuleType("app.utils.device")
    utils_device_module.human_size = lambda value: str(value)

    modules_module = types.ModuleType("app.modules")
    modules_module.ErrorMsg = types.SimpleNamespace(Success=200)

    routes_module = types.ModuleType("app.routes")
    routes_module.__path__ = []
    routes_module.ARLResource = object
    routes_module.conn = lambda name: types.SimpleNamespace(
        count_documents=lambda query=None: 0,
        aggregate=lambda pipeline: [],
        find=lambda *args, **kwargs: [],
    )

    app_module.utils = utils_module

    backup = {}
    for name, module in (
        ("flask", flask_module),
        ("flask_restx", flask_restx_module),
        ("bson", bson_module),
        ("app", app_module),
        ("app.utils", utils_module),
        ("app.utils.device", utils_device_module),
        ("app.modules", modules_module),
        ("app.routes", routes_module),
    ):
        backup[name] = sys.modules.get(name)
        sys.modules[name] = module

    try:
        console_path = pathlib.Path(__file__).resolve().parents[1] / "app" / "routes" / "console.py"
        spec = importlib.util.spec_from_file_location(module_name, console_path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        assert spec and spec.loader
        spec.loader.exec_module(module)
        return module
    finally:
        for name, old_module in backup.items():
            if old_module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = old_module


console = _load_console_module()


class TestConsoleDashboardTrend(unittest.TestCase):
    def test_asset_trend_uses_daily_growth_series(self):
        original_count_documents = console._count_documents
        original_count_daily_records = console._count_daily_records
        try:
            now = datetime.now()
            start = (now - timedelta(days=6)).replace(hour=0, minute=0, second=0, microsecond=0)
            day_keys = [(start + timedelta(days=i)).strftime("%Y-%m-%d") for i in range(7)]
            asset_daily = [0, 1, 0, 3, 0, 2, 0]
            vuln_daily = [1, 0, 1, 0, 0, 0, 1]

            def _fake_count_documents(collection, query=None):
                if collection == "asset_site" and (query or {}) == {}:
                    return 8177
                if collection == "vuln" and (query or {}) == {}:
                    return 305
                return 0

            def _fake_count_daily_records(collection, day_start, day_end, day_key, primary_field="save_date"):
                idx = day_keys.index(day_key)
                if collection == "asset_site":
                    return asset_daily[idx]
                if collection == "vuln":
                    return vuln_daily[idx]
                return 0

            console._count_documents = _fake_count_documents
            console._count_daily_records = _fake_count_daily_records

            trend = console._build_asset_trend_7d(asset_collection="asset_site")

            self.assertEqual(7, len(trend))
            self.assertEqual(asset_daily, [int(item.get("assets", -1)) for item in trend])
            self.assertEqual(vuln_daily, [int(item.get("vulns", -1)) for item in trend])
            self.assertEqual(8177, int(trend[-1].get("assets_total", 0)))
            self.assertNotEqual(8177, int(trend[-1].get("assets", 0)))
        finally:
            console._count_documents = original_count_documents
            console._count_daily_records = original_count_daily_records

    def test_count_daily_records_falls_back_to_update_date_when_save_date_missing(self):
        original_count_documents = console._count_documents
        try:
            def _fake_count_documents(collection, query=None):
                query_obj = query or {}
                if "$and" in query_obj:
                    return 5
                return 0

            console._count_documents = _fake_count_documents
            day_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
            day_end = day_start + timedelta(days=1)
            day_key = day_start.strftime("%Y-%m-%d")
            count = console._count_daily_records("asset_site", day_start, day_end, day_key, primary_field="save_date")
            self.assertEqual(5, count)
        finally:
            console._count_documents = original_count_documents

    def test_count_daily_records_does_not_double_count_when_primary_hits(self):
        original_count_documents = console._count_documents
        try:
            def _fake_count_documents(collection, query=None):
                query_obj = query or {}
                if "$and" in query_obj:
                    return 9
                return 4

            console._count_documents = _fake_count_documents
            day_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
            day_end = day_start + timedelta(days=1)
            day_key = day_start.strftime("%Y-%m-%d")
            count = console._count_daily_records("asset_site", day_start, day_end, day_key, primary_field="save_date")
            self.assertEqual(4, count)
        finally:
            console._count_documents = original_count_documents

    def test_count_daily_records_falls_back_to_object_id_when_dates_missing(self):
        original_count_documents = console._count_documents
        try:
            def _fake_count_documents(collection, query=None):
                query_obj = query or {}
                clauses = query_obj.get("$and") or []
                if any("_id" in clause for clause in clauses):
                    return 3
                return 0

            console._count_documents = _fake_count_documents
            day_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
            day_end = day_start + timedelta(days=1)
            day_key = day_start.strftime("%Y-%m-%d")
            count = console._count_daily_records("site", day_start, day_end, day_key, primary_field="save_date")
            self.assertEqual(3, count)
        finally:
            console._count_documents = original_count_documents


if __name__ == "__main__":
    unittest.main()
