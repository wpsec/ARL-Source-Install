import importlib.util
import pathlib
import sys
import types
import unittest


def _build_logger():
    return types.SimpleNamespace(
        info=lambda *args, **kwargs: None,
        warning=lambda *args, **kwargs: None,
        error=lambda *args, **kwargs: None,
    )


def _load_ai_pen_route_module():
    module_name = "app.routes.ai_pen_test_test_module"
    if module_name in sys.modules:
        return sys.modules[module_name]

    app_module = types.ModuleType("app")
    app_module.__path__ = []
    routes_module = types.ModuleType("app.routes")
    routes_module.__path__ = []
    services_module = types.ModuleType("app.services")
    services_module.__path__ = []
    common_task_module = types.ModuleType("app.services.commonTask")
    utils_module = types.ModuleType("app.utils")
    modules_module = types.ModuleType("app.modules")
    bson_module = types.ModuleType("bson")
    flask_restx_module = types.ModuleType("flask_restx")

    class _Fields(object):
        @staticmethod
        def String(**kwargs):
            return {"type": "string", **kwargs}

        @staticmethod
        def Integer(**kwargs):
            return {"type": "integer", **kwargs}

        @staticmethod
        def List(inner, **kwargs):
            return {"type": "list", "inner": inner, **kwargs}

    class _Namespace(object):
        def __init__(self, *args, **kwargs):
            self.args = args
            self.kwargs = kwargs

        def model(self, _name, schema):
            return schema

        def route(self, *_args, **_kwargs):
            return lambda obj: obj

        def expect(self, *_args, **_kwargs):
            return lambda obj: obj

    class _ARLResource(object):
        def parse_args(self, _fields):
            return {}

        def build_data(self, **kwargs):
            return kwargs

    class _WebSiteFetch(object):
        AI_PEN_TEST_MCP_MAX_TOOL_CALLS = 4

        @staticmethod
        def _build_ai_pen_retry_seed_tool_plan(*args, **kwargs):
            return []

        @staticmethod
        def _summarize_ai_pen_tool_results_for_agent(*args, **kwargs):
            return []

    utils_module.conn_db = lambda _name: None
    utils_module.build_ret = lambda code, data: {"code": code, "data": data}
    utils_module.curr_date = lambda: "2026-03-31 00:00:00"
    utils_module.get_logger = _build_logger
    utils_module.domain_parsed = lambda value: {"fld": value}

    modules_module.ErrorMsg = types.SimpleNamespace(Success="Success", Error="Error")
    common_task_module.WebSiteFetch = _WebSiteFetch
    bson_module.ObjectId = lambda value=None: value
    flask_restx_module.fields = _Fields
    flask_restx_module.Namespace = _Namespace

    utils_submodule = types.ModuleType("app.utils")
    utils_submodule.auth = lambda func: func
    utils_submodule.get_logger = _build_logger

    routes_module.base_query_fields = {}
    routes_module.ARLResource = _ARLResource
    routes_module.get_arl_parser = lambda *_args, **_kwargs: types.SimpleNamespace(parse_args=lambda: {})

    sys.modules["app"] = app_module
    sys.modules["app.routes"] = routes_module
    sys.modules["app.services"] = services_module
    sys.modules["app.services.commonTask"] = common_task_module
    sys.modules["app.utils"] = utils_submodule
    sys.modules["app.modules"] = modules_module
    sys.modules["bson"] = bson_module
    sys.modules["flask_restx"] = flask_restx_module

    app_module.utils = utils_module
    app_module.modules = modules_module
    app_module.services = services_module

    route_path = pathlib.Path(__file__).resolve().parents[1] / "app" / "routes" / "ai_pen_test.py"
    spec = importlib.util.spec_from_file_location(module_name, route_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


ai_pen_test_module = _load_ai_pen_route_module()


class _FakeCollection(object):
    def __init__(self, rows):
        self.rows = list(rows or [])

    def _match_rows(self, query):
        if not isinstance(query, dict) or not query:
            return list(self.rows)
        matched = []
        for item in self.rows:
            if not isinstance(item, dict):
                continue
            if all(item.get(key) == value for key, value in query.items()):
                matched.append(item)
        return matched

    def count_documents(self, query):
        return len(self._match_rows(query))

    def aggregate(self, pipeline):
        query = {}
        field_name = ""
        for stage in list(pipeline or []):
            if not isinstance(stage, dict):
                continue
            if "$match" in stage and isinstance(stage.get("$match"), dict):
                query = stage.get("$match") or {}
            if "$group" in stage and isinstance(stage.get("$group"), dict):
                raw_field = (((stage["$group"].get("_id") or {}).get("$ifNull") or [""])[0])
                field_name = str(raw_field or "").lstrip("$")

        counts = {}
        for item in self._match_rows(query):
            key = str(item.get(field_name) or "")
            counts[key] = counts.get(key, 0) + 1

        rows = [{"_id": name, "count": count} for name, count in counts.items()]
        rows.sort(key=lambda item: (-int(item.get("count") or 0), str(item.get("_id") or "")))
        return rows

    def find(self, query, _projection=None):
        return list(self._match_rows(query))


class TestAiPenStats(unittest.TestCase):
    def test_build_ai_pen_quant_metrics_calculates_phase_f_indicators(self):
        metrics = ai_pen_test_module._build_ai_pen_quant_metrics(
            [
                {
                    "decision": "verified",
                    "status": "ok",
                    "verification_step": "mcp_api_doc_probe",
                    "budget_used": {"turns": 3, "tool_calls": 2},
                },
                {
                    "decision": "likely_false_positive",
                    "status": "ok",
                    "verification_step": "mcp_jwt_probe",
                    "budget_used": {"turns": 2, "tool_calls": 1},
                },
                {
                    "decision": "needs_manual_review",
                    "status": "skipped",
                },
                {
                    "decision": "needs_manual_review",
                    "status": "error",
                    "agent_trace": [{"action": "agent_turn"}, {"action": "tool_call"}],
                    "tool_calls": [{"tool": "http_fetch"}],
                },
            ],
            total=4,
        )

        self.assertEqual(3, metrics["coverage"]["covered_count"])
        self.assertEqual(0.75, metrics["coverage"]["coverage_rate"])
        self.assertEqual(1, metrics["decision_metrics"]["verified_count"])
        self.assertEqual(0.25, metrics["decision_metrics"]["success_rate"])
        self.assertEqual(0.25, metrics["decision_metrics"]["false_positive_rate"])
        self.assertEqual(3, metrics["budget_metrics"]["sample_count"])
        self.assertEqual(2.0, metrics["budget_metrics"]["avg_turns"])
        self.assertEqual(1.3333, metrics["budget_metrics"]["avg_tool_calls"])

    def test_stats_route_returns_quant_metrics_summary(self):
        rows = [
            {
                "task_id": "507f1f77bcf86cd799439011",
                "decision": "verified",
                "status": "ok",
                "risk_type": "api_doc",
                "verification_step": "mcp_api_doc_probe",
                "high_value_family": "api_doc_surface",
                "tool_plan_source": "ai_plan",
                "stop_reason": "final_decision",
                "budget_used": {"turns": 3, "tool_calls": 2},
            },
            {
                "task_id": "507f1f77bcf86cd799439011",
                "decision": "likely_false_positive",
                "status": "ok",
                "risk_type": "jwt",
                "verification_step": "mcp_jwt_probe",
                "high_value_family": "token_auth_flow",
                "tool_plan_source": "retry_history",
                "stop_reason": "manual_required",
                "budget_used": {"turns": 2, "tool_calls": 1},
            },
            {
                "task_id": "507f1f77bcf86cd799439011",
                "decision": "needs_manual_review",
                "status": "error",
                "risk_type": "websocket",
                "verification_step": "mcp_websocket_probe",
                "high_value_family": "realtime_channel_surface",
                "tool_plan_source": "inferred",
                "stop_reason": "timeout",
                "agent_trace": [{"action": "agent_turn"}],
                "tool_calls": [{"tool": "websocket_probe"}],
            },
        ]

        ai_pen_test_module.utils.conn_db = lambda _name: _FakeCollection(rows)
        ai_pen_test_module.StatsAiPenTest.parser = types.SimpleNamespace(
            parse_args=lambda: {"task_id": "507f1f77bcf86cd799439011"}
        )

        response = ai_pen_test_module.StatsAiPenTest().get()
        data = response["data"]

        self.assertEqual(3, data["total"])
        self.assertEqual(3, data["quant_metrics"]["coverage"]["covered_count"])
        self.assertEqual(0.3333, data["quant_metrics"]["decision_metrics"]["success_rate"])
        self.assertEqual(2.0, data["quant_metrics"]["budget_metrics"]["avg_turns"])
        self.assertEqual(1.3333, data["quant_metrics"]["budget_metrics"]["avg_tool_calls"])
        self.assertTrue(any(item.get("name") == "api_doc_surface" for item in data.get("high_value_family", [])))


if __name__ == "__main__":
    unittest.main()
