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

    def test_build_ai_pen_group_benchmarks_groups_by_risk_type(self):
        benchmarks = ai_pen_test_module._build_ai_pen_group_benchmarks(
            [
                {
                    "risk_type": "api_doc",
                    "payload_type": "api_doc_probe",
                    "decision": "verified",
                    "status": "ok",
                    "verification_step": "mcp_api_doc_probe",
                    "budget_used": {"turns": 3, "tool_calls": 2},
                },
                {
                    "risk_type": "api_doc",
                    "payload_type": "api_doc_probe",
                    "decision": "needs_manual_review",
                    "status": "error",
                    "agent_trace": [{"action": "agent_turn"}],
                    "tool_calls": [{"tool": "http_fetch"}],
                },
                {
                    "risk_type": "jwt",
                    "payload_type": "jwt_probe",
                    "decision": "likely_false_positive",
                    "status": "ok",
                    "verification_step": "mcp_jwt_probe",
                    "budget_used": {"turns": 2, "tool_calls": 1},
                },
            ],
            "risk_type",
        )

        self.assertEqual("api_doc", benchmarks[0]["name"])
        self.assertEqual(2, benchmarks[0]["total_count"])
        self.assertEqual(1, benchmarks[0]["verified_count"])
        self.assertEqual(0.5, benchmarks[0]["success_rate"])
        self.assertEqual(2.0, benchmarks[0]["avg_turns"])
        self.assertEqual("jwt", benchmarks[1]["name"])

    def test_build_ai_pen_phase_f_readiness_summarizes_core_capabilities(self):
        readiness = ai_pen_test_module._build_ai_pen_phase_f_readiness(
            [
                {
                    "risk_type": "weak_password",
                    "payload_type": "weak_password_probe",
                    "high_value_family": "login_entry_surface",
                    "decision": "verified",
                    "status": "ok",
                    "budget_used": {"turns": 4, "tool_calls": 3},
                },
                {
                    "risk_type": "jwt",
                    "payload_type": "jwt_probe",
                    "high_value_family": "token_auth_flow",
                    "decision": "likely_false_positive",
                    "status": "ok",
                    "budget_used": {"turns": 2, "tool_calls": 2},
                },
                {
                    "risk_type": "api_doc",
                    "payload_type": "api_doc_probe",
                    "high_value_family": "api_doc_surface",
                    "decision": "needs_manual_review",
                    "status": "error",
                    "agent_trace": [{"action": "agent_turn"}],
                    "tool_calls": [{"tool": "http_fetch"}],
                },
            ]
        )

        summary = readiness["summary"]
        self.assertEqual(9, summary["total_capabilities"])
        self.assertEqual(2, summary["covered_count"])
        self.assertEqual(1, summary["partial_count"])
        self.assertEqual(6, summary["missing_count"])
        self.assertEqual("covered", readiness["capabilities"][0]["status"])
        self.assertEqual("covered", readiness["capabilities"][1]["status"])
        self.assertEqual("partial", readiness["capabilities"][2]["status"])
        self.assertGreater(readiness["capabilities"][0]["priority_score"], readiness["capabilities"][2]["priority_score"])

    def test_build_ai_pen_engineer_focus_queue_prioritizes_verified_entries(self):
        readiness = ai_pen_test_module._build_ai_pen_phase_f_readiness(
            [
                {
                    "risk_type": "weak_password",
                    "payload_type": "weak_password_probe",
                    "high_value_family": "login_entry_surface",
                    "decision": "verified",
                    "status": "ok",
                    "budget_used": {"turns": 4, "tool_calls": 3},
                },
                {
                    "risk_type": "jwt",
                    "payload_type": "jwt_probe",
                    "high_value_family": "token_auth_flow",
                    "decision": "likely_false_positive",
                    "status": "ok",
                    "budget_used": {"turns": 2, "tool_calls": 2},
                },
                {
                    "risk_type": "api_doc",
                    "payload_type": "api_doc_probe",
                    "high_value_family": "api_doc_surface",
                    "decision": "needs_manual_review",
                    "status": "ok",
                    "budget_used": {"turns": 3, "tool_calls": 2},
                },
            ]
        )

        queue = ai_pen_test_module._build_ai_pen_engineer_focus_queue(readiness)

        self.assertEqual("登录/默认口令", queue[0]["label"])
        self.assertEqual("covered", queue[0]["status"])
        self.assertIn("verified", queue[0]["focus_reason"])
        self.assertGreater(queue[0]["priority_score"], queue[1]["priority_score"])

    def test_build_ai_pen_engineer_focus_entries_prioritizes_verified_high_value_rows(self):
        entries = ai_pen_test_module._build_ai_pen_engineer_focus_entries(
            [
                {
                    "_id": "a1",
                    "target": "https://example.com/login",
                    "vuln_url": "https://example.com/login",
                    "risk_type": "weak_password",
                    "risk_name": "弱口令登录入口",
                    "payload_type": "weak_password_probe",
                    "payload_variant": "minimal_default_creds",
                    "payload_expected_signal": "login_success_or_session_creation",
                    "verification_step": "mcp_login_probe",
                    "high_value_family": "login_entry_surface",
                    "high_value_family_rank": 72,
                    "decision": "verified",
                    "status": "ok",
                    "confidence": 0.93,
                    "http_status": 200,
                    "session_auth_hit": True,
                    "request_template_mode": "form_data",
                    "request_template_content_type": "application/x-www-form-urlencoded",
                    "request_template_params": ["username", "password"],
                    "request_template_summary": "mode=form_data | content_type=application/x-www-form-urlencoded | params=username,password",
                    "proof_type": "login_success",
                    "proof_signals": ["login_success", "session_auth"],
                    "proof_summary": "type=login_success | variant=minimal_default_creds | expect=login_success_or_session_creation | template=mode=form_data | content_type=application/x-www-form-urlencoded | params=username,password | signals=login_success,session_auth",
                    "reason": "登录后访问 dashboard 成功",
                },
                {
                    "_id": "a2",
                    "target": "https://example.com/api-docs",
                    "vuln_url": "https://example.com/api-docs",
                    "risk_type": "api_doc",
                    "risk_name": "API文档入口",
                    "payload_type": "api_doc_probe",
                    "verification_step": "mcp_api_doc_probe",
                    "high_value_family": "api_doc_surface",
                    "high_value_family_rank": 96,
                    "decision": "needs_manual_review",
                    "status": "ok",
                    "confidence": 0.61,
                    "http_status": 200,
                    "reason": "开放 paths 但需人工确认鉴权",
                },
            ]
        )

        self.assertEqual("a1", entries[0]["result_id"])
        self.assertEqual("verified", entries[0]["decision"])
        self.assertEqual("form_data", entries[0]["request_template_mode"])
        self.assertEqual("minimal_default_creds", entries[0]["payload_variant"])
        self.assertEqual("auth_bypass", entries[0]["proof_family"])
        self.assertEqual("login_success", entries[0]["proof_type"])
        self.assertIn("session_auth", entries[0]["proof_signals"])
        self.assertIn("variant=minimal_default_creds", entries[0]["proof_summary"])
        self.assertEqual(
            "mode=form_data | content_type=application/x-www-form-urlencoded | params=username,password",
            entries[0]["request_template_summary"],
        )
        self.assertIn("优先接手", entries[0]["focus_reason"])
        self.assertGreater(entries[0]["priority_score"], entries[1]["priority_score"])

    def test_build_ai_pen_phase_f_readiness_matches_unauth_access_proof_family(self):
        readiness = ai_pen_test_module._build_ai_pen_phase_f_readiness(
            [
                {
                    "risk_type": "sensitive_info",
                    "payload_type": "replay",
                    "proof_family": "unauth_access",
                    "proof_type": "unauth_management_surface",
                    "high_value_family": "admin_debug_surface",
                    "decision": "verified",
                    "status": "ok",
                    "budget_used": {"turns": 1, "tool_calls": 1},
                }
            ]
        )

        capability = next(item for item in readiness["capabilities"] if item["id"] == "idor_access")
        self.assertEqual("covered", capability["status"])
        self.assertEqual("未授权/对象访问线索", capability["label"])

    def test_build_ai_pen_phase_f_readiness_surfaces_unauth_negative_summary(self):
        readiness = ai_pen_test_module._build_ai_pen_phase_f_readiness(
            [
                {
                    "risk_type": "idor",
                    "payload_type": "idor_probe",
                    "proof_family": "access_control",
                    "decision": "likely_false_positive",
                    "status": "ok",
                    "unauth_negative_type": "guarded_mixed",
                    "budget_used": {"turns": 1, "tool_calls": 1},
                }
            ]
        )

        capability = next(item for item in readiness["capabilities"] if item["id"] == "idor_access")
        self.assertEqual("partial", capability["status"])
        self.assertEqual("guarded_mixed", capability["dominant_unauth_negative_type"])
        self.assertEqual(1, capability["negative_signal_count"])
        self.assertIn("鉴权拦截", capability["focus_reason"])

    def test_build_ai_pen_unauth_access_overview_distinguishes_positive_and_negative_signals(self):
        overview = ai_pen_test_module._build_ai_pen_unauth_access_overview(
            [
                {
                    "decision": "verified",
                    "proof_family": "unauth_access",
                    "proof_type": "unauth_admin_portal",
                    "unauth_access_type": "unauth_admin_portal",
                    "payload_type": "replay",
                },
                {
                    "decision": "needs_manual_review",
                    "proof_family": "unauth_access",
                    "proof_type": "unauth_health_endpoint",
                    "unauth_access_type": "unauth_health_endpoint",
                    "payload_type": "replay",
                },
                {
                    "decision": "likely_false_positive",
                    "proof_family": "access_control",
                    "unauth_negative_type": "guarded_mixed",
                    "payload_type": "idor_probe",
                },
            ]
        )

        self.assertEqual(3, overview["total_count"])
        self.assertEqual(1, overview["verified_count"])
        self.assertEqual(1, overview["needs_manual_review_count"])
        self.assertEqual(1, overview["negative_signal_count"])
        self.assertEqual("unauth_admin_portal", overview["dominant_positive_type"])
        self.assertEqual("guarded_mixed", overview["dominant_negative_type"])
        self.assertIn("优先复核", overview["recommended_action"])
        self.assertTrue(any("登录链" in item or "会话" in item for item in overview["next_actions"]))

    def test_build_ai_pen_engineer_focus_entries_surfaces_unauth_access_fields(self):
        entries = ai_pen_test_module._build_ai_pen_engineer_focus_entries(
            [
                {
                    "_id": "u1",
                    "target": "https://example.com/admin/dashboard",
                    "vuln_url": "https://example.com/admin/dashboard",
                    "risk_type": "sensitive_info",
                    "risk_name": "高价值管理端点",
                    "payload_type": "replay",
                    "verification_step": "http_fetch_replay",
                    "high_value_family": "admin_debug_surface",
                    "high_value_family_rank": 90,
                    "decision": "verified",
                    "status": "ok",
                    "confidence": 0.88,
                    "http_status": 200,
                    "proof_family": "unauth_access",
                    "proof_type": "unauth_admin_portal",
                    "unauth_access_type": "unauth_admin_portal",
                    "unauth_access_reason": "管理/办公入口返回成功状态且出现后台语义，疑似可未授权直接访问",
                    "proof_signals": ["unauth_access"],
                    "proof_summary": "proof=unauth_admin_portal | family=unauth_access | signals=unauth_access",
                    "reason": "管理/办公入口返回成功状态且出现后台语义，疑似可未授权直接访问",
                }
            ]
        )

        self.assertEqual("unauth_access", entries[0]["proof_family"])
        self.assertEqual("unauth_admin_portal", entries[0]["unauth_access_type"])
        self.assertIn("未授权直接访问", entries[0]["unauth_access_reason"])
        self.assertIn("无登录直访", entries[0]["focus_reason"])

    def test_build_ai_pen_engineer_focus_entries_downgrades_health_endpoint_focus(self):
        entries = ai_pen_test_module._build_ai_pen_engineer_focus_entries(
            [
                {
                    "_id": "u2",
                    "target": "https://example.com/actuator/health",
                    "vuln_url": "https://example.com/actuator/health",
                    "risk_type": "sensitive_info",
                    "risk_name": "健康检查端点",
                    "payload_type": "replay",
                    "verification_step": "http_fetch_replay",
                    "high_value_family": "admin_debug_surface",
                    "high_value_family_rank": 86,
                    "decision": "needs_manual_review",
                    "status": "ok",
                    "confidence": 0.72,
                    "http_status": 200,
                    "proof_family": "unauth_access",
                    "proof_type": "unauth_health_endpoint",
                    "unauth_access_type": "unauth_health_endpoint",
                    "unauth_access_reason": "健康检查/信息端点返回成功状态，存在公开未授权访问线索",
                    "proof_signals": ["unauth_access"],
                    "proof_summary": "proof=unauth_health_endpoint | family=unauth_access | signals=unauth_access",
                    "reason": "健康检查/信息端点返回成功状态，存在公开未授权访问线索",
                }
            ]
        )

        self.assertEqual("unauth_health_endpoint", entries[0]["unauth_access_type"])
        self.assertIn("健康检查/信息端点", entries[0]["focus_reason"])

    def test_build_ai_pen_engineer_focus_entries_surfaces_unauth_probe_summary(self):
        entries = ai_pen_test_module._build_ai_pen_engineer_focus_entries(
            [
                {
                    "_id": "u3",
                    "target": "https://example.com/",
                    "vuln_url": "https://example.com/",
                    "risk_type": "sensitive_info",
                    "risk_name": "未授权入口复核",
                    "payload_type": "replay",
                    "verification_step": "http_fetch_replay",
                    "decision": "likely_false_positive",
                    "status": "ok",
                    "confidence": 0.64,
                    "http_status": 200,
                    "unauth_negative_type": "guarded_mixed",
                    "unauth_probe_summary": "targets=4 | blocked=2 | login_wall=1 | sample=https://example.com/admin",
                    "reason": "已复核 4 个高价值未授权目标，2 个被鉴权拦截，1 个回到登录页/登录墙，当前不判定为未授权入口",
                }
            ]
        )

        self.assertIn("鉴权拦截", entries[0]["focus_reason"])
        self.assertIn("blocked=2", entries[0]["unauth_probe_summary"])
        self.assertEqual("guarded_mixed", entries[0]["unauth_negative_type"])

    def test_build_ai_pen_engineer_focus_entries_surfaces_login_wall_negative_type(self):
        entries = ai_pen_test_module._build_ai_pen_engineer_focus_entries(
            [
                {
                    "_id": "u4",
                    "target": "https://example.com/",
                    "vuln_url": "https://example.com/",
                    "risk_type": "sensitive_info",
                    "risk_name": "未授权入口复核",
                    "payload_type": "replay",
                    "verification_step": "http_fetch_replay",
                    "decision": "likely_false_positive",
                    "status": "ok",
                    "confidence": 0.60,
                    "http_status": 200,
                    "unauth_negative_type": "login_wall",
                    "unauth_probe_summary": "targets=3 | login_wall=2 | sample=https://example.com/login",
                    "reason": "已复核 3 个高价值未授权目标，2 个回到登录页/登录墙，当前不判定为未授权入口",
                }
            ]
        )

        self.assertEqual("login_wall", entries[0]["unauth_negative_type"])
        self.assertIn("登录页/登录墙", entries[0]["focus_reason"])

    def test_build_ai_pen_engineer_focus_entries_surfaces_decision_guard_fields(self):
        entries = ai_pen_test_module._build_ai_pen_engineer_focus_entries(
            [
                {
                    "_id": "u4-guard",
                    "target": "https://example.com/actuator/health",
                    "vuln_url": "https://example.com/actuator/health",
                    "risk_type": "sensitive_info",
                    "risk_name": "健康检查端点",
                    "payload_type": "replay",
                    "verification_step": "http_fetch_replay",
                    "decision": "needs_manual_review",
                    "status": "ok",
                    "confidence": 0.72,
                    "http_status": 200,
                    "proof_family": "unauth_access",
                    "proof_type": "unauth_health_endpoint",
                    "proof_strength": "weak",
                    "decision_guard_action": "downgrade_health_only",
                    "decision_guard_reason": "当前命中主要是健康检查/信息端点，先不直接判定为高价值未授权入口",
                    "unauth_access_type": "unauth_health_endpoint",
                    "unauth_negative_type": "health_only",
                    "proof_summary": "proof=unauth_health_endpoint | family=unauth_access | signals=unauth_access",
                    "reason": "健康检查/信息端点返回成功状态，存在公开未授权访问线索",
                }
            ]
        )

        self.assertEqual("weak", entries[0]["proof_strength"])
        self.assertEqual("downgrade_health_only", entries[0]["decision_guard_action"])
        self.assertIn("自动守门已下调", entries[0]["focus_reason"])

    def test_build_ai_pen_engineer_focus_queue_surfaces_unauth_negative_summary(self):
        readiness = ai_pen_test_module._build_ai_pen_phase_f_readiness(
            [
                {
                    "risk_type": "idor",
                    "payload_type": "idor_probe",
                    "proof_family": "access_control",
                    "decision": "likely_false_positive",
                    "status": "ok",
                    "unauth_negative_type": "guarded_mixed",
                    "budget_used": {"turns": 1, "tool_calls": 1},
                }
            ]
        )

        queue = ai_pen_test_module._build_ai_pen_engineer_focus_queue(readiness)

        idor_item = next(item for item in queue if item["id"] == "idor_access")
        self.assertEqual("guarded_mixed", idor_item["dominant_unauth_negative_type"])
        self.assertEqual(1, idor_item["negative_signal_count"])
        self.assertIn("阻断", idor_item["focus_reason"])

    def test_build_ai_pen_decision_guard_summary(self):
        summary = ai_pen_test_module._build_ai_pen_decision_guard_summary(
            [
                {
                    "decision_guard_action": "downgrade_health_only",
                    "proof_strength": "weak",
                },
                {
                    "decision_guard_action": "downgrade_access_control",
                    "proof_strength": "weak",
                },
                {
                    "decision_guard_action": "boost_multi_hit",
                    "proof_strength": "strong",
                },
            ]
        )

        self.assertEqual(3, summary["guarded_count"])
        self.assertEqual(2, summary["downgrade_count"])
        self.assertEqual(1, summary["boost_count"])
        self.assertEqual("downgrade_access_control", summary["dominant_guard_action"])
        self.assertTrue(any(item.get("name") == "weak" for item in summary["proof_strength_distribution"]))

    def test_stats_route_returns_quant_metrics_summary(self):
        rows = [
            {
                "_id": "r1",
                "task_id": "507f1f77bcf86cd799439011",
                "decision": "verified",
                "status": "ok",
                "risk_type": "api_doc",
                "payload_type": "api_doc_probe",
                "payload_variant": "openapi_fetch",
                "payload_expected_signal": "api_doc_schema_exposed",
                "verification_step": "mcp_api_doc_probe",
                "high_value_family": "api_doc_surface",
                "tool_plan_source": "ai_plan",
                "stop_reason": "final_decision",
                "budget_used": {"turns": 3, "tool_calls": 2},
                "target": "https://example.com/api-docs",
                "vuln_url": "https://example.com/api-docs",
                "risk_name": "API文档入口",
                "confidence": 0.91,
                "http_status": 200,
                "request_template_mode": "json_data",
                "request_template_content_type": "application/json",
                "request_template_params": ["query", "page"],
                "request_template_summary": "mode=json_data | content_type=application/json | params=query,page",
                "proof_type": "api_schema_exposed",
                "proof_signals": ["openapi_paths"],
                "proof_summary": "type=api_schema_exposed | variant=openapi_fetch | expect=api_doc_schema_exposed | template=mode=json_data | content_type=application/json | params=query,page | signals=openapi_paths",
                "reason": "开放 API schema",
            },
            {
                "_id": "r2",
                "task_id": "507f1f77bcf86cd799439011",
                "decision": "likely_false_positive",
                "status": "ok",
                "risk_type": "jwt",
                "payload_type": "jwt_probe",
                "payload_variant": "alg_none_header_swap",
                "payload_expected_signal": "jwt_none_accept_or_weak_secret",
                "verification_step": "mcp_jwt_probe",
                "high_value_family": "token_auth_flow",
                "tool_plan_source": "retry_history",
                "stop_reason": "manual_required",
                "budget_used": {"turns": 2, "tool_calls": 1},
                "target": "https://example.com/.well-known/openid-configuration",
                "vuln_url": "https://example.com/.well-known/openid-configuration",
                "risk_name": "JWT协议入口",
                "confidence": 0.67,
                "http_status": 200,
                "request_template_mode": "query",
                "request_template_params": ["token"],
                "request_template_summary": "mode=query | params=token",
                "proof_type": "auth_protocol_open",
                "proof_signals": ["oidc_metadata"],
                "proof_summary": "type=auth_protocol_open | variant=alg_none_header_swap | expect=jwt_none_accept_or_weak_secret | template=mode=query | params=token | signals=oidc_metadata",
                "reason": "仅协议元数据可访问",
            },
            {
                "_id": "r3",
                "task_id": "507f1f77bcf86cd799439011",
                "decision": "needs_manual_review",
                "status": "error",
                "risk_type": "websocket",
                "payload_type": "websocket_probe",
                "payload_variant": "websocket_upgrade_probe",
                "payload_expected_signal": "websocket_upgrade_or_socketio_banner",
                "verification_step": "mcp_websocket_probe",
                "high_value_family": "realtime_channel_surface",
                "tool_plan_source": "inferred",
                "stop_reason": "timeout",
                "agent_trace": [{"action": "agent_turn"}],
                "tool_calls": [{"tool": "websocket_probe"}],
                "target": "https://example.com/ws",
                "vuln_url": "wss://example.com/ws",
                "risk_name": "WebSocket入口",
                "confidence": 0.55,
                "http_status": 101,
                "request_template_mode": "body",
                "request_template_content_type": "application/xml",
                "request_template_params": ["root"],
                "request_template_summary": "mode=body | content_type=application/xml | params=root",
                "proof_type": "websocket_upgrade_open",
                "proof_signals": ["websocket_upgrade"],
                "proof_summary": "type=websocket_upgrade_open | variant=websocket_upgrade_probe | expect=websocket_upgrade_or_socketio_banner | template=mode=body | content_type=application/xml | params=root | signals=websocket_upgrade",
                "reason": "握手存在但语义待确认",
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
        self.assertTrue(any(item.get("name") == "api_doc" for item in data["capability_benchmarks"]["risk_type"]))
        self.assertTrue(any(item.get("name") == "api_doc_probe" for item in data["capability_benchmarks"]["payload_type"]))
        self.assertTrue(any(item.get("name") == "openapi_fetch" for item in data["payload_variant"]))
        self.assertTrue(any(item.get("name") == "surface_exposure" for item in data["proof_family"]))
        self.assertTrue(any(item.get("name") == "api_schema_exposed" for item in data["proof_type"]))
        self.assertTrue(any(item.get("name") == "openapi_fetch" for item in data["capability_benchmarks"]["payload_variant"]))
        self.assertTrue(any(item.get("name") == "surface_exposure" for item in data["capability_benchmarks"]["proof_family"]))
        self.assertTrue(any(item.get("name") == "api_schema_exposed" for item in data["capability_benchmarks"]["proof_type"]))
        self.assertTrue(any(item.get("name") == "realtime_channel_surface" for item in data["capability_benchmarks"]["high_value_family"]))
        self.assertTrue(any(item.get("name") == "mcp_websocket_probe" for item in data["capability_benchmarks"]["verification_step"]))
        self.assertTrue(any(item.get("name") == "json_data" for item in data["request_template_mode"]))
        self.assertTrue(any(item.get("name") == "json_data" for item in data["capability_benchmarks"]["request_template_mode"]))
        self.assertTrue(any(item.get("name") == "medium" for item in data["proof_strength"]))
        self.assertTrue(any(item.get("name") == "medium" for item in data["capability_benchmarks"]["proof_strength"]))
        self.assertEqual(2, data["phase_f_readiness"]["summary"]["covered_count"])
        self.assertEqual(0, data["phase_f_readiness"]["summary"]["partial_count"])
        self.assertEqual(7, data["phase_f_readiness"]["summary"]["missing_count"])
        self.assertEqual("API文档/GraphQL", data["engineer_focus_queue"][0]["label"])
        self.assertTrue("focus_reason" in data["engineer_focus_queue"][0])
        self.assertEqual("r1", data["engineer_focus_entries"][0]["result_id"])
        self.assertEqual("api_doc", data["engineer_focus_entries"][0]["risk_type"])
        self.assertEqual("json_data", data["engineer_focus_entries"][0]["request_template_mode"])
        self.assertEqual("openapi_fetch", data["engineer_focus_entries"][0]["payload_variant"])
        self.assertEqual("surface_exposure", data["engineer_focus_entries"][0]["proof_family"])
        self.assertEqual("api_schema_exposed", data["engineer_focus_entries"][0]["proof_type"])
        self.assertIn("openapi_paths", data["engineer_focus_entries"][0]["proof_signals"])
        self.assertEqual(
            "mode=json_data | content_type=application/json | params=query,page",
            data["engineer_focus_entries"][0]["request_template_summary"],
        )
        self.assertIn("type=api_schema_exposed", data["engineer_focus_entries"][0]["proof_summary"])
        self.assertTrue("focus_reason" in data["engineer_focus_entries"][0])

    def test_stats_route_returns_unauth_access_groups(self):
        rows = [
            {
                "_id": "u1",
                "task_id": "507f1f77bcf86cd799439011",
                "decision": "verified",
                "status": "ok",
                "risk_type": "sensitive_info",
                "payload_type": "replay",
                "verification_step": "http_fetch_replay",
                "high_value_family": "admin_debug_surface",
                "tool_plan_source": "inferred",
                "stop_reason": "final_decision",
                "budget_used": {"turns": 1, "tool_calls": 1},
                "target": "https://example.com/admin/dashboard",
                "vuln_url": "https://example.com/admin/dashboard",
                "risk_name": "高价值管理端点",
                "confidence": 0.88,
                "http_status": 200,
                "request_template_mode": "query",
                "request_template_params": ["admin"],
                "request_template_summary": "mode=query | params=admin",
                "proof_family": "unauth_access",
                "proof_type": "unauth_management_surface",
                "unauth_access_type": "unauth_management_surface",
                "unauth_access_reason": "高价值管理/配置端点返回成功状态，疑似可未授权直接访问",
                "unauth_negative_type": "",
                "proof_signals": ["unauth_access"],
                "proof_summary": "proof=unauth_management_surface | family=unauth_access | signals=unauth_access",
                "reason": "高价值管理/配置端点返回成功状态，疑似可未授权直接访问",
            }
        ]

        ai_pen_test_module.utils.conn_db = lambda _name: _FakeCollection(rows)
        ai_pen_test_module.StatsAiPenTest.parser = types.SimpleNamespace(
            parse_args=lambda: {"task_id": "507f1f77bcf86cd799439011"}
        )

        response = ai_pen_test_module.StatsAiPenTest().get()
        data = response["data"]

        self.assertTrue(any(item.get("name") == "unauth_management_surface" for item in data["unauth_access_type"]))
        self.assertTrue(any(item.get("name") == "unauth_management_surface" for item in data["capability_benchmarks"]["unauth_access_type"]))
        self.assertEqual("unauth_access", data["engineer_focus_entries"][0]["proof_family"])
        self.assertEqual("unauth_management_surface", data["engineer_focus_entries"][0]["unauth_access_type"])

    def test_stats_route_returns_unauth_negative_type_groups(self):
        rows = [
            {
                "_id": "u5",
                "task_id": "507f1f77bcf86cd799439011",
                "decision": "likely_false_positive",
                "status": "ok",
                "risk_type": "sensitive_info",
                "payload_type": "replay",
                "verification_step": "http_fetch_replay",
                "high_value_family": "admin_debug_surface",
                "tool_plan_source": "inferred",
                "stop_reason": "final_decision",
                "budget_used": {"turns": 1, "tool_calls": 3},
                "target": "https://example.com/",
                "vuln_url": "https://example.com/",
                "risk_name": "未授权入口复核",
                "confidence": 0.64,
                "http_status": 200,
                "request_template_mode": "query",
                "request_template_params": [],
                "request_template_summary": "mode=query",
                "proof_family": "",
                "proof_type": "",
                "unauth_access_type": "",
                "unauth_access_reason": "",
                "unauth_negative_type": "guarded_mixed",
                "unauth_probe_summary": "targets=4 | blocked=2 | login_wall=1 | sample=https://example.com/admin",
                "proof_signals": [],
                "proof_summary": "",
                "reason": "已复核 4 个高价值未授权目标，2 个被鉴权拦截，1 个回到登录页/登录墙，当前不判定为未授权入口",
            }
        ]

        ai_pen_test_module.utils.conn_db = lambda _name: _FakeCollection(rows)
        ai_pen_test_module.StatsAiPenTest.parser = types.SimpleNamespace(
            parse_args=lambda: {"task_id": "507f1f77bcf86cd799439011"}
        )

        response = ai_pen_test_module.StatsAiPenTest().get()
        data = response["data"]

        self.assertTrue(any(item.get("name") == "guarded_mixed" for item in data["unauth_negative_type"]))
        self.assertTrue(any(item.get("name") == "guarded_mixed" for item in data["capability_benchmarks"]["unauth_negative_type"]))
        self.assertEqual("guarded_mixed", data["engineer_focus_entries"][0]["unauth_negative_type"])
        self.assertEqual("guarded_mixed", data["unauth_negative_summary"]["dominant_negative_type"])
        self.assertEqual(1, data["unauth_negative_summary"]["negative_signal_count"])
        self.assertEqual("guarded_mixed", data["unauth_access_overview"]["dominant_negative_type"])
        self.assertIn("会话复核", data["unauth_access_overview"]["recommended_action"])

    def test_stats_route_returns_decision_guard_groups(self):
        rows = [
            {
                "_id": "g1",
                "task_id": "507f1f77bcf86cd799439011",
                "decision": "needs_manual_review",
                "status": "ok",
                "risk_type": "sensitive_info",
                "payload_type": "replay",
                "verification_step": "http_fetch_replay",
                "high_value_family": "admin_debug_surface",
                "tool_plan_source": "inferred",
                "stop_reason": "manual_required",
                "budget_used": {"turns": 1, "tool_calls": 2},
                "target": "https://example.com/actuator/health",
                "vuln_url": "https://example.com/actuator/health",
                "risk_name": "健康检查端点",
                "confidence": 0.72,
                "http_status": 200,
                "request_template_mode": "query",
                "request_template_summary": "mode=query",
                "proof_family": "unauth_access",
                "proof_type": "unauth_health_endpoint",
                "proof_strength": "weak",
                "decision_guard_action": "downgrade_health_only",
                "decision_guard_reason": "当前命中主要是健康检查/信息端点，先不直接判定为高价值未授权入口",
                "unauth_access_type": "unauth_health_endpoint",
                "unauth_negative_type": "health_only",
                "proof_signals": ["unauth_access"],
                "proof_summary": "proof=unauth_health_endpoint | family=unauth_access | signals=unauth_access",
                "reason": "健康检查/信息端点返回成功状态，存在公开未授权访问线索",
            }
        ]

        ai_pen_test_module.utils.conn_db = lambda _name: _FakeCollection(rows)
        ai_pen_test_module.StatsAiPenTest.parser = types.SimpleNamespace(
            parse_args=lambda: {"task_id": "507f1f77bcf86cd799439011"}
        )

        response = ai_pen_test_module.StatsAiPenTest().get()
        data = response["data"]

        self.assertTrue(any(item.get("name") == "downgrade_health_only" for item in data["decision_guard_action"]))
        self.assertTrue(any(item.get("name") == "downgrade_health_only" for item in data["capability_benchmarks"]["decision_guard_action"]))
        self.assertEqual("downgrade_health_only", data["decision_guard_summary"]["dominant_guard_action"])
        self.assertEqual(1, data["decision_guard_summary"]["guarded_count"])


if __name__ == "__main__":
    unittest.main()
