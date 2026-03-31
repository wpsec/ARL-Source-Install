import importlib.util
import json
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


def _load_common_task_module():
    module_name = "commonTask_test_module"
    if module_name in sys.modules:
        return sys.modules[module_name]

    app_module = types.ModuleType("app")
    utils_module = types.ModuleType("app.utils")
    utils_module.get_logger = _build_logger

    services_module = types.ModuleType("app.services")
    services_module.run_risk_cruising = lambda *args, **kwargs: None
    services_module.BaseUpdateTask = object

    config_module = types.ModuleType("app.config")
    config_module.Config = type("Config", (), {})
    config_module.normalize_dict_path_compat = lambda value: value

    modules_module = types.ModuleType("app.modules")
    modules_module.CollectSource = object
    modules_module.WebSiteFetchStatus = object
    modules_module.WebSiteFetchOption = object

    nuclei_scan_module = types.ModuleType("app.services.nuclei_scan")
    nuclei_scan_module.nuclei_scan = lambda *args, **kwargs: None
    nuclei_scan_module.NucleiScan = object

    afrog_scan_module = types.ModuleType("app.services.afrog_scan")
    afrog_scan_module.run_afrog_scan = lambda *args, **kwargs: None

    waf_guard_module = types.ModuleType("app.services.waf_guard")
    waf_guard_module.WAFSmartSkipGuard = object

    ai_pen_runtime_module = types.ModuleType("app.services.ai_pen_mcp_runtime")
    ai_pen_runtime_module.AiPenMcpRuntime = type(
        "AiPenMcpRuntime",
        (),
        {
            "build_artifacts_from_tool_trace": staticmethod(
                lambda **kwargs: {
                    "agent_trace": [],
                    "tool_calls": [],
                    "tool_results": [],
                    "stop_reason": "final_decision",
                    "budget_used": {},
                    "runtime_version": "p0-local-v1",
                }
            )
        },
    )
    ai_pen_runtime_module.ToolSchema = object

    task_scope_guard_module = types.ModuleType("app.services.task_scope_guard")
    task_scope_guard_module.load_task_scope_context = lambda *args, **kwargs: {
        "allowed_hosts": [],
        "allowed_flds": [],
    }
    task_scope_guard_module.host_in_scope = lambda *args, **kwargs: True
    task_scope_guard_module.url_in_scope = lambda *args, **kwargs: True

    bson_module = types.ModuleType("bson")
    bson_module.ObjectId = lambda value=None: value

    pymongo_module = types.ModuleType("pymongo")
    pymongo_errors_module = types.ModuleType("pymongo.errors")
    pymongo_errors_module.NetworkTimeout = type("NetworkTimeout", (Exception,), {})
    pymongo_errors_module.AutoReconnect = type("AutoReconnect", (Exception,), {})
    pymongo_errors_module.ServerSelectionTimeoutError = type("ServerSelectionTimeoutError", (Exception,), {})
    pymongo_module.errors = pymongo_errors_module

    sys.modules.setdefault("app", app_module)
    sys.modules["app.utils"] = utils_module
    sys.modules["app.services"] = services_module
    sys.modules["app.config"] = config_module
    sys.modules["app.modules"] = modules_module
    sys.modules["app.services.nuclei_scan"] = nuclei_scan_module
    sys.modules["app.services.afrog_scan"] = afrog_scan_module
    sys.modules["app.services.waf_guard"] = waf_guard_module
    sys.modules["app.services.ai_pen_mcp_runtime"] = ai_pen_runtime_module
    sys.modules["app.services.task_scope_guard"] = task_scope_guard_module
    sys.modules["bson"] = bson_module
    sys.modules["pymongo"] = pymongo_module
    sys.modules["pymongo.errors"] = pymongo_errors_module

    app_module.utils = utils_module
    app_module.services = services_module

    common_task_path = pathlib.Path(__file__).resolve().parents[1] / "app" / "services" / "commonTask.py"
    spec = importlib.util.spec_from_file_location(module_name, common_task_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


WebSiteFetch = _load_common_task_module().WebSiteFetch
Config = sys.modules["app.config"].Config


class TestAiPenJsContext(unittest.TestCase):
    def test_collect_ai_pen_knowledge_hits_returns_structured_fields(self):
        original_loader = WebSiteFetch._load_ai_pen_knowledge_index_data
        try:
            WebSiteFetch._load_ai_pen_knowledge_index_data = classmethod(
                lambda cls: (
                    {
                        "token_index": {
                            "swagger": {
                                "count": 3,
                                "sources": {"poc_library": 3},
                                "samples": ["poc_library:wpoc/示例/漏洞.md"],
                                "product_labels": [{"name": "Admin Portal", "count": 2}],
                                "vuln_types": [{"name": "api_doc", "count": 2}],
                                "entry_paths": ["/swagger-ui/index.html"],
                                "verify_actions": ["get /swagger-ui/index.html"],
                                "record_refs": [
                                    {
                                        "source": "poc_library",
                                        "path": "wpoc/示例/漏洞.md",
                                        "title": "示例漏洞",
                                        "product_labels": ["Admin Portal"],
                                        "vuln_types": ["api_doc"],
                                        "entry_paths": ["/swagger-ui/index.html"],
                                        "verify_actions": ["get /swagger-ui/index.html"],
                                    }
                                ],
                            }
                        }
                    },
                    "/tmp/fake_index.json",
                )
            )
            task = WebSiteFetch.__new__(WebSiteFetch)
            hit_info = task._collect_ai_pen_knowledge_hits(
                {
                    "risk_name": "站点疑似暴露Swagger API文档",
                    "target": "https://example.com/swagger-ui/index.html",
                }
            )
        finally:
            WebSiteFetch._load_ai_pen_knowledge_index_data = original_loader

        self.assertIn("swagger", hit_info.get("hit_tokens", []))
        self.assertIn("Admin Portal", hit_info.get("hit_product_labels", []))
        self.assertIn("api_doc", hit_info.get("hit_vuln_types", []))
        self.assertIn("/swagger-ui/index.html", hit_info.get("hit_entry_paths", []))

    def test_route_hint_marks_js_sensitive_context(self):
        route_hint = WebSiteFetch._build_ai_pen_route_hint(
            {
                "target": "https://example.com/_nuxt/app.js",
                "risk_type": "sensitive_info",
            }
        )

        self.assertEqual("js_sensitive_context", route_hint)

    def test_route_hint_marks_file_handling_context(self):
        route_hint = WebSiteFetch._build_ai_pen_route_hint(
            {
                "target": "https://example.com/api/export/report",
                "risk_type": "file_read",
            }
        )

        self.assertEqual("file_handling_context", route_hint)

    def test_route_hint_marks_login_entry_context(self):
        route_hint = WebSiteFetch._build_ai_pen_route_hint(
            {
                "target": "https://example.com/login",
                "risk_type": "login_surface",
                "browser_surface_summary": {
                    "page_title": "统一身份认证登录",
                    "page_url": "https://example.com/login",
                },
                "dom_form_summary": [
                    {
                        "action": "/login",
                        "method": "POST",
                        "has_password_input": "true",
                        "fields": "username,password,captcha",
                    }
                ],
            }
        )

        self.assertEqual("login_entry_context", route_hint)

    def test_high_value_url_candidate_detects_api_docs(self):
        candidate = WebSiteFetch._build_ai_pen_high_value_url_candidate(
            source_collection="url",
            source_id="507f1f77bcf86cd799439011",
            target_url="https://api-docs.example.test:9090/api/v2/api-docs",
            status_code=200,
            title_text="OpenAPI",
            source_text="url",
        )

        self.assertEqual("api_doc", candidate.get("risk_type"))
        self.assertEqual("高价值接口说明/Schema端点", candidate.get("risk_name"))
        self.assertTrue(bool(candidate.get("high_value_target")))
        self.assertGreater(int(candidate.get("priority_score", 0) or 0), 0)

    def test_high_value_url_candidate_detects_actuator_env(self):
        candidate = WebSiteFetch._build_ai_pen_high_value_url_candidate(
            source_collection="fileleak",
            source_id="507f1f77bcf86cd799439012",
            target_url="https://config.example.test:10443/api/actuator/env",
            status_code=200,
            title_text="Spring Boot",
            source_text="fileleak",
        )

        self.assertEqual("sensitive_info", candidate.get("risk_type"))
        self.assertEqual("高价值配置/环境信息端点", candidate.get("risk_name"))
        self.assertTrue(bool(candidate.get("high_value_target")))

    def test_high_value_url_candidate_detects_management_endpoint(self):
        candidate = WebSiteFetch._build_ai_pen_high_value_url_candidate(
            source_collection="url",
            source_id="507f1f77bcf86cd799439019",
            target_url="https://example.com/actuator/prometheus",
            status_code=200,
            title_text="Prometheus",
            source_text="url",
        )

        self.assertEqual("sensitive_info", candidate.get("risk_type"))
        self.assertEqual("高价值管理/诊断端点", candidate.get("risk_name"))
        self.assertTrue(bool(candidate.get("high_value_target")))

    def test_high_value_url_candidate_detects_auth_entry(self):
        candidate = WebSiteFetch._build_ai_pen_high_value_url_candidate(
            source_collection="url",
            source_id="507f1f77bcf86cd799439020",
            target_url="https://example.com/passport/login",
            status_code=200,
            title_text="登录",
            source_text="url",
        )

        self.assertEqual("login_surface", candidate.get("risk_type"))
        self.assertEqual("高价值认证入口", candidate.get("risk_name"))

    def test_high_value_url_candidate_detects_file_surface(self):
        candidate = WebSiteFetch._build_ai_pen_high_value_url_candidate(
            source_collection="url",
            source_id="507f1f77bcf86cd799439021",
            target_url="https://example.com/api/export/report",
            status_code=200,
            title_text="导出报表",
            source_text="url",
        )

        self.assertEqual("file_read", candidate.get("risk_type"))
        self.assertEqual("高价值文件处理入口", candidate.get("risk_name"))

    def test_high_value_url_candidate_detects_graphql_surface(self):
        candidate = WebSiteFetch._build_ai_pen_high_value_url_candidate(
            source_collection="url",
            source_id="507f1f77bcf86cd799439022",
            target_url="https://example.com/graphql",
            status_code=200,
            title_text="GraphQL Playground",
            source_text="url",
        )

        self.assertEqual("graphql", candidate.get("risk_type"))
        self.assertEqual("高价值 GraphQL 入口", candidate.get("risk_name"))
        self.assertTrue(bool(candidate.get("high_value_target")))

    def test_sensitive_config_response_detects_actuator_env_json(self):
        self.assertTrue(
            WebSiteFetch._looks_like_sensitive_config_response(
                "https://config.example.test:10443/api/actuator/env",
                '{"activeProfiles":["prod"],"propertySources":[{"name":"systemProperties"}]}',
                headers={"Content-Type": "application/json"},
            )
        )

    def test_normalize_ai_pen_tool_plan_filters_unsupported_steps(self):
        plan = WebSiteFetch._normalize_ai_pen_tool_plan(
            [
                {"tool": "http_fetch", "url": "https://example.com/api/v2/api-docs", "summary": "fetch"},
                {"tool": "rm -rf", "url": "https://evil.example.com", "summary": "bad"},
                {"tool": "api_doc_probe", "params": {"url": "https://example.com/v3/api-docs", "method": "get"}},
            ],
            default_url="https://example.com/",
            max_steps=4,
        )

        self.assertEqual(2, len(plan))
        self.assertEqual("http_fetch", plan[0].get("tool"))
        self.assertEqual("api_doc_probe", plan[1].get("tool"))

    def test_collect_ai_pen_runtime_observation_detects_api_doc(self):
        observation = WebSiteFetch._collect_ai_pen_runtime_observation(
            [
                {
                    "turn": 1,
                    "tool": "api_doc_probe",
                    "status": "ok",
                    "result": {
                        "response": {
                            "url": "https://example.com/v3/api-docs",
                            "status_code": 200,
                            "headers": {"Content-Type": "application/json"},
                            "body_text": '{"openapi":"3.0.1","paths":{"/login":{"post":{"parameters":[{"name":"username"}]}}}}',
                            "body_md5": "abc123",
                        }
                    },
                }
            ],
            evidence_seed="openapi",
            js_api_targets=[],
        )

        self.assertTrue(bool(observation.get("api_doc_hit")))
        self.assertEqual("https://example.com/v3/api-docs", observation.get("api_doc_hit_url"))
        self.assertTrue(bool(observation.get("evidence_hit")))
        self.assertIn("username", list(observation.get("api_doc_summary", {}).get("parameter_names", [])))

    def test_collect_ai_pen_runtime_observation_detects_graphql(self):
        observation = WebSiteFetch._collect_ai_pen_runtime_observation(
            [
                {
                    "turn": 1,
                    "tool": "graphql_probe",
                    "status": "ok",
                    "result": {
                        "response": {
                            "url": "https://example.com/graphql",
                            "status_code": 200,
                            "headers": {"Content-Type": "application/json"},
                            "body_text": '{"data":{"__typename":"Query"}}',
                            "body_md5": "ghi789",
                        }
                    },
                }
            ],
            evidence_seed="typename",
            js_api_targets=[],
        )

        self.assertTrue(bool(observation.get("graphql_hit")))
        self.assertEqual("https://example.com/graphql", observation.get("graphql_hit_url"))
        self.assertEqual("typename", observation.get("graphql_summary", {}).get("mode"))

    def test_collect_ai_pen_runtime_observation_detects_login_success(self):
        observation = WebSiteFetch._collect_ai_pen_runtime_observation(
            [
                {
                    "turn": 2,
                    "tool": "detect_login_success",
                    "status": "ok",
                    "result": {
                        "analysis": {
                            "success": True,
                            "reason": "登录后进入非登录页路径",
                        },
                        "response": {
                            "url": "https://example.com/dashboard",
                            "status_code": 200,
                            "headers": {"Content-Type": "text/html"},
                            "body_text": "<html>dashboard</html>",
                            "body_md5": "def456",
                        },
                    },
                }
            ],
            evidence_seed="login",
            js_api_targets=[],
        )

        self.assertTrue(bool(observation.get("login_success_hit")))
        self.assertIn("非登录页路径", str(observation.get("login_success_reason") or ""))

    def test_build_ai_pen_fallback_tool_plan_for_api_doc(self):
        plan = WebSiteFetch._build_ai_pen_fallback_tool_plan(
            target_url="https://example.com/app/index",
            payload_type="api_doc_probe",
            payload="",
            max_steps=3,
        )

        self.assertTrue(bool(plan))
        self.assertEqual("api_doc_probe", plan[0].get("tool"))
        self.assertLessEqual(len(plan), 3)

    def test_build_ai_pen_fallback_tool_plan_for_graphql(self):
        plan = WebSiteFetch._build_ai_pen_fallback_tool_plan(
            target_url="https://example.com/app/index",
            payload_type="graphql_probe",
            payload='{"query":"query { __typename }"}',
            max_steps=2,
        )

        self.assertTrue(bool(plan))
        self.assertEqual("graphql_probe", plan[0].get("tool"))
        self.assertEqual("post", plan[0].get("params", {}).get("method"))
        self.assertEqual("query { __typename }", plan[0].get("params", {}).get("json_data", {}).get("query"))

    def test_build_ai_pen_fallback_tool_plan_for_payload_probe(self):
        plan = WebSiteFetch._build_ai_pen_fallback_tool_plan(
            target_url="https://example.com/search?q=test",
            payload_type="xss_probe",
            payload="<svg/onload=alert(1)>",
            max_steps=2,
        )

        self.assertEqual(1, len(plan))
        self.assertEqual("xss_probe", plan[0].get("tool"))
        self.assertIn("%3Csvg%2Fonload%3Dalert%281%29%3E", str(plan[0].get("params", {}).get("url", "")))

    def test_build_ai_pen_fallback_tool_plan_for_config_probe(self):
        plan = WebSiteFetch._build_ai_pen_fallback_tool_plan(
            target_url="https://example.com/actuator/env",
            payload_type="config_probe",
            payload="",
            max_steps=2,
        )

        self.assertEqual(2, len(plan))
        self.assertTrue(all(item.get("tool") == "config_probe" for item in plan))
        self.assertEqual("get", plan[0].get("params", {}).get("method"))
        self.assertIn("/actuator/env", str(plan[0].get("params", {}).get("url", "")))

    def test_build_ai_pen_fallback_tool_plan_for_idor_uses_multiple_targets(self):
        plan = WebSiteFetch._build_ai_pen_fallback_tool_plan(
            target_url="https://example.com/api/user/detail?id=100&order_id=200",
            payload_type="idor_probe",
            payload="id=1 -> id=2",
            max_steps=3,
        )

        self.assertEqual(2, len(plan))
        self.assertTrue(all(item.get("tool") == "idor_probe" for item in plan))
        self.assertIn("id=101", str(plan[0].get("params", {}).get("url", "")))
        self.assertIn("order_id=201", str(plan[1].get("params", {}).get("url", "")))

    def test_build_ai_pen_fallback_tool_plan_for_weak_password(self):
        plan = WebSiteFetch._build_ai_pen_fallback_tool_plan(
            target_url="https://example.com/login",
            payload_type="weak_password_probe",
            payload="username=admin&password=admin",
            max_steps=3,
            candidate={"target": "https://example.com/login", "risk_type": "weak_password"},
            body_text=(
                '<form action="/doLogin" method="post">'
                '<input type="hidden" name="csrf_token" value="abc123" />'
                '<input type="text" name="username" />'
                '<input type="password" name="password" />'
                '</form>'
            ),
            dom_form_summary=[],
            login_surface_summary={"password_form_count": 1, "captcha_form_count": 0},
        )

        self.assertEqual(3, len(plan))
        self.assertEqual("extract_csrf_token", plan[0].get("tool"))
        self.assertEqual("credential_probe", plan[1].get("tool"))
        self.assertEqual("detect_login_success", plan[2].get("tool"))
        self.assertEqual("https://example.com/doLogin", plan[1].get("params", {}).get("url"))
        self.assertEqual("admin", plan[1].get("params", {}).get("form_data", {}).get("username"))
        self.assertEqual("abc123", plan[1].get("params", {}).get("form_data", {}).get("csrf_token"))
        self.assertEqual("weak_password", plan[1].get("params", {}).get("session_key"))

    def test_build_ai_pen_fallback_tool_plan_skips_weak_password_when_captcha_present(self):
        plan = WebSiteFetch._build_ai_pen_fallback_tool_plan(
            target_url="https://example.com/login",
            payload_type="weak_password_probe",
            payload="username=admin&password=admin",
            max_steps=3,
            candidate={"target": "https://example.com/login", "risk_type": "weak_password"},
            body_text='<form action="/doLogin"><input type="text" name="username" /><input type="password" name="password" /></form>',
            dom_form_summary=[],
            login_surface_summary={"password_form_count": 1, "captcha_form_count": 1},
        )

        self.assertEqual([], plan)

    def test_product_hints_collect_generic_surface_families(self):
        hints = WebSiteFetch._collect_ai_pen_surface_hints(
            {
                "target": "https://oa.example.com/swagger-ui/index.html",
                "risk_name": "站点疑似暴露API文档",
                "knowledge_hit_tokens": ["swagger", "dashboard", "office"],
            }
        )

        self.assertIn("api_doc_surface", hints)
        self.assertIn("admin_office_portal", hints)

    def test_capability_profile_prefers_file_handling_surface(self):
        profile = WebSiteFetch._select_ai_pen_capability_profile(
            {
                "target": "https://example.com/api/export/report",
                "risk_type": "file_read",
                "route_hint": "file_handling_context",
                "api_surface_summary": {
                    "download_like_count": 2,
                    "upload_like_count": 0,
                    "sample_paths": ["/api/export/report"],
                    "parameter_names": ["reportId"],
                },
                "surface_hints": ["file_handling_surface"],
            }
        )

        self.assertEqual("file_handling_surface", profile.get("name"))
        self.assertEqual("file_probe", profile.get("preferred_payload_type"))

    def test_capability_profile_prefers_upload_probe_for_file_upload_context(self):
        profile = WebSiteFetch._select_ai_pen_capability_profile(
            {
                "target": "https://example.com/api/upload/avatar",
                "risk_type": "file_upload",
                "route_hint": "file_handling_context",
                "api_surface_summary": {
                    "download_like_count": 0,
                    "upload_like_count": 3,
                    "sample_paths": ["/api/upload/avatar"],
                    "parameter_names": ["file", "userId"],
                },
                "surface_hints": ["file_handling_surface"],
            }
        )

        self.assertEqual("file_handling_surface", profile.get("name"))
        self.assertEqual("upload_probe", profile.get("preferred_payload_type"))

    def test_capability_profile_prefers_graphql_surface(self):
        profile = WebSiteFetch._select_ai_pen_capability_profile(
            {
                "target": "https://example.com/graphql",
                "risk_type": "graphql",
                "route_hint": "graphql_schema_context",
                "surface_hints": ["graphql_surface"],
            }
        )

        self.assertEqual("graphql_surface", profile.get("name"))
        self.assertEqual("graphql_probe", profile.get("preferred_payload_type"))

    def test_capability_profile_prefers_login_entry_surface(self):
        profile = WebSiteFetch._select_ai_pen_capability_profile(
            {
                "target": "https://example.com/login",
                "risk_type": "login_surface",
                "route_hint": "login_entry_context",
                "surface_hints": ["login_entry_surface"],
            }
        )

        self.assertEqual("login_entry_surface", profile.get("name"))
        self.assertEqual("replay", profile.get("preferred_payload_type"))

    def test_api_doc_summary_extracts_paths_and_params(self):
        summary = WebSiteFetch._extract_api_doc_summary(
            '{"openapi":"3.0.0","paths":{"/api/login":{"post":{"parameters":[{"name":"tenant"}],"requestBody":{"content":{"application/json":{"schema":{"properties":{"username":{},"password":{}}}}}}}},"/api/user/{id}":{"get":{"parameters":[{"name":"id"}]}}},"components":{"securitySchemes":{"BearerAuth":{"type":"http","scheme":"bearer"}}}}'
        )

        self.assertEqual(2, summary.get("path_count"))
        self.assertGreaterEqual(summary.get("security_scheme_count", 0), 1)
        self.assertIn("tenant", summary.get("parameter_names", []))
        self.assertIn("username", summary.get("parameter_names", []))

    def test_api_doc_summary_text_contains_structure(self):
        summary_text = WebSiteFetch._format_api_doc_summary_text(
            {
                "path_count": 2,
                "sample_paths": ["/api/login", "/api/user/{id}"],
                "auth_path_count": 1,
                "auth_paths": ["/api/login"],
                "parameter_names": ["tenant", "username", "password"],
                "security_scheme_count": 1,
            }
        )

        self.assertIn("paths=2", summary_text)
        self.assertIn("auth_paths=1", summary_text)
        self.assertIn("securitySchemes=1", summary_text)
        self.assertIn("/api/login", summary_text)
        self.assertIn("tenant", summary_text)

    def test_extract_js_api_targets_collects_method_and_params(self):
        targets = WebSiteFetch._extract_js_api_targets(
            "https://example.com/static/app.js",
            """
            fetch('/api/search?scene=web', {
              method: 'POST',
              body: JSON.stringify({ keyword: query, page: currentPage })
            });
            axios.get('/api/user/detail', { params: { id: userId, profile: mode } });
            """
        )

        target_map = {item["url"]: item for item in targets}
        self.assertIn("https://example.com/api/search?scene=web", target_map)
        self.assertEqual("POST", target_map["https://example.com/api/search?scene=web"]["method"])
        self.assertIn("keyword", target_map["https://example.com/api/search?scene=web"]["params"])
        self.assertIn("https://example.com/api/user/detail", target_map)
        self.assertIn("id", target_map["https://example.com/api/user/detail"]["params"])

    def test_normalize_js_api_target_keeps_query_param_names(self):
        target = WebSiteFetch._normalize_js_api_target(
            "https://example.com/static/app.js",
            "/api/search?scene=web",
            "POST",
            ["keyword", "page"],
            "js_api_extract",
        )

        self.assertEqual("https://example.com/api/search?scene=web", target.get("url"))
        self.assertIn("scene", target.get("params", []))
        self.assertIn("keyword", target.get("params", []))

    def test_build_idor_probe_targets_supports_query_and_path_tokens(self):
        query_targets = WebSiteFetch._build_idor_probe_targets(
            "https://example.com/api/user/detail?user_id=100",
            max_count=3,
        )
        path_targets = WebSiteFetch._build_idor_probe_targets(
            "https://example.com/api/orders/507f1f77bcf86cd799439011",
            max_count=3,
        )

        self.assertEqual("https://example.com/api/user/detail?user_id=101", query_targets[0].get("url"))
        self.assertEqual("user_id", query_targets[0].get("mutation_key"))
        self.assertEqual("numeric", query_targets[0].get("mutation_kind"))
        self.assertIn("507f1f77bcf86cd799439011", path_targets[0].get("mutation_from"))
        self.assertEqual("object_id", path_targets[0].get("mutation_kind"))

    def test_build_idor_diff_summary_marks_sensitive_fields(self):
        summary = WebSiteFetch._build_idor_diff_summary(
            base_status=200,
            base_body='{"code":0,"data":{"id":100}}',
            probe_status=200,
            probe_body='{"code":0,"data":{"id":101,"email":"user@example.com","role":"admin"}}',
            probe_target={
                "mutation_key": "user_id",
                "mutation_from": "100",
                "mutation_to": "101",
                "mutation_kind": "numeric",
            },
        )

        self.assertTrue(bool(summary.get("material_change")))
        self.assertIn("email", list(summary.get("sensitive_hits", [])))
        self.assertIn("role", list(summary.get("sensitive_hits", [])))
        self.assertEqual("user_id", summary.get("mutation_key"))

    def test_idor_diff_summary_text_and_score(self):
        summary = WebSiteFetch._build_idor_diff_summary(
            base_status=200,
            base_body='{"code":0,"data":{"id":100}}',
            probe_status=403,
            probe_body='{"code":403,"msg":"forbidden"}',
            probe_target={
                "mutation_key": "id",
                "mutation_from": "100",
                "mutation_to": "101",
                "mutation_kind": "numeric",
            },
        )

        summary_text = WebSiteFetch._format_idor_diff_summary_text(summary)
        score = WebSiteFetch._score_idor_diff_summary(summary)

        self.assertIn("mutation=id:100->101", summary_text)
        self.assertIn("status_changed=1", summary_text)
        self.assertGreaterEqual(score, 6)

    def test_classify_ai_pen_idor_outcome_marks_verified_for_sensitive_success_diff(self):
        summary = WebSiteFetch._build_idor_diff_summary(
            base_status=200,
            base_body='{"code":0,"data":{"id":100}}',
            probe_status=200,
            probe_body='{"code":0,"data":{"id":101,"email":"user@example.com","role":"admin"}}',
            probe_target={
                "mutation_key": "user_id",
                "mutation_from": "100",
                "mutation_to": "101",
                "mutation_kind": "numeric",
            },
        )
        outcome = WebSiteFetch._classify_ai_pen_idor_outcome(200, 200, summary)

        self.assertEqual("verified", outcome.get("decision"))
        self.assertGreaterEqual(float(outcome.get("confidence", 0) or 0), 0.82)

    def test_classify_ai_pen_idor_outcome_marks_likely_fp_for_forbidden_after_mutation(self):
        summary = WebSiteFetch._build_idor_diff_summary(
            base_status=200,
            base_body='{"code":0,"data":{"id":100}}',
            probe_status=403,
            probe_body='{"code":403,"msg":"forbidden"}',
            probe_target={
                "mutation_key": "id",
                "mutation_from": "100",
                "mutation_to": "101",
                "mutation_kind": "numeric",
            },
        )
        outcome = WebSiteFetch._classify_ai_pen_idor_outcome(200, 403, summary)

        self.assertEqual("likely_false_positive", outcome.get("decision"))
        self.assertIn("访问控制生效", str(outcome.get("reason", "")))

    def test_api_surface_summary_merges_api_doc_and_js_targets(self):
        summary = WebSiteFetch._build_api_surface_summary(
            api_doc_summary={
                "path_count": 2,
                "sample_paths": ["/api/login", "/api/user/{id}"],
                "auth_path_count": 1,
                "auth_paths": ["/api/login"],
                "parameter_names": ["tenant", "username", "password"],
                "security_scheme_count": 1,
            },
            js_api_targets=[
                {
                    "method": "GET",
                    "url": "https://example.com/api/order/detail?id=1",
                    "params": ["id", "token"],
                    "source": "js_api_extract",
                }
            ],
        )

        self.assertEqual(2, summary.get("path_count"))
        self.assertEqual(1, summary.get("js_api_count"))
        self.assertGreaterEqual(summary.get("object_id_like_count", 0), 1)
        self.assertGreaterEqual(summary.get("security_scheme_count", 0), 1)
        self.assertIn("token", summary.get("parameter_names", []))

    def test_ai_pen_graph_summary_is_small_and_structured(self):
        summary = WebSiteFetch._build_ai_pen_graph_summary(
            {
                "target": "https://example.com",
                "api_surface_summary": {
                    "path_count": 3,
                    "sample_paths": ["/api/login", "/api/user/{id}", "/api/export"],
                    "auth_path_count": 1,
                    "auth_paths": ["/api/login"],
                    "parameter_names": ["id", "token", "file"],
                    "security_scheme_count": 1,
                    "object_id_like_count": 1,
                    "upload_like_count": 1,
                    "download_like_count": 1,
                },
                "browser_surface_summary": {
                    "source_role": "runtime_enrichment",
                    "script_count": 2,
                },
                "runtime_api_calls": [
                    {"method": "GET", "url": "https://example.com/api/me", "status": "200"},
                    {"method": "POST", "url": "https://example.com/api/login", "status": "200"},
                ],
                "dom_form_summary": [
                    {"action": "/login", "method": "POST", "fields": "username,password"},
                ],
                "knowledge_hit_vuln_types": ["api_doc", "idor"],
                "knowledge_hit_entry_paths": ["/api/login"],
            }
        )

        self.assertGreater(summary.get("node_count", 0), 0)
        self.assertGreaterEqual(summary.get("edge_count", 0), 0)
        self.assertIn("/api/login", summary.get("top_paths", []))
        self.assertIn("token", summary.get("top_params", []))
        self.assertIn("auth_cluster", summary)
        self.assertIn("object_ref_cluster", summary)
        self.assertIn("file_cluster", summary)
        self.assertIn("intel_layers", summary)
        self.assertIn("browser_runtime", summary.get("intel_layers", {}).get("active_layers", []))
        self.assertEqual(
            "runtime_enrichment",
            summary.get("intel_layers", {}).get("runtime_layer", {}).get("role"),
        )

    def test_task_ai_pen_graph_context_aggregates_candidates(self):
        context = WebSiteFetch._build_task_ai_pen_graph_context(
            [
                {
                    "source_collection": "site",
                    "route_hint": "api_doc_structure",
                    "knowledge_hit_tokens": ["swagger"],
                    "task_ai_pen_graph_summary": {
                        "top_paths": ["/api/login", "/api/user/{id}"],
                        "top_params": ["id", "token"],
                        "auth_cluster": {
                            "auth_path_count": 1,
                            "security_scheme_count": 1,
                            "top_auth_paths": ["/api/login"],
                        },
                        "object_ref_cluster": {"object_id_like_count": 1},
                        "file_cluster": {"upload_like_count": 0, "download_like_count": 1},
                        "browser_runtime_call_count": 0,
                        "dom_form_count": 0,
                        "knowledge_vuln_types": ["api_doc"],
                        "intel_layers": {"active_layers": ["static_surface", "knowledge_index"]},
                    },
                },
                {
                    "source_collection": "wih",
                    "route_hint": "http_replay_then_context",
                    "runtime_api_calls": [{"method": "GET", "url": "https://example.com/api/me", "status": "200"}],
                    "browser_surface_summary": {"page_url": "https://example.com/dashboard"},
                    "task_ai_pen_graph_summary": {
                        "top_paths": ["/api/me"],
                        "top_params": ["username"],
                        "auth_cluster": {
                            "auth_path_count": 0,
                            "security_scheme_count": 0,
                            "top_auth_paths": [],
                        },
                        "object_ref_cluster": {"object_id_like_count": 0},
                        "file_cluster": {"upload_like_count": 0, "download_like_count": 0},
                        "browser_runtime_call_count": 1,
                        "dom_form_count": 1,
                        "knowledge_vuln_types": ["idor"],
                        "intel_layers": {"active_layers": ["static_surface", "browser_runtime"]},
                    },
                },
            ]
        )

        self.assertEqual(2, context.get("candidate_count"))
        self.assertIn("/api/login", context.get("top_paths", []))
        self.assertIn("token", context.get("top_params", []))
        self.assertTrue(any(item.get("name") == "site" for item in context.get("source_mix", [])))
        self.assertTrue(any(item.get("name") == "api_doc_structure" for item in context.get("route_mix", [])))
        self.assertTrue(any(item.get("name") == "browser_runtime" for item in context.get("layer_mix", [])))
        self.assertGreaterEqual(context.get("feature_presence", {}).get("auth_surface_candidates", 0), 1)
        self.assertIn("https://example.com/dashboard", context.get("runtime_targets", []))

    def test_file_context_detects_upload_surface_from_forms(self):
        result = WebSiteFetch._analyze_ai_pen_file_context(
            target_url="https://example.com/upload",
            body_text='<form enctype="multipart/form-data"><input type="file" name="file"></form>',
            headers={"Content-Type": "text/html"},
            risk_type="file_upload",
            payload_type="upload_probe",
            evidence_seed="upload",
            api_surface_summary={"upload_like_count": 1, "download_like_count": 0},
            browser_surface_summary={"page_url": "https://example.com/upload"},
            runtime_api_calls=[],
            dom_form_summary=[{"action": "/upload", "method": "POST", "enctype": "multipart/form-data", "has_file_input": "true", "fields": "file"}],
        )

        self.assertEqual("needs_manual_review", result.get("decision"))
        self.assertIn("上传表单", str(result.get("reason") or ""))

    def test_file_context_detects_download_surface_from_headers(self):
        result = WebSiteFetch._analyze_ai_pen_file_context(
            target_url="https://example.com/export/report",
            body_text="",
            headers={
                "Content-Type": "application/octet-stream",
                "Content-Disposition": 'attachment; filename="report.xlsx"',
            },
            risk_type="file_read",
            payload_type="replay",
            evidence_seed="download",
            api_surface_summary={"upload_like_count": 0, "download_like_count": 1},
            browser_surface_summary={},
            runtime_api_calls=[],
            dom_form_summary=[],
        )

        self.assertEqual("needs_manual_review", result.get("decision"))
        self.assertIn("下载/导出响应特征", str(result.get("reason") or ""))

    def test_file_context_verifies_upload_probe_from_runtime_response(self):
        result = WebSiteFetch._analyze_ai_pen_file_context(
            target_url="https://example.com/api/upload",
            body_text="",
            headers={"Content-Type": "application/json"},
            risk_type="file_upload",
            payload_type="upload_probe",
            evidence_seed="arl-safe-upload.txt",
            api_surface_summary={"upload_like_count": 1, "download_like_count": 0},
            browser_surface_summary={},
            runtime_api_calls=[],
            dom_form_summary=[],
            probe_status=200,
            probe_headers={"Content-Type": "application/json"},
            probe_body_text='{"code":0,"name":"arl-safe-upload.txt","url":"/download/arl-safe-upload.txt"}',
            payload="arl-safe-upload.txt",
        )

        self.assertEqual("verified", result.get("decision"))
        self.assertEqual("file_context(upload_verified)", result.get("tool_trace"))

    def test_file_context_verifies_download_probe_from_runtime_response(self):
        result = WebSiteFetch._analyze_ai_pen_file_context(
            target_url="https://example.com/api/export",
            body_text="",
            headers={"Content-Type": "text/html"},
            risk_type="file_read",
            payload_type="file_probe",
            evidence_seed="download",
            api_surface_summary={"upload_like_count": 0, "download_like_count": 1},
            browser_surface_summary={},
            runtime_api_calls=[],
            dom_form_summary=[],
            probe_status=200,
            probe_headers={
                "Content-Type": "application/octet-stream",
                "Content-Disposition": "attachment; filename=report.csv",
            },
            probe_body_text="",
            payload="",
        )

        self.assertEqual("verified", result.get("decision"))
        self.assertEqual("file_context(download_verified)", result.get("tool_trace"))

    def test_login_surface_summary_detects_password_and_captcha(self):
        summary = WebSiteFetch._build_ai_pen_login_surface_summary(
            {
                "target": "https://example.com/login",
                "browser_surface_summary": {
                    "page_title": "统一身份认证登录",
                    "page_url": "https://example.com/login",
                },
                "runtime_api_calls": [
                    {"method": "POST", "url": "https://example.com/api/auth/login", "status": "200"},
                    {"method": "GET", "url": "https://example.com/api/captcha", "status": "200"},
                ],
                "dom_form_summary": [
                    {
                        "action": "/login",
                        "method": "POST",
                        "has_password_input": "true",
                        "password_fields": "password",
                        "has_captcha_hint": "true",
                        "fields": "username,password,captcha",
                    }
                ],
                "api_surface_summary": {
                    "auth_paths": ["/api/auth/login"],
                },
            }
        )

        self.assertTrue(summary.get("login_page_hint"))
        self.assertEqual(1, summary.get("password_form_count"))
        self.assertEqual(1, summary.get("captcha_form_count"))
        self.assertGreaterEqual(summary.get("auth_runtime_call_count", 0), 1)
        self.assertIn("/login", summary.get("form_actions", []))

    def test_login_surface_analysis_is_passive_and_conservative(self):
        result = WebSiteFetch._analyze_ai_pen_login_surface(
            target_url="https://example.com/login",
            risk_type="login_surface",
            login_surface_summary={
                "login_page_hint": True,
                "password_form_count": 1,
                "captcha_form_count": 1,
                "auth_runtime_call_count": 1,
                "auth_api_path_count": 1,
                "form_actions": ["/login"],
                "runtime_auth_paths": ["/api/auth/login"],
                "indicators": ["login_keyword", "password_form", "captcha_hint"],
            },
        )

        self.assertEqual("needs_manual_review", result.get("decision"))
        self.assertIn("登录入口或认证链路线索", str(result.get("reason") or ""))

    def test_login_probe_context_extracts_form_fields_from_html(self):
        context = WebSiteFetch._build_ai_pen_login_probe_context(
            target_url="https://example.com/login",
            body_text=(
                '<form action="/auth/login" method="post">'
                '<input type="hidden" name="_token" value="csrf-1" />'
                '<input type="text" name="email" />'
                '<input type="password" name="passwd" />'
                '</form>'
            ),
            dom_form_summary=[],
            login_surface_summary={"password_form_count": 1, "captcha_form_count": 0},
        )

        self.assertEqual("https://example.com/auth/login", context.get("submit_url"))
        self.assertEqual("email", context.get("username_field"))
        self.assertEqual("passwd", context.get("password_field"))
        self.assertEqual("_token", context.get("csrf_field"))
        self.assertFalse(bool(context.get("captcha_required")))

    def test_analyze_ai_pen_login_success_detects_redirect_to_dashboard(self):
        result = WebSiteFetch._analyze_ai_pen_login_success(
            login_url="https://example.com/login",
            response_summary={
                "url": "https://example.com/dashboard",
                "headers": {"Content-Type": "text/html"},
                "body_text": "<html>dashboard</html>",
                "history_urls": ["https://example.com/login"],
                "cookie_names": ["SESSIONID"],
            },
            base_body_text="<html><title>Login</title></html>",
        )

        self.assertTrue(bool(result.get("success")))
        self.assertTrue(bool(str(result.get("reason") or "").strip()))
        self.assertEqual("https://example.com/dashboard", result.get("final_url"))

    def test_should_collect_browser_intel_for_page_style_api_doc_target(self):
        original_enable = getattr(Config, "BROWSER_INTEL_ENABLE", False)
        original_max_targets = getattr(Config, "BROWSER_INTEL_MAX_TARGETS", 8)
        original_ai_pen_enable = getattr(Config, "AI_PEN_TEST_ENABLE", True)
        try:
            Config.AI_PEN_TEST_ENABLE = True
            Config.BROWSER_INTEL_ENABLE = True
            Config.BROWSER_INTEL_MAX_TARGETS = 8
            task = WebSiteFetch.__new__(WebSiteFetch)
            task.ai_pen_browser_intel_cache = {}
            task.waf_guard = None
            result = task._should_collect_ai_pen_browser_intel(
                {
                    "target": "https://example.com/swagger-ui/index.html",
                    "risk_type": "api_doc",
                    "source_collection": "site",
                }
            )
        finally:
            Config.AI_PEN_TEST_ENABLE = original_ai_pen_enable
            Config.BROWSER_INTEL_ENABLE = original_enable
            Config.BROWSER_INTEL_MAX_TARGETS = original_max_targets

        self.assertTrue(result)

    def test_should_not_collect_browser_intel_when_ai_pen_disabled(self):
        original_enable = getattr(Config, "BROWSER_INTEL_ENABLE", False)
        original_ai_pen_enable = getattr(Config, "AI_PEN_TEST_ENABLE", True)
        try:
            Config.AI_PEN_TEST_ENABLE = False
            Config.BROWSER_INTEL_ENABLE = True
            task = WebSiteFetch.__new__(WebSiteFetch)
            task.ai_pen_browser_intel_cache = {}
            task.waf_guard = None
            result = task._should_collect_ai_pen_browser_intel(
                {
                    "target": "https://example.com/swagger-ui/index.html",
                    "risk_type": "api_doc",
                    "source_collection": "site",
                }
            )
        finally:
            Config.AI_PEN_TEST_ENABLE = original_ai_pen_enable
            Config.BROWSER_INTEL_ENABLE = original_enable

        self.assertFalse(result)

    def test_should_not_collect_browser_intel_when_static_context_is_sufficient(self):
        original_enable = getattr(Config, "BROWSER_INTEL_ENABLE", False)
        original_max_targets = getattr(Config, "BROWSER_INTEL_MAX_TARGETS", 8)
        original_ai_pen_enable = getattr(Config, "AI_PEN_TEST_ENABLE", True)
        try:
            Config.AI_PEN_TEST_ENABLE = True
            Config.BROWSER_INTEL_ENABLE = True
            Config.BROWSER_INTEL_MAX_TARGETS = 8
            task = WebSiteFetch.__new__(WebSiteFetch)
            task.ai_pen_browser_intel_cache = {}
            task.waf_guard = None
            result = task._should_collect_ai_pen_browser_intel(
                {
                    "target": "https://example.com/swagger-ui/index.html",
                    "risk_type": "api_doc",
                    "source_collection": "site",
                    "api_surface_summary": {
                        "path_count": 8,
                        "auth_path_count": 2,
                        "security_scheme_count": 1,
                        "js_api_count": 7,
                        "parameter_names": ["id", "token", "userId", "file", "page", "size"],
                    },
                }
            )
        finally:
            Config.AI_PEN_TEST_ENABLE = original_ai_pen_enable
            Config.BROWSER_INTEL_ENABLE = original_enable
            Config.BROWSER_INTEL_MAX_TARGETS = original_max_targets

        self.assertFalse(result)

    def test_should_not_collect_browser_intel_for_js_asset(self):
        original_enable = getattr(Config, "BROWSER_INTEL_ENABLE", False)
        original_ai_pen_enable = getattr(Config, "AI_PEN_TEST_ENABLE", True)
        try:
            Config.AI_PEN_TEST_ENABLE = True
            Config.BROWSER_INTEL_ENABLE = True
            task = WebSiteFetch.__new__(WebSiteFetch)
            task.ai_pen_browser_intel_cache = {}
            task.waf_guard = None
            result = task._should_collect_ai_pen_browser_intel(
                {
                    "target": "https://example.com/_nuxt/app.js",
                    "risk_type": "sensitive_info",
                }
            )
        finally:
            Config.AI_PEN_TEST_ENABLE = original_ai_pen_enable
            Config.BROWSER_INTEL_ENABLE = original_enable

        self.assertFalse(result)

    def test_sensitive_info_js_noise_is_downgraded(self):
        result = WebSiteFetch._analyze_ai_pen_js_context(
            target_url="https://example.com/_nuxt/app.js",
            body_text='function a(){var x=\'\';token="+n)}localStorage[location.host]=r.webCustomize.title?r.webCustomize.title:"demo"}',
            headers={"Content-Type": "application/javascript"},
            risk_type="sensitive_info",
            payload_type="replay",
            evidence_seed='token="+n)}localStorage[location.host]=r.webCustomize.title',
        )

        self.assertEqual("likely_false_positive", result.get("decision"))
        self.assertIn("未发现硬编码敏感值", str(result.get("reason") or ""))

    def test_sensitive_info_hardcoded_client_secret_is_promoted(self):
        result = WebSiteFetch._analyze_ai_pen_js_context(
            target_url="https://example.com/static/main.js",
            body_text='const client_secret = "AbCdEf1234567890ZXCVBNMqwerty";',
            headers={"Content-Type": "application/javascript"},
            risk_type="sensitive_info",
            payload_type="replay",
            evidence_seed="client_secret",
        )

        self.assertEqual("verified", result.get("decision"))
        self.assertIn("硬编码", str(result.get("reason") or ""))

    def test_sensitive_info_hardcoded_secret_infers_component_and_application(self):
        result = WebSiteFetch._analyze_ai_pen_js_context(
            target_url="https://example.com/umi.6b38f726.js",
            body_text=(
                'const secret_key = "AbCdEf1234567890ZXCVBNMqwerty";'
                'function getRouter(){return history;}'
                'const sign = hmac(secret_key);'
                'const loginUrl = "/passport/login";'
            ),
            headers={"Content-Type": "application/javascript"},
            risk_type="sensitive_info",
            payload_type="replay",
            evidence_seed="secret_key",
        )

        summary = result.get("js_context_summary") if isinstance(result.get("js_context_summary"), dict) else {}
        self.assertEqual("verified", result.get("decision"))
        self.assertIn("应用签名/加密密钥", str(result.get("reason") or ""))
        self.assertEqual("应用签名/加密密钥", summary.get("key_type"))
        self.assertEqual("UMI/React Router 路由组件", summary.get("component_hint"))
        self.assertEqual("认证/登录应用", summary.get("application_hint"))

    def test_dom_xss_framework_chunk_without_sink_is_downgraded(self):
        result = WebSiteFetch._analyze_ai_pen_js_context(
            target_url="https://example.com/_nuxt/chunk-vendors.js",
            body_text='window.__NUXT__={};__webpack_require__.e=function(){return Promise.resolve()};',
            headers={"Content-Type": "application/javascript"},
            risk_type="xss",
            payload_type="xss_probe",
            evidence_seed="<svg/onload=alert(1)>",
        )

        self.assertEqual("likely_false_positive", result.get("decision"))
        self.assertIn("未发现危险 DOM sink", str(result.get("reason") or ""))

    def test_dom_xss_source_and_sink_without_popup_proof_is_downgraded(self):
        result = WebSiteFetch._analyze_ai_pen_js_context(
            target_url="https://example.com/static/app.js",
            body_text="const hashValue = location.hash; document.body.innerHTML = hashValue;",
            headers={"Content-Type": "application/javascript"},
            risk_type="xss",
            payload_type="xss_probe",
            evidence_seed="innerHTML",
        )

        self.assertEqual("likely_false_positive", result.get("decision"))
        self.assertIn("缺少可触发弹窗", str(result.get("reason") or ""))

    def test_generic_js_header_keyword_noise_is_downgraded(self):
        result = WebSiteFetch._analyze_ai_pen_js_context(
            target_url="https://example.com/umi.6b38f726.js",
            body_text=(
                "Location:mt,getAction:_t,getRouter:rt,getSearch:Pt,getHash:rn,"
                "createMatchSelector:On}},ea=ga,la=function(){}"
            ),
            headers={"Content-Type": "application/javascript"},
            risk_type="cmdi",
            payload_type="cmdi_probe",
            evidence_seed="Location:mt,getAction",
        )

        self.assertEqual("likely_false_positive", result.get("decision"))
        self.assertIn("Location", str(result.get("reason") or ""))
        self.assertIn("无关", str(result.get("reason") or ""))

    def test_xss_popup_proof_requires_raw_executable_reflection(self):
        self.assertTrue(
            WebSiteFetch._has_xss_popup_proof(
                payload="<svg/onload=alert(1)>",
                base_body="<html><body>normal</body></html>",
                probe_body="<html><body><svg/onload=alert(1)></body></html>",
            )
        )
        self.assertFalse(
            WebSiteFetch._has_xss_popup_proof(
                payload="<svg/onload=alert(1)>",
                base_body="<html><body>normal</body></html>",
                probe_body="<html><body>&lt;svg/onload=alert(1)&gt;</body></html>",
            )
        )

    def test_classify_weak_password_risk_type(self):
        risk_type = WebSiteFetch._classify_ai_pen_risk_type(
            raw_type="nuclei",
            risk_name="后台弱口令",
            source_module="nuclei",
        )
        self.assertEqual("weak_password", risk_type)

    def test_payload_hint_for_config_surface_prefers_config_probe(self):
        task = WebSiteFetch.__new__(WebSiteFetch)
        payload_type, payload = task._build_ai_pen_payload_hint(
            risk_type="sensitive_info",
            risk_name="高价值配置/环境信息端点",
        )

        self.assertEqual("config_probe", payload_type)
        self.assertEqual("", payload)

    def test_infer_tool_plan_uses_config_probe_for_actuator_endpoint(self):
        plan = WebSiteFetch._infer_ai_pen_tool_plan(
            candidate={"target": "https://example.com/actuator/env"},
            payload_type="config_probe",
            payload="",
            max_steps=2,
        )

        self.assertEqual(2, len(plan))
        self.assertEqual("config_probe", plan[0].get("tool"))
        self.assertTrue(any("/actuator/env" in str(item.get("params", {}).get("url", "")) for item in plan))

    def test_build_config_probe_targets_covers_management_family(self):
        targets = WebSiteFetch._build_config_probe_targets(
            "https://example.com/api/actuator/env",
            max_count=6,
        )

        self.assertEqual(6, len(targets))
        self.assertIn("https://example.com/api/actuator/env", targets)
        self.assertTrue(any(item.endswith("/actuator/configprops") for item in targets))
        self.assertTrue(any(item.endswith("/api/actuator/configprops") for item in targets))

    def test_build_auth_protocol_probe_targets_covers_openid_family(self):
        targets = WebSiteFetch._build_auth_protocol_probe_targets(
            "https://example.com/api/login",
            max_count=6,
        )

        self.assertEqual(6, len(targets))
        self.assertTrue(any(item.endswith("/.well-known/openid-configuration") for item in targets))
        self.assertTrue(any(item.endswith("/oauth/token") for item in targets))

    def test_looks_like_auth_protocol_response_detects_openid_configuration(self):
        body = json.dumps(
            {
                "issuer": "https://example.com",
                "authorization_endpoint": "https://example.com/oauth/authorize",
                "token_endpoint": "https://example.com/oauth/token",
                "jwks_uri": "https://example.com/.well-known/jwks.json",
            },
            ensure_ascii=False,
        )

        hit = WebSiteFetch._looks_like_auth_protocol_response(
            "https://example.com/.well-known/openid-configuration",
            body,
            headers={"Content-Type": "application/json"},
        )
        self.assertTrue(hit)

        summary = WebSiteFetch._extract_auth_protocol_summary(
            body,
            url_text="https://example.com/.well-known/openid-configuration",
        )
        self.assertEqual("openid_configuration", summary.get("mode"))
        self.assertEqual("/oauth/token", summary.get("token_endpoint"))

    def test_infer_tool_plan_for_weak_password_uses_session_chain(self):
        plan = WebSiteFetch._infer_ai_pen_tool_plan(
            candidate={
                "target": "https://example.com/login",
                "risk_type": "weak_password",
                "dom_form_summary": [
                    {
                        "action": "/doLogin",
                        "method": "POST",
                        "has_password_input": "true",
                        "password_fields": "password",
                        "has_captcha_hint": "false",
                        "fields": "username,password,csrf_token",
                    }
                ],
                "login_surface_summary": {
                    "password_form_count": 1,
                    "captcha_form_count": 0,
                },
            },
            payload_type="weak_password_probe",
            payload="username=admin&password=admin",
            max_steps=4,
        )

        self.assertEqual(4, len(plan))
        self.assertEqual("session_start", plan[0].get("tool"))
        self.assertEqual("extract_csrf_token", plan[1].get("tool"))
        self.assertEqual("credential_probe", plan[2].get("tool"))
        self.assertEqual("detect_login_success", plan[3].get("tool"))
        self.assertEqual("weak_password", plan[2].get("params", {}).get("session_key"))

    def test_infer_tool_plan_for_jwt_extends_to_auth_protocol_targets(self):
        plan = WebSiteFetch._infer_ai_pen_tool_plan(
            candidate={"target": "https://example.com/api/login"},
            payload_type="jwt_probe",
            payload="",
            max_steps=4,
        )

        self.assertEqual(4, len(plan))
        self.assertEqual("jwt_probe", plan[0].get("tool"))
        urls = [str(item.get("params", {}).get("url", "") or "") for item in plan]
        self.assertTrue(any("/.well-known/openid-configuration" in item for item in urls))

    def test_runtime_tool_registry_contains_session_and_config_tools(self):
        for tool_name in ("session_request", "extract_csrf_token", "token_replay", "config_probe", "xss_probe", "ssti_probe", "xxe_probe"):
            self.assertIn(tool_name, WebSiteFetch.AI_PEN_RUNTIME_TOOL_NAMES)

    def test_infer_tool_plan_for_jwt_adds_token_replay_when_token_present(self):
        token = "aaaaaaaa.bbbbbbbb.cccccccc"
        plan = WebSiteFetch._infer_ai_pen_tool_plan(
            candidate={
                "target": "https://example.com/api/profile",
                "evidence_seed": "Authorization: Bearer {}".format(token),
            },
            payload_type="jwt_probe",
            payload="",
            max_steps=3,
        )

        tools = [str(item.get("tool") or "").strip() for item in plan]
        self.assertIn("token_replay", tools)
        replay_step = next(item for item in plan if str(item.get("tool") or "").strip() == "token_replay")
        auth_header = str(replay_step.get("params", {}).get("headers", {}).get("Authorization", "") or "")
        self.assertTrue(auth_header.startswith("Bearer "))
        self.assertTrue(auth_header.endswith("."))

    def test_fallback_tool_plan_for_jwt_includes_token_replay_and_jwt_probe(self):
        token = "aaaaaaaa.bbbbbbbb.cccccccc"
        plan = WebSiteFetch._build_ai_pen_fallback_tool_plan(
            target_url="https://example.com/api/profile",
            payload_type="jwt_probe",
            payload="",
            max_steps=3,
            candidate={"evidence_seed": token},
            body_text="",
        )

        tools = [str(item.get("tool") or "").strip() for item in plan]
        self.assertIn("token_replay", tools)
        self.assertIn("jwt_probe", tools)

    def test_weak_password_requires_login_success_proof(self):
        self.assertTrue(
            WebSiteFetch._has_weak_password_login_proof(
                evidence_seed="username=admin password=admin 登录成功",
                base_body="",
                probe_body="",
            )
        )
        self.assertFalse(
            WebSiteFetch._has_weak_password_login_proof(
                evidence_seed="username=admin password=admin",
                base_body="",
                probe_body="",
            )
        )

    def test_sqli_error_based_proof_is_detected(self):
        proof_type = WebSiteFetch._detect_sqli_proof_type(
            base_body="normal page",
            probe_body="You have an error in your SQL syntax near '' at line 1",
        )
        self.assertEqual("error_based", proof_type)

    def test_verified_proof_guard_blocks_missing_xss_proof(self):
        reason = WebSiteFetch._get_ai_pen_verified_proof_guard_reason(
            risk_type_text="xss",
            payload_type_text="xss_probe",
            xss_popup_proof=False,
            weak_password_login_proof=False,
            sqli_proof_type="",
        )
        self.assertIn("XSS", reason)

    def test_verified_proof_guard_allows_external_sqli_proof(self):
        reason = WebSiteFetch._get_ai_pen_verified_proof_guard_reason(
            risk_type_text="sqli",
            payload_type_text="sqli_probe",
            xss_popup_proof=False,
            weak_password_login_proof=False,
            sqli_proof_type="external_tool",
        )
        self.assertEqual("", reason)


if __name__ == "__main__":
    unittest.main()
