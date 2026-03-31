import importlib.util
import json
import pathlib
import sys
import types
import unittest
from unittest import mock


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

    def test_high_value_url_candidate_detects_auth_protocol_endpoint(self):
        candidate = WebSiteFetch._build_ai_pen_high_value_url_candidate(
            source_collection="url",
            source_id="507f1f77bcf86cd7994390aa",
            target_url="https://example.com/.well-known/openid-configuration",
            status_code=200,
            title_text="OpenID Provider Metadata",
            source_text="url",
        )

        self.assertEqual("jwt", candidate.get("risk_type"))
        self.assertEqual("高价值认证协议端点", candidate.get("risk_name"))
        self.assertEqual("auth_protocol_endpoint", candidate.get("high_value_reason"))

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

    def test_high_value_url_candidate_detects_socketio_surface(self):
        candidate = WebSiteFetch._build_ai_pen_high_value_url_candidate(
            source_collection="url",
            source_id="507f1f77bcf86cd799439033",
            target_url="https://example.com/socket.io/?EIO=4&transport=polling&t=abc",
            status_code=200,
            title_text="Socket Service",
            source_text="url",
        )

        self.assertEqual("socketio", candidate.get("risk_type"))
        self.assertEqual("高价值 Socket.IO/SockJS 入口", candidate.get("risk_name"))
        self.assertEqual("socketio_endpoint", candidate.get("high_value_reason"))

    def test_high_value_url_candidate_detects_websocket_surface(self):
        candidate = WebSiteFetch._build_ai_pen_high_value_url_candidate(
            source_collection="url",
            source_id="507f1f77bcf86cd7994390bb",
            target_url="https://example.com/api/websocket/chat",
            status_code=200,
            title_text="Realtime Chat",
            source_text="url",
        )

        self.assertEqual("websocket", candidate.get("risk_type"))
        self.assertEqual("高价值 WebSocket 入口", candidate.get("risk_name"))
        self.assertEqual("websocket_endpoint", candidate.get("high_value_reason"))

    def test_high_value_url_candidate_detects_path_traversal_surface(self):
        candidate = WebSiteFetch._build_ai_pen_high_value_url_candidate(
            source_collection="url",
            source_id="507f1f77bcf86cd799439034",
            target_url="https://example.com/download?file=../../../../etc/passwd",
            status_code=200,
            title_text="download",
            source_text="url",
        )

        self.assertEqual("path_traversal", candidate.get("risk_type"))
        self.assertEqual("高价值路径穿越入口", candidate.get("risk_name"))

    def test_build_ai_pen_high_value_summary_merges_runtime_browser_and_login_families(self):
        summary = WebSiteFetch._build_ai_pen_high_value_summary(
            {
                "source_collection": "wih",
                "source_module": "wih",
                "target": "https://example.com/",
                "vuln_url": "https://example.com/",
                "risk_name": "WIH-info",
                "evidence_seed": "发现 swagger ui 和 openid configuration 以及 websocket 入口",
                "status_code_hint": 200,
                "browser_surface_summary": {
                    "page_title": "Swagger UI",
                    "page_url": "https://example.com/",
                },
                "runtime_api_calls": [
                    {"method": "GET", "url": "https://example.com/.well-known/openid-configuration"},
                    {"method": "GET", "url": "wss://example.com/ws/chat"},
                ],
                "dom_form_summary": [
                    {"action": "/passport/login", "method": "POST", "has_password_input": "true"},
                ],
                "login_surface_summary": {
                    "runtime_auth_paths": ["/api/auth/login"],
                },
            }
        )

        self.assertTrue(bool(summary.get("used")))
        self.assertEqual("api_doc_surface", summary.get("best_family"))
        self.assertIn("token_auth_flow", list(summary.get("families", []) or []))
        self.assertIn("realtime_channel_surface", list(summary.get("families", []) or []))
        self.assertIn("login_entry_surface", list(summary.get("families", []) or []))
        self.assertTrue(any("/.well-known/openid-configuration" in item for item in list(summary.get("matched_urls", []) or [])))

    def test_build_ai_pen_high_value_summary_uses_browser_title_for_site_root(self):
        summary = WebSiteFetch._build_ai_pen_high_value_summary(
            {
                "source_collection": "site",
                "source_module": "site",
                "target": "https://portal.example.com/",
                "vuln_url": "https://portal.example.com/",
                "risk_name": "站点疑似暴露API文档",
                "evidence_seed": "title=Swagger UI",
                "status_code_hint": 200,
                "browser_surface_summary": {
                    "page_title": "Swagger UI",
                    "page_url": "https://portal.example.com/",
                },
            }
        )

        self.assertTrue(bool(summary.get("used")))
        self.assertEqual("api_doc_surface", summary.get("best_family"))
        self.assertIn("swagger", ",".join(list(summary.get("keywords", []) or [])))

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

    def test_collect_ai_pen_runtime_observation_detects_web_policy(self):
        observation = WebSiteFetch._collect_ai_pen_runtime_observation(
            [
                {
                    "turn": 1,
                    "tool": "web_policy_probe",
                    "status": "ok",
                    "result": {
                        "response": {
                            "url": "https://example.com/api/profile",
                            "status_code": 200,
                            "headers": {
                                "Content-Type": "application/json",
                                "Access-Control-Allow-Origin": "*",
                                "Access-Control-Allow-Credentials": "true",
                            },
                            "body_text": '{"ok":true}',
                        }
                    },
                }
            ],
            evidence_seed="",
            js_api_targets=[],
        )

        self.assertTrue(bool(observation.get("web_policy_hit")))
        self.assertEqual("https://example.com/api/profile", observation.get("web_policy_url"))
        self.assertEqual(
            "cors_credentialed_wildcard",
            str(observation.get("web_policy_summary", {}).get("proof_type") or ""),
        )

    def test_collect_ai_pen_runtime_observation_web_policy_uses_baseline_control_pair(self):
        observation = WebSiteFetch._collect_ai_pen_runtime_observation(
            [
                {
                    "turn": 1,
                    "tool": "web_policy_probe",
                    "status": "ok",
                    "result": {
                        "response": {
                            "url": "https://example.com/api/profile",
                            "status_code": 200,
                            "request_headers": {"Accept": "application/json"},
                            "headers": {"Content-Type": "application/json"},
                            "body_text": '{"ok":true}',
                        }
                    },
                },
                {
                    "turn": 2,
                    "tool": "web_policy_probe",
                    "status": "ok",
                    "result": {
                        "response": {
                            "url": "https://example.com/api/profile",
                            "status_code": 200,
                            "request_headers": {"Origin": "https://arl-probe.example"},
                            "headers": {
                                "Content-Type": "application/json",
                                "Access-Control-Allow-Origin": "*",
                                "Access-Control-Allow-Credentials": "true",
                            },
                            "body_text": '{"ok":true}',
                        }
                    },
                },
                {
                    "turn": 3,
                    "tool": "web_policy_probe",
                    "status": "ok",
                    "result": {
                        "response": {
                            "url": "https://example.com/api/profile",
                            "status_code": 204,
                            "request_headers": {"Access-Control-Request-Method": "GET"},
                            "headers": {"Content-Type": "text/plain"},
                            "body_text": "",
                        }
                    },
                },
            ],
            evidence_seed="",
            js_api_targets=[],
        )

        self.assertTrue(bool(observation.get("web_policy_hit")))
        self.assertEqual("cors_credentialed_wildcard", str(observation.get("web_policy_summary", {}).get("proof_type") or ""))
        self.assertEqual("baseline_control", str(observation.get("web_policy_summary", {}).get("pair_mode") or ""))
        self.assertTrue(bool(observation.get("web_policy_baseline_summary")))
        self.assertTrue(bool(observation.get("web_policy_control_summary")))

    def test_collect_ai_pen_runtime_observation_detects_socketio(self):
        observation = WebSiteFetch._collect_ai_pen_runtime_observation(
            [
                {
                    "turn": 1,
                    "tool": "socketio_probe",
                    "status": "ok",
                    "result": {
                        "response": {
                            "url": "https://example.com/socket.io/?EIO=4&transport=polling&t=arlprobe",
                            "status_code": 200,
                            "headers": {"Content-Type": "text/plain; charset=utf-8"},
                            "body_text": '0{"sid":"abc","upgrades":["websocket"]}',
                        }
                    },
                }
            ],
            evidence_seed="",
            js_api_targets=[],
        )

        self.assertTrue(bool(observation.get("socketio_hit")))
        self.assertEqual(
            "socketio_polling_open",
            str(observation.get("socketio_summary", {}).get("proof_type") or ""),
        )

    def test_collect_ai_pen_runtime_observation_socketio_keeps_stronger_proof(self):
        observation = WebSiteFetch._collect_ai_pen_runtime_observation(
            [
                {
                    "turn": 1,
                    "tool": "socketio_probe",
                    "status": "ok",
                    "result": {
                        "response": {
                            "url": "https://example.com/socket.io/?EIO=4&transport=polling&t=arlprobe",
                            "status_code": 200,
                            "headers": {"Content-Type": "text/plain; charset=utf-8"},
                            "body_text": '0{"sid":"abc","upgrades":["websocket"]}',
                        }
                    },
                },
                {
                    "turn": 2,
                    "tool": "socketio_probe",
                    "status": "ok",
                    "result": {
                        "response": {
                            "url": "https://example.com/socket.io/?EIO=4&transport=websocket&t=arlprobe",
                            "status_code": 400,
                            "headers": {"Content-Type": "text/plain; charset=utf-8"},
                            "body_text": '{"code":3,"message":"transport unknown"}',
                        }
                    },
                },
            ],
            evidence_seed="",
            js_api_targets=[],
        )

        self.assertTrue(bool(observation.get("socketio_hit")))
        self.assertEqual("socketio_polling_open", str(observation.get("socketio_summary", {}).get("proof_type") or ""))

    def test_extract_socketio_summary_detects_websocket_upgrade(self):
        summary = WebSiteFetch._extract_socketio_summary(
            url_text="https://example.com/socket.io/?EIO=4&transport=websocket",
            status_code=101,
            headers={"Upgrade": "websocket", "Content-Type": "text/plain"},
            body_text="",
        )
        self.assertEqual("socketio_websocket_upgrade", str(summary.get("proof_type") or ""))

    def test_collect_ai_pen_runtime_observation_detects_path_traversal_with_baseline_diff(self):
        observation = WebSiteFetch._collect_ai_pen_runtime_observation(
            [
                {
                    "turn": 1,
                    "tool": "path_traversal_probe",
                    "status": "ok",
                    "result": {
                        "response": {
                            "url": "https://example.com/download?file=readme.txt",
                            "status_code": 200,
                            "headers": {"Content-Type": "text/plain"},
                            "body_text": "welcome to demo file",
                        }
                    },
                },
                {
                    "turn": 2,
                    "tool": "path_traversal_probe",
                    "status": "ok",
                    "result": {
                        "response": {
                            "url": "https://example.com/download?file=..%2f..%2f..%2f..%2fetc%2fpasswd",
                            "status_code": 200,
                            "headers": {"Content-Type": "text/plain"},
                            "body_text": "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33",
                        }
                    },
                },
            ],
            evidence_seed="",
            js_api_targets=[],
        )

        self.assertTrue(bool(observation.get("path_traversal_hit")))
        self.assertEqual("passwd_disclosure", str(observation.get("path_traversal_proof_type") or ""))
        self.assertEqual(
            "https://example.com/download?file=readme.txt",
            str(observation.get("path_traversal_baseline_url") or ""),
        )

    def test_collect_ai_pen_runtime_observation_path_traversal_uses_baseline_to_reduce_fp(self):
        observation = WebSiteFetch._collect_ai_pen_runtime_observation(
            [
                {
                    "turn": 1,
                    "tool": "path_traversal_probe",
                    "status": "ok",
                    "result": {
                        "response": {
                            "url": "https://example.com/download?file=readme.txt",
                            "status_code": 200,
                            "headers": {"Content-Type": "text/plain"},
                            "body_text": "root:x:0:0:root:/root:/bin/bash",
                        }
                    },
                },
                {
                    "turn": 2,
                    "tool": "path_traversal_probe",
                    "status": "ok",
                    "result": {
                        "response": {
                            "url": "https://example.com/download?file=..%2f..%2f..%2f..%2fetc%2fpasswd",
                            "status_code": 200,
                            "headers": {"Content-Type": "text/plain"},
                            "body_text": "root:x:0:0:root:/root:/bin/bash",
                        }
                    },
                },
            ],
            evidence_seed="",
            js_api_targets=[],
        )

        self.assertTrue(bool(observation.get("path_traversal_hit")))
        self.assertEqual("", str(observation.get("path_traversal_proof_type") or ""))

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

    def test_build_ai_pen_fallback_tool_plan_for_path_traversal_probe(self):
        plan = WebSiteFetch._build_ai_pen_fallback_tool_plan(
            target_url="https://example.com/download?file=report.txt",
            payload_type="path_traversal_probe",
            payload="",
            max_steps=2,
        )

        self.assertEqual(2, len(plan))
        self.assertTrue(all(item.get("tool") == "path_traversal_probe" for item in plan))
        self.assertTrue(any("file=" in str(item.get("params", {}).get("url", "")) for item in plan))

    def test_build_ai_pen_fallback_tool_plan_for_web_policy_probe(self):
        plan = WebSiteFetch._build_ai_pen_fallback_tool_plan(
            target_url="https://example.com/api/profile",
            payload_type="web_policy_probe",
            payload="",
            max_steps=2,
        )

        self.assertEqual(2, len(plan))
        self.assertTrue(all(item.get("tool") == "web_policy_probe" for item in plan))
        self.assertTrue(any(str(item.get("params", {}).get("method", "")).lower() == "options" for item in plan))

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
        sample_interfaces = list(summary.get("sample_interfaces", []) or [])
        self.assertTrue(any(item.get("mode") == "json_data" for item in sample_interfaces if isinstance(item, dict)))
        self.assertTrue(any("application/json" in str(item.get("content_type") or "") for item in sample_interfaces if isinstance(item, dict)))

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

    def test_build_idor_probe_targets_supports_access_control_param_mutation(self):
        targets = WebSiteFetch._build_idor_probe_targets(
            "https://example.com/api/project/list?role=user&scope=read",
            max_count=4,
        )

        urls = [str(item.get("url") or "") for item in targets]
        kinds = [str(item.get("mutation_kind") or "") for item in targets]
        self.assertTrue(any("role=admin" in item for item in urls))
        self.assertTrue(any(kind in {"access_control", "access_control_numeric"} for kind in kinds))

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

    def test_build_idor_diff_summary_marks_vertical_indicator_for_admin_signal(self):
        summary = WebSiteFetch._build_idor_diff_summary(
            base_status=200,
            base_body='{"code":0,"data":{"role":"user"}}',
            probe_status=200,
            probe_body='{"code":0,"data":{"role":"admin","permissions":["manage_users"]}}',
            probe_target={
                "mutation_key": "role",
                "mutation_from": "user",
                "mutation_to": "admin",
                "mutation_kind": "access_control",
            },
        )

        self.assertTrue(bool(summary.get("vertical_indicator")))
        self.assertTrue(bool(summary.get("admin_hits")))

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

    def test_idor_diff_summary_score_boosts_consistency_signal(self):
        summary = {
            "mutation_key": "user_id",
            "mutation_from": "100",
            "mutation_to": "101",
            "mutation_kind": "numeric",
            "status_changed": False,
            "body_changed": True,
            "length_delta": 88,
            "sensitive_hits": ["email", "role"],
            "material_change": True,
            "consistency_hits": 2,
            "consistent_sensitive_fields": ["email", "role"],
        }

        summary_text = WebSiteFetch._format_idor_diff_summary_text(summary)
        score = WebSiteFetch._score_idor_diff_summary(summary)

        self.assertIn("consistency=2", summary_text)
        self.assertIn("consistent_fields=email,role", summary_text)
        self.assertGreaterEqual(score, 14)

    def test_classify_ai_pen_idor_outcome_marks_manual_review_for_sensitive_success_diff(self):
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

        self.assertEqual("needs_manual_review", outcome.get("decision"))
        self.assertIn("人工复核", str(outcome.get("reason", "")))

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

    def test_classify_ai_pen_idor_outcome_marks_manual_review_for_access_control_diff(self):
        summary = WebSiteFetch._build_idor_diff_summary(
            base_status=200,
            base_body='{"code":0,"data":{"role":"user","menu":["home"]}}',
            probe_status=200,
            probe_body='{"code":0,"data":{"role":"admin","menu":["home","admin"],"permissions":["manage_users"]}}',
            probe_target={
                "mutation_key": "role",
                "mutation_from": "user",
                "mutation_to": "admin",
                "mutation_kind": "access_control",
            },
        )
        outcome = WebSiteFetch._classify_ai_pen_idor_outcome(200, 200, summary)

        self.assertEqual("needs_manual_review", outcome.get("decision"))
        self.assertIn("访问控制线索", str(outcome.get("reason", "")))

    def test_api_surface_summary_merges_api_doc_and_js_targets(self):
        summary = WebSiteFetch._build_api_surface_summary(
            api_doc_summary={
                "path_count": 2,
                "sample_paths": ["/api/login", "/api/user/{id}"],
                "auth_path_count": 1,
                "auth_paths": ["/api/login"],
                "parameter_names": ["tenant", "username", "password"],
                "sample_interfaces": [
                    {
                        "method": "POST",
                        "path": "/api/login",
                        "params": ["tenant", "username", "password"],
                        "mode": "json_data",
                        "content_type": "application/json",
                        "source": "api_doc",
                    }
                ],
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
        self.assertTrue(any(str(item.get("mode") or "") == "json_data" for item in list(summary.get("sample_interfaces", []) or []) if isinstance(item, dict)))

    def test_api_surface_summary_merges_runtime_form_and_hidden_parameters(self):
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
            runtime_api_calls=[
                {
                    "method": "POST",
                    "url": "https://example.com/api/auth/login?tenant=corp",
                    "request_body": "username=alice&password=secret",
                },
                {
                    "method": "GET",
                    "url": "https://example.com/api/project/list?role=user",
                },
            ],
            dom_form_summary=[
                {
                    "action": "/auth/login",
                    "method": "post",
                    "has_password_input": "true",
                    "fields": "username,password,captcha",
                    "hidden_fields": {"csrf_token": "x", "tenant_id": "corp"},
                },
                {
                    "action": "/api/upload",
                    "method": "post",
                    "has_file_input": "true",
                    "fields": "file,desc",
                    "hidden_fields": {"upload_token": "1"},
                },
            ],
        )

        source_types = list(summary.get("source_types", []) or [])
        param_names = list(summary.get("parameter_names", []) or [])
        self.assertIn("runtime", source_types)
        self.assertIn("form", source_types)
        self.assertIn("hidden", source_types)
        self.assertIn("role", param_names)
        self.assertIn("csrf_token", param_names)
        self.assertGreaterEqual(summary.get("auth_path_count", 0), 2)
        self.assertGreaterEqual(summary.get("upload_like_count", 0), 1)
        probe_families = [str(item.get("tool") or "") for item in list(summary.get("parameter_probe_families", []) or [])]
        self.assertIn("jwt_probe", probe_families)
        self.assertIn("upload_probe", probe_families)
        self.assertIn("sqli_probe", probe_families)
        self.assertTrue(any(str(item.get("mode") or "") == "form_data" for item in list(summary.get("sample_interfaces", []) or []) if isinstance(item, dict)))

    def test_tag_ai_pen_parameter_name_does_not_misclassify_redirect_as_file_path(self):
        tags = WebSiteFetch._tag_ai_pen_parameter_name("redirect")

        self.assertIn("url", tags)
        self.assertNotIn("file_path", tags)

    def test_api_surface_summary_marks_runtime_json_interface_mode(self):
        summary = WebSiteFetch._build_api_surface_summary(
            runtime_api_calls=[
                {
                    "method": "POST",
                    "url": "https://example.com/api/search",
                    "request_headers": {"Content-Type": "application/json"},
                    "request_body": '{"q":"alice","page":1}',
                }
            ]
        )

        sample_interfaces = [item for item in list(summary.get("sample_interfaces", []) or []) if isinstance(item, dict)]
        self.assertTrue(bool(sample_interfaces))
        self.assertEqual("json_data", str(sample_interfaces[0].get("mode") or ""))
        self.assertEqual("application/json", str(sample_interfaces[0].get("content_type") or ""))
        self.assertIn("q", list(sample_interfaces[0].get("params", []) or []))

    def test_collect_runtime_observation_merges_runtime_form_and_hidden_into_api_surface(self):
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
                        }
                    },
                }
            ],
            evidence_seed="openapi",
            js_api_targets=[
                {
                    "method": "GET",
                    "url": "https://example.com/api/user?id=1",
                    "params": ["id"],
                    "source": "js_api_extract",
                }
            ],
            runtime_api_calls=[
                {
                    "method": "GET",
                    "url": "https://example.com/api/project/list?role=user",
                }
            ],
            dom_form_summary=[
                {
                    "action": "/auth/login",
                    "method": "post",
                    "has_password_input": "true",
                    "fields": "username,password",
                    "hidden_fields": {"csrf_token": "x"},
                }
            ],
        )

        source_types = list(observation.get("api_surface_summary", {}).get("source_types", []) or [])
        param_names = list(observation.get("api_surface_summary", {}).get("parameter_names", []) or [])
        self.assertTrue(bool(observation.get("api_doc_hit")))
        self.assertIn("runtime", source_types)
        self.assertIn("form", source_types)
        self.assertIn("hidden", source_types)
        self.assertIn("role", param_names)
        self.assertIn("csrf_token", param_names)

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
        with mock.patch.object(
            WebSiteFetch,
            "_load_ai_pen_controlled_dict_resource",
            return_value={"ready": True, "user_count": 2, "pass_count": 3},
        ):
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
        self.assertTrue(bool(context.get("controlled_dict_ready")))
        self.assertEqual(2, context.get("controlled_dict_user_count"))
        self.assertEqual(3, context.get("controlled_dict_pass_count"))

    def test_build_ai_pen_minimal_default_credentials_prefers_safe_controlled_dict_pairs(self):
        with mock.patch.object(
            WebSiteFetch,
            "_load_ai_pen_controlled_dict_resource",
            return_value={
                "ready": True,
                "user_count": 2,
                "pass_count": 3,
                "_candidate_usernames": ["admin", "root"],
                "_candidate_passwords": ["admin", "root", "123456"],
            },
        ):
            credentials = WebSiteFetch._build_ai_pen_minimal_default_credentials(
                candidate={
                    "target": "https://example.com/admin/login",
                    "risk_type": "weak_password",
                    "risk_name": "Admin Login",
                    "high_value_family": "auth_entry",
                },
                payload="",
                max_count=3,
            )

        self.assertGreaterEqual(len(credentials), 2)
        self.assertEqual("controlled_dict", credentials[0].get("source"))
        self.assertEqual("admin", credentials[0].get("username"))
        self.assertEqual("admin", credentials[0].get("password"))
        self.assertTrue(any(item.get("source") == "controlled_dict" for item in credentials))

    def test_format_ai_pen_login_probe_context_summary_includes_controlled_dict_state(self):
        summary = WebSiteFetch._format_ai_pen_login_probe_context_summary(
            {
                "login_url": "https://example.com/login",
                "submit_url": "https://example.com/auth/login",
                "method": "post",
                "username_field": "username",
                "password_field": "password",
                "csrf_field": "_token",
                "captcha_required": False,
                "hidden_fields": {"_token": "csrf-1"},
                "fields": ["username", "password"],
                "controlled_dict_ready": True,
                "controlled_dict_user_count": 2,
                "controlled_dict_pass_count": 3,
            }
        )

        self.assertIn("dict=1(2x3)", summary)

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

    def test_analyze_ai_pen_unauth_access_detects_admin_portal(self):
        result = WebSiteFetch._analyze_ai_pen_unauth_access(
            target_url="https://example.com/admin/dashboard",
            status_code=200,
            headers={"Content-Type": "text/html"},
            body_text="<html><body>dashboard manage users logout</body></html>",
            high_value_family="",
            payload_type="replay",
        )

        self.assertTrue(bool(result.get("hit")))
        self.assertEqual("unauth_admin_portal", result.get("proof_type"))

    def test_analyze_ai_pen_unauth_access_detects_profile_api(self):
        result = WebSiteFetch._analyze_ai_pen_unauth_access(
            target_url="https://example.com/api/account/current",
            status_code=200,
            headers={"Content-Type": "application/json"},
            body_text='{"username":"alice","email":"alice@example.com","role":"user"}',
            high_value_family="",
            payload_type="replay",
        )

        self.assertTrue(bool(result.get("hit")))
        self.assertEqual("unauth_profile_data", result.get("proof_type"))

    def test_analyze_ai_pen_unauth_access_detects_actuator_surface(self):
        result = WebSiteFetch._analyze_ai_pen_unauth_access(
            target_url="https://example.com/actuator/env",
            status_code=200,
            headers={"Content-Type": "application/json"},
            body_text='{"activeProfiles":["prod"],"propertySources":[{"name":"systemProperties"}]}',
            high_value_family="config_exposure_surface",
            payload_type="replay",
        )

        self.assertTrue(bool(result.get("hit")))
        self.assertEqual("unauth_actuator_surface", result.get("proof_type"))

    def test_analyze_ai_pen_unauth_access_downgrades_health_endpoint_type(self):
        result = WebSiteFetch._analyze_ai_pen_unauth_access(
            target_url="https://example.com/actuator/health",
            status_code=200,
            headers={"Content-Type": "application/json"},
            body_text='{"status":"UP"}',
            high_value_family="config_exposure_surface",
            payload_type="replay",
        )

        self.assertTrue(bool(result.get("hit")))
        self.assertEqual("unauth_health_endpoint", result.get("proof_type"))

    def test_analyze_ai_pen_unauth_access_prefers_best_multi_response_hit(self):
        result = WebSiteFetch._analyze_ai_pen_unauth_access(
            target_url="https://example.com/",
            high_value_family="admin_debug_surface",
            payload_type="replay",
            response_items=[
                {
                    "tool": "http_fetch",
                    "url": "https://example.com/admin/dashboard",
                    "status_code": 200,
                    "headers": {"Content-Type": "text/html"},
                    "body_text": "<html><body>dashboard manage users logout</body></html>",
                    "body_md5": "a1",
                },
                {
                    "tool": "http_fetch",
                    "url": "https://example.com/actuator/health",
                    "status_code": 200,
                    "headers": {"Content-Type": "application/json"},
                    "body_text": '{"status":"UP"}',
                    "body_md5": "ah",
                },
                {
                    "tool": "http_fetch",
                    "url": "https://example.com/api/account/current",
                    "status_code": 200,
                    "headers": {"Content-Type": "application/json"},
                    "body_text": '{"username":"alice","email":"alice@example.com","role":"user"}',
                    "body_md5": "a2",
                },
            ],
        )

        self.assertTrue(bool(result.get("hit")))
        self.assertEqual("unauth_profile_data", result.get("proof_type"))
        self.assertEqual("https://example.com/api/account/current", result.get("matched_url"))

    def test_build_ai_pen_login_followup_targets_prefers_session_and_logout_paths(self):
        targets = WebSiteFetch._build_ai_pen_login_followup_targets(
            target_url="https://example.com/login",
            login_context={
                "login_url": "https://example.com/login",
                "submit_url": "https://example.com/api/auth/login",
            },
            candidate={
                "login_surface_summary": {
                    "runtime_auth_paths": ["/api/auth/login", "/api/user/profile"],
                    "auth_api_paths": ["/api/logout"],
                },
                "api_surface_summary": {
                    "sample_paths": ["/api/account/current", "/dashboard"],
                    "sample_interfaces": [{"path": "/signout"}],
                },
                "runtime_api_calls": [
                    {"method": "GET", "url": "https://example.com/api/me"},
                ],
            },
        )

        session_targets = list(targets.get("session_targets", []) or [])
        logout_targets = list(targets.get("logout_targets", []) or [])
        self.assertIn("https://example.com/api/user/profile", session_targets)
        self.assertTrue(any(item.endswith("/api/logout") or item.endswith("/signout") for item in logout_targets))

    def test_collect_ai_pen_runtime_observation_detects_session_auth_and_logout(self):
        observation = WebSiteFetch._collect_ai_pen_runtime_observation(
            [
                {
                    "turn": 1,
                    "tool": "session_request",
                    "status": "ok",
                    "result": {
                        "response": {
                            "request_url": "https://example.com/api/me",
                            "url": "https://example.com/api/me",
                            "status_code": 200,
                            "headers": {"Content-Type": "application/json"},
                            "body_text": '{"username":"admin","role":"admin"}',
                        }
                    },
                },
                {
                    "turn": 2,
                    "tool": "logout_probe",
                    "status": "ok",
                    "result": {
                        "response": {
                            "request_url": "https://example.com/logout",
                            "url": "https://example.com/login",
                            "status_code": 200,
                            "headers": {"Content-Type": "text/html"},
                            "body_text": "<html>统一身份认证登录</html>",
                        }
                    },
                },
            ],
            evidence_seed="",
            js_api_targets=[],
            login_url="https://example.com/login",
        )

        self.assertTrue(bool(observation.get("session_auth_hit")))
        self.assertIn("/api/me", str(observation.get("session_auth_url") or ""))
        self.assertTrue(bool(observation.get("logout_effective")))
        self.assertIn("登录", str(observation.get("logout_reason") or ""))

    def test_build_ai_pen_runtime_session_summary_extracts_cookie_state(self):
        class _CookieJar:
            def keys(self):
                return ["SESSIONID", "csrftoken"]

        summary = WebSiteFetch._build_ai_pen_runtime_session_summary(
            {
                "weak_password": {
                    "session": types.SimpleNamespace(cookies=_CookieJar()),
                    "last_response": {
                        "url": "https://example.com/dashboard",
                        "status_code": 200,
                    },
                }
            }
        )

        self.assertEqual(1, summary.get("session_count"))
        self.assertEqual(["weak_password"], summary.get("session_keys"))
        self.assertEqual(2, summary.get("cookie_total"))
        self.assertTrue(bool(summary.get("auth_cookie_hit")))
        self.assertIn("/dashboard", str(summary.get("sessions", [])[0].get("last_url") or ""))

    def test_build_ai_pen_retry_seed_tool_plan_falls_back_to_history_tool_calls(self):
        plan = WebSiteFetch._build_ai_pen_retry_seed_tool_plan(
            {
                "target": "https://example.com/login",
                "tool_calls": [
                    {"tool": "http_fetch", "params": {"url": "https://example.com/login"}},
                    {"tool": "session_start", "params": {"url": "https://example.com/login", "session_key": "weak_password"}},
                    {"tool": "credential_probe", "params": {"url": "https://example.com/doLogin", "method": "post"}},
                ],
            },
            default_url="https://example.com/login",
            max_steps=3,
        )

        self.assertEqual(2, len(plan))
        self.assertEqual("session_start", plan[0].get("tool"))
        self.assertEqual("credential_probe", plan[1].get("tool"))
        self.assertIn("重试沿用历史工具", str(plan[0].get("summary") or ""))

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
        self.assertEqual("source_sink_only", result.get("dom_xss_proof_type"))

    def test_dom_xss_source_sink_with_popup_hint_has_proof_type(self):
        result = WebSiteFetch._analyze_ai_pen_js_context(
            target_url="https://example.com/static/app.js",
            body_text=(
                "const hashValue = location.hash;"
                "document.body.innerHTML = hashValue;"
                "if(hashValue){alert(hashValue);}"
            ),
            headers={"Content-Type": "application/javascript"},
            risk_type="xss",
            payload_type="xss_probe",
            evidence_seed="<svg/onload=alert(1)>",
        )

        self.assertEqual("needs_manual_review", result.get("decision"))
        self.assertEqual("source_sink_popup_hint", result.get("dom_xss_proof_type"))

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

    def test_classify_oauth_risk_type_to_jwt(self):
        risk_type = WebSiteFetch._classify_ai_pen_risk_type(
            raw_type="oauth2",
            risk_name="OpenID Connect discovery endpoint",
            source_module="url",
        )
        self.assertEqual("jwt", risk_type)

    def test_classify_socketio_risk_type(self):
        risk_type = WebSiteFetch._classify_ai_pen_risk_type(
            raw_type="url",
            risk_name="sockjs endpoint",
            source_module="wih",
        )
        self.assertEqual("socketio", risk_type)

    def test_classify_web_policy_risk_type(self):
        risk_type = WebSiteFetch._classify_ai_pen_risk_type(
            raw_type="nuclei",
            risk_name="CORS misconfiguration",
            source_module="nuclei",
        )
        self.assertEqual("web_policy", risk_type)

    def test_payload_hint_for_config_surface_prefers_config_probe(self):
        task = WebSiteFetch.__new__(WebSiteFetch)
        payload_type, payload = task._build_ai_pen_payload_hint(
            risk_type="sensitive_info",
            risk_name="高价值配置/环境信息端点",
        )

        self.assertEqual("config_probe", payload_type)
        self.assertEqual("", payload)

    def test_payload_hint_for_path_traversal_prefers_path_probe(self):
        task = WebSiteFetch.__new__(WebSiteFetch)
        payload_type, payload = task._build_ai_pen_payload_hint(
            risk_type="path_traversal",
            risk_name="Directory Traversal",
        )

        self.assertEqual("path_traversal_probe", payload_type)
        self.assertIn("etc/passwd", payload)

    def test_payload_hint_for_web_policy_prefers_policy_probe(self):
        task = WebSiteFetch.__new__(WebSiteFetch)
        payload_type, payload = task._build_ai_pen_payload_hint(
            risk_type="web_policy",
            risk_name="CORS misconfiguration",
        )

        self.assertEqual("web_policy_probe", payload_type)
        self.assertIn("origin=", payload)

    def test_select_ai_pen_controlled_payload_template_prefers_json_variant(self):
        template = WebSiteFetch._select_ai_pen_controlled_payload_template(
            payload_type="sqli_probe",
            request_mode="json_data",
            content_type="application/json",
        )

        self.assertEqual("boolean_json_string", str(template.get("variant") or ""))
        self.assertEqual("\" OR \"1\"=\"1", str(template.get("payload") or ""))
        self.assertIn("boolean_based", list(template.get("proof_candidates", []) or []))

    def test_select_ai_pen_controlled_payload_template_prefers_xml_body_variant(self):
        template = WebSiteFetch._select_ai_pen_controlled_payload_template(
            payload_type="xxe_probe",
            request_mode="body",
            content_type="application/xml",
        )

        self.assertEqual("entity_file_read_hosts", str(template.get("variant") or ""))
        self.assertIn("etc/hosts", str(template.get("payload") or ""))
        self.assertIn("entity_file_read", list(template.get("proof_candidates", []) or []))

    def test_build_ai_pen_proof_summary_summarizes_json_sqli_variant(self):
        summary = WebSiteFetch._build_ai_pen_proof_summary(
            {
                "payload_type": "sqli_probe",
                "payload_variant": "boolean_json_string",
                "payload_expected_signal": "error_or_boolean_diff",
                "request_template_summary": "mode=json_data | content_type=application/json | params=q,page",
                "sqli_proof_type": "boolean_based",
            }
        )

        self.assertEqual("response_differential", str(summary.get("proof_family") or ""))
        self.assertEqual("boolean_based", str(summary.get("proof_type") or ""))
        self.assertIn("variant=boolean_json_string", str(summary.get("summary") or ""))
        self.assertIn("mode=json_data", str(summary.get("summary") or ""))

    def test_build_ai_pen_proof_summary_summarizes_weak_password_signals(self):
        summary = WebSiteFetch._build_ai_pen_proof_summary(
            {
                "payload_type": "weak_password_probe",
                "payload_variant": "minimal_default_creds",
                "payload_expected_signal": "login_success_or_session_creation",
                "weak_password_login_proof": True,
                "session_auth_hit": True,
                "logout_effective": True,
            }
        )

        self.assertEqual("auth_bypass", str(summary.get("proof_family") or ""))
        self.assertEqual("login_success", str(summary.get("proof_type") or ""))
        self.assertIn("session_auth", list(summary.get("proof_signals", []) or []))
        self.assertIn("logout_effective", list(summary.get("proof_signals", []) or []))

    def test_build_ai_pen_proof_summary_summarizes_unauth_access(self):
        summary = WebSiteFetch._build_ai_pen_proof_summary(
            {
                "payload_type": "replay",
                "unauth_access_hit": True,
                "unauth_access_type": "unauth_profile_data",
                "request_template_summary": "mode=query | params=user_id",
            }
        )

        self.assertEqual("unauth_access", str(summary.get("proof_family") or ""))
        self.assertEqual("unauth_profile_data", str(summary.get("proof_type") or ""))
        self.assertIn("unauth_access", list(summary.get("proof_signals", []) or []))

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

    def test_build_path_traversal_probe_targets_mutates_file_param(self):
        targets = WebSiteFetch._build_path_traversal_probe_targets(
            "https://example.com/download?file=a.txt",
            max_count=3,
        )

        self.assertEqual(3, len(targets))
        self.assertTrue(any("etc%2Fpasswd" in item or "etc/passwd" in item for item in targets))
        self.assertTrue(all("file=" in item for item in targets))

    def test_infer_tool_plan_for_web_policy_uses_policy_probe_steps(self):
        plan = WebSiteFetch._infer_ai_pen_tool_plan(
            candidate={"target": "https://example.com/api/profile"},
            payload_type="web_policy_probe",
            payload="",
            max_steps=3,
        )

        self.assertEqual(3, len(plan))
        self.assertTrue(all(str(item.get("tool") or "") == "web_policy_probe" for item in plan))
        methods = [str(item.get("params", {}).get("method", "") or "").lower() for item in plan]
        self.assertIn("options", methods)
        self.assertIn("get", methods)

    def test_build_web_policy_probe_steps_includes_baseline_and_control(self):
        steps = WebSiteFetch._build_web_policy_probe_steps(
            "https://example.com/api/profile",
            max_count=3,
        )

        self.assertEqual(3, len(steps))
        first_headers = dict(steps[0].get("headers") or {})
        second_headers = dict(steps[1].get("headers") or {})
        self.assertEqual("get", str(steps[0].get("method") or "").lower())
        self.assertNotIn("Origin", first_headers)
        self.assertEqual("https://arl-probe.example", str(second_headers.get("Origin") or ""))

    def test_infer_tool_plan_for_socketio_uses_socketio_probe(self):
        plan = WebSiteFetch._infer_ai_pen_tool_plan(
            candidate={"target": "https://example.com/app"},
            payload_type="socketio_probe",
            payload="",
            max_steps=2,
        )

        self.assertEqual(2, len(plan))
        self.assertTrue(all(str(item.get("tool") or "") == "socketio_probe" for item in plan))
        self.assertTrue(any("/socket.io/" in str(item.get("params", {}).get("url", "") or "") for item in plan))

    def test_build_websocket_probe_targets_prefers_runtime_and_sample_paths(self):
        targets = WebSiteFetch._build_websocket_probe_targets(
            "https://example.com/app",
            candidate_paths=[
                "/ws/chat",
                "wss://example.com/realtime",
            ],
            max_count=3,
        )

        self.assertEqual(3, len(targets))
        self.assertEqual("https://example.com/ws/chat", targets[0])
        self.assertIn("https://example.com/ws/chat", targets)
        self.assertIn("https://example.com/realtime", targets)
        self.assertNotIn("https://example.com/app", targets)

    def test_infer_tool_plan_for_websocket_uses_realtime_candidate_paths(self):
        plan = WebSiteFetch._infer_ai_pen_tool_plan(
            candidate={
                "target": "https://example.com/app",
                "api_surface_summary": {
                    "sample_paths": ["/ws/chat"],
                    "sample_interfaces": [{"path": "/websocket"}],
                },
                "runtime_api_calls": [
                    {"method": "GET", "url": "wss://example.com/realtime?token=1"},
                ],
            },
            payload_type="websocket_probe",
            payload="",
            max_steps=4,
        )

        urls = [str(item.get("params", {}).get("url", "") or "") for item in plan]
        self.assertEqual(4, len(plan))
        self.assertTrue(all(str(item.get("tool") or "") == "websocket_probe" for item in plan))
        self.assertIn("https://example.com/ws/chat", urls)
        self.assertIn("https://example.com/websocket", urls)
        self.assertTrue(any(item.startswith("https://example.com/realtime") for item in urls))

    def test_param_orchestrated_tool_plan_queues_websocket_probe_from_realtime_hints(self):
        plan = WebSiteFetch._build_ai_pen_param_orchestrated_tool_plan(
            candidate={
                "target": "https://example.com/dashboard",
                "risk_type": "websocket",
                "route_hint": "websocket_handshake",
                "api_surface_summary": {
                    "sample_paths": ["/ws/chat"],
                    "parameter_assets": [],
                    "parameter_names": [],
                },
            },
            max_steps=2,
        )

        self.assertTrue(bool(plan))
        self.assertEqual("websocket_probe", str(plan[0].get("tool") or ""))
        self.assertIn("/ws/chat", str(plan[0].get("params", {}).get("url", "") or ""))

    def test_param_orchestrated_tool_plan_uses_parameter_probe_family_priority(self):
        summary = WebSiteFetch._build_api_surface_summary(
            api_doc_summary={
                "path_count": 1,
                "sample_paths": ["/api/user/detail"],
                "parameter_names": ["id", "redirect", "q"],
            },
        )

        plan = WebSiteFetch._build_ai_pen_param_orchestrated_tool_plan(
            candidate={
                "target": "https://example.com/api/user/detail?id=1&redirect=https://a.example&q=test",
                "api_surface_summary": summary,
            },
            max_steps=4,
        )

        tools = [str(item.get("tool") or "") for item in plan]
        self.assertGreaterEqual(len(tools), 3)
        self.assertEqual("idor_probe", tools[0])
        self.assertIn("ssrf_probe", tools[:2])
        self.assertIn("sqli_probe", tools)
        self.assertIn("xss_probe", tools)

    def test_build_ai_pen_payload_probe_targets_prefers_tag_matched_parameter(self):
        targets = WebSiteFetch._build_ai_pen_payload_probe_targets(
            "https://example.com/api/user/detail?id=1&redirect=https://a.example&q=test",
            "http://127.0.0.1/",
            preferred_tags=["url", "host"],
            parameter_names=["id", "redirect", "q"],
            max_count=2,
        )

        self.assertTrue(bool(targets))
        self.assertEqual("redirect", str(targets[0].get("param") or ""))
        self.assertIn("redirect=http%3A%2F%2F127.0.0.1%2F", str(targets[0].get("url") or ""))

    def test_build_ai_pen_sample_interface_payload_targets_supports_post_form_probe(self):
        targets = WebSiteFetch._build_ai_pen_sample_interface_payload_targets(
            "https://example.com/search",
            "<svg/onload=alert(1)>",
            preferred_tags=["input"],
            api_surface_summary={
                "sample_interfaces": [
                    {
                        "method": "POST",
                        "path": "/api/search",
                        "params": ["q", "page"],
                        "source": "api_doc",
                    }
                ]
            },
            max_count=1,
        )

        self.assertTrue(bool(targets))
        self.assertEqual("post", str(targets[0].get("method") or ""))
        self.assertEqual("q", str(targets[0].get("param") or ""))
        self.assertEqual("<svg/onload=alert(1)>", str(targets[0].get("form_data", {}).get("q") or ""))
        self.assertEqual(1, targets[0].get("form_data", {}).get("page"))

    def test_build_ai_pen_sample_interface_payload_targets_supports_json_probe(self):
        targets = WebSiteFetch._build_ai_pen_sample_interface_payload_targets(
            "https://example.com/search",
            "' OR '1'='1",
            preferred_tags=["input"],
            api_surface_summary={
                "sample_interfaces": [
                    {
                        "method": "POST",
                        "path": "/api/search",
                        "params": ["q", "page"],
                        "mode": "json_data",
                        "content_type": "application/json",
                        "source": "api_doc",
                    }
                ]
            },
            max_count=1,
        )

        self.assertTrue(bool(targets))
        self.assertEqual("post", str(targets[0].get("method") or ""))
        self.assertEqual("q", str(targets[0].get("param") or ""))
        self.assertEqual("' OR '1'='1", str(targets[0].get("json_data", {}).get("q") or ""))
        self.assertEqual("application/json", str(targets[0].get("headers", {}).get("Content-Type") or ""))
        self.assertEqual(1, targets[0].get("json_data", {}).get("page"))

    def test_build_ai_pen_sample_interface_payload_targets_supports_xml_body_probe(self):
        payload = '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><root>&xxe;</root>'
        targets = WebSiteFetch._build_ai_pen_sample_interface_payload_targets(
            "https://example.com/xml",
            payload,
            preferred_tags=["xml"],
            api_surface_summary={
                "sample_interfaces": [
                    {
                        "method": "POST",
                        "path": "/api/xml",
                        "params": ["xml"],
                        "mode": "body",
                        "content_type": "application/xml",
                        "source": "api_doc",
                    }
                ]
            },
            max_count=1,
        )

        self.assertTrue(bool(targets))
        self.assertEqual("post", str(targets[0].get("method") or ""))
        self.assertEqual("xml", str(targets[0].get("param") or ""))
        self.assertEqual(payload, str(targets[0].get("body_data") or ""))
        self.assertEqual("application/xml", str(targets[0].get("headers", {}).get("Content-Type") or ""))

    def test_build_ai_pen_sample_interface_payload_targets_builds_query_scaffold(self):
        targets = WebSiteFetch._build_ai_pen_sample_interface_payload_targets(
            "https://example.com/search",
            "' OR '1'='1",
            preferred_tags=["input"],
            api_surface_summary={
                "sample_interfaces": [
                    {
                        "method": "GET",
                        "path": "/api/search",
                        "params": ["q", "page"],
                        "source": "api_doc",
                    }
                ]
            },
            max_count=1,
        )

        self.assertTrue(bool(targets))
        self.assertIn("q=%27+OR+%271%27%3D%271", str(targets[0].get("url") or ""))
        self.assertIn("page=1", str(targets[0].get("url") or ""))

    def test_infer_tool_plan_for_replay_uses_param_orchestrator_path_traversal(self):
        plan = WebSiteFetch._infer_ai_pen_tool_plan(
            candidate={
                "target": "https://example.com/download/report",
                "api_surface_summary": {
                    "parameter_names": ["file", "download"],
                    "parameter_assets": [{"name": "file", "tags": ["file_path"]}],
                },
            },
            payload_type="replay",
            payload="",
            max_steps=2,
        )

        self.assertEqual(2, len(plan))
        self.assertTrue(all(str(item.get("tool") or "") == "path_traversal_probe" for item in plan))
        self.assertTrue(any("file=" in str(item.get("params", {}).get("url", "")) for item in plan))

    def test_build_ai_pen_unauth_probe_targets_collects_runtime_and_default_paths(self):
        targets = WebSiteFetch._build_ai_pen_unauth_probe_targets(
            "https://example.com/",
            candidate={
                "target": "https://example.com/",
                "high_value_family": "admin_debug_surface",
                "high_value_summary": {
                    "matched_urls": ["https://example.com/admin/dashboard"],
                },
                "runtime_api_calls": [
                    {"method": "GET", "url": "https://example.com/api/account/current"},
                ],
                "api_surface_summary": {
                    "auth_path_count": 1,
                    "sample_paths": ["/manage/health"],
                    "sample_interfaces": [
                        {"path": "/userinfo"},
                    ],
                },
            },
            max_count=8,
        )

        urls = [str(item.get("url") or "") for item in targets]
        proof_types = [str(item.get("proof_type") or "") for item in targets]
        self.assertIn("https://example.com/api/account/current", urls)
        self.assertIn("https://example.com/userinfo", urls)
        self.assertTrue(any("/actuator" in item or "/manage" in item for item in urls))
        self.assertIn("unauth_health_endpoint", proof_types)

    def test_summarize_ai_pen_unauth_probe_responses_tracks_blocked_and_login_wall(self):
        summary = WebSiteFetch._summarize_ai_pen_unauth_probe_responses(
            [
                {
                    "tool": "http_fetch",
                    "url": "https://example.com/admin/dashboard",
                    "status_code": 401,
                    "headers": {"Content-Type": "text/html"},
                    "body_text": "unauthorized",
                },
                {
                    "tool": "http_fetch",
                    "url": "https://example.com/login",
                    "status_code": 200,
                    "headers": {"Content-Type": "text/html"},
                    "body_text": "<html><body>login password username</body></html>",
                },
                {
                    "tool": "http_fetch",
                    "url": "https://example.com/actuator/health",
                    "status_code": 200,
                    "headers": {"Content-Type": "application/json"},
                    "body_text": '{"status":"UP"}',
                },
            ],
            target_url="https://example.com/",
        )

        self.assertEqual(3, summary.get("probe_count"))
        self.assertEqual(1, summary.get("blocked_count"))
        self.assertEqual(1, summary.get("login_wall_count"))
        self.assertEqual(1, summary.get("health_like_count"))
        self.assertIn("blocked=1", str(summary.get("text") or ""))

    def test_classify_ai_pen_unauth_negative_type(self):
        self.assertEqual(
            "auth_blocked",
            WebSiteFetch._classify_ai_pen_unauth_negative_type(
                {"probe_count": 2, "blocked_count": 2, "login_wall_count": 0, "success_count": 0}
            ),
        )
        self.assertEqual(
            "login_wall",
            WebSiteFetch._classify_ai_pen_unauth_negative_type(
                {"probe_count": 2, "blocked_count": 0, "login_wall_count": 2, "success_count": 0}
            ),
        )
        self.assertEqual(
            "guarded_mixed",
            WebSiteFetch._classify_ai_pen_unauth_negative_type(
                {"probe_count": 3, "blocked_count": 1, "login_wall_count": 1, "success_count": 1}
            ),
        )
        self.assertEqual(
            "health_only",
            WebSiteFetch._classify_ai_pen_unauth_negative_type(
                {"probe_count": 2, "success_count": 2, "health_like_count": 2}
            ),
        )

    def test_infer_tool_plan_for_replay_prefers_unauth_http_fetch_targets(self):
        plan = WebSiteFetch._infer_ai_pen_tool_plan(
            candidate={
                "target": "https://example.com/",
                "high_value_family": "admin_debug_surface",
                "high_value_summary": {
                    "matched_urls": ["https://example.com/admin/dashboard"],
                },
                "runtime_api_calls": [
                    {"method": "GET", "url": "https://example.com/api/account/current"},
                ],
                "api_surface_summary": {
                    "auth_path_count": 1,
                    "sample_paths": ["/manage/health"],
                    "sample_interfaces": [
                        {"path": "/userinfo"},
                    ],
                },
            },
            payload_type="replay",
            payload="",
            max_steps=4,
        )

        urls = [str(item.get("params", {}).get("url", "") or "") for item in plan]
        self.assertEqual(4, len(plan))
        self.assertTrue(all(str(item.get("tool") or "") == "http_fetch" for item in plan))
        self.assertIn("https://example.com/api/account/current", urls)
        self.assertTrue(any("/actuator" in item or "/manage" in item for item in urls))

    def test_fallback_tool_plan_for_replay_uses_param_orchestrator_idor(self):
        plan = WebSiteFetch._build_ai_pen_fallback_tool_plan(
            target_url="https://example.com/api/user?id=100",
            payload_type="replay",
            payload="",
            max_steps=2,
            candidate={
                "target": "https://example.com/api/user?id=100",
                "api_surface_summary": {
                    "parameter_assets": [{"name": "id", "tags": ["object_id"]}],
                    "parameter_names": ["id"],
                },
            },
            body_text="",
        )

        self.assertTrue(bool(plan))
        self.assertEqual("idor_probe", str(plan[0].get("tool") or ""))
        self.assertIn("id=101", str(plan[0].get("params", {}).get("url", "") or ""))

    def test_fallback_tool_plan_for_replay_prefers_unauth_http_fetch_targets(self):
        plan = WebSiteFetch._build_ai_pen_fallback_tool_plan(
            target_url="https://example.com/",
            payload_type="replay",
            payload="",
            max_steps=3,
            candidate={
                "target": "https://example.com/",
                "high_value_family": "admin_debug_surface",
                "runtime_api_calls": [
                    {"method": "GET", "url": "https://example.com/api/account/current"},
                ],
                "api_surface_summary": {
                    "auth_path_count": 1,
                    "sample_paths": ["/manage/health"],
                },
            },
            body_text="",
        )

        urls = [str(item.get("params", {}).get("url", "") or "") for item in plan]
        self.assertEqual(3, len(plan))
        self.assertTrue(all(str(item.get("tool") or "") == "http_fetch" for item in plan))
        self.assertIn("https://example.com/api/account/current", urls)
        self.assertTrue(any("/actuator" in item or "/manage" in item for item in urls))

    def test_fallback_tool_plan_for_ssrf_targets_redirect_parameter_first(self):
        plan = WebSiteFetch._build_ai_pen_fallback_tool_plan(
            target_url="https://example.com/redirect?id=1&redirect=https://safe.example/path",
            payload_type="ssrf_probe",
            payload="http://127.0.0.1/",
            max_steps=2,
            candidate={
                "target": "https://example.com/redirect?id=1&redirect=https://safe.example/path",
                "api_surface_summary": {
                    "parameter_names": ["id", "redirect"],
                },
            },
            body_text="",
        )

        self.assertTrue(bool(plan))
        self.assertEqual("ssrf_probe", str(plan[0].get("tool") or ""))
        self.assertIn("redirect=http%3A%2F%2F127.0.0.1%2F", str(plan[0].get("params", {}).get("url", "") or ""))
        self.assertIn("param=redirect", str(plan[0].get("summary") or ""))

    def test_fallback_tool_plan_for_empty_sqli_payload_uses_controlled_json_variant(self):
        plan = WebSiteFetch._build_ai_pen_fallback_tool_plan(
            target_url="https://example.com/search",
            payload_type="sqli_probe",
            payload="",
            max_steps=1,
            candidate={
                "target": "https://example.com/search",
                "api_surface_summary": {
                    "sample_interfaces": [
                        {
                            "method": "POST",
                            "path": "/api/search",
                            "params": ["q", "page"],
                            "mode": "json_data",
                            "content_type": "application/json",
                            "source": "api_doc",
                        }
                    ]
                },
            },
            body_text="",
        )

        self.assertTrue(bool(plan))
        self.assertEqual("post", str(plan[0].get("params", {}).get("method") or ""))
        self.assertEqual("application/json", str(plan[0].get("params", {}).get("headers", {}).get("Content-Type") or ""))
        self.assertEqual("\" OR \"1\"=\"1", str(plan[0].get("params", {}).get("json_data", {}).get("q") or ""))
        self.assertIn("variant=boolean_json_string", str(plan[0].get("summary") or ""))

    def test_param_orchestrated_tool_plan_uses_post_sample_interface_when_url_has_no_query(self):
        summary = WebSiteFetch._build_api_surface_summary(
            js_api_targets=[
                {
                    "method": "POST",
                    "url": "https://example.com/api/search",
                    "params": ["q", "page"],
                    "source": "js_api_extract",
                }
            ]
        )

        plan = WebSiteFetch._build_ai_pen_param_orchestrated_tool_plan(
            candidate={
                "target": "https://example.com/search",
                "api_surface_summary": summary,
            },
            max_steps=2,
        )

        self.assertTrue(bool(plan))
        self.assertIn(str(plan[0].get("tool") or ""), {"sqli_probe", "xss_probe"})
        self.assertEqual("post", str(plan[0].get("params", {}).get("method") or ""))
        self.assertEqual("<svg/onload=alert(1)>", str(plan[1].get("params", {}).get("form_data", {}).get("q") or ""))

    def test_param_orchestrated_tool_plan_uses_json_sample_interface_when_available(self):
        summary = WebSiteFetch._build_api_surface_summary(
            api_doc_summary={
                "path_count": 1,
                "sample_paths": ["/api/search"],
                "parameter_names": ["q", "page"],
                "sample_interfaces": [
                    {
                        "method": "POST",
                        "path": "/api/search",
                        "params": ["q", "page"],
                        "mode": "json_data",
                        "content_type": "application/json",
                        "source": "api_doc",
                    }
                ],
            }
        )

        plan = WebSiteFetch._build_ai_pen_param_orchestrated_tool_plan(
            candidate={
                "target": "https://example.com/search",
                "api_surface_summary": summary,
            },
            max_steps=2,
        )

        self.assertTrue(bool(plan))
        self.assertEqual("post", str(plan[0].get("params", {}).get("method") or ""))
        self.assertEqual("application/json", str(plan[0].get("params", {}).get("headers", {}).get("Content-Type") or ""))
        self.assertTrue(bool(plan[0].get("params", {}).get("json_data")))
        self.assertEqual("1", str(plan[0].get("params", {}).get("json_data", {}).get("page")))
        self.assertIn("variant=", str(plan[0].get("summary") or ""))
        self.assertIn("expect=", str(plan[0].get("summary") or ""))

    def test_param_orchestrated_tool_plan_uses_xml_body_sample_interface_when_available(self):
        summary = WebSiteFetch._build_api_surface_summary(
            api_doc_summary={
                "path_count": 1,
                "sample_paths": ["/api/xml"],
                "parameter_names": ["xml"],
                "sample_interfaces": [
                    {
                        "method": "POST",
                        "path": "/api/xml",
                        "params": ["xml"],
                        "mode": "body",
                        "content_type": "application/xml",
                        "source": "api_doc",
                    }
                ],
            }
        )

        plan = WebSiteFetch._build_ai_pen_param_orchestrated_tool_plan(
            candidate={
                "target": "https://example.com/xml",
                "api_surface_summary": summary,
            },
            max_steps=1,
        )

        self.assertTrue(bool(plan))
        self.assertEqual("xxe_probe", str(plan[0].get("tool") or ""))
        self.assertEqual("post", str(plan[0].get("params", {}).get("method") or ""))
        self.assertEqual("application/xml", str(plan[0].get("params", {}).get("headers", {}).get("Content-Type") or ""))
        self.assertIn("<!DOCTYPE root", str(plan[0].get("params", {}).get("body_data") or ""))
        self.assertIn("variant=entity_file_read_hosts", str(plan[0].get("summary") or ""))
        self.assertIn("proof=entity_file_read", str(plan[0].get("summary") or ""))

    def test_build_ai_pen_request_packet_prefers_tool_call_json_payload(self):
        packet = WebSiteFetch._build_ai_pen_request_packet(
            target_url="https://example.com/search",
            payload_type="sqli_probe",
            payload="' OR '1'='1",
            verification_step="mcp_sqli_probe",
            tool_calls=[
                {
                    "tool": "sqli_probe",
                    "params": {
                        "url": "https://example.com/api/search",
                        "method": "post",
                        "headers": {"Content-Type": "application/json"},
                        "json_data": {"q": "' OR '1'='1", "page": 1},
                    },
                }
            ],
        )

        self.assertEqual("POST", str(packet.get("method") or ""))
        self.assertEqual("application/json", str(packet.get("headers", {}).get("Content-Type") or ""))
        self.assertIn('"q": "\' OR \'1\'=\'1"', str(packet.get("body") or ""))

    def test_build_ai_pen_request_template_summary_detects_xml_body_mode(self):
        packet = WebSiteFetch._build_ai_pen_request_packet(
            target_url="https://example.com/xml",
            payload_type="xxe_probe",
            payload='<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><root>&xxe;</root>',
            verification_step="mcp_xxe_probe",
            tool_calls=[
                {
                    "tool": "xxe_probe",
                    "params": {
                        "url": "https://example.com/api/xml",
                        "method": "post",
                        "headers": {"Content-Type": "application/xml"},
                        "body_data": '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><root>&xxe;</root>',
                    },
                }
            ],
        )
        summary = WebSiteFetch._build_ai_pen_request_template_summary(packet)

        self.assertEqual("body", str(summary.get("mode") or ""))
        self.assertEqual("application/xml", str(summary.get("content_type") or ""))
        self.assertTrue(any(str(item or "").strip().lower() == "root" for item in list(summary.get("param_names", []) or [])))

    def test_build_auth_protocol_probe_targets_covers_openid_family(self):
        targets = WebSiteFetch._build_auth_protocol_probe_targets(
            "https://example.com/api/login",
            max_count=6,
        )

        self.assertEqual(6, len(targets))
        self.assertTrue(any(item.endswith("/.well-known/openid-configuration") for item in targets))
        self.assertTrue(any(item.endswith("/oauth/token") for item in targets))

    def test_build_auth_protocol_probe_steps_sets_post_for_token_endpoint(self):
        steps = WebSiteFetch._build_auth_protocol_probe_steps(
            "https://example.com/oauth/token",
            max_count=4,
        )

        token_step = next((item for item in steps if "/oauth/token" in str(item.get("url", "") or "")), {})
        self.assertEqual("post", str(token_step.get("method") or ""))
        self.assertTrue(bool(token_step.get("form_data")))

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

    def test_classify_auth_protocol_outcome_for_metadata_returns_likely_fp(self):
        summary = {
            "mode": "openid_configuration",
            "issuer": "https://example.com",
            "token_endpoint": "/oauth/token",
            "jwks_uri": "/.well-known/jwks.json",
        }
        outcome = WebSiteFetch._classify_ai_pen_auth_protocol_outcome(
            auth_url="https://example.com/.well-known/openid-configuration",
            status_code=200,
            headers={"Content-Type": "application/json"},
            body_text='{"issuer":"https://example.com","token_endpoint":"https://example.com/oauth/token"}',
            summary=summary,
        )

        self.assertEqual("likely_false_positive", outcome.get("decision"))
        self.assertIn("不直接判定漏洞", str(outcome.get("reason", "")))

    def test_classify_auth_protocol_outcome_for_token_fields_returns_verified(self):
        outcome = WebSiteFetch._classify_ai_pen_auth_protocol_outcome(
            auth_url="https://example.com/oauth/token",
            status_code=200,
            headers={"Content-Type": "application/json"},
            body_text='{"access_token":"abc","token_type":"bearer","expires_in":3600}',
            summary={"mode": "token_endpoint"},
        )

        self.assertEqual("verified", outcome.get("decision"))
        self.assertIn("令牌字段", str(outcome.get("reason", "")))

    def test_classify_auth_protocol_outcome_for_invalid_client_returns_likely_fp(self):
        outcome = WebSiteFetch._classify_ai_pen_auth_protocol_outcome(
            auth_url="https://example.com/oauth/token",
            status_code=400,
            headers={"Content-Type": "application/json"},
            body_text='{"error":"invalid_client"}',
            summary={"mode": "token_endpoint"},
        )

        self.assertEqual("likely_false_positive", outcome.get("decision"))
        self.assertIn("生效", str(outcome.get("reason", "")))

    def test_extract_auth_protocol_error_semantics_detects_scope_insufficient(self):
        semantics = WebSiteFetch._extract_auth_protocol_error_semantics(
            body_text='{"error":"insufficient_scope","error_description":"scope too narrow"}',
            headers={"WWW-Authenticate": 'Bearer error="insufficient_scope"'},
        )

        self.assertEqual("scope_insufficient", semantics.get("category"))
        self.assertEqual("insufficient_scope", semantics.get("error"))

    def test_classify_auth_protocol_outcome_for_userinfo_with_probe_token_returns_verified(self):
        outcome = WebSiteFetch._classify_ai_pen_auth_protocol_outcome(
            auth_url="https://example.com/userinfo",
            status_code=200,
            headers={"Content-Type": "application/json"},
            body_text='{"sub":"1001","email":"demo@example.com","name":"demo"}',
            summary={"mode": "token_endpoint"},
        )

        self.assertEqual("verified", outcome.get("decision"))
        self.assertIn("userinfo", str(outcome.get("reason", "")).lower())

    def test_classify_auth_protocol_outcome_for_introspect_active_false_returns_likely_fp(self):
        outcome = WebSiteFetch._classify_ai_pen_auth_protocol_outcome(
            auth_url="https://example.com/oauth/introspect",
            status_code=200,
            headers={"Content-Type": "application/json"},
            body_text='{"active":false}',
            summary={"mode": "token_endpoint"},
        )

        self.assertEqual("likely_false_positive", outcome.get("decision"))
        self.assertIn("active=false", str(outcome.get("reason", "")))

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

    def test_infer_tool_plan_for_weak_password_extends_to_session_and_logout(self):
        plan = WebSiteFetch._infer_ai_pen_tool_plan(
            candidate={
                "target": "https://example.com/login",
                "risk_type": "weak_password",
                "runtime_api_calls": [
                    {"method": "GET", "url": "https://example.com/api/user/profile"},
                ],
                "api_surface_summary": {
                    "auth_paths": ["/api/user/profile", "/api/logout"],
                },
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
                    "runtime_auth_paths": ["/api/user/profile"],
                    "auth_api_paths": ["/api/logout"],
                },
            },
            payload_type="weak_password_probe",
            payload="username=admin&password=admin",
            max_steps=6,
        )

        tools = [str(item.get("tool") or "") for item in plan]
        self.assertEqual(
            ["session_start", "extract_csrf_token", "credential_probe", "detect_login_success", "session_request", "logout_probe"],
            tools,
        )
        self.assertIn("/api/user/profile", str(plan[4].get("params", {}).get("url", "") or ""))
        self.assertEqual("weak_password", plan[5].get("params", {}).get("session_key"))

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
        for tool_name in (
            "session_request",
            "extract_csrf_token",
            "token_replay",
            "config_probe",
            "xss_probe",
            "ssti_probe",
            "xxe_probe",
            "path_traversal_probe",
            "web_policy_probe",
            "socketio_probe",
        ):
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

    def test_sqli_boolean_based_proof_is_detected(self):
        proof_type = WebSiteFetch._detect_sqli_proof_type(
            base_body='{"code":403,"msg":"forbidden"}',
            probe_body='{"code":0,"msg":"ok","data":[1,2,3]}',
            payload="' OR '1'='1",
            base_status=403,
            probe_status=200,
        )
        self.assertEqual("boolean_based", proof_type)

    def test_sqli_time_based_proof_is_detected(self):
        proof_type = WebSiteFetch._detect_sqli_proof_type(
            base_body='{"code":0}',
            probe_body='{"code":0}',
            payload="1' AND SLEEP(5)-- ",
            base_status=200,
            probe_status=200,
            base_elapsed_ms=120,
            probe_elapsed_ms=5300,
        )
        self.assertEqual("time_based", proof_type)

    def test_ssti_expression_eval_proof_is_detected(self):
        proof_type = WebSiteFetch._detect_ssti_proof_type(
            payload="{{7*7}}",
            base_body="normal page",
            probe_body='{"result":"49"}',
        )
        self.assertEqual("expression_eval", proof_type)

    def test_cmdi_id_output_proof_is_detected(self):
        proof_type = WebSiteFetch._detect_cmdi_proof_type(
            base_body="normal page",
            probe_body="uid=1000(www-data) gid=1000(www-data) groups=1000(www-data)",
        )
        self.assertEqual("id_output", proof_type)

    def test_xxe_entity_file_read_proof_is_detected(self):
        proof_type = WebSiteFetch._detect_xxe_proof_type(
            base_body="normal page",
            probe_body="127.0.0.1 localhost\n::1 localhost ip6-localhost",
        )
        self.assertEqual("entity_file_read", proof_type)

    def test_ssrf_metadata_disclosure_proof_is_detected(self):
        proof_type = WebSiteFetch._detect_ssrf_proof_type(
            base_body="normal page",
            probe_body='{"instance-id":"i-123456"}',
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual("metadata_disclosure", proof_type)

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

    def test_verified_proof_guard_blocks_missing_ssti_proof(self):
        reason = WebSiteFetch._get_ai_pen_verified_proof_guard_reason(
            risk_type_text="ssti",
            payload_type_text="ssti_probe",
            xss_popup_proof=False,
            weak_password_login_proof=False,
            sqli_proof_type="",
            ssti_proof_type="",
        )
        self.assertIn("SSTI", reason)


if __name__ == "__main__":
    unittest.main()
