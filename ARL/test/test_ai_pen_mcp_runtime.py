import importlib.util
import pathlib
import sys
import unittest


def _load_runtime_module():
    module_name = "ai_pen_mcp_runtime_test_module"
    if module_name in sys.modules:
        return sys.modules[module_name]

    runtime_path = pathlib.Path(__file__).resolve().parents[1] / "app" / "services" / "ai_pen_mcp_runtime.py"
    spec = importlib.util.spec_from_file_location(module_name, runtime_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


runtime_module = _load_runtime_module()
AiPenMcpRuntime = runtime_module.AiPenMcpRuntime
ToolSchema = runtime_module.ToolSchema


class TestAiPenMcpRuntime(unittest.TestCase):
    def test_runtime_run_plan_records_tool_audit(self):
        runtime = AiPenMcpRuntime(max_turns=3, max_tool_calls=3, timeout_sec=12)

        def _http_fetch(_ctx, params):
            return {"status": "ok", "message": "fetched", "url": params.get("url")}

        def _payload_probe(_ctx, params):
            return {"status": "ok", "message": "probed", "payload": params.get("payload")}

        runtime.register_tool(
            ToolSchema(
                name="http_fetch",
                description="获取目标响应",
                input_schema={"type": "object"},
                execute=_http_fetch,
            )
        )
        runtime.register_tool(
            ToolSchema(
                name="payload_probe",
                description="注入探针",
                input_schema={"type": "object"},
                execute=_payload_probe,
            )
        )

        result = runtime.run_plan(
            [
                {"tool": "http_fetch", "params": {"url": "https://example.com"}, "summary": "获取基线响应"},
                {"tool": "payload_probe", "params": {"payload": "<svg/onload=alert(1)>"}, "summary": "执行 xss 探针"},
            ],
            context={"task_id": "demo-task"},
        )

        self.assertEqual("final_decision", result.get("stop_reason"))
        self.assertEqual(2, len(result.get("tool_calls", [])))
        self.assertEqual(2, len(result.get("tool_results", [])))
        self.assertEqual(2, len(result.get("agent_trace", [])))
        self.assertEqual("http_fetch", result["tool_calls"][0]["tool"])
        self.assertEqual("payload_probe", result["tool_calls"][1]["tool"])

    def test_build_artifacts_from_tool_trace_parses_trace(self):
        artifacts = AiPenMcpRuntime.build_artifacts_from_tool_trace(
            tool_trace_parts=[
                "http_fetch(get,url=https://example.com)",
                "payload_probe(get,url=https://example.com?a=%3Csvg/onload=alert(1)%3E)",
            ],
            max_tool_calls=3,
            timeout_sec=12,
            status="ok",
            decision="needs_manual_review",
        )

        self.assertEqual("manual_required", artifacts.get("stop_reason"))
        self.assertEqual(2, len(artifacts.get("tool_calls", [])))
        self.assertEqual(2, len(artifacts.get("tool_results", [])))
        self.assertEqual(2, len(artifacts.get("agent_trace", [])))
        self.assertEqual("http_fetch", artifacts["tool_calls"][0]["tool"])

    def test_runtime_run_agent_loop_records_turns_and_final_output(self):
        runtime = AiPenMcpRuntime(max_turns=3, max_tool_calls=3, timeout_sec=12)

        def _http_fetch(_ctx, params):
            return {
                "status": "ok",
                "message": "fetched",
                "response": {
                    "url": params.get("url"),
                    "status_code": 200,
                    "body_text": "{\"openapi\":\"3.0.0\"}",
                },
            }

        runtime.register_tool(
            ToolSchema(
                name="http_fetch",
                description="获取目标响应",
                input_schema={"type": "object"},
                execute=_http_fetch,
            )
        )

        def _decide_next(state):
            if not list(state.get("tool_results", []) or []):
                return {
                    "action": "tool_call",
                    "reason": "先获取基线响应",
                    "tool_call": {
                        "tool": "http_fetch",
                        "params": {"url": "https://example.com/api-docs"},
                        "summary": "获取 API 文档基线",
                    },
                }
            return {
                "action": "final_decision",
                "reason": "已经拿到明确的 API 文档结构，停止继续探测",
                "final_decision": {
                    "decision": "verified",
                    "confidence": 0.88,
                    "reason": "命中 API 文档结构",
                    "payload_type": "api_doc_probe",
                    "payload": "",
                    "evidence": ["openapi=3.0.0"],
                    "next_actions": ["复核 paths 与鉴权要求"],
                },
            }

        result = runtime.run_agent_loop(_decide_next, context={"task_id": "demo-task"})

        self.assertEqual("final_decision", result.get("stop_reason"))
        self.assertEqual(2, result.get("budget_used", {}).get("turns"))
        self.assertEqual(1, len(result.get("tool_calls", [])))
        self.assertEqual("verified", result.get("final_output", {}).get("decision"))
        self.assertTrue(any(item.get("action") == "agent_turn" for item in result.get("agent_trace", [])))

    def test_runtime_run_agent_loop_supports_three_turn_closed_loop(self):
        runtime = AiPenMcpRuntime(max_turns=4, max_tool_calls=4, timeout_sec=12)

        def _http_fetch(_ctx, params):
            return {
                "status": "ok",
                "message": "fetched",
                "response": {
                    "url": params.get("url"),
                    "status_code": 200,
                    "body_text": params.get("url"),
                },
            }

        runtime.register_tool(
            ToolSchema(
                name="http_fetch",
                description="获取目标响应",
                input_schema={"type": "object"},
                execute=_http_fetch,
            )
        )

        def _decide_next(state):
            tool_calls = list(state.get("tool_calls", []) or [])
            if len(tool_calls) == 0:
                return {
                    "action": "tool_call",
                    "tool_call": {
                        "tool": "http_fetch",
                        "params": {"url": "https://example.com/"},
                        "summary": "第一轮基线抓取",
                    },
                }
            if len(tool_calls) == 1:
                return {
                    "action": "tool_call",
                    "tool_call": {
                        "tool": "http_fetch",
                        "params": {"url": "https://example.com/v3/api-docs"},
                        "summary": "第二轮补 API 文档观察",
                    },
                }
            return {
                "action": "final_decision",
                "final_decision": {
                    "decision": "needs_manual_review",
                    "confidence": 0.8,
                    "reason": "已完成 2 轮工具验证，进入人工复核",
                    "payload_type": "api_doc_probe",
                    "payload": "",
                    "evidence": ["baseline", "api-docs"],
                    "next_actions": ["复核 paths 与鉴权要求"],
                },
            }

        result = runtime.run_agent_loop(_decide_next, context={"task_id": "demo-task"})

        self.assertEqual("final_decision", result.get("stop_reason"))
        self.assertEqual(3, result.get("budget_used", {}).get("turns"))
        self.assertEqual(2, len(result.get("tool_calls", [])))
        self.assertEqual("needs_manual_review", result.get("final_output", {}).get("decision"))

    def test_runtime_invoke_skips_duplicate_semantic_tool_call(self):
        runtime = AiPenMcpRuntime(max_turns=4, max_tool_calls=4, timeout_sec=12)
        seen = {"count": 0}

        def _http_fetch(_ctx, params):
            seen["count"] += 1
            return {"status": "ok", "message": "fetched", "url": params.get("url")}

        runtime.register_tool(
            ToolSchema(
                name="http_fetch",
                description="获取目标响应",
                input_schema={"type": "object"},
                execute=_http_fetch,
            )
        )

        first = runtime.invoke(
            tool_name="http_fetch",
            params={"url": "https://example.com", "method": "get"},
            summary="获取基线响应",
        )
        second = runtime.invoke(
            tool_name="http_fetch",
            params={"url": "https://example.com", "method": "get"},
            summary="相同请求但不同文案",
        )

        self.assertEqual("ok", first.get("status"))
        self.assertEqual("skipped", second.get("status"))
        self.assertEqual(1, seen["count"])
        self.assertEqual(1, len(runtime.tool_calls))
        self.assertEqual(2, len(runtime.tool_results))


if __name__ == "__main__":
    unittest.main()
