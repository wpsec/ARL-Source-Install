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


if __name__ == "__main__":
    unittest.main()
