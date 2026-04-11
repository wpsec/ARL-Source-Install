import unittest
from unittest.mock import patch


IMPORT_ERROR = None
try:
    from app.routes import api_console as api_console_module
except Exception as exc:
    api_console_module = None
    IMPORT_ERROR = exc


@unittest.skipIf(IMPORT_ERROR is not None, "requires api_console dependencies: {}".format(IMPORT_ERROR))
class TestAiDenoiseWihEndpoint(unittest.TestCase):
    def test_rule_analyze_marks_high_value_endpoint(self):
        item = {
            "task_id": "task-1",
            "target": "https://portal.example.com",
            "page_url": "https://portal.example.com/admin/user/list",
            "url": "https://portal.example.com/api/admin/user/resetPassword",
            "method": "POST",
            "status_code": 200,
            "response_size": 512,
            "body_kind": "json",
            "request_template": {
                "body": {
                    "userId": "<value>",
                    "newPassword": "<value>",
                    "roleId": "<value>",
                },
                "headers": {
                    "Content-Type": "application/json",
                    "Authorization": "Bearer demo-token",
                },
            },
        }

        with patch.object(
            api_console_module,
            "_build_wih_endpoint_site_summary",
            return_value={"site": "https://portal.example.com", "title": "统一管理后台", "finger": ["Spring Boot"]},
        ):
            result = api_console_module._rule_analyze_wih_endpoint_item(item)

        self.assertEqual("danger", result["result_level"])
        self.assertEqual("高", result["risk_level"])
        self.assertEqual("高价值", result["trust"])
        self.assertEqual("高价值", result["display_text"])
        self.assertTrue(any("后台" in text or "参数名" in text for text in result["evidence"]))

    def test_build_context_includes_site_and_parameter_summary(self):
        item = {
            "task_id": "task-2",
            "target": "https://api.example.com",
            "page_url": "https://api.example.com/order",
            "url": "https://api.example.com/api/order/export",
            "method": "POST",
            "status_code": 403,
            "response_size": 0,
            "content_type": "application/json",
            "body_kind": "json",
            "source_types": ["xhr", "runtime"],
            "request_template": {
                "query": {"tenantId": "<value>"},
                "body": {"orderId": "<value>", "amount": "<value>"},
                "path": {"id": "<value>"},
                "headers": {
                    "Content-Type": "application/json",
                    "Authorization": "Bearer secret-token",
                    "X-Trace-Id": "trace-demo",
                },
            },
        }

        with patch.object(
            api_console_module,
            "_build_wih_endpoint_site_summary",
            return_value={"site": "https://api.example.com", "title": "订单中心", "finger": ["Vue", "Spring Boot"]},
        ):
            context = api_console_module._build_ai_denoise_context("wih_endpoint", item)

        self.assertEqual("POST", context["method"])
        self.assertEqual("订单中心", context["site_title"])
        self.assertIn("tenantId", context["param_names"])
        self.assertIn("orderId", context["param_names"])
        self.assertIn("id", context["path_params"])
        self.assertIn("X-Trace-Id", context["request_header_names"])
        self.assertNotIn("Authorization", context["request_header_names"])

    def test_normalize_output_keeps_value_labels(self):
        rule_result = {
            "result_level": "suspicious",
            "risk_level": "中",
            "trust": "中价值",
            "summary": "规则初判为中价值接口。",
            "evidence": ["规则证据"],
            "suggestions": ["规则建议"],
            "display_text": "中价值",
        }
        ai_output = {
            "result_level": "danger",
            "risk_level": "高",
            "trust": "高价值",
            "summary": "AI 判断该接口可直接进入高优先级验证。",
            "evidence": ["AI证据1", "AI证据2"],
            "suggestions": ["AI建议1"],
        }

        normalized = api_console_module._normalize_ai_denoise_output("wih_endpoint", ai_output, rule_result)

        self.assertEqual("danger", normalized["result_level"])
        self.assertEqual("高", normalized["risk_level"])
        self.assertEqual("高价值", normalized["trust"])
        self.assertEqual("高价值", normalized["display_text"])
        self.assertEqual("AI 判断该接口可直接进入高优先级验证。", normalized["summary"])

    def test_normalize_modules_enables_wih_endpoint_by_default(self):
        normalized = api_console_module._normalize_ai_denoise_modules({})
        self.assertIn("wih_endpoint", normalized)
        self.assertTrue(normalized["wih_endpoint"])

    def test_rule_analyze_uses_ai_fill_summary_and_params(self):
        item = {
            "task_id": "task-3",
            "target": "https://api.example.com",
            "page_url": "https://api.example.com/report/list",
            "url": "https://api.example.com/api/report/export",
            "method": "POST",
            "body_kind": "form_urlencoded",
            "ai_fill_status": "tested",
            "ai_fill_source": "ai",
            "ai_fill_note": "已补齐导出参数并验证成功",
            "ai_fill_params": [
                {"name": "tenantId", "location": "body", "type": "id", "value": "1"},
                {"name": "exportType", "location": "body", "type": "enum", "value": "full"},
            ],
            "ai_fill_response_summary": "JSON键: token, user, tenantId, exportUrl",
            "request_template": {
                "body": {
                    "tenantId": "<value>",
                    "exportType": "<value>",
                }
            },
        }

        with patch.object(
            api_console_module,
            "_build_wih_endpoint_site_summary",
            return_value={"site": "https://api.example.com", "title": "报表管理后台", "finger": ["Spring Boot"]},
        ):
            result = api_console_module._rule_analyze_wih_endpoint_item(item)

        self.assertEqual("danger", result["result_level"])
        self.assertEqual("高价值", result["display_text"])
        self.assertTrue(any("AI填充测试响应摘要" in text for text in result["evidence"]))
        self.assertTrue(any("AI填充补齐参数" in text for text in result["evidence"]))


if __name__ == "__main__":
    unittest.main()
