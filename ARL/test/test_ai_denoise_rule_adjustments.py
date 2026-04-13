import unittest


IMPORT_ERROR = None
try:
    from app.routes import api_console as api_console_module
except Exception as exc:
    api_console_module = None
    IMPORT_ERROR = exc


@unittest.skipIf(IMPORT_ERROR is not None, "requires api_console dependencies: {}".format(IMPORT_ERROR))
class TestAiDenoiseRuleAdjustments(unittest.TestCase):
    def test_site_login_shell_should_not_be_marked_danger(self):
        item = {
            "site": "https://admin.example.com",
            "title": "统一管理后台登录",
            "status_code": 200,
            "headers": "Server: nginx\nContent-Type: text/html",
            "finger": [{"name": "Nginx"}],
            "body_length": 2048,
        }

        result = api_console_module._rule_analyze_site_item(item)

        self.assertEqual("suspicious", result["result_level"])
        self.assertEqual("中", result["risk_level"])
        self.assertTrue(any("登录" in text or "认证" in text for text in result["evidence"]))

    def test_fileleak_404_backup_should_be_safe(self):
        item = {
            "url": "https://files.example.com/backup/app-backup.zip",
            "title": "404 Not Found",
            "status_code": 404,
            "content_length": 0,
        }

        result = api_console_module._rule_analyze_fileleak_item(item)

        self.assertEqual("safe", result["result_level"])
        self.assertEqual("低", result["risk_level"])
        self.assertTrue(any("404" in text or "错误页" in text for text in result["evidence"]))

    def test_url_login_shell_should_not_be_marked_danger(self):
        item = {
            "url": "https://portal.example.com/admin/login",
            "title": "统一身份认证登录",
            "status_code": 200,
            "source": "spider",
        }

        result = api_console_module._rule_analyze_url_item(item)

        self.assertEqual("suspicious", result["result_level"])
        self.assertEqual("中", result["risk_level"])
        self.assertTrue(any("登录壳" in text or "认证入口" in text for text in result["evidence"]))

    def test_url_open_swagger_should_remain_danger(self):
        item = {
            "url": "https://portal.example.com/swagger-ui/index.html",
            "title": "Swagger UI",
            "status_code": 200,
            "source": "urlfinder_url_probe",
        }

        result = api_console_module._rule_analyze_url_item(item)

        self.assertEqual("danger", result["result_level"])
        self.assertEqual("高", result["risk_level"])

    def test_vuln_without_verify_should_be_marked_false_positive(self):
        item = {
            "vul_name": "某高危模板命中",
            "target": "https://app.example.com",
            "severity": "high",
            "plg_type": "命令执行",
            "verify_data": "",
        }

        result = api_console_module._rule_analyze_vuln_item(item, module_id="vuln")

        self.assertEqual("疑似误报", result["trust"])
        self.assertEqual("suspicious", result["result_level"])
        self.assertTrue(any("缺少明确验证信息" in text for text in result["evidence"]))

    def test_vuln_permission_denied_verify_should_be_downgraded(self):
        item = {
            "vul_name": "某高危接口未授权",
            "target": "https://api.example.com/admin/export",
            "severity": "high",
            "plg_type": "未授权访问",
            "verify_data": "HTTP/1.1 200\n{\"code\":403,\"message\":\"请先登录，权限不足\"}",
        }

        result = api_console_module._rule_analyze_vuln_item(item, module_id="nuclei_result")

        self.assertEqual("疑似误报", result["trust"])
        self.assertEqual("suspicious", result["result_level"])
        self.assertTrue(any("auth_blocked" in text for text in result["evidence"]))

    def test_vuln_sensitive_leak_should_keep_trust(self):
        item = {
            "vul_name": "AK/SK 泄漏",
            "target": "https://static.example.com/app.js",
            "severity": "medium",
            "plg_type": "敏感信息泄露",
            "verify_data": "AKIAIOSFODNN7EXAMPLE\nsecretAccessKey=demo-secret",
        }

        result = api_console_module._rule_analyze_vuln_item(item, module_id="vuln")
        context = api_console_module._build_ai_denoise_context("vuln", item)

        self.assertEqual("可信", result["trust"])
        self.assertTrue(any("强信号" in text for text in result["evidence"]))
        self.assertIn("sensitive_leak", context["verify_signals"])

    def test_url_context_should_include_surface_and_query_params(self):
        item = {
            "url": "https://portal.example.com/openapi?token=eyJhbGciOiJIUzI1NiJ9.demo.demo",
            "title": "OpenAPI Docs",
            "status_code": 200,
            "source": "wih_url_probe",
        }

        context = api_console_module._build_ai_denoise_context("url", item)

        self.assertIn("api_doc", context["surface_signals"])
        self.assertIn("token", context["query_params"])


if __name__ == "__main__":
    unittest.main()
