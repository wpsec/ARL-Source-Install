"""
Web 专项渗透测试链路回归测试。
"""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

try:
    from app.services.penetration_scan import PenetrationScanService
except ModuleNotFoundError:
    PenetrationScanService = None


@unittest.skipIf(
    PenetrationScanService is None,
    "运行依赖未安装，跳过专项渗透测试回归",
)
class TestPenetrationScan(unittest.TestCase):
    """
    专项渗透测试服务测试。
    """

    def test_parse_page_form_record(self):
        """
        应能解析页面情报里的表单摘要。
        """
        parsed = PenetrationScanService._parse_form_record(
            "POST https://example.com/login [username,password]"
        )

        self.assertEqual("POST", parsed["method"])
        self.assertEqual("https://example.com/login", parsed["url"])
        self.assertEqual(["username", "password"], parsed["params"])

    def test_collect_seed_targets_only_keeps_structured_in_scope_targets(self):
        """
        仅保留同范围内、具备参数的结构化入口。
        """
        service = PenetrationScanService(
            task_id="task-demo",
            sites=["https://example.com"],
            page_url_set={
                "https://example.com/search?q=test",
                "https://cdn.example.com/static/app.js",
                "https://example.com/profile",
            },
        )

        with patch.object(service, "_load_db_urls", return_value=[
            "https://example.com/user?id=1",
            "https://example.com/logo.png",
        ]), patch.object(service, "_load_wih_records", return_value=[
            {
                "record_type": "page_form",
                "content": "POST https://example.com/login [username,password]",
            },
            {
                "record_type": "api_doc_endpoint",
                "content": "GET https://example.com/api/query?keyword=test",
            },
            {
                "record_type": "urlfinder_url",
                "content": "https://api.other.com/openapi.json?x=1",
            },
        ]), patch("app.services.penetration_scan.utils.check_dns_policy_for_url", return_value=(True, {})):
            targets = service._collect_seed_targets()

        url_set = {item["url"] for item in targets}
        self.assertIn("https://example.com/search?q=test", url_set)
        self.assertIn("https://example.com/user?id=1", url_set)
        self.assertIn("https://example.com/login", url_set)
        self.assertIn("https://example.com/api/query?keyword=test", url_set)
        self.assertNotIn("https://example.com/profile", url_set)
        self.assertNotIn("https://api.other.com/openapi.json?x=1", url_set)

    def test_significant_difference_detects_new_sql_error(self):
        """
        SQL 错误关键字相对基线新增时，应判定为差分命中。
        """
        service = PenetrationScanService(
            task_id="task-demo",
            sites=["https://example.com"],
            page_url_set=[],
        )
        baseline = {
            "status_code": 200,
            "content_length": 100,
            "content_hash": "abc",
            "response_time": 0.2,
            "error_keywords": [],
        }

        matched, reason = service._is_significant_difference(
            body="You have an error in your SQL syntax near mysql",
            status_code=200,
            baseline=baseline,
            vuln_type="sqli",
            elapsed=0.3,
        )

        self.assertTrue(matched)
        self.assertIn("SQL", reason)

    def test_significant_difference_ignores_length_only_for_sqli(self):
        """
        SQLi 不应仅凭长度/结构差异直接报风险，避免动态页面误报。
        """
        service = PenetrationScanService(
            task_id="task-demo",
            sites=["https://example.com"],
            page_url_set=[],
        )
        baseline = {
            "status_code": 200,
            "content_length": 100,
            "content_hash": service._stable_hash(("A" * 100)[:4096]),
            "response_time": 0.2,
            "error_keywords": [],
        }

        matched, reason = service._is_significant_difference(
            body="B" * 260,
            status_code=200,
            baseline=baseline,
            vuln_type="sqli",
            elapsed=0.3,
        )

        self.assertFalse(matched)
        self.assertEqual("", reason)

    def test_xss_finding_requires_unescaped_reflection(self):
        """
        仅当响应直接回显 payload 时，才应记录 XSS。
        """
        service = PenetrationScanService(
            task_id="task-demo",
            sites=["https://example.com"],
            page_url_set=[],
        )
        target = {
            "method": "GET",
            "url": "https://example.com/search",
            "params": ["q"],
            "source": "query_url",
            "original_values": {"q": "normal"},
        }
        findings = []

        with patch.object(service, "_build_baseline", return_value={"body": "", "original_params": {"q": "normal"}}), \
                patch.object(service, "_request", return_value=SimpleNamespace(status_code=200, text="<svg/onload=alert(1337)>ARL_XSS_MARK", headers={})):
            service._test_xss(target, findings)

        self.assertEqual(1, len(findings))
        self.assertEqual("xss", findings[0]["type"])

    def test_dom_xss_static_analysis_detects_unsanitized_source_to_sink(self):
        """
        JS 中存在 source -> sink 且未过滤时，应记录 DOM XSS。
        """
        service = PenetrationScanService(
            task_id="task-demo",
            sites=["https://example.com"],
            page_url_set=[],
        )
        findings = []
        js_resp = SimpleNamespace(
            status_code=200,
            content=b"document.querySelector('#app').innerHTML = location.hash;",
            headers={},
        )

        with patch("app.services.penetration_scan.utils.check_dns_policy_for_url", return_value=(True, {})), \
                patch("app.services.penetration_scan.utils.http_req", return_value=js_resp):
            service._scan_dom_xss_js("https://example.com/static/app.js", findings)

        self.assertEqual(1, len(findings))
        self.assertEqual("dom_xss", findings[0]["type"])

    def test_dom_xss_static_analysis_tracks_tainted_variable(self):
        """
        source 先赋值给变量、再流入 sink 时，也应识别为 DOM XSS。
        """
        service = PenetrationScanService(
            task_id="task-demo",
            sites=["https://example.com"],
            page_url_set=[],
        )
        findings = []
        js_resp = SimpleNamespace(
            status_code=200,
            content=b"const hashValue = location.hash; document.body.innerHTML = hashValue;",
            headers={},
        )

        with patch.object(service, "_request", return_value=js_resp), \
                patch("app.services.penetration_scan.utils.check_dns_policy_for_url", return_value=(True, {})):
            service._scan_dom_xss_js("https://example.com/static/app.js", findings)

        self.assertEqual(1, len(findings))
        self.assertEqual("dom_xss", findings[0]["type"])
        self.assertIn("tainted_var", findings[0]["param"])

    def test_dom_xss_static_analysis_skips_common_third_party_js(self):
        """
        常见第三方压缩库默认跳过 DOM XSS 静态命中，降低误报噪声。
        """
        service = PenetrationScanService(
            task_id="task-demo",
            sites=["https://example.com"],
            page_url_set=[],
        )
        findings = []
        js_resp = SimpleNamespace(
            status_code=200,
            content=b"const hashValue = location.hash; document.body.innerHTML = hashValue;",
            headers={},
        )

        with patch.object(service, "_request", return_value=js_resp), \
                patch("app.services.penetration_scan.utils.check_dns_policy_for_url", return_value=(True, {})):
            service._scan_dom_xss_js("https://example.com/static/swiper-bundle.min.js", findings)

        self.assertEqual(0, len(findings))

    def test_extract_js_api_targets_collects_endpoint_and_param_names(self):
        """
        应能从 fetch / axios / ajax 中提取 API 端点与参数名。
        """
        service = PenetrationScanService(
            task_id="task-demo",
            sites=["https://example.com"],
            page_url_set=[],
        )
        content = """
        fetch('/api/search?scene=web', {
          method: 'POST',
          body: JSON.stringify({ keyword: query, page: currentPage })
        });
        axios.get('/api/user/detail', { params: { id: userId, profile: mode } });
        $.ajax({ url: '/api/profile/update', type: 'POST', data: { nickname: nickName, email: mail } });
        """

        targets = service._extract_js_api_targets("https://example.com/static/app.js", content)
        target_map = {item["url"]: item for item in targets}

        self.assertIn("https://example.com/api/search?scene=web", target_map)
        self.assertIn("keyword", target_map["https://example.com/api/search?scene=web"]["params"])
        self.assertIn("page", target_map["https://example.com/api/search?scene=web"]["params"])
        self.assertIn("scene", target_map["https://example.com/api/search?scene=web"]["params"])
        self.assertIn("https://example.com/api/user/detail", target_map)
        self.assertIn("id", target_map["https://example.com/api/user/detail"]["params"])
        self.assertIn("https://example.com/api/profile/update", target_map)
        self.assertIn("nickname", target_map["https://example.com/api/profile/update"]["params"])

    def test_assess_target_risk_marks_dangerous_payment_form_as_critical(self):
        """
        危险动作表单应被标记为高风险，避免主动插入脏数据。
        """
        service = PenetrationScanService(
            task_id="task-demo",
            sites=["https://example.com"],
            page_url_set=[],
        )

        risk_info = service._build_target_test_policy(
            method="POST",
            url="https://example.com/api/payment/checkout",
            params=["amount", "csrf_token"],
            source="page_form",
        )

        self.assertTrue(risk_info["skip_active"])
        self.assertEqual("critical", risk_info["risk_level"])

    def test_sqli_boolean_based_diff_detects_true_false_split(self):
        """
        当 true 请求接近基线、false 请求明显偏离时，应命中布尔型 SQL 注入。
        """
        service = PenetrationScanService(
            task_id="task-demo",
            sites=["https://example.com"],
            page_url_set=[],
        )
        target = {
            "method": "GET",
            "url": "https://example.com/item",
            "params": ["id"],
            "source": "query_url",
            "original_values": {"id": "1"},
        }
        findings = []
        baseline_body = "normal product page"
        baseline = {
            "status_code": 200,
            "content_length": len(baseline_body),
            "content_hash": service._stable_hash(baseline_body[:4096]),
            "response_time": 0.1,
            "error_keywords": [],
            "original_params": {"id": "1"},
            "body": baseline_body,
        }
        responses = [
            SimpleNamespace(status_code=200, text=baseline_body, headers={}),
            SimpleNamespace(status_code=200, text=baseline_body, headers={}),
            SimpleNamespace(status_code=200, text=baseline_body, headers={}),
            SimpleNamespace(status_code=500, text="database error", headers={}),
        ]

        with patch.object(service, "_build_baseline", return_value=baseline), \
                patch.object(service, "_request", side_effect=responses):
            service._test_sqli(target, findings)

        self.assertEqual(1, len(findings))
        self.assertIn("布尔差分", findings[0]["detail"])

    def test_admin_unauthorized_access_requires_admin_signals_without_login(self):
        """
        后台入口未登录可访问且命中后台特征时，应记录后台未授权访问风险。
        """
        service = PenetrationScanService(
            task_id="task-demo",
            sites=["https://example.com"],
            page_url_set={"https://example.com/admin/dashboard"},
        )
        findings = []
        resp = SimpleNamespace(
            status_code=200,
            text="""
            <html><head><title>管理后台 - 控制台</title></head>
            <body>系统管理 用户管理 角色管理 权限管理</body></html>
            """,
            headers={},
        )

        with patch.object(service, "_load_db_urls", return_value=[]), \
                patch.object(service, "_request", return_value=resp):
            service._test_admin_unauthorized_access(findings, [])

        self.assertEqual(1, len(findings))
        self.assertEqual("admin_unauthorized_access", findings[0]["type"])

    def test_horizontal_privilege_escalation_requires_sensitive_response_diff(self):
        """
        切换对象标识后，若响应显著变化且包含敏感字段，应记录水平越权风险。
        """
        service = PenetrationScanService(
            task_id="task-demo",
            sites=["https://example.com"],
            page_url_set=[],
        )
        target = {
            "method": "GET",
            "url": "https://example.com/api/user/detail",
            "params": ["userId"],
            "source": "js_api_extract",
            "original_values": {"userId": "1"},
            "test_policy": {"skip_active": False, "param_limit": 4},
        }
        findings = []
        baseline_body = '{"id":1,"username":"alice","email":"alice@example.com"}'
        baseline = {
            "ok": True,
            "status_code": 200,
            "content_length": len(baseline_body),
            "content_hash": service._stable_hash(baseline_body[:4096]),
            "response_time": 0.1,
            "error_keywords": [],
            "original_params": {"userId": "1"},
            "body": baseline_body,
        }
        alt_resp = SimpleNamespace(
            status_code=200,
            text='{"id":2,"username":"bob","email":"bob@example.com","mobile":"13800000000"}',
            headers={},
        )

        with patch.object(service, "_build_baseline", return_value=baseline), \
                patch.object(service, "_request", return_value=alt_resp):
            service._test_horizontal_privilege_escalation(target, findings)

        self.assertEqual(1, len(findings))
        self.assertEqual("horizontal_privilege_escalation", findings[0]["type"])

    def test_vertical_privilege_escalation_requires_admin_signal_growth(self):
        """
        权限相关参数变更后，若响应出现更强后台权限特征，应记录垂直越权风险。
        """
        service = PenetrationScanService(
            task_id="task-demo",
            sites=["https://example.com"],
            page_url_set=[],
        )
        target = {
            "method": "GET",
            "url": "https://example.com/api/user/profile",
            "params": ["role"],
            "source": "js_api_extract",
            "original_values": {"role": "guest"},
            "test_policy": {"skip_active": False, "param_limit": 4},
        }
        findings = []
        baseline_body = '{"role":"guest","menu":["profile"]}'
        baseline = {
            "ok": True,
            "status_code": 200,
            "content_length": len(baseline_body),
            "content_hash": service._stable_hash(baseline_body[:4096]),
            "response_time": 0.1,
            "error_keywords": [],
            "original_params": {"role": "guest"},
            "body": baseline_body,
        }
        alt_resp = SimpleNamespace(
            status_code=200,
            text='{"role":"admin","menus":["dashboard","system management","permission management"]}',
            headers={},
        )

        with patch.object(service, "_build_baseline", return_value=baseline), \
                patch.object(service, "_request", return_value=alt_resp):
            service._test_vertical_privilege_escalation(target, findings)

        self.assertEqual(1, len(findings))
        self.assertEqual("vertical_privilege_escalation", findings[0]["type"])


if __name__ == "__main__":
    unittest.main()
