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


if __name__ == "__main__":
    unittest.main()
