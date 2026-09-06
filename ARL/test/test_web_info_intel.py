import json
import unittest
from unittest.mock import patch

IMPORT_ERROR = None
try:
    from app.modules import WihRecord
    from app.services.api_doc_scan import run_api_doc_scan
    from app.services.js_intel_scan import run_js_intel_scan
    from app.services.page_intel_scan import run_page_intel_scan
    from app.services.urlfinder_extract import run_urlfinder_extract
    from app.services.web_info_intel_utils import normalize_in_scope_url
except Exception as exc:
    WihRecord = None
    run_api_doc_scan = None
    run_js_intel_scan = None
    run_page_intel_scan = None
    run_urlfinder_extract = None
    normalize_in_scope_url = None
    IMPORT_ERROR = exc


class _FakeResponse:
    def __init__(self, body: str, status_code: int = 200, content_type: str = "text/html"):
        self.status_code = status_code
        self.content = body.encode("utf-8")
        self.headers = {"Content-Type": content_type}


@unittest.skipIf(IMPORT_ERROR is not None, "requires web intel test dependencies: {}".format(IMPORT_ERROR))
class TestWebInfoIntel(unittest.TestCase):
    def test_normalize_in_scope_url_skips_malformed_netloc_and_ipv6(self):
        allowed_hosts = {"example.com"}

        malformed_netloc = normalize_in_scope_url(
            "https://example.com/static/app.js",
            "https://:前缀吗？/x.js",
            allowed_hosts,
            allow_js=True,
        )
        malformed_ipv6 = normalize_in_scope_url(
            "https://example.com/static/app.js",
            "http://[::1/x.js",
            allowed_hosts,
            allow_js=True,
        )
        normal_url = normalize_in_scope_url(
            "https://example.com/static/app.js",
            "/api/user/list",
            allowed_hosts,
            allow_js=False,
        )

        self.assertEqual("", malformed_netloc)
        self.assertEqual("", malformed_ipv6)
        self.assertEqual("https://example.com/api/user/list", normal_url)

    @patch("app.services.page_intel_scan.utils.check_dns_policy_for_url")
    @patch("app.services.page_intel_scan.utils.http_req")
    def test_page_intel_extracts_links_forms_scripts_and_domains(self, mock_http_req, mock_dns_policy):
        mock_dns_policy.return_value = (True, {"reason": "pass", "resolver_ips": ["1.1.1.1"], "system_ips": ["1.1.1.1"]})

        def _http_req(url, *args, **kwargs):
            if url == "https://example.com":
                return _FakeResponse(
                    """
                    <html>
                      <body>
                        <a href="/admin">admin</a>
                        <form action="/login" method="post">
                          <input name="username" />
                          <input name="password" />
                        </form>
                        <script src="/static/app.js"></script>
                        <a href="https://api.example.com/console">api</a>
                      </body>
                    </html>
                    """,
                    content_type="text/html",
                )
            if url == "https://example.com/admin":
                return _FakeResponse("<html><body>ok</body></html>", content_type="text/html")
            raise AssertionError("unexpected url {}".format(url))

        mock_http_req.side_effect = _http_req

        results = run_page_intel_scan(["https://example.com"], [])
        result_map = {(item.recordType, item.content) for item in results}

        self.assertIn(("page_link", "https://example.com/admin"), result_map)
        self.assertIn(("urlfinder_url", "https://example.com/admin"), result_map)
        self.assertIn(("urlfinder_js", "https://example.com/static/app.js"), result_map)
        self.assertIn(("domain", "api.example.com"), result_map)
        self.assertTrue(any(item.recordType == "page_form" and "https://example.com/login" in item.content for item in results))
        self.assertEqual("rust", results.metrics["backend"])
        self.assertEqual(2, results.metrics["network_request_count"])
        self.assertGreaterEqual(results.metrics["network_wait_sec"], 0)

    @patch("app.services.js_intel_scan.utils.check_dns_policy_for_url")
    @patch("app.services.js_intel_scan.utils.http_req")
    def test_js_intel_extracts_endpoints_and_api_doc_seeds(self, mock_http_req, mock_dns_policy):
        mock_dns_policy.return_value = (True, {"reason": "pass", "resolver_ips": ["1.1.1.1"], "system_ips": ["1.1.1.1"]})
        mock_http_req.return_value = _FakeResponse(
            """
            const config = {
              contactEmail: "sec@example.com"
            };
            fetch("/api/v1/users");
            axios.get("api/profile/list");
            const docs = "/v3/api-docs";
            const other = "https://api.example.com/v1/orders";
            """,
            content_type="application/javascript",
        )

        records = [
            WihRecord(
                "urlfinder_js",
                "https://example.com/static/app.js",
                "https://example.com",
                "https://example.com",
                1,
            )
        ]
        results = run_js_intel_scan(["https://example.com"], records)
        result_map = {(item.recordType, item.content) for item in results}

        self.assertIn(("urlfinder_url", "https://example.com/api/v1/users"), result_map)
        self.assertIn(("urlfinder_url", "https://example.com/static/api/profile/list"), result_map)
        self.assertIn(("api_doc_url", "https://example.com/v3/api-docs"), result_map)
        self.assertEqual("rust", results.metrics["backend"])
        self.assertEqual(1, results.metrics["network_request_count"])
        self.assertGreaterEqual(results.metrics["network_wait_sec"], 0)

    @patch("app.services.js_intel_scan.utils.check_dns_policy_for_url")
    @patch("app.services.js_intel_scan.utils.http_req")
    def test_js_intel_graphql_wsdl_urls_emit_api_doc_records(self):
        """第 10 批口径：JS 发现 GraphQL/WSDL 文档入口发射 api_doc_url 记录。

        行为与 native/Python 两侧一致（三面关键词钉 + golden 门禁），故不断言
        backend；legacy 请求面不因此扩大（`_DOC_KEYWORDS` 不扫 graphql 形态）。
        """
        mock_dns_policy.return_value = (True, {"reason": "pass", "resolver_ips": ["1.1.1.1"], "system_ips": ["1.1.1.1"]})
        mock_http_req.return_value = _FakeResponse(
            """
            const gql = "/graphql";
            const ide = "/graphiql";
            const ws = "/service?singleWsdl";
            fetch("/api/v1/orders");
            """,
            content_type="application/javascript",
        )
        records = [
            WihRecord(
                "urlfinder_js",
                "https://example.com/static/app.js",
                "https://example.com",
                "https://example.com",
                1,
            )
        ]
        results = run_js_intel_scan(["https://example.com"], records)
        result_map = {(item.recordType, item.content) for item in results}

        for url in (
            "https://example.com/graphql",
            "https://example.com/graphiql",
            "https://example.com/service?singleWsdl",
        ):
            self.assertIn(("api_doc_url", url), result_map)
            self.assertIn(("urlfinder_url", url), result_map)
        self.assertIn(("urlfinder_url", "https://example.com/api/v1/orders"), result_map)
        self.assertNotIn(("api_doc_url", "https://example.com/api/v1/orders"), result_map)

    @patch("app.services.api_doc_scan.utils.check_dns_policy_for_url")
    @patch("app.services.api_doc_scan.utils.http_req")
    def test_api_doc_scan_parses_openapi(self, mock_http_req, mock_dns_policy):
        mock_dns_policy.return_value = (True, {"reason": "pass", "resolver_ips": ["1.1.1.1"], "system_ips": ["1.1.1.1"]})

        def _http_req(url, *args, **kwargs):
            if url == "https://example.com/v3/api-docs":
                payload = {
                    "openapi": "3.0.0",
                    "servers": [{"url": "https://example.com"}],
                    "paths": {
                        "/api/users": {"get": {}, "post": {}},
                        "/api/orders/{id}": {"get": {}},
                    },
                }
                return _FakeResponse(json.dumps(payload), content_type="application/json")
            return _FakeResponse("", status_code=404, content_type="text/plain")

        mock_http_req.side_effect = _http_req

        results = run_api_doc_scan(["https://example.com"], [])
        result_map = {(item.recordType, item.content) for item in results}

        self.assertIn(("api_doc_url", "https://example.com/v3/api-docs"), result_map)
        self.assertIn(("api_doc_endpoint", "GET https://example.com/api/users"), result_map)
        self.assertIn(("api_doc_endpoint", "POST https://example.com/api/users"), result_map)
        self.assertIn(("urlfinder_url", "https://example.com/api/users"), result_map)

    @patch("app.services.api_doc_scan.utils.check_dns_policy_for_url")
    @patch("app.services.api_doc_scan.utils.http_req")
    def test_api_doc_scan_parses_postman(self, mock_http_req, mock_dns_policy):
        mock_dns_policy.return_value = (True, {"reason": "pass", "resolver_ips": ["1.1.1.1"], "system_ips": ["1.1.1.1"]})

        def _http_req(url, *args, **kwargs):
            if url == "https://example.com/postman.json":
                payload = {
                    "info": {"name": "demo"},
                    "item": [
                        {
                            "name": "users",
                            "request": {
                                "method": "GET",
                                "url": {
                                    "raw": "https://example.com/api/users"
                                },
                            },
                        }
                    ],
                }
                return _FakeResponse(json.dumps(payload), content_type="application/json")
            return _FakeResponse("", status_code=404, content_type="text/plain")

        mock_http_req.side_effect = _http_req

        seed_records = [
            WihRecord("api_doc_url", "https://example.com/postman.json", "https://example.com", "https://example.com", 1)
        ]
        results = run_api_doc_scan(["https://example.com"], seed_records)
        result_map = {(item.recordType, item.content) for item in results}

        self.assertIn(("api_doc_url", "https://example.com/postman.json"), result_map)
        self.assertIn(("api_doc_endpoint", "GET https://example.com/api/users"), result_map)
        self.assertIn(("urlfinder_url", "https://example.com/api/users"), result_map)

    @patch("app.services.urlfinder_extract.utils.check_dns_policy_for_url")
    @patch("app.services.urlfinder_extract.utils.http_req")
    def test_urlfinder_extract_skips_malformed_urls_without_crashing(self, mock_http_req, mock_dns_policy):
        mock_dns_policy.return_value = (True, {"reason": "pass", "resolver_ips": ["1.1.1.1"], "system_ips": ["1.1.1.1"]})

        def _http_req(url, *args, **kwargs):
            if url == "https://example.test":
                return _FakeResponse(
                    """
                    <html>
                      <body>
                        <script src="/static/app.js"></script>
                      </body>
                    </html>
                    """,
                    content_type="text/html",
                )
            if url == "https://example.test/static/app.js":
                return _FakeResponse(
                    """
                    const good = "/api/users";
                    const bad1 = "https://:前缀吗？/foo";
                    const bad2 = "http://[::1/foo";
                    """,
                    content_type="application/javascript",
                )
            raise AssertionError("unexpected url {}".format(url))

        mock_http_req.side_effect = _http_req

        results = run_urlfinder_extract(["https://example.test"], [])
        result_map = {(item.recordType, item.content) for item in results}

        self.assertIn(("urlfinder_js", "https://example.test/static/app.js"), result_map)
        self.assertIn(("urlfinder_url", "https://example.test/api/users"), result_map)
        self.assertFalse(any("前缀吗" in item.content for item in results))
        self.assertEqual("rust", results.metrics["backend"])
        self.assertEqual(2, results.metrics["network_request_count"])
        self.assertGreaterEqual(results.metrics["network_wait_sec"], 0)


if __name__ == "__main__":
    unittest.main()
