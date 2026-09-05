import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ARL_ROOT = Path(__file__).resolve().parents[1]
if str(ARL_ROOT) not in sys.path:
    sys.path.insert(0, str(ARL_ROOT))

from test._api_unified_bootstrap import (  # noqa: E402
    UNIFIED_SERVICE_MODULES,
    load_modules,
)

# P2-13 口径：bootstrap 临时桩加载真实子模块，绕开 app.services.__init__ 的
# 重依赖（npoc → xing），本文件因此可在标准入口与独立进程双向运行。
# 必须连同统一解析器依赖闭包一起预载：GraphQL operation 拆解路径
# （api_unified_parser._parse_request_document）函数体内懒导入
# web_info_intel_utils，槽位还原后无缓存条目会回到真实包 __init__。
try:
    _BUNDLE = load_modules(*UNIFIED_SERVICE_MODULES,
                           "app.services.browser_intel_scan")
    _BROWSER_MOD = _BUNDLE["app.services.browser_intel_scan"]
    run_browser_intel_scan = _BROWSER_MOD.run_browser_intel_scan
except Exception:
    _BROWSER_MOD = None
    run_browser_intel_scan = None


def _browser_patch(target, attribute, **kwargs):
    """对象形态 patch：打真实 bootstrap 模块对象，避免字符串形式触发
    app.services 包 __init__ 重依赖（本文件带 bootstrap 时收集期即报 xing）。"""

    if _BROWSER_MOD is None:
        return lambda func: func
    return patch.object(getattr(_BROWSER_MOD, target), attribute, **kwargs)


@unittest.skipIf(run_browser_intel_scan is None, "requires browser intel service")
class TestBrowserIntelScan(unittest.TestCase):
    @_browser_patch("Config", "BROWSER_INTEL_ENABLE", new=True)
    @_browser_patch("BrowserIntelScan", "_open_playwright")
    def test_browser_intel_collects_runtime_calls_forms_and_scripts(self, mock_sync_playwright):
        class FakePage:
            def __init__(self):
                self._handlers = {}
                self.url = "https://example.com/dashboard"

            def on(self, event, handler):
                self._handlers[event] = handler

            def goto(self, site, wait_until=None, timeout=None):
                class Req:
                    method = "GET"
                    resource_type = "fetch"
                class Resp:
                    request = Req()
                    url = "https://example.com/api/me"
                    status = 200
                if "response" in self._handlers:
                    self._handlers["response"](Resp())

            def wait_for_timeout(self, ms):
                return None

            def title(self):
                return "Example Dashboard"

            def evaluate(self, script):
                if "querySelectorAll('form')" in script:
                    return [{
                        "action": "/login",
                        "method": "POST",
                        "enctype": "multipart/form-data",
                        "has_file_input": "true",
                        "has_password_input": "true",
                        "password_fields": "password",
                        "has_captcha_hint": "true",
                        "submit_text": "登录",
                        "fields": "username,password,captcha,file",
                    }]
                return [{"src": "/static/app.js"}]

        class FakeContext:
            def new_page(self):
                return FakePage()

            def close(self):
                return None

        class FakeBrowser:
            def new_context(self, **kwargs):
                return FakeContext()

            def close(self):
                return None

        class FakeChromium:
            def launch(self, **kwargs):
                return FakeBrowser()

        class FakePlaywright:
            chromium = FakeChromium()

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        mock_sync_playwright.return_value = FakePlaywright()

        result = run_browser_intel_scan(["https://example.com"])
        item = result.get("https://example.com", {})

        self.assertEqual("Example Dashboard", item.get("browser_surface_summary", {}).get("page_title"))
        self.assertEqual("runtime_enrichment", item.get("browser_surface_summary", {}).get("source_role"))
        self.assertEqual("passive", item.get("browser_surface_summary", {}).get("interaction_level"))
        self.assertEqual(1, item.get("browser_surface_summary", {}).get("runtime_api_count"))
        self.assertEqual(1, len(item.get("runtime_api_calls", [])))
        self.assertEqual(1, len(item.get("dom_form_summary", [])))
        self.assertEqual("multipart/form-data", item.get("dom_form_summary", [])[0].get("enctype"))
        self.assertTrue(bool(item.get("dom_form_summary", [])[0].get("has_file_input")))
        self.assertTrue(bool(item.get("dom_form_summary", [])[0].get("has_password_input")))
        self.assertTrue(bool(item.get("dom_form_summary", [])[0].get("has_captcha_hint")))

    @_browser_patch("Config", "BROWSER_INTEL_ENABLE", new=True)
    @_browser_patch("BrowserIntelScan", "_open_playwright")
    def test_browser_intel_collects_runtime_post_request_shape(self, mock_sync_playwright):
        class FakeRequest:
            method = "POST"
            resource_type = "fetch"
            headers = {
                "Content-Type": "application/json",
                "Authorization": "Bearer demo-token",
            }
            post_data = '{"query":"query { viewer { id } }","variables":{"id":1}}'

        class FakeResponse:
            request = FakeRequest()
            url = "https://example.com/graphql"
            status = 200

        class FakePage:
            def __init__(self):
                self._handlers = {}
                self.url = "https://example.com/dashboard"

            def on(self, event, handler):
                self._handlers[event] = handler

            def goto(self, site, wait_until=None, timeout=None):
                if "response" in self._handlers:
                    self._handlers["response"](FakeResponse())

            def wait_for_timeout(self, ms):
                return None

            def title(self):
                return "Example Dashboard"

            def evaluate(self, script):
                if "querySelectorAll('form')" in script:
                    return []
                return [{"src": "/static/app.js"}]

        class FakeContext:
            def new_page(self):
                return FakePage()

            def close(self):
                return None

        class FakeBrowser:
            def new_context(self, **kwargs):
                return FakeContext()

            def close(self):
                return None

        class FakeChromium:
            def launch(self, **kwargs):
                return FakeBrowser()

        class FakePlaywright:
            chromium = FakeChromium()

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        mock_sync_playwright.return_value = FakePlaywright()

        result = run_browser_intel_scan(["https://example.com"])
        runtime_item = result.get("https://example.com", {}).get("runtime_api_calls", [])[0]

        self.assertEqual("POST", runtime_item.get("method"))
        self.assertEqual("json_data", runtime_item.get("mode"))
        self.assertEqual("graphql", runtime_item.get("body_kind"))
        self.assertEqual("application/json", runtime_item.get("content_type"))
        self.assertIn("query", runtime_item.get("param_names", []))
        self.assertIn("variables", runtime_item.get("param_names", []))
        self.assertEqual("<redacted>", runtime_item.get("request_headers", {}).get("Authorization"))
        self.assertIn('"query": "<value>"', str(runtime_item.get("request_body_template") or ""))


def _run_scan_single_request(post_data, content_type,
                             url="https://example.com/graphql", method="POST"):
    """单请求驱动 run_browser_intel_scan，返回 (site 结果, runtime 事件)。"""

    class FakeRequest:
        pass
    FakeRequest.method = method
    FakeRequest.resource_type = "fetch"
    FakeRequest.headers = {"Content-Type": content_type,
                           "Authorization": "Bearer SECRET_BROWSER_TOKEN"}
    FakeRequest.post_data = post_data

    class FakeResponse:
        pass
    FakeResponse.request = FakeRequest()
    FakeResponse.url = url
    FakeResponse.status = 200

    class FakePage:
        def __init__(self):
            self._handlers = {}
            self.url = "https://example.com/dashboard"

        def on(self, event, handler):
            self._handlers[event] = handler

        def goto(self, site, wait_until=None, timeout=None):
            if "response" in self._handlers:
                self._handlers["response"](FakeResponse())

        def wait_for_timeout(self, ms):
            return None

        def title(self):
            return "Example"

        def evaluate(self, script):
            if "querySelectorAll('form')" in script:
                return []
            return [{"src": "/static/app.js"}]

    class FakeContext:
        def new_page(self):
            return FakePage()

        def close(self):
            return None

    class FakeBrowser:
        def new_context(self, **kwargs):
            return FakeContext()

        def close(self):
            return None

    class FakeChromium:
        def launch(self, **kwargs):
            return FakeBrowser()

    class FakePlaywright:
        chromium = FakeChromium()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    with patch.object(_BROWSER_MOD.Config, "BROWSER_INTEL_ENABLE", True), \
            patch.object(_BROWSER_MOD.BrowserIntelScan, "_open_playwright",
                         return_value=FakePlaywright()):
        result = run_browser_intel_scan(["https://example.com"])
    site_result = result.get("https://example.com", {})
    calls = site_result.get("runtime_api_calls", [])
    return site_result, (calls[0] if calls else None)


class TestBrowserGraphqlOperationIngest(unittest.TestCase):
    """计划 6 第 8 批 P0-05：浏览器运行时 GraphQL operation 级拆解与泄露门禁。"""

    QUERY = ("query GetPet($petId: ID!) { pet(id: $petId) { name } }")

    def test_graphql_event_carries_operation_endpoints_without_raw_leak(self):
        import json as _json
        payload = _json.dumps({
            "operationName": "GetPet",
            "variables": {"petId": "SECRET_VAR_VALUE_9527"},
            "query": self.QUERY,
        })
        _site, item = _run_scan_single_request(
            payload, "application/json")
        self.assertEqual("graphql", item.get("body_kind"))
        endpoints = item.get("_graphql_endpoints") or []
        self.assertEqual(1, len(endpoints), "operation 级拆解必须就地完成")
        endpoint = endpoints[0]
        self.assertEqual("graphql", endpoint.api_type)
        self.assertEqual("query", endpoint.graphql_operation)
        self.assertEqual("GetPet", endpoint.graphql_operation_name)
        self.assertEqual(64, len(endpoint.graphql_query_hash))
        self.assertEqual({"petId"}, {p.name for p in endpoint.parameters})
        self.assertEqual(
            "ok", (item.get("graphql_diagnostics") or {}).get("status"))
        # 序列化面零泄露：raw query、变量取值、敏感 header 原值都不出现。
        serializable = {k: v for k, v in item.items() if k != "_graphql_endpoints"}
        blob = _json.dumps(serializable, ensure_ascii=False, default=str)
        for secret in ("SECRET_BROWSER_TOKEN", "SECRET_VAR_VALUE_9527",
                       "pet(id: $petId)"):
            self.assertNotIn(secret, blob)
        self.assertEqual("<redacted>", item["request_headers"]["Authorization"])
        # 端点对象自身序列化也过脱敏守卫（variables 取值无落点）。
        endpoint_blob = _json.dumps(endpoint.to_dict(), ensure_ascii=False)
        self.assertNotIn("SECRET_VAR_VALUE_9527", endpoint_blob)

    def test_non_graphql_json_still_no_endpoints(self):
        import json as _json
        payload = _json.dumps({"user": "u1", "pass": "SECRET_PW_9527"})
        _site, item = _run_scan_single_request(
            payload, "application/json", url="https://example.com/api/login")
        self.assertEqual("json", item.get("body_kind"))
        self.assertFalse(item.get("_graphql_endpoints"))
        self.assertNotIn("SECRET_PW_9527", _json.dumps(item, ensure_ascii=False, default=str))

    def test_form_urlencoded_event_not_swallowed(self):
        import json as _json
        # urlencode 导入缺失回归：form_urlencoded 事件曾因 NameError 被整条吞掉。
        _site, item = _run_scan_single_request(
            "user=alice&pass=SECRET_PW_9527",
            "application/x-www-form-urlencoded",
            url="https://example.com/login")
        self.assertIsNotNone(item, "form_urlencoded 请求事件不得被异常吞掉")
        self.assertEqual("form_urlencoded", item.get("body_kind"))
        self.assertNotIn("SECRET_PW_9527", _json.dumps(item, ensure_ascii=False, default=str))
        self.assertEqual("<value>", (item.get("form_data") or {}).get("pass"))


if __name__ == "__main__":
    unittest.main()
