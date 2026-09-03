"""endpoint 探测接入统一响应缓存的回归测试。"""
import unittest

try:
    from app.services.discovery_context import DiscoveryContext
except Exception:
    DiscoveryContext = None


class _Resp(object):
    def __init__(self, status_code=200, body=b"hello", headers=None):
        self.status_code = status_code
        self.content = body
        self.headers = headers if headers is not None else {"Content-Type": "text/html"}
        self.reason = "OK"
        self.encoding = "utf-8"


@unittest.skipIf(DiscoveryContext is None, "运行依赖未安装")
class TestProbeCache(unittest.TestCase):
    def setUp(self):
        from app.services import wih_endpoint_probe as probe_mod
        self.probe_mod = probe_mod
        self.calls = []
        self.original_request = probe_mod.requests.request
        self.original_dns = probe_mod.utils.check_dns_policy_for_url
        probe_mod.utils.check_dns_policy_for_url = (
            lambda url, cache_map=None: (True, {}))

        def fake_request(method, url, **kwargs):
            self.calls.append((str(method).upper(), url))
            return _Resp()

        probe_mod.requests.request = fake_request

    def tearDown(self):
        self.probe_mod.requests.request = self.original_request
        self.probe_mod.utils.check_dns_policy_for_url = self.original_dns

    def test_probe_fills_registry_and_second_probe_reuses(self):
        ctx = DiscoveryContext("task-1")
        item = {"url": "http://api.example.com/v1/users", "method": "GET"}
        out1 = self.probe_mod._probe_one(
            dict(item), dns_policy_cache={}, discovery_context=ctx)
        self.assertEqual("probed", out1["verification_status"])
        self.assertEqual(200, out1["status_code"])
        self.assertEqual(1, len(self.calls))

        out2 = self.probe_mod._probe_one(
            dict(item), dns_policy_cache={}, discovery_context=ctx)
        self.assertEqual(1, len(self.calls), "第二次探测不得再发网络请求")
        self.assertEqual("probed", out2["verification_status"])
        self.assertEqual(200, out2["status_code"])
        self.assertIn("缓存", out2["verification_note"])
        self.assertIn("HTTP/1.1 200", out2["verification_response_packet"])
        self.assertIn("hello", out2["verification_response_packet"])

    def test_get_probe_reuses_page_fetch_cache(self):
        # GET 探测与页面抓取链路共用 html_get profile。
        ctx = DiscoveryContext("task-1")
        url = "http://www.example.com/portal"
        ctx.put_response(
            url=url, method="GET", request_profile="html_get",
            status_code=200, headers={"Content-Type": "text/html"},
            content_type="text/html", body=b"<html>cached</html>",
            source="fetch_site", consumer="fetch_site")
        out = self.probe_mod._probe_one(
            {"url": url, "method": "GET"},
            dns_policy_cache={}, discovery_context=ctx)
        self.assertEqual(0, len(self.calls), "缓存命中不得回源")
        self.assertEqual(200, out["status_code"])
        self.assertIn("cached", out["verification_response_packet"])

    def test_post_body_signature_separates_profiles(self):
        # 同 URL 不同 body 的 POST 必须各自成 key，相同 body 可复用。
        ctx = DiscoveryContext("task-1")
        a = {"url": "http://api.example.com/search", "method": "POST",
             "content_type": "application/json",
             "request_template": {"body": {"q": "1"}, "body_text": ""}}
        b = {"url": "http://api.example.com/search", "method": "POST",
             "content_type": "application/json",
             "request_template": {"body": {"q": "2"}, "body_text": ""}}
        self.probe_mod._probe_one(dict(a), dns_policy_cache={}, discovery_context=ctx)
        self.probe_mod._probe_one(dict(b), dns_policy_cache={}, discovery_context=ctx)
        self.assertEqual(2, len(self.calls))
        self.probe_mod._probe_one(dict(a), dns_policy_cache={}, discovery_context=ctx)
        self.assertEqual(2, len(self.calls), "相同 body 的 POST 应命中缓存")

    def test_blocked_lease_does_not_leak_fetch_slot(self):
        # WAF blocked 拒发路径：探测作为 single-flight 先行者拿到槽位后被
        # 拒发，槽位必须随 finally 释放，否则同 key 等待方要干等超时。
        ctx = DiscoveryContext("task-1")
        url = "http://blocked.example.com/api"
        ctx.record_waf_signal(url, "wih", reason="unit", force=True)
        out = self.probe_mod._probe_one(
            {"url": url, "method": "GET"},
            dns_policy_cache={}, discovery_context=ctx)
        self.assertEqual("skipped", out["verification_status"])
        self.assertEqual(0, len(self.calls))
        profile = self.probe_mod._probe_request_profile("GET", {"url": url})
        self.assertIsNone(
            ctx.acquire_fetch_slot(url, method="GET", request_profile=profile),
            "blocked 拒发后 single-flight 槽位应已释放")

    def test_probe_without_context_still_requests(self):
        out = self.probe_mod._probe_one(
            {"url": "http://api.example.com/x", "method": "GET"},
            dns_policy_cache={}, discovery_context=None)
        self.assertEqual(1, len(self.calls))
        self.assertEqual("probed", out["verification_status"])


if __name__ == "__main__":
    unittest.main()
