"""
WAF 观测与智能跳过回归测试。
"""
import unittest
from types import SimpleNamespace

try:
    from app.services.waf_guard import WAFSmartSkipGuard
except ModuleNotFoundError:
    WAFSmartSkipGuard = None


@unittest.skipIf(
    WAFSmartSkipGuard is None,
    "运行依赖未安装，跳过 WAF 守卫回归",
)
class TestWAFSmartSkipGuard(unittest.TestCase):
    """
    WAF 守卫行为测试。
    """

    def test_observe_response_detects_vendor_and_blocks(self):
        """
        强信号响应应记录厂商特征，并在启用跳过时标记为阻断主机。
        """
        guard = WAFSmartSkipGuard(
            enabled=True,
            smart_skip_enabled=True,
            task_id="task-demo",
            scope_sites=["https://example.com"],
        )
        response = SimpleNamespace(
            status_code=403,
            headers={"CF-Ray": "abc123", "Server": "cloudflare"},
            content=b"Access denied by security policy",
        )

        guard.observe_response("https://example.com/login", response, module="fetch_site")
        summary = guard.summary()

        self.assertEqual(1, summary["detected_host_count"])
        self.assertEqual(1, summary["blocked_host_count"])
        self.assertEqual("Cloudflare", summary["detected_hosts"][0]["waf_name"])

    def test_bypass_allows_penetration_module_before_skip(self):
        """
        开启试探绕过后，主动渗透模块应先获得有限放行机会。
        """
        guard = WAFSmartSkipGuard(
            enabled=True,
            smart_skip_enabled=True,
            bypass_enabled=True,
            task_id="task-demo",
            scope_sites=["https://example.com"],
            bypass_attempt_limit=2,
        )
        blocked_response = SimpleNamespace(
            status_code=403,
            headers={"X-Safedog": "deny"},
            content=b"\xe8\xae\xbf\xe9\x97\xae\xe6\x8b\xa6\xe6\x88\xaa",
        )
        allowed_response = SimpleNamespace(
            status_code=200,
            headers={"Content-Type": "text/html"},
            content=b"<html>ok</html>",
        )

        guard.observe_response("https://example.com/admin", blocked_response, module="fetch_site")
        should_skip_fetch, _ = guard.should_skip("https://example.com/admin", module="fetch_site")
        should_skip_pen_test, _ = guard.should_skip("https://example.com/admin", module="penetration_test")
        headers, delay, detail = guard.prepare_request(
            "https://example.com/admin",
            module="penetration_test",
            method="GET",
            headers={},
        )
        guard.observe_response("https://example.com/admin", allowed_response, module="penetration_test")
        summary = guard.summary()

        self.assertTrue(should_skip_fetch)
        self.assertFalse(should_skip_pen_test)
        self.assertGreater(delay, 0.0)
        self.assertEqual("127.0.0.1", headers["X-Forwarded-For"])
        self.assertEqual("penetration_test", detail["module"])
        self.assertEqual(1, summary["bypass_success_host_count"])

    def test_filter_targets_respects_smart_skip_flag(self):
        """
        仅开启观测或试探绕过时，不应让被动链路提前过滤目标。
        """
        guard = WAFSmartSkipGuard(
            enabled=True,
            smart_skip_enabled=False,
            bypass_enabled=True,
            task_id="task-demo",
            scope_sites=["https://example.com"],
        )
        blocked_response = SimpleNamespace(
            status_code=403,
            headers={"X-Yunaq": "deny"},
            content=b"request blocked",
        )

        guard.observe_response("https://example.com/test", blocked_response, module="fetch_site")
        targets, skipped = guard.filter_targets(["https://example.com/test"])

        self.assertEqual(["https://example.com/test"], targets)
        self.assertEqual(0, skipped)


if __name__ == "__main__":
    unittest.main()
