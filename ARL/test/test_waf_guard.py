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
        self.assertEqual(1, summary["observed_site_count"])
        self.assertEqual(1, summary["request_count"])
        self.assertEqual("Cloudflare", summary["detected_hosts"][0]["waf_name"])

    def test_penetration_bypass_semantics_removed(self):
        """计划 1 收口：penetration_test 试探绕过语义删除后的行为钉。

        旧语义下该模块可对已封锁主机获得有限放行并注入伪造 Header；
        现在所有模块统一保守跳过，prepare_request 为无副作用直通。
        """
        guard = WAFSmartSkipGuard(
            enabled=True,
            smart_skip_enabled=True,
            task_id="task-demo",
            scope_sites=["https://example.com"],
        )
        blocked_response = SimpleNamespace(
            status_code=403,
            headers={"X-Safedog": "deny"},
            content=b"\xe8\xae\xbf\xe9\x97\xae\xe6\x8b\xa6\xe6\x88\xaa",
        )

        guard.observe_response("https://example.com/admin", blocked_response, module="fetch_site")
        should_skip_pen_test, detail = guard.should_skip("https://example.com/admin", module="penetration_test")
        headers, delay, prepared_detail = guard.prepare_request(
            "https://example.com/admin",
            module="penetration_test",
            method="GET",
            headers={},
        )

        self.assertTrue(should_skip_pen_test)
        self.assertEqual("host", detail["scope"])
        self.assertEqual({}, headers)
        self.assertEqual(0.0, delay)
        self.assertEqual({}, prepared_detail)
        self.assertNotIn("bypass_enabled", guard.summary())

    def test_filter_targets_records_site_and_request_units(self):
        guard = WAFSmartSkipGuard(
            enabled=True,
            smart_skip_enabled=True,
            task_id="task-demo",
            scope_sites=["https://example.com"],
        )
        blocked_response = SimpleNamespace(
            status_code=403,
            headers={"X-Yunaq": "deny"},
            content=b"request blocked",
        )

        guard.observe_response("https://example.com/login", blocked_response, module="fetch_site")
        targets, skipped = guard.filter_targets(
            [
                "https://example.com/api/users",
                "https://example.com/api/orders",
            ]
        )
        summary = guard.summary()

        self.assertEqual([], targets)
        self.assertEqual(2, skipped)
        self.assertEqual(1, summary["observed_site_count"])
        self.assertEqual(1, summary["skip_site_count"])
        self.assertEqual(0, summary["skip_request_count"])

    def test_filter_targets_respects_smart_skip_flag(self):
        """
        仅开启观测（smart_skip 关闭）时，不应让被动链路提前过滤目标。
        """
        guard = WAFSmartSkipGuard(
            enabled=True,
            smart_skip_enabled=False,
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

    def test_requested_response_vendor_signals_are_detected(self):
        cases = [
            (
                "网宿WAF",
                {"Server": "wswaf", "Via": "(Cdn Cache Server V2.0)"},
                b"",
            ),
            ("安全宝/Anquanbao", {"Server": "Anquanbao"}, b""),
            ("安域/AnYu", {"Server": "AnYu"}, b""),
            ("字节跳动CDN/WAF", {"Server": "bytedns"}, b""),
        ]

        for vendor, headers, content in cases:
            response = SimpleNamespace(status_code=403, headers=headers, content=content)
            name, confidence, evidence = WAFSmartSkipGuard._identify_vendor(
                WAFSmartSkipGuard._extract_response_context(response)[2]
            )
            self.assertEqual(vendor, name)
            self.assertIn(confidence, {"low", "medium", "high"})
            self.assertTrue(evidence)

    def test_header_signal_does_not_scan_response_body(self):
        response = SimpleNamespace(
            status_code=200,
            headers={"Content-Type": "text/html"},
            content=b"the page contains x-yunaq as ordinary text",
        )

        strong_hit, signals, _ = WAFSmartSkipGuard._collect_signals(response)

        self.assertFalse(strong_hit)
        self.assertEqual([], signals)

    def test_dns_vendor_signals_use_exact_suffix_matching(self):
        vendor, confidence, evidence = WAFSmartSkipGuard.identify_vendor_from_dns(
            cname="edge.365cyd.cn."
        )
        self.assertEqual("知道创宇/创宇盾", vendor)
        self.assertEqual("high", confidence)
        self.assertIn("dns:365cyd.cn", evidence)

        vendor, _, _ = WAFSmartSkipGuard.identify_vendor_from_dns(
            cname="edge.not365cyd.cn"
        )
        self.assertEqual("", vendor)

        vendor, confidence, evidence = WAFSmartSkipGuard.identify_vendor_from_dns(
            cname="foo.bytedns1.com"
        )
        self.assertEqual("字节跳动CDN/WAF", vendor)
        self.assertEqual("high", confidence)
        self.assertTrue(evidence)

        vendor, confidence, evidence = WAFSmartSkipGuard.identify_vendor_from_dns(
            cname="edge.yundunwaf2.com."
        )
        self.assertEqual("知道创宇/创宇盾", vendor)
        self.assertEqual("high", confidence)
        self.assertTrue(evidence)

    def test_observe_dns_keeps_dns_evidence_separate_from_http_requests(self):
        guard = WAFSmartSkipGuard(
            enabled=True,
            smart_skip_enabled=True,
            scope_sites=["https://example.com"],
        )

        result = guard.observe_dns(
            "https://example.com",
            cname="edge.365cyd.cn",
            module="domain_cname",
        )
        summary = guard.summary()

        self.assertEqual("知道创宇/创宇盾", result["waf_name"])
        self.assertEqual(0, summary["request_count"])
        self.assertEqual("domain_cname", summary["detected_hosts"][0]["module"])
        self.assertIn("dns:365cyd.cn", summary["detected_hosts"][0]["dns_evidence"])


    def test_directory_signal_only_pauses_directory_queue(self):
        """目录流量触发的阻断只暂停 directory 队列，不升级为整主机连坐。"""
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

        guard.observe_response("https://example.com/backup.zip", response, module="file_leak")

        skip_directory, detail = guard.should_skip("https://example.com/secret.sql", module="file_leak")
        skip_fetch, _ = guard.should_skip("https://example.com/admin", module="fetch_site")
        skip_wih, _ = guard.should_skip("https://example.com/api", module="urlfinder_extract")
        self.assertTrue(skip_directory)
        self.assertEqual("directory_class", detail.get("scope"))
        self.assertFalse(skip_fetch)
        self.assertFalse(skip_wih)

        summary = guard.summary()
        self.assertEqual(0, summary["blocked_host_count"])
        self.assertEqual(1, summary["class_blocked_host_count"])
        self.assertEqual(["directory"], summary["class_blocked_hosts"][0]["blocked_classes"])
        self.assertFalse(guard.is_blocked_host("example.com"))
        keep, skipped = guard.filter_targets(["https://example.com"])
        self.assertEqual(1, len(keep))
        self.assertEqual(0, skipped)

    def test_non_directory_signal_keeps_host_wide_block(self):
        """非目录来源信号维持既有主机级阻断口径。"""
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

        guard.observe_response("https://example.com/login", response, module="page_intel_scan")

        skip_directory, detail = guard.should_skip("https://example.com/admin", module="file_leak")
        self.assertTrue(skip_directory)
        self.assertEqual("host", detail.get("scope"))
        summary = guard.summary()
        self.assertEqual(1, summary["blocked_host_count"])
        self.assertEqual(0, summary["class_blocked_host_count"])

    def test_signal_sink_receives_block_and_swallows_errors(self):
        """确认阻断要回流 discovery 上下文；回调异常不能打断守卫。"""
        captured = []

        def sink(url, module, reason, block_scope=""):
            captured.append((url, module, reason, block_scope))

        guard = WAFSmartSkipGuard(
            enabled=True,
            smart_skip_enabled=True,
            task_id="task-demo",
            scope_sites=["https://example.com"],
            signal_sink=sink,
        )
        response = SimpleNamespace(
            status_code=403,
            headers={"CF-Ray": "abc123", "Server": "cloudflare"},
            content=b"Access denied by security policy",
        )
        guard.observe_response("https://example.com/backup.zip", response, module="file_leak")
        self.assertEqual(1, len(captured))
        self.assertEqual("file_leak", captured[0][1])

        def bad_sink(url, module, reason, block_scope=""):
            raise RuntimeError("sink boom")

        guard_broken = WAFSmartSkipGuard(
            enabled=True,
            smart_skip_enabled=True,
            task_id="task-demo",
            scope_sites=["https://example.com"],
            signal_sink=bad_sink,
        )
        guard_broken.observe_response("https://example.com/backup.zip", response, module="file_leak")
        self.assertEqual(1, guard_broken.summary()["class_blocked_host_count"])

    def test_weak_status_escalates_only_source_class(self):
        """非目录弱证据只暂停来源类别，不主机级连坐。"""
        guard = WAFSmartSkipGuard(
            enabled=True,
            smart_skip_enabled=True,
            task_id="task-demo",
            scope_sites=["https://example.com"],
            weak_block_threshold=2,
        )
        # Server 头无厂商强特征，403 属弱证据
        weak_response = SimpleNamespace(
            status_code=403,
            headers={"Server": "Apache"},
            content=b"",
        )
        guard.observe_response("https://example.com/admin", weak_response, module="page_intel_scan")
        guard.observe_response("https://example.com/login", weak_response, module="page_intel_scan")
        summary = guard.summary()

        self.assertEqual(0, summary["blocked_host_count"])
        self.assertEqual(1, summary["class_blocked_host_count"])
        self.assertEqual(["wih"], summary["class_blocked_hosts"][0]["blocked_classes"])
        # 来源类别被暂停，其它类别不受影响
        skip_wih, _ = guard.should_skip("https://example.com/api", module="urlfinder_extract")
        skip_fetch, _ = guard.should_skip("https://example.com/", module="fetch_site")
        self.assertTrue(skip_wih)
        self.assertFalse(skip_fetch)

    def test_strong_signal_still_host_wide_and_sink_reports_scope(self):
        captured = []
        guard = WAFSmartSkipGuard(
            enabled=True,
            smart_skip_enabled=True,
            task_id="task-demo",
            scope_sites=["https://example.com"],
            signal_sink=lambda url, module, reason, block_scope: captured.append(block_scope),
        )
        strong = SimpleNamespace(
            status_code=403,
            headers={"CF-Ray": "abc123", "Server": "cloudflare"},
            content=b"Access denied by security policy",
        )
        guard.observe_response("https://example.com/login", strong, module="fetch_site")
        skip_wih, _ = guard.should_skip("https://example.com/api", module="urlfinder_extract")
        self.assertTrue(skip_wih)
        self.assertEqual(["host"], captured)
        self.assertEqual(1, guard.summary()["blocked_host_count"])

    def test_add_scope_host_extends_observation(self):
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
        # 未加入 scope 的新子域不会被观测
        guard.observe_response("https://api.example.com/", response, module="fetch_site")
        self.assertEqual(0, guard.summary()["detected_host_count"])

        self.assertTrue(guard.add_scope_host("api.example.com"))
        self.assertFalse(guard.add_scope_host("api.example.com"))
        guard.observe_response("https://api.example.com/", response, module="fetch_site")
        self.assertEqual(1, guard.summary()["blocked_host_count"])
        self.assertTrue(guard.is_blocked_host("api.example.com"))

        # 空 scope（不限制）时追加会被跳过，避免反向收窄
        unrestricted = WAFSmartSkipGuard(enabled=True, smart_skip_enabled=True, task_id="t")
        self.assertFalse(unrestricted.add_scope_host("any.example.org"))


if __name__ == "__main__":
    unittest.main()
