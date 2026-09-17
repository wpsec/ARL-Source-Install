"""wafw00f 适配器和 Guard 联动回归测试。"""

import unittest
import types
from unittest import mock
from types import SimpleNamespace

import requests

try:
    from app.services.waf_guard import WAFSmartSkipGuard
    from app.services.wafw00f_adapter import WAFW00FAdapter
except ModuleNotFoundError:
    WAFSmartSkipGuard = None
    WAFW00FAdapter = None


@unittest.skipIf(
    WAFW00FAdapter is None or WAFSmartSkipGuard is None,
    "运行依赖未安装，跳过 wafw00f 适配器回归",
)
class TestWAFW00FAdapter(unittest.TestCase):
    def test_library_constructor_is_constrained_and_generic_is_fail_open(self):
        constructor_args = {}

        class Detector(object):
            requestnumber = 2

            def __init__(self, **kwargs):
                constructor_args.update(kwargs)

            def identwaf(self, findall=False):
                self.findall = findall
                return ["Generic Detection"], "https://outside.example/attack"

        waf_module = types.ModuleType("wafw00f")
        waf_main = types.ModuleType("wafw00f.main")
        waf_main.WAFW00F = Detector
        waf_module.main = waf_main
        with mock.patch.dict("sys.modules", {"wafw00f": waf_module, "wafw00f.main": waf_main}):
            adapter = WAFW00FAdapter(
                config=SimpleNamespace(PROXY_URL="http://proxy.example:8080", WAFW00F_TIMEOUT_SEC=7)
            )
            result = adapter.probe("https://example.com/a?token=secret")

        self.assertEqual("generic", result["status"])
        self.assertFalse(constructor_args["followredirect"])
        self.assertEqual({}, constructor_args["extraheaders"])
        self.assertEqual("http://proxy.example:8080", constructor_args["proxies"]["https"])
        self.assertEqual(7, constructor_args["timeout"])

    def test_endpoint_key_deduplicates_paths_but_keeps_scheme_and_port(self):
        self.assertEqual(
            "https://example.com:443",
            WAFW00FAdapter.endpoint_key("https://example.com/login?token=secret"),
        )
        self.assertNotEqual(
            WAFW00FAdapter.endpoint_key("http://example.com/"),
            WAFW00FAdapter.endpoint_key("https://example.com/"),
        )
        self.assertNotEqual(
            WAFW00FAdapter.endpoint_key("https://example.com:8443/"),
            WAFW00FAdapter.endpoint_key("https://example.com/"),
        )

    def test_run_deduplicates_same_endpoint_and_keeps_scheme_and_port(self):
        captured_targets = []

        class Detector(object):
            requestnumber = 1

            def identwaf(self, findall=False):
                return [], ""

        def build_detector(target):
            captured_targets.append(target)
            return Detector()

        guard = WAFSmartSkipGuard(
            enabled=True,
            smart_skip_enabled=True,
            scope_sites=["https://example.com"],
        )
        adapter = WAFW00FAdapter(
            detector_factory=build_detector,
            config=SimpleNamespace(
                WAFW00F_TIMEOUT_SEC=7,
                WAFW00F_CONCURRENCY=1,
                WAFW00F_MAX_TARGETS=10,
                WAFW00F_STAGE_TIMEOUT_SEC=10,
            ),
        )

        metrics = adapter.run(
            [
                "https://example.com/a",
                "https://example.com/b",
                "https://example.com:8443/c",
                "http://example.com/",
            ],
            guard,
        )

        self.assertEqual(3, metrics["input_count"])
        self.assertEqual(3, metrics["checked_count"])
        self.assertEqual(
            {
                "https://example.com:443/a",
                "https://example.com:8443/c",
                "http://example.com:80/",
            },
            set(captured_targets),
        )

    def test_named_vendor_only_blocks_active_risk(self):
        calls = []

        class Detector(object):
            requestnumber = 2

            def identwaf(self, findall=False):
                calls.append(findall)
                return ["Cloudflare"], "https://outside.example/attack"

        guard = WAFSmartSkipGuard(
            enabled=True,
            smart_skip_enabled=True,
            task_id="task-demo",
            scope_sites=["https://example.com"],
        )
        adapter = WAFW00FAdapter(
            detector_factory=lambda target: Detector(),
            config=SimpleNamespace(
                WAFW00F_TIMEOUT_SEC=7,
                WAFW00F_CONCURRENCY=1,
                WAFW00F_MAX_TARGETS=10,
                WAFW00F_STAGE_TIMEOUT_SEC=10,
            ),
        )

        metrics = adapter.run(
            ["https://example.com/a", "https://example.com/b"],
            guard,
            task_id="task-demo",
        )

        self.assertEqual(1, metrics["checked_count"])
        self.assertEqual([False], calls)
        summary = guard.summary()
        self.assertEqual("detected", summary["detected_hosts"][0]["wafw00f_status"])
        self.assertEqual(["wafw00f"], summary["detected_hosts"][0]["detection_sources"])
        self.assertFalse(guard.is_blocked_host("example.com"))
        self.assertTrue(guard.should_skip("https://example.com/npoc", module="npoc")[0])
        self.assertFalse(guard.should_skip("https://example.com/page", module="site_spider")[0])

    def test_not_detected_and_error_are_fail_open(self):
        class Detector(object):
            requestnumber = 1

            def __init__(self, result):
                self.result = result

            def identwaf(self, findall=False):
                if isinstance(self.result, Exception):
                    raise self.result
                return self.result, ""

        guard = WAFSmartSkipGuard(
            enabled=True,
            smart_skip_enabled=True,
            scope_sites=["https://example.com", "https://error.example"],
        )
        results = {
            "example.com": ([], ""),
            "error.example": RuntimeError("provider failed"),
        }
        adapter = WAFW00FAdapter(
            detector_factory=lambda target: Detector(results[target.split("//", 1)[1].split(":", 1)[0]]),
            config=SimpleNamespace(
                WAFW00F_TIMEOUT_SEC=7,
                WAFW00F_CONCURRENCY=1,
                WAFW00F_MAX_TARGETS=10,
                WAFW00F_STAGE_TIMEOUT_SEC=10,
            ),
        )
        metrics = adapter.run(
            ["https://example.com/", "https://error.example/"],
            guard,
        )

        self.assertEqual(1, metrics["not_detected_count"])
        self.assertEqual(1, metrics["error_count"])
        self.assertFalse(guard.should_skip("https://example.com/npoc", module="npoc")[0])
        self.assertFalse(guard.should_skip("https://error.example/npoc", module="npoc")[0])

    def test_timeout_is_recorded_and_remains_fail_open(self):
        class Detector(object):
            requestnumber = 0

            def identwaf(self, findall=False):
                raise requests.exceptions.Timeout("detector timeout")

        guard = WAFSmartSkipGuard(
            enabled=True,
            smart_skip_enabled=True,
            scope_sites=["https://example.com"],
        )
        adapter = WAFW00FAdapter(
            detector_factory=lambda target: Detector(),
            config=SimpleNamespace(
                WAFW00F_TIMEOUT_SEC=7,
                WAFW00F_CONCURRENCY=1,
                WAFW00F_MAX_TARGETS=10,
                WAFW00F_STAGE_TIMEOUT_SEC=10,
            ),
        )

        metrics = adapter.run(["https://example.com/"], guard)

        self.assertEqual(1, metrics["timeout_count"])
        self.assertEqual(0, metrics["error_count"])
        self.assertFalse(guard.should_skip("https://example.com/npoc", module="npoc")[0])
        self.assertEqual("timeout", guard.summary()["detected_hosts"][0]["wafw00f_status"])

    def test_passive_high_confidence_waf_is_not_probed(self):
        http_guard = WAFSmartSkipGuard(
            enabled=True,
            smart_skip_enabled=True,
            scope_sites=["https://http.example"],
        )
        http_guard.observe_response(
            "https://http.example/",
            SimpleNamespace(
                status_code=403,
                headers={
                    "X-WAF-Vendor": "cloudflare",
                    "CF-Ray": "abc",
                    "CF-Cache-Status": "MISS",
                },
                content=b"",
            ),
            module="fetch_site",
        )

        dns_guard = WAFSmartSkipGuard(
            enabled=True,
            smart_skip_enabled=True,
            scope_sites=["https://dns.example"],
        )
        dns_guard.observe_dns("dns.example", cname="edge.365cyd.cn")

        self.assertFalse(http_guard.can_probe_wafw00f("https://http.example/"))
        self.assertFalse(dns_guard.can_probe_wafw00f("https://dns.example/"))

    def test_cdn_only_target_is_probeable_once_and_not_waf_blocked(self):
        calls = []

        class Detector(object):
            requestnumber = 1

            def identwaf(self, findall=False):
                calls.append(findall)
                return [], ""

        guard = WAFSmartSkipGuard(
            enabled=True,
            smart_skip_enabled=True,
            scope_sites=["https://cdn.example"],
        )
        guard.observe_dns("cdn.example", cname="edge.cloudfront.net")
        adapter = WAFW00FAdapter(
            detector_factory=lambda target: Detector(),
            config=SimpleNamespace(
                WAFW00F_TIMEOUT_SEC=7,
                WAFW00F_CONCURRENCY=1,
                WAFW00F_MAX_TARGETS=10,
                WAFW00F_STAGE_TIMEOUT_SEC=10,
            ),
        )

        metrics = adapter.run(
            ["https://cdn.example/a", "https://cdn.example/b"],
            guard,
        )
        host = guard.summary()["detected_hosts"][0]

        self.assertEqual(1, metrics["checked_count"])
        self.assertEqual([False], calls)
        self.assertEqual("cdn", host["edge_kind"])
        self.assertEqual(0, guard.summary()["waf_detected_host_count"])
        self.assertFalse(guard.should_skip("https://cdn.example/", module="nuclei")[0])

    def test_named_result_filters_all_active_modules_but_not_passive_modules(self):
        guard = WAFSmartSkipGuard(
            enabled=True,
            smart_skip_enabled=True,
            scope_sites=["https://example.com"],
        )
        self.assertTrue(
            guard.record_wafw00f_result(
                "https://example.com/",
                {
                    "status": "detected",
                    "names": ["Cloudflare"],
                    "confidence": "high",
                    "evidence": ["wafw00f:Cloudflare"],
                    "request_count": 2,
                },
            )
        )

        for module in ("npoc", "poc", "nuclei", "afrog"):
            kept, skipped = guard.filter_targets(
                ["https://example.com/"], module=module, stage_name=module
            )
            self.assertEqual([], kept)
            self.assertEqual(1, skipped)
        for module in ("wih", "site_spider", "directory", "site_identify"):
            self.assertFalse(guard.should_skip("https://example.com/", module=module)[0])

    def test_restored_endpoint_result_is_not_probed_again(self):
        source = WAFSmartSkipGuard(
            enabled=True,
            smart_skip_enabled=True,
            scope_sites=["https://example.com"],
        )
        source.record_wafw00f_result(
            "https://example.com/first",
            {"status": "not_detected", "request_count": 1},
        )
        restored = WAFSmartSkipGuard(
            enabled=True,
            smart_skip_enabled=True,
            scope_sites=["https://example.com"],
        )
        restored.merge_summary(source.summary(include_all=True))
        constructed = []
        adapter = WAFW00FAdapter(
            detector_factory=lambda target: constructed.append(target),
            config=SimpleNamespace(
                WAFW00F_TIMEOUT_SEC=7,
                WAFW00F_CONCURRENCY=1,
                WAFW00F_MAX_TARGETS=10,
                WAFW00F_STAGE_TIMEOUT_SEC=10,
            ),
        )

        metrics = adapter.run(["https://example.com/retry"], restored)

        self.assertEqual(0, metrics["checked_count"])
        self.assertEqual(1, metrics["skipped_by_passive_count"])
        self.assertEqual([], constructed)

    def test_cross_worker_merge_is_endpoint_idempotent_and_aggregates_metrics(self):
        first = WAFSmartSkipGuard(
            enabled=True,
            smart_skip_enabled=True,
            scope_sites=["https://example.com"],
        )
        first.record_wafw00f_result(
            "https://example.com/",
            {"status": "not_detected", "request_count": 1, "elapsed_sec": 0.25},
        )
        second = WAFSmartSkipGuard(
            enabled=True,
            smart_skip_enabled=True,
            scope_sites=["https://example.com"],
        )
        second.record_wafw00f_result(
            "https://example.com:8443/",
            {"status": "detected", "names": ["Cloudflare"], "request_count": 2, "elapsed_sec": 0.5},
        )
        restored = WAFSmartSkipGuard(
            enabled=True,
            smart_skip_enabled=True,
            scope_sites=["https://example.com"],
        )

        restored.merge_summary(first.summary(include_all=True))
        restored.merge_summary(second.summary(include_all=True))
        restored.merge_summary(second.summary(include_all=True))
        item = restored.summary()["detected_hosts"][0]

        self.assertEqual(3, item["wafw00f_request_count"])
        self.assertEqual(0.75, item["wafw00f_elapsed_sec"])
        self.assertEqual("detected", item["wafw00f_status"])
        self.assertEqual(2, len(item["wafw00f_endpoints"]))

    def test_disabled_guard_does_not_construct_detector(self):
        constructed = []
        adapter = WAFW00FAdapter(detector_factory=lambda target: constructed.append(target))
        guard = WAFSmartSkipGuard(enabled=False, smart_skip_enabled=False)

        metrics = adapter.run(["https://example.com/"], guard)

        self.assertEqual("smart_skip_disabled", metrics["end_reason"])
        self.assertEqual([], constructed)


if __name__ == "__main__":
    unittest.main()
