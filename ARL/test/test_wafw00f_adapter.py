"""wafw00f 适配器和 Guard 联动回归测试。"""

import unittest
import types
from unittest import mock
from types import SimpleNamespace

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

    def test_disabled_guard_does_not_construct_detector(self):
        constructed = []
        adapter = WAFW00FAdapter(detector_factory=lambda target: constructed.append(target))
        guard = WAFSmartSkipGuard(enabled=False, smart_skip_enabled=False)

        metrics = adapter.run(["https://example.com/"], guard)

        self.assertEqual("smart_skip_disabled", metrics["end_reason"])
        self.assertEqual([], constructed)


if __name__ == "__main__":
    unittest.main()
