"""NPoC 目标配对过滤回归测试。"""

import unittest
import socket
from types import SimpleNamespace
from unittest.mock import patch

from app.services.npoc import NPoC
from app.services.waf_guard import WAFSmartSkipGuard
from xing.core.PluginRunner import PluginRunner
from xing.core.request_context import RequestExecutionContext
from xing.utils import http_req
from xing.yaml_poc import _TcpConnection
from app.services.discovery_context import DiscoveryContext


class TestNPoCPairFilter(unittest.TestCase):
    def test_scheme_and_fingerprint_reduce_pairs(self):
        instance = NPoC(
            target_profiles={
                "https://example.com": {
                    "schemes": {"https"},
                    "fingerprints": {"jenkins"},
                    "services": set(),
                }
            }
        )
        matching = SimpleNamespace(
            scheme=["https"], target_scheme="https", finger="jenkins", _plugin_name="matching"
        )
        wrong_scheme = SimpleNamespace(
            scheme=["http"], target_scheme="http", finger="jenkins", _plugin_name="scheme"
        )
        wrong_finger = SimpleNamespace(
            scheme=["https"], target_scheme="https", finger="grafana", _plugin_name="finger"
        )

        runner = PluginRunner(
            [matching, wrong_scheme, wrong_finger],
            ["https://example.com"],
            pair_filter=instance._pair_is_eligible,
        )

        self.assertEqual(1, runner.plan())
        self.assertEqual(2, runner.filtered_pair_count)

    def test_target_deadline_is_shared_by_plugin_first_schedule(self):
        context = RequestExecutionContext(
            plugin_timeout_sec=5,
            target_timeout_sec=0.02,
            stage_timeout_sec=5,
        )
        first = context.target_deadline_for("https://example.com")
        second = context.target_deadline_for("https://example.com")
        self.assertEqual(first, second)

    def test_same_timeout_exception_is_counted_once(self):
        context = RequestExecutionContext(
            plugin_timeout_sec=5,
            target_timeout_sec=5,
            stage_timeout_sec=5,
        )
        error = TimeoutError("timed out")
        with context.bind("demo", "https://example.com"):
            context.observe_error("https://example.com", error)
            context.observe_error("https://example.com", error)
        self.assertEqual(1, context.snapshot()["timeout_count"])

    def test_raw_tcp_read_timeout_is_observed_once(self):
        class FakeSocket:
            def settimeout(self, _timeout):
                return None

            def recv(self, _size):
                raise socket.timeout("read timed out")

            def close(self):
                return None

        context = RequestExecutionContext(
            plugin_timeout_sec=5,
            target_timeout_sec=5,
            stage_timeout_sec=5,
        )
        with patch("xing.yaml_poc.socket.create_connection", return_value=FakeSocket()):
            with context.bind("demo", "tcp://example.com:1234"):
                conn = _TcpConnection(
                    "example.com",
                    1234,
                    1,
                    request_context=context,
                    request_url="tcp://example.com:1234",
                )
                self.assertEqual("", conn.ReadStr())
                self.assertEqual("", conn.ReadStr())
                conn.Close()
        self.assertEqual(1, context.snapshot()["timeout_count"])

    def test_npoc_timeout_signal_is_supported_by_discovery_context(self):
        context = DiscoveryContext(
            task_id="task-demo",
            allowed_hosts=["https://example.com"],
        )
        result = context.record_waf_signal(
            "https://example.com",
            "npoc",
            reason="timeout threshold",
            force=True,
        )
        self.assertTrue(result["blocked"])
        self.assertTrue(context.waf_policy.allow("https://example.com", "normal"))
        self.assertFalse(context.waf_policy.allow("https://example.com", "npoc"))

    def test_prepared_runner_still_applies_waf_filter(self):
        guard = WAFSmartSkipGuard(
            enabled=True,
            smart_skip_enabled=True,
            scope_sites=["https://example.com"],
        )
        guard.observe_response(
            "https://example.com/login",
            SimpleNamespace(
                status_code=403,
                headers={"X-Waf-Action": "deny"},
                content=b"",
            ),
            module="fetch_site",
        )
        instance = NPoC(
            waf_guard=guard,
            tmp_dir="/tmp",
            target_profiles={},
        )
        plugin = SimpleNamespace(
            _plugin_name="demo",
            plugin_type=1,
            scheme=["https"],
            target_scheme="https",
            finger="",
        )
        with patch.object(instance, "filter_plugin_by_name", return_value=[plugin]):
            instance.prepare_runner(["demo"], ["https://example.com"])
            with patch.object(instance.runner, "run") as run:
                result = instance.run_poc(["demo"], ["https://example.com"])

        run.assert_not_called()
        self.assertEqual("waf_circuit_breaker", result.metrics["end_reason"])
        self.assertEqual(1, result.metrics["waf_skipped_count"])
        self.assertEqual(1, result.metrics["requested_pair_count"])

    def test_http_request_reports_response_to_waf_guard(self):
        guard = WAFSmartSkipGuard(
            enabled=True,
            smart_skip_enabled=True,
            scope_sites=["https://example.com"],
        )
        context = RequestExecutionContext(
            guard=guard,
            module="npoc",
            plugin_timeout_sec=5,
            target_timeout_sec=5,
            stage_timeout_sec=5,
        )
        response = SimpleNamespace(
            status_code=403,
            headers={"X-Waf-Action": "deny"},
            content=b"",
        )

        with patch("xing.utils.requests.get", return_value=response) as request:
            with context.bind("demo", "https://example.com"):
                self.assertIs(response, http_req("https://example.com/test"))

        request.assert_called_once()
        self.assertTrue(guard.should_skip("https://example.com/next", module="npoc")[0])
        self.assertEqual(1, context.snapshot()["response_count"])

    def test_http_timeouts_trip_npoc_waf_circuit_breaker(self):
        guard = WAFSmartSkipGuard(
            enabled=True,
            smart_skip_enabled=True,
            scope_sites=["https://example.com"],
            timeout_block_threshold=2,
        )
        context = RequestExecutionContext(
            guard=guard,
            module="npoc",
            plugin_timeout_sec=5,
            target_timeout_sec=5,
            stage_timeout_sec=5,
        )

        with patch("xing.utils.requests.get", side_effect=TimeoutError("timed out")):
            for path in ("/first", "/second"):
                with context.bind("demo", "https://example.com{}".format(path)):
                    with self.assertRaises(TimeoutError):
                        http_req("https://example.com{}".format(path))

        self.assertTrue(guard.should_skip("https://example.com/next", module="npoc")[0])
        self.assertFalse(guard.should_skip("https://example.com/next", module="fetch_site")[0])
        self.assertEqual(2, guard.summary()["timeout_count"])


if __name__ == "__main__":
    unittest.main()
