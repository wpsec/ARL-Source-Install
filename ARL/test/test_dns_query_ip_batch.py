import time
import unittest
from unittest.mock import patch

from app.config import Config
from app.services.dns_query import DNSQueryBase, run_query_plugin_by_ip


class _BatchPlugin(DNSQueryBase):
    delay = 0.03
    failed_ips = set()
    started_ips = set()

    def __init__(self):
        super().__init__()
        self.source_name = "batch_test"
        self.support_ip_query = True
        self.support_cert_query = False

    def init_key(self, **kwargs):
        return None

    def sub_domains(self, target):
        return []

    def sub_domains_by_ip(self, ip):
        self.started_ips.add(ip)
        time.sleep(self.delay)
        if ip in self.failed_ips:
            raise RuntimeError("synthetic provider failure")
        return ["host-{}.example.com".format(ip.replace(".", "-"))]


class TestDnsQueryIpBatch(unittest.TestCase):
    def setUp(self):
        self.old_config = {
            "plugins": Config.QUERY_PLUGIN_CONFIG,
            "concurrency": Config.SEARCH_PROVIDER_CONCURRENCY,
            "budget": Config.SEARCH_PROVIDER_STAGE_TIMEOUT_SEC,
            "threshold": Config.SEARCH_PROVIDER_CIRCUIT_BREAKER_THRESHOLD,
        }
        Config.QUERY_PLUGIN_CONFIG = {"batch_test": {"enable": True}}
        Config.SEARCH_PROVIDER_CONCURRENCY = 2
        Config.SEARCH_PROVIDER_STAGE_TIMEOUT_SEC = 10
        Config.SEARCH_PROVIDER_CIRCUIT_BREAKER_THRESHOLD = 3
        _BatchPlugin.delay = 0.03
        _BatchPlugin.failed_ips = set()
        _BatchPlugin.started_ips = set()

    def tearDown(self):
        Config.QUERY_PLUGIN_CONFIG = self.old_config["plugins"]
        Config.SEARCH_PROVIDER_CONCURRENCY = self.old_config["concurrency"]
        Config.SEARCH_PROVIDER_STAGE_TIMEOUT_SEC = self.old_config["budget"]
        Config.SEARCH_PROVIDER_CIRCUIT_BREAKER_THRESHOLD = self.old_config["threshold"]

    def test_ip_queries_use_bounded_batch_workers(self):
        ips = ["192.0.2.{}".format(index) for index in range(1, 5)]
        with patch("app.services.dns_query.utils.load_query_plugins", return_value=[_BatchPlugin()]):
            started = time.monotonic()
            result = run_query_plugin_by_ip(ips, target_domain="example.com")
            elapsed = time.monotonic() - started

        self.assertEqual(4, len(result))
        self.assertLess(elapsed, 0.11)
        self.assertTrue(all(item.get("pivot_ip") in ips for item in result))

    def test_failed_ip_call_does_not_hide_successful_calls(self):
        _BatchPlugin.failed_ips = {"192.0.2.2"}
        ips = ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
        with patch("app.services.dns_query.utils.load_query_plugins", return_value=[_BatchPlugin()]):
            result = run_query_plugin_by_ip(ips, target_domain="example.com")

        self.assertEqual(2, len(result))
        self.assertEqual(
            {"192-0-2-1", "192-0-2-3"},
            {item["domain"].split("host-", 1)[1].split(".", 1)[0] for item in result},
        )

    def test_circuit_breaker_does_not_prequeue_all_ips(self):
        _BatchPlugin.delay = 0.01
        _BatchPlugin.failed_ips = {
            "192.0.2.1",
            "192.0.2.2",
            "192.0.2.3",
            "192.0.2.4",
        }
        Config.SEARCH_PROVIDER_CIRCUIT_BREAKER_THRESHOLD = 2
        ips = ["192.0.2.{}".format(index) for index in range(1, 11)]
        with patch("app.services.dns_query.utils.load_query_plugins", return_value=[_BatchPlugin()]):
            result = run_query_plugin_by_ip(ips, target_domain="example.com")

        self.assertEqual([], result)
        # 已启动的并发窗口可能在主线程收到第二个失败前补投一个任务，
        # 但不能退化为把全部 IP 预先放入线程池。
        self.assertLessEqual(len(_BatchPlugin.started_ips), Config.SEARCH_PROVIDER_CONCURRENCY + 1)


if __name__ == "__main__":
    unittest.main()
