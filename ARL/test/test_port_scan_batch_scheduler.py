import threading
import time
import unittest
from unittest.mock import patch

from app.config import Config
from app.modules import DomainInfo
from app.tasks.domain import ScanPort
from app.services import portScan


class _HostData(dict):
    def all_protocols(self):
        return ["tcp"]


class _FakeScanner:
    active = 0
    peak = 0
    lock = threading.Lock()
    failed_hosts = set()

    def __init__(self):
        self.host = ""

    def scan(self, hosts, ports, arguments, timeout=None):
        if timeout != 2:
            raise AssertionError("batch timeout was not forwarded")
        self.host = hosts.split()[0]
        with self.lock:
            type(self).active += 1
            type(self).peak = max(type(self).peak, type(self).active)
        try:
            time.sleep(0.03)
            if self.host in type(self).failed_hosts:
                raise RuntimeError("synthetic batch failure")
        finally:
            with self.lock:
                type(self).active -= 1

    def all_hosts(self):
        return [self.host]

    def __getitem__(self, host):
        return _HostData({
            "tcp": {80: {"name": "http", "version": "", "product": ""}},
            "osmatch": [],
        })


class TestPortScanBatchScheduler(unittest.TestCase):
    def setUp(self):
        self.old_concurrency = getattr(Config, "PORT_SCAN_BATCH_CONCURRENCY", 2)
        self.old_timeout = getattr(Config, "PORT_SCAN_BATCH_TIMEOUT_SEC", 600)
        Config.PORT_SCAN_BATCH_CONCURRENCY = 2
        Config.PORT_SCAN_BATCH_TIMEOUT_SEC = 2
        _FakeScanner.active = 0
        _FakeScanner.peak = 0
        _FakeScanner.failed_hosts = set()

    def tearDown(self):
        Config.PORT_SCAN_BATCH_CONCURRENCY = self.old_concurrency
        Config.PORT_SCAN_BATCH_TIMEOUT_SEC = self.old_timeout

    def test_batches_run_with_bounded_concurrency_and_metrics(self):
        with patch.object(portScan.nmap, "PortScanner", _FakeScanner):
            scanner = portScan.PortScan(["a", "b", "c", "d"], ports="80")
            result, timeout_hit = scanner._scan_with_batches(
                ["a", "b", "c", "d"],
                "80",
                "",
                "test",
                force_batch_size=1,
                stage_timeout_sec=5,
            )

        self.assertFalse(timeout_hit)
        self.assertEqual(4, len(result))
        self.assertEqual(2, _FakeScanner.peak)
        self.assertEqual(4, scanner.last_scan_metrics["processed_batch_count"])
        self.assertEqual(0, scanner.last_scan_metrics["failed_batch_count"])

    def test_failed_batch_is_counted_without_empty_success(self):
        _FakeScanner.failed_hosts = {"b"}
        with patch.object(portScan.nmap, "PortScanner", _FakeScanner):
            scanner = portScan.PortScan(["a", "b", "c", "d", "e"], ports="80")
            result, timeout_hit = scanner._scan_with_batches(
                ["a", "b", "c", "d", "e"],
                "80",
                "",
                "test",
                force_batch_size=1,
                stage_timeout_sec=5,
            )

        self.assertFalse(timeout_hit)
        self.assertEqual({"a", "c", "d", "e"}, set(result))
        self.assertEqual(1, scanner.last_scan_metrics["failed_batch_count"])

    def test_syn_scan_falls_back_only_for_raw_socket_permission_error(self):
        class _SynPermissionScanner(_FakeScanner):
            calls = []

            def scan(self, hosts, ports, arguments, timeout=None):
                type(self).calls.append(arguments)
                if "-sS" in arguments.split():
                    raise RuntimeError("requires root privileges for raw socket")
                return super().scan(hosts, ports, arguments, timeout=timeout)

        with patch.object(portScan.nmap, "PortScanner", _SynPermissionScanner):
            scanner = portScan.PortScan(["a"], ports="80")
            result, timeout_hit = scanner._scan_with_batches(
                ["a"],
                "80",
                "-sS -n --open",
                "test",
                force_batch_size=1,
                stage_timeout_sec=5,
            )

        self.assertFalse(timeout_hit)
        self.assertEqual(1, len(result))
        self.assertEqual(1, scanner.last_scan_metrics["fallback_count"])
        self.assertEqual("connect_fallback", scanner.last_scan_metrics["scan_type"])
        self.assertEqual(2, len(_SynPermissionScanner.calls))
        self.assertIn("-sT", _SynPermissionScanner.calls[-1].split())

    def test_syn_scan_can_be_disabled_explicitly(self):
        with patch.object(Config, "PORT_SCAN_SYN_ENABLE", False):
            scanner = portScan.PortScan(["a"], ports="80")

        self.assertIn("-sT", scanner._build_nmap_arguments())
        self.assertNotIn("-sS", scanner._build_nmap_arguments())

    def test_suspected_all_open_result_keeps_original_ports(self):
        class _AllOpenScanner(_FakeScanner):
            def __getitem__(self, host):
                return _HostData({
                    "tcp": {
                        port: {"name": "", "version": "", "product": ""}
                        for port in range(1, 1001)
                    },
                    "osmatch": [],
                })

        scanner = portScan.PortScan(["a"], ports="0-65535")
        with patch.object(portScan.nmap, "PortScanner", _AllOpenScanner):
            result = scanner._run_batch_scan(["a"], "0-65535", "", "all", 1, 1)

        self.assertEqual(1000, len(result[0]["port_info"]))
        self.assertTrue(result[0]["_suspected_all_open"])
        self.assertEqual([], scanner._build_precise_plan({"a": result[0]}))

    def test_internal_all_open_marker_is_removed_at_ipinfo_boundary(self):
        domain_info = DomainInfo(
            domain="a.example.com",
            record=["1.2.3.4"],
            type="A",
            ips=["1.2.3.4"],
        )
        port_result = [{
            "ip": "1.2.3.4",
            "port_info": [],
            "os_info": {},
            "_suspected_all_open": True,
        }]

        with patch.object(ScanPort, "get_cdn_name", return_value=""), \
                patch("app.tasks.domain.services.port_scan", return_value=port_result):
            result = ScanPort([domain_info], {"ports": "80"}).run()

        self.assertEqual(len(result), 1)
        dumped = result[0].dump_json(flag=False)
        self.assertNotIn("_suspected_all_open", dumped)


if __name__ == "__main__":
    unittest.main()
