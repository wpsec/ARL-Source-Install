import threading
import time
import unittest
from unittest.mock import patch

from app.config import Config
from app.modules import DomainInfo, PortInfo
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
        self.arguments = ""
        self.ports = ""

    def scan(self, hosts, ports, arguments, timeout=None):
        if timeout != 2:
            raise AssertionError("batch timeout was not forwarded")
        self.host = hosts.split()[0]
        self.arguments = arguments
        self.ports = ports
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
            "tcp": {
                80: {
                    "state": "open",
                    "reason": "syn-ack",
                    "name": "http",
                    "version": "",
                    "product": "",
                    "method": "table",
                    "conf": "3",
                }
            },
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
                scanner._build_nmap_arguments(),
                "single",
                force_batch_size=1,
                stage_timeout_sec=5,
            )

        self.assertFalse(timeout_hit)
        self.assertEqual({"a", "c", "d", "e"}, set(result))
        self.assertEqual(1, scanner.last_scan_metrics["failed_batch_count"])
        self.assertEqual(
            {"a": "syn", "c": "syn", "d": "syn", "e": "syn"},
            scanner._last_completed_scan_methods,
        )

    def test_nmap_reported_error_does_not_count_as_completed_coverage(self):
        class _ReportedErrorScanner(_FakeScanner):
            def scan(self, hosts, ports, arguments, timeout=None):
                super(_ReportedErrorScanner, self).scan(hosts, ports, arguments, timeout)
                return {"nmap": {"scaninfo": {"error": ["synthetic Nmap error"]}}}

        with patch.object(portScan.nmap, "PortScanner", _ReportedErrorScanner):
            scanner = portScan.PortScan(["a"], ports="80")
            result, timeout_hit = scanner._scan_with_batches(
                ["a"],
                "80",
                scanner._build_nmap_arguments(),
                "single",
                force_batch_size=1,
                stage_timeout_sec=5,
            )

        self.assertFalse(timeout_hit)
        self.assertEqual({}, result)
        self.assertEqual({}, scanner._last_completed_scan_methods)
        self.assertEqual(1, scanner.last_scan_metrics["failed_batch_count"])
        self.assertEqual({"NmapScanError": 1}, scanner.last_scan_metrics["failed_reasons"])

    def test_nmap_interrupted_exit_status_is_preserved_and_rejected(self):
        xml = (
            '<nmaprun args="nmap -sT -p 80 192.0.2.10">'
            '<scaninfo type="connect" protocol="tcp" services="80"/>'
            '<runstats><finished time="1" timestr="now" elapsed="0.1" '
            'summary="interrupted" exit="error" errormsg="scan interrupted"/>'
            '<hosts up="0" down="1" total="1"/></runstats></nmaprun>'
        )
        scanner = portScan.nmap.PortScanner.__new__(portScan.nmap.PortScanner)

        result = scanner.analyse_nmap_xml_scan(nmap_xml_output=xml)

        self.assertEqual("error", result["nmap"]["scanstats"]["exit"])
        self.assertEqual("scan interrupted", result["nmap"]["scanstats"]["errormsg"])
        self.assertTrue(portScan.PortScan._nmap_scan_errors(result))

    def test_nmap_xml_service_method_reaches_port_normalization(self):
        xml = (
            '<nmaprun args="nmap -sV -p 12302-12303 192.0.2.10">'
            '<scaninfo type="connect" protocol="tcp" services="12302-12303"/>'
            '<host><status state="up" reason="user-set"/>'
            '<address addr="192.0.2.10" addrtype="ipv4"/><ports>'
            '<port protocol="tcp" portid="12302"><state state="open" reason="syn-ack"/>'
            '<service name="rads" method="table" conf="3"/></port>'
            '<port protocol="tcp" portid="12303"><state state="open" reason="syn-ack"/>'
            '<service name="custom-proto" method="probed" conf="10" product="Custom"/></port>'
            '</ports></host>'
            '<runstats><finished time="1" timestr="now" elapsed="0.1" exit="success"/>'
            '<hosts up="1" down="0" total="1"/></runstats></nmaprun>'
        )
        scanner = portScan.nmap.PortScanner.__new__(portScan.nmap.PortScanner)
        scanner.analyse_nmap_xml_scan(nmap_xml_output=xml)
        port_scanner = portScan.PortScan(["192.0.2.10"], ports="12302-12303")

        result = port_scanner._extract_scan_result(scanner, scan_method="syn")
        ports = {item["port_id"]: item for item in result[0]["port_info"]}

        self.assertEqual("table", ports[12302]["nmap_service_method"])
        self.assertEqual("rads", ports[12302]["nmap_service_table_name"])
        self.assertEqual("", ports[12302]["service_name"])
        self.assertEqual("probed", ports[12303]["nmap_service_method"])
        self.assertEqual("custom-proto", ports[12303]["service_name"])
        self.assertEqual("Custom", ports[12303]["product"])

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

    def test_completed_connect_scan_keeps_coverage_when_no_hosts_have_open_ports(self):
        class _NoOpenConnectScanner(_FakeScanner):
            def all_hosts(self):
                return []

        with patch.object(Config, "PORT_SCAN_SYN_ENABLE", False):
            scanner = portScan.PortScan(["a"], ports="80")
        with patch.object(portScan.nmap, "PortScanner", _NoOpenConnectScanner):
            result = scanner.run()

        self.assertEqual([], result)
        self.assertEqual(
            {"a": "connect"},
            result.scan_coverage["completed_targets"],
        )

    def test_suspected_all_open_ports_are_connect_verified(self):
        class _AllOpenScanner(_FakeScanner):
            calls = []

            def scan(self, hosts, ports, arguments, timeout=None):
                type(self).calls.append((ports, arguments))
                super(_AllOpenScanner, self).scan(hosts, ports, arguments, timeout=timeout)

            def __getitem__(self, host):
                return _HostData({
                    "tcp": {
                        port: {
                            "state": "open",
                            "reason": "syn-ack",
                            "name": "",
                            "version": "",
                            "product": "",
                            "method": "table",
                            "conf": "3",
                        }
                        for port in range(1, 1001)
                    },
                    "osmatch": [],
                })

        scanner = portScan.PortScan(["a"], ports="0-65535")
        with patch.object(portScan.nmap, "PortScanner", _AllOpenScanner):
            result = scanner.run()

        self.assertEqual(1000, len(result[0]["port_info"]))
        self.assertTrue(result[0]["_suspected_all_open"])
        self.assertEqual(
            {
                "complete": True,
                "ports": "0-65535",
                "scan_method": "syn",
            },
            result[0]["_scan_coverage"],
        )
        self.assertEqual(
            {"a": "syn"},
            result.scan_coverage["completed_targets"],
        )
        self.assertEqual(1, result[0]["port_info"][0]["port_id"])
        self.assertTrue(all(item["verified"] for item in result[0]["port_info"]))
        self.assertTrue(all(item["scan_method"] == "connect_validation" for item in result[0]["port_info"]))
        self.assertTrue(any("-sT" in arguments.split() for _, arguments in _AllOpenScanner.calls))
        self.assertEqual(1000, result.metrics["connect_validation_verified_count"])

    def test_custom_dense_run_drops_syn_only_false_open_ports(self):
        candidate_ports = [1211, 1213] + [
            port for port in range(12285, 12310)
            if port not in {12291, 12295, 12304}
        ]

        class _MixedScanner(_FakeScanner):
            calls = []

            def scan(self, hosts, ports, arguments, timeout=None):
                type(self).calls.append((ports, arguments))
                super(_MixedScanner, self).scan(hosts, ports, arguments, timeout=timeout)

            def __getitem__(self, host):
                if "-sT" in self.arguments.split():
                    ports = [12300]
                    reason = "syn-ack"
                else:
                    ports = candidate_ports
                    reason = "syn-ack"
                return _HostData({
                    "tcp": {
                        port: {
                            "state": "open",
                            "reason": reason,
                            "name": "rads" if port == 12302 else "",
                            "version": "",
                            "product": "",
                            "method": "table",
                            "conf": "3",
                        }
                        for port in ports
                    },
                    "osmatch": [],
                })

        scanner = portScan.PortScan(
            ["a"],
            ports="1211,1213,12285-12309",
        )
        with patch.object(portScan.nmap, "PortScanner", _MixedScanner):
            result = scanner.run()

        self.assertEqual([12300], [item["port_id"] for item in result[0]["port_info"]])
        self.assertTrue(result[0]["_suspected_all_open"])
        self.assertTrue(result[0]["port_info"][0]["verified"])
        self.assertEqual("connect_validation", result[0]["port_info"][0]["scan_method"])
        self.assertEqual(24, result.metrics["connect_validation_candidate_count"])
        self.assertEqual(23, result.metrics["connect_validation_not_open_count"])
        self.assertEqual(0, result.metrics["connect_validation_unverified_count"])
        self.assertEqual(
            {port for port in candidate_ports if port != 12300},
            {
                item["port_id"]
                for item in result[0]["_connect_validation"]["not_open_ports"]
            },
        )
        self.assertEqual("", result[0]["port_info"][0]["service_name"])

    def test_failed_connect_validation_drops_candidates_and_marks_scan_partial(self):
        class _FailedValidationScanner(_FakeScanner):
            def __getitem__(self, host):
                return _HostData({
                    "tcp": {
                        port: {
                            "state": "open",
                            "reason": "syn-ack",
                            "name": "",
                            "version": "",
                            "product": "",
                            "method": "table",
                            "conf": "3",
                        }
                        for port in range(1000, 1010)
                    },
                    "osmatch": [],
                })

            def scan(self, hosts, ports, arguments, timeout=None):
                if "-sT" in arguments.split():
                    raise RuntimeError("synthetic connect validation failure")
                return super(_FailedValidationScanner, self).scan(
                    hosts, ports, arguments, timeout=timeout
                )

        scanner = portScan.PortScan(["a"], ports="1000-1009")
        with patch.object(portScan.nmap, "PortScanner", _FailedValidationScanner):
            result = scanner.run()

        self.assertEqual([], result[0]["port_info"])
        self.assertEqual(10, result.metrics["connect_validation_unverified_count"])
        self.assertEqual(0, result.metrics["connect_validation_not_open_count"])
        self.assertEqual(1, result.metrics["connect_validation_error_count"])
        self.assertEqual("partial", result.metrics["status"])
        self.assertEqual([], result[0]["_connect_validation"]["not_open_ports"])

    def test_nmap_reported_validation_error_does_not_mark_ports_closed(self):
        class _ReportedValidationErrorScanner(_FakeScanner):
            def __getitem__(self, host):
                return _HostData({
                    "tcp": {
                        port: {
                            "state": "open",
                            "reason": "syn-ack",
                            "name": "",
                            "version": "",
                            "product": "",
                            "method": "table",
                            "conf": "3",
                        }
                        for port in range(1000, 1010)
                    },
                    "osmatch": [],
                })

            def scan(self, hosts, ports, arguments, timeout=None):
                super(_ReportedValidationErrorScanner, self).scan(hosts, ports, arguments, timeout)
                if "-sT" in arguments.split():
                    return {"nmap": {"scaninfo": {"error": ["synthetic Nmap error"]}}}
                return None

        scanner = portScan.PortScan(["a"], ports="1000-1009")
        with patch.object(portScan.nmap, "PortScanner", _ReportedValidationErrorScanner):
            result = scanner.run()

        self.assertEqual([], result[0]["port_info"])
        self.assertEqual(10, result.metrics["connect_validation_unverified_count"])
        self.assertEqual(0, result.metrics["connect_validation_not_open_count"])
        self.assertEqual(1, result.metrics["connect_validation_error_count"])
        self.assertEqual("partial", result.metrics["status"])
        self.assertEqual([], result[0]["_connect_validation"]["not_open_ports"])

    def test_nmap_ambiguous_states_are_not_persisted_as_open(self):
        class _StateScanner(_FakeScanner):
            def __getitem__(self, host):
                return _HostData({
                    "tcp": {
                        80: {
                            "state": "open",
                            "reason": "syn-ack",
                            "name": "http",
                            "method": "probed",
                            "conf": "10",
                        },
                        81: {"state": "open|filtered", "reason": "no-response", "method": "table", "conf": "3"},
                        82: {"state": "unfiltered", "reason": "reset", "method": "table", "conf": "3"},
                    83: {"state": "open", "reason": "syn-ack", "name": "rads", "method": "table", "conf": "3"},
                    },
                    "osmatch": [],
                })

        scanner = portScan.PortScan(["a"], ports="80-83")
        state_scanner = _StateScanner()
        state_scanner.host = "a"
        with patch.object(portScan.nmap, "PortScanner", _StateScanner):
            result = scanner._extract_scan_result(state_scanner, scan_method="syn")

        self.assertEqual([80, 83], [item["port_id"] for item in result[0]["port_info"]])
        self.assertEqual("probed", result[0]["port_info"][0]["nmap_service_method"])
        self.assertEqual("10", result[0]["port_info"][0]["nmap_service_confidence"])
        self.assertEqual(90, result[0]["port_info"][0]["service_confidence"])
        self.assertEqual(["nmap_service_name"], result[0]["port_info"][0]["service_sources"])
        self.assertEqual("", result[0]["port_info"][1]["service_name"])
        self.assertEqual("table", result[0]["port_info"][1]["nmap_service_method"])
        self.assertEqual("rads", result[0]["port_info"][1]["nmap_service_table_name"])

    def test_port_info_serializes_scan_evidence(self):
        dumped = PortInfo(
            port_id=443,
            state="open",
            reason="syn-ack",
            scan_method="connect_validation",
            verified=True,
            nmap_service_method="probed",
            nmap_service_confidence="10",
            nmap_service_table_name="",
            service_confidence=100,
            service_sources=["npoc_scheme"],
        ).dump_json(flag=False)

        self.assertEqual("open", dumped["state"])
        self.assertEqual("syn-ack", dumped["reason"])
        self.assertTrue(dumped["verified"])
        self.assertEqual("connect_validation", dumped["scan_method"])
        self.assertEqual(100, dumped["service_confidence"])
        self.assertEqual(["npoc_scheme"], dumped["service_sources"])

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
            "_connect_validation": {"not_open_ports": []},
            "_scan_coverage": {"complete": True, "ports": "80", "scan_method": "connect"},
        }]

        with patch.object(ScanPort, "get_cdn_name", return_value=""), \
                patch("app.tasks.domain.services.port_scan", return_value=port_result):
            result = ScanPort([domain_info], {"ports": "80"}).run()

        self.assertEqual(len(result), 1)
        dumped = result[0].dump_json(flag=False)
        self.assertNotIn("_suspected_all_open", dumped)
        self.assertNotIn("_connect_validation", dumped)
        self.assertNotIn("_scan_coverage", dumped)


if __name__ == "__main__":
    unittest.main()
