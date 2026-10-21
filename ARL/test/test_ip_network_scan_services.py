"""IP 网络具体阶段服务回归测试。"""

import unittest
from types import SimpleNamespace

from app.services.ip_network_scan_services import (
    IPPortScanStageService,
    IPSiteDiscoveryStageService,
)


class _Collection(object):
    def __init__(self):
        self.items = []

    def insert_one(self, item):
        self.items.append(item)


class _Utils(object):
    def __init__(self):
        self.collection = _Collection()

    @staticmethod
    def not_in_black_ips(_value):
        return True

    @staticmethod
    def get_ip_type(_value):
        return "PUBLIC"

    @staticmethod
    def get_ip_asn(_value):
        return {"asn": "demo"}

    @staticmethod
    def get_ip_city(_value):
        return {"city": "demo"}

    def conn_db(self, _name):
        return self.collection


class _Services(object):
    def __init__(self):
        self.port_call = None
        self.http_call = None
        self.port_result = None

    def port_scan(self, targets, **kwargs):
        self.port_call = (targets, kwargs)
        return self.port_result or [
            {
                "ip": "192.0.2.10",
                "port_info": [],
                "os_info": {},
            }
        ]

    def check_http(self, urls):
        self.http_call = urls
        return {
            "http://192.0.2.10",
            "https://192.0.2.10",
            "http://192.0.2.10:8080",
            "https://192.0.2.10:8080",
        }


class TestIPNetworkScanServices(unittest.TestCase):
    def test_port_scan_keeps_options_enrichment_and_writeback(self):
        task = SimpleNamespace(
            options={
                "port_scan_type": "custom",
                "port_custom": "8080,8443",
                "service_detection": True,
                "os_detection": True,
                "port_parallelism": 96,
                "port_min_rate": 700,
                "host_timeout_type": "custom",
                "host_timeout": 120,
            },
            ip_target="192.0.2.10 192.0.2.11",
            ip_info_list=[],
            ip_set=set(),
            task_tag="task",
            task_id="task-1",
        )
        service_api = _Services()
        utils_api = _Utils()

        result = IPPortScanStageService(
            task,
            services_module=service_api,
            utils_module=utils_api,
            config=SimpleNamespace(
                PORT_PARALLELISM=32,
                PORT_MIN_RATE=300,
                HOST_TIMEOUT_TYPE="default",
                HOST_TIMEOUT=60,
            ),
        ).run()

        self.assertEqual(1, len(result))
        self.assertEqual(["192.0.2.10", "192.0.2.11"], service_api.port_call[0])
        self.assertEqual("8080,8443", service_api.port_call[1]["ports"])
        self.assertEqual(96, service_api.port_call[1]["port_parallelism"])
        self.assertEqual(120, service_api.port_call[1]["custom_host_timeout"])
        self.assertEqual({"192.0.2.10"}, task.ip_set)
        self.assertEqual("PUBLIC", result[0]["ip_type"])
        self.assertEqual(1, len(utils_api.collection.items))

    def test_internal_scan_marker_is_not_written_to_ip_results(self):
        task = SimpleNamespace(
            options={"port_scan": True},
            ip_target="192.0.2.10",
            ip_info_list=[],
            ip_set=set(),
            task_tag="task",
            task_id="task-2",
        )
        service_api = _Services()
        service_api.port_result = [{
            "ip": "192.0.2.10",
            "port_info": [],
            "os_info": {},
            "_suspected_all_open": True,
            "_scan_coverage": {"complete": True, "ports": "80", "scan_method": "connect"},
        }]
        utils_api = _Utils()

        result = IPPortScanStageService(
            task,
            services_module=service_api,
            utils_module=utils_api,
            config=SimpleNamespace(
                PORT_PARALLELISM=32,
                PORT_MIN_RATE=300,
                HOST_TIMEOUT_TYPE="default",
                HOST_TIMEOUT=60,
            ),
        ).run()

        self.assertTrue(result[0]["_suspected_all_open"])
        self.assertTrue(task.ip_info_list[0]["_suspected_all_open"])
        self.assertNotIn("_suspected_all_open", utils_api.collection.items[0])
        self.assertNotIn("_scan_coverage", utils_api.collection.items[0])

    def test_complete_connect_scan_reports_only_in_scope_existing_tcp_ports(self):
        scan_result = [{
            "ip": "192.0.2.10",
            "port_info": [{"port_id": 1211, "protocol": "tcp"}],
            "_scan_coverage": {
                "complete": True,
                "ports": "1211,1213,12285-12309,U:12289",
                "scan_method": "connect_fallback",
            },
        }]
        asset_map = {
            "192.0.2.10": {
                "port_info": [
                    {"port_id": 1211, "protocol": "tcp"},
                    {"port_id": 1213, "protocol": "tcp"},
                    {"port_id": 12200, "protocol": "tcp"},
                    {"port_id": 12289, "protocol": "udp"},
                ],
            },
        }

        IPPortScanStageService._attach_complete_connect_scan_evidence(
            scan_result,
            "1211,1213,12285-12309,U:12289",
            asset_map,
        )

        self.assertEqual(
            [{"protocol": "tcp", "port_id": 1213}],
            scan_result[0]["_connect_validation"]["not_open_ports"],
        )

    def test_partial_connect_scan_does_not_authorize_asset_cleanup(self):
        scan_result = [{
            "ip": "192.0.2.10",
            "port_info": [],
            "_scan_coverage": {
                "complete": False,
                "ports": "1211-1213",
                "scan_method": "connect_fallback",
            },
        }]

        IPPortScanStageService._attach_complete_connect_scan_evidence(
            scan_result,
            "1211-1213",
            {"192.0.2.10": {"port_info": [{"port_id": 1211, "protocol": "tcp"}]}},
        )

        self.assertNotIn("_connect_validation", scan_result[0])

    def test_completed_connect_target_without_open_hosts_still_cleans_asset(self):
        class _ScanResult(list):
            scan_coverage = {
                "ports": "1211,1213",
                "completed_targets": {"192.0.2.10": "connect_fallback"},
            }

        scan_result = _ScanResult()
        asset_map = {
            "192.0.2.10": {
                "port_info": [
                    {"port_id": 1211, "protocol": "tcp"},
                    {"port_id": 12200, "protocol": "tcp"},
                ],
            },
        }

        IPPortScanStageService._attach_complete_connect_scan_evidence(
            scan_result,
            "1211,1213",
            asset_map,
        )

        self.assertEqual(1, len(scan_result))
        self.assertEqual("192.0.2.10", scan_result[0]["ip"])
        self.assertEqual(
            [{"protocol": "tcp", "port_id": 1211}],
            scan_result[0]["_connect_validation"]["not_open_ports"],
        )

    def test_completed_connect_ip_range_matches_assets_without_open_host_rows(self):
        class _ScanResult(list):
            scan_coverage = {
                "ports": "1211",
                "completed_targets": {"192.0.2.10-20": "connect"},
            }

        scan_result = _ScanResult()
        asset_map = {
            "192.0.2.15": {
                "port_info": [{"port_id": 1211, "protocol": "tcp"}],
            },
            "192.0.2.21": {
                "port_info": [{"port_id": 1211, "protocol": "tcp"}],
            },
        }

        IPPortScanStageService._attach_complete_connect_scan_evidence(
            scan_result,
            "1211",
            asset_map,
        )

        self.assertEqual(["192.0.2.15"], [item["ip"] for item in scan_result])
        self.assertEqual(
            [{"protocol": "tcp", "port_id": 1211}],
            scan_result[0]["_connect_validation"]["not_open_ports"],
        )

    def test_overlapping_completed_targets_prefer_connect_coverage(self):
        class _ScanResult(list):
            scan_coverage = {
                "ports": "1211",
                "completed_targets": {
                    "192.0.2.0/24": "syn",
                    "192.0.2.15": "connect_fallback",
                },
            }

        scan_result = _ScanResult()
        asset_map = {
            "192.0.2.15": {
                "port_info": [{"port_id": 1211, "protocol": "tcp"}],
            },
        }

        IPPortScanStageService._attach_complete_connect_scan_evidence(
            scan_result,
            "1211",
            asset_map,
        )

        self.assertEqual(["192.0.2.15"], [item["ip"] for item in scan_result])
        self.assertEqual(
            "connect_fallback",
            scan_result[0]["_scan_coverage"]["scan_method"],
        )
        self.assertEqual(
            [{"protocol": "tcp", "port_id": 1211}],
            scan_result[0]["_connect_validation"]["not_open_ports"],
        )

    def test_site_discovery_prefers_https_per_endpoint(self):
        task = SimpleNamespace(
            ip_info_list=[
                {
                    "ip": "192.0.2.10",
                    "port_info": [
                        {"port_id": 80},
                        {"port_id": 443},
                        {"port_id": 8080},
                    ],
                }
            ],
            site_list=[],
        )
        service_api = _Services()

        result = IPSiteDiscoveryStageService(task, services_module=service_api).run()

        self.assertEqual(
            {
                "https://192.0.2.10",
                "https://192.0.2.10:8080",
            },
            set(result),
        )
        self.assertEqual(result, task.site_list)
        self.assertIn("http://192.0.2.10:8080", service_api.http_call)
        self.assertIn("https://192.0.2.10:8080", service_api.http_call)

    def test_site_discovery_normalizes_persisted_string_ports(self):
        task = SimpleNamespace(
            ip_info_list=[
                {
                    "ip": "192.0.2.11",
                    "port_info": [
                        {"port_id": "80"},
                        {"port_id": "443"},
                    ],
                }
            ],
            site_list=[],
        )

        candidates = IPSiteDiscoveryStageService(task)._build_candidates()

        self.assertEqual(
            {"http://192.0.2.11", "https://192.0.2.11"},
            set(candidates),
        )


if __name__ == "__main__":
    unittest.main()
