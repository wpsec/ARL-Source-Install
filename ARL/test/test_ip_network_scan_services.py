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

    def port_scan(self, targets, **kwargs):
        self.port_call = (targets, kwargs)
        return [
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


if __name__ == "__main__":
    unittest.main()
