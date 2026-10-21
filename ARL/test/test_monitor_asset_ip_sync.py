"""监控资产端口结果的有证据校正测试。"""

import unittest
from unittest.mock import patch

from app.tasks import scheduler


class _Collection(object):
    def __init__(self):
        self.updates = []
        self.inserts = []

    def update_one(self, query, update):
        self.updates.append((query, update))

    def insert_one(self, document):
        self.inserts.append(document)


class _Utils(object):
    def __init__(self):
        self.collections = {
            "asset_ip": _Collection(),
            "ip": _Collection(),
        }

    def conn_db(self, name):
        return self.collections[name]

    @staticmethod
    def curr_date_obj():
        return "now"


def _executor(asset_ip_info, ip_info_list, asset_port_keys):
    executor = scheduler.IPExecutor.__new__(scheduler.IPExecutor)
    executor.task_tag = "monitor"
    executor.scope_id = "scope-1"
    executor.ip_info_list = ip_info_list
    executor.asset_ip_info_map = {asset_ip_info["ip"]: asset_ip_info}
    executor.asset_ip_port_set = set(asset_port_keys)
    return executor


class TestMonitorAssetIPSync(unittest.TestCase):
    def test_only_connect_verified_negative_ports_are_removed(self):
        ip = "192.0.2.10"
        asset_ip_info = {
            "_id": "asset-1",
            "ip": ip,
            "port_info": [
                {"port_id": 12309, "protocol": "tcp", "service_name": "rads"},
                {"port_id": 12309, "protocol": "udp", "service_name": "dns"},
            ],
        }
        executor = _executor(
            asset_ip_info,
            [{
                "ip": ip,
                "port_info": [],
                "_connect_validation": {
                    "not_open_ports": [{"port_id": 12309, "protocol": "tcp"}],
                },
            }],
            {(ip, "tcp", 12309), (ip, "udp", 12309)},
        )
        utils = _Utils()

        with patch.object(scheduler, "utils", utils):
            executor.async_ip_info()

        self.assertEqual(
            [{"port_id": 12309, "protocol": "udp", "service_name": "dns"}],
            asset_ip_info["port_info"],
        )
        self.assertEqual({(ip, "udp", 12309)}, executor.asset_ip_port_set)
        self.assertEqual(1, len(utils.collections["asset_ip"].updates))
        self.assertEqual([], utils.collections["ip"].inserts)

    def test_new_table_hint_clears_legacy_service_name_but_keeps_npoc_name(self):
        ip = "192.0.2.11"
        asset_ip_info = {
            "_id": "asset-2",
            "ip": ip,
            "port_info": [
                {
                    "port_id": 12302,
                    "protocol": "tcp",
                    "service_name": "rads",
                    # 旧版曾把 Nmap 端口表名称标成 nmap_service_name。
                    "service_confidence": 90,
                    "service_sources": ["nmap_service_name"],
                },
                {
                    "port_id": 12303,
                    "protocol": "tcp",
                    "service_name": "custom-proto",
                    "service_sources": ["npoc_scheme"],
                },
                {
                    "port_id": 12304,
                    "protocol": "tcp",
                    "service_name": "http",
                    "nmap_service_method": "probed",
                },
            ],
        }
        executor = _executor(
            asset_ip_info,
            [{
                "ip": ip,
                "port_info": [
                    {
                        "port_id": 12302,
                        "protocol": "tcp",
                        "service_name": "",
                        "nmap_service_method": "table",
                        "nmap_service_table_name": "rads",
                        "state": "open",
                    },
                    {
                        "port_id": 12303,
                        "protocol": "tcp",
                        "service_name": "",
                        "nmap_service_method": "table",
                        "nmap_service_table_name": "custom-proto",
                        "state": "open",
                    },
                    {
                        "port_id": 12304,
                        "protocol": "tcp",
                        "service_name": "",
                        "nmap_service_method": "table",
                        "nmap_service_table_name": "http",
                        "state": "open",
                    },
                ],
            }],
            {(ip, "tcp", 12302), (ip, "tcp", 12303), (ip, "tcp", 12304)},
        )
        utils = _Utils()

        with patch.object(scheduler, "utils", utils):
            executor.async_ip_info()

        self.assertEqual("", asset_ip_info["port_info"][0]["service_name"])
        self.assertEqual("custom-proto", asset_ip_info["port_info"][1]["service_name"])
        self.assertEqual(["npoc_scheme"], asset_ip_info["port_info"][1]["service_sources"])
        self.assertEqual("http", asset_ip_info["port_info"][2]["service_name"])
        self.assertEqual(1, len(utils.collections["asset_ip"].updates))

    def test_unverified_or_unscanned_ports_are_retained(self):
        ip = "192.0.2.12"
        existing_port = {"port_id": 12309, "protocol": "tcp", "service_name": "rads"}
        asset_ip_info = {
            "_id": "asset-3",
            "ip": ip,
            "port_info": [existing_port],
        }
        executor = _executor(
            asset_ip_info,
            [{
                "ip": ip,
                "port_info": [],
                "_connect_validation": {"not_open_ports": []},
            }],
            {(ip, "tcp", 12309)},
        )
        utils = _Utils()

        with patch.object(scheduler, "utils", utils):
            executor.async_ip_info()

        self.assertEqual([existing_port], asset_ip_info["port_info"])
        self.assertEqual([], utils.collections["asset_ip"].updates)


if __name__ == "__main__":
    unittest.main()
