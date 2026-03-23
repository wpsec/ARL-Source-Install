import unittest
from unittest.mock import patch
from app.tasks.domain import scan_port
from app.modules import ScanPortType, DomainInfo
from app import services


class TestCDNName(unittest.TestCase):
    def test_scan_port(self):
        scan_port_option = {
            "ports": ScanPortType.TEST,
            "service_detect": False,
            "os_detect": False,
            "skip_scan_cdn_ip": False  # 跳过扫描CDN IP
        }
        domain_info = services.build_domain_info(['join.lianjia.com', 'gzh.qq.com'], concurrency=10)
        print(domain_info)

        self.assertTrue(len(domain_info) == 2)

        ip_info_list = scan_port(domain_info, scan_port_option)
        print(ip_info_list)
        for info in ip_info_list:
            self.assertTrue(info.cdn_name)

    def test_scan_port_skip(self):
        scan_port_option = {
            "ports": ScanPortType.TEST,
            "service_detect": False,
            "os_detect": False,
            "skip_scan_cdn_ip": True  # 跳过扫描CDN IP
        }
        domain_info = services.build_domain_info(['www.taobao.com', 'www.aliyun.com'], concurrency=10)
        self.assertTrue(len(domain_info) == 2)

        ip_info_list = scan_port(domain_info, scan_port_option)
        for info in ip_info_list:
            self.assertTrue(info.cdn_name)
            self.assertTrue(len(info.port_info_list) == 2)

    def test_scan_port_option_reuse_not_mutated(self):
        scan_port_option = {
            "ports": ScanPortType.TEST,
            "service_detect": False,
            "os_detect": False,
            "skip_scan_cdn_ip": False
        }
        domain_info = [
            DomainInfo(
                domain="example.com",
                record=["1.1.1.1"],
                type="A",
                ips=["1.1.1.1"]
            )
        ]
        fake_scan_result = [{
            "ip": "1.1.1.1",
            "port_info": [{
                "port_id": 80,
                "service_name": "http",
                "version": "",
                "protocol": "tcp",
                "product": ""
            }],
            "os_info": {}
        }]

        with patch("app.tasks.domain.services.port_scan", return_value=fake_scan_result) as mock_port_scan, \
                patch("app.tasks.domain.utils.get_cdn_name_by_ip", return_value=""), \
                patch("app.tasks.domain.utils.infer_cdn_by_dns", return_value=""):
            first = scan_port(domain_info, scan_port_option)
            second = scan_port(domain_info, scan_port_option)

        self.assertEqual(1, len(first))
        self.assertEqual(1, len(second))
        self.assertEqual(2, mock_port_scan.call_count)
        self.assertIn("skip_scan_cdn_ip", scan_port_option)


if __name__ == '__main__':
    unittest.main()
