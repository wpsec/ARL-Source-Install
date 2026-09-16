import unittest
from unittest.mock import patch

from app.helpers.message_notify import _extract_alert_domain
from app import modules
from app.services.fetchCert import SSLCert, _build_cert_scan_targets, _build_target_info


class TestSSLMultiSNIScan(unittest.TestCase):
    """SSL 多SNI扫描与域名选择逻辑测试。"""

    def test_build_cert_scan_targets_should_include_default_and_sni(self):
        target_info = _build_target_info(
            endpoint="1.1.1.1:443",
            connect_host="1.1.1.1",
            port=443,
            domains=["b.example.com", "example.com", "a.example.com"],
            base_domain="example.com",
        )

        targets = _build_cert_scan_targets(target_info, max_sni_per_endpoint=2)
        self.assertGreaterEqual(len(targets), 3)
        self.assertEqual(targets[0].get("scan_mode"), "default")
        self.assertEqual(targets[0].get("sni_domain"), "")

        sni_domains = [item.get("sni_domain") for item in targets if item.get("scan_mode") == "sni"]
        self.assertEqual(len(sni_domains), 2)
        self.assertIn("example.com", sni_domains)

    def test_extract_alert_domain_should_prefer_item_sni_domain(self):
        cert_obj = {
            "extensions": {
                "subjectAltName": "DNS:legacy.example.com,DNS:backup.example.com"
            },
            "subject": {
                "common_name": "cn.example.com"
            },
        }

        domain = _extract_alert_domain(
            cert_obj=cert_obj,
            ip="1.1.1.1",
            port="443",
            item={
                "sni_domain": "api.example.com",
                "domain": "unused.example.com",
                "domains": ["fallback.example.com"],
            },
            ip_domain_map={"1.1.1.1": ["legacy.example.com"]},
            task_domain_set={"legacy.example.com"},
        )
        self.assertEqual(domain, "api.example.com")

    @patch("app.services.fetchCert.fetch_cert", return_value={})
    def test_suspected_all_open_host_limits_certificate_endpoints(self, mock_fetch_cert):
        info = modules.IPInfo(
            ip="203.0.113.12",
            port_info=[
                modules.PortInfo(port_id=443),
                modules.PortInfo(port_id=12345),
                modules.PortInfo(port_id=23456),
            ],
            os_info={},
            domain=["all-open.example.com"],
            cdn_name="",
        )
        info._suspected_all_open = True

        SSLCert([info], "example.com").run()

        targets = mock_fetch_cert.call_args.args[0]
        self.assertTrue(targets)
        self.assertEqual({443}, {item["port"] for item in targets})


if __name__ == "__main__":
    unittest.main()
