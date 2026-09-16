import unittest
from unittest.mock import patch

from app.services.probe_policy import cap_http_probe_urls, select_probe_port_infos
from app.services import checkHTTP


class TestProbePolicy(unittest.TestCase):
    def test_suspected_all_open_keeps_web_ports_and_service_hints_only(self):
        ports = [
            {"port_id": 80},
            {"port_id": 443},
            {"port_id": 12345},
            {"port_id": 23456, "service_name": "http-proxy"},
        ]

        selected = select_probe_port_infos(
            ports,
            max_ports_per_host=3,
            suspected_all_open=True,
            probe_kind="http",
        )

        self.assertEqual([80, 443, 23456], [item["port_id"] for item in selected])

    def test_normal_hosts_keep_priority_before_other_ports(self):
        ports = [{"port_id": 12345}, {"port_id": 8080}, {"port_id": 443}]
        selected = select_probe_port_infos(ports, max_ports_per_host=2, probe_kind="http")
        self.assertEqual([443, 8080], [item["port_id"] for item in selected])

    def test_global_url_cap_is_deterministic_and_prioritizes_web_ports(self):
        urls = {
            "http://a.example:12345",
            "https://b.example:8080",
            "https://a.example",
            "http://b.example",
        }
        selected, dropped = cap_http_probe_urls(urls, max_candidates=2)
        self.assertEqual(["http://b.example", "https://a.example"], selected)
        self.assertEqual(2, dropped)

    def test_check_http_metrics_keep_raw_input_count_after_candidate_cap(self):
        raw_urls = [
            "http://a.example",
            "http://b.example",
            "http://a.example",
        ]

        with patch.object(checkHTTP.Config, "SITE_DISCOVERY_MAX_CANDIDATES", 1), patch.object(
            checkHTTP.CheckHTTP,
            "run",
            autospec=True,
            side_effect=lambda checker: dict(checker._metrics),
        ):
            metrics = checkHTTP.check_http(raw_urls, concurrency=1)

        self.assertEqual(3, metrics["candidate_input_count"])
        self.assertEqual(1, metrics["candidate_capped_count"])


if __name__ == "__main__":
    unittest.main()
