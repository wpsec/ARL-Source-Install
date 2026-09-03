"""域名阶段服务的边界回归测试。"""

import unittest
from unittest.mock import patch

from app.config import Config
from app.services.domain_stage_services import (
    DomainDiscoveryStageService,
    DomainNetworkStageService,
    DomainPostProcessStageService,
)


class _Executor(object):
    def __init__(self):
        self.names = []

    def execute(self, name, func, **kwargs):
        self.names.append(name)
        return func()


class _Task(object):
    def __init__(self, options=None):
        self.base_domain = "example.com"
        self.task_tag = "monitor"
        self.options = options or {}
        self.domain_info_list = []
        self._last_dns_query_metrics = {}
        self.executor = _Executor()
        self.calls = []

    def _get_stage_executor(self):
        return self.executor

    def update_task_field(self, field, value):
        self.calls.append(("update", field, value))

    def update_services(self, name, elapsed, metrics=None):
        self.calls.append(("service", name, metrics or {}))

    def domain_brute(self):
        self.calls.append("domain_brute")

    def build_single_domain_info(self, domain):
        self.calls.append(("build", domain))
        return "base-domain-info"

    def add_domain_source_map(self, values, source):
        self.calls.append(("source", source))

    def save_domain_info_list(self, values, source=None):
        self.calls.append(("save_domain", source))

    def dns_query_plugin(self):
        self.calls.append("dns_query_plugin")

    def arl_search(self):
        self.calls.append("arl_search")

    def alt_dns(self):
        self.calls.append("alt_dns")

    def gen_ipv4_map(self):
        self.calls.append("gen_ipv4_map")

    def port_scan(self):
        self.calls.append("port_scan")

    def ssl_cert(self):
        self.calls.append("ssl_cert")

    def save_ip_info(self):
        self.calls.append("save_ip_info")

    def _enable_protocol_detection(self):
        return False

    def save_service_info(self):
        self.calls.append("save_service_info")

    def find_vhost_vuln(self):
        self.calls.append("find_vhost_vuln")


class TestDomainStageServices(unittest.TestCase):
    def test_discovery_service_owns_discovery_stage_order(self):
        task = _Task({"domain_brute": True, "dns_query_plugin": True, "arl_search": True, "alt_dns": True})

        DomainDiscoveryStageService(task).run()

        self.assertEqual(
            ["domain_brute", "dns_query_plugin", "arl_search", "alt_dns"],
            [item for item in task.calls if isinstance(item, str)],
        )
        self.assertEqual(["domain_brute", "dns_query_plugin", "arl_search", "alt_dns"], [
            item[1] for item in task.calls if isinstance(item, tuple) and item[0] == "service"
        ])

    def test_network_service_keeps_port_and_certificate_as_separate_stages(self):
        task = _Task({"port_scan": True, "ssl_cert": True})
        with patch.object(Config, "CERT_PIVOT_QUERY_ENABLE", False):
            DomainNetworkStageService(task).run()

        self.assertEqual(["port_scan", "ssl_cert"], task.executor.names)
        self.assertEqual(["gen_ipv4_map", "port_scan", "ssl_cert", "save_ip_info"], task.calls)

    def test_post_process_service_does_not_run_disabled_stages(self):
        task = _Task({})

        DomainPostProcessStageService(task).run_poc()
        DomainPostProcessStageService(task).run_find_vhost()

        self.assertEqual([], task.calls)
        self.assertEqual([], task.executor.names)


if __name__ == "__main__":
    unittest.main()
