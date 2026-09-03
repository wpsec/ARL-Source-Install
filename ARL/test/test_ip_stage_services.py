"""IP 阶段服务边界回归测试。"""

import unittest

from app.services.ip_stage_services import IPNetworkStageService, IPPostProcessStageService


class _Executor(object):
    def __init__(self):
        self.names = []

    def execute(self, name, func, **kwargs):
        self.names.append(name)
        return func()


class _WebSiteFetch(object):
    def __init__(self):
        self.calls = []

    def risk_cruising(self, targets):
        self.calls.append(set(targets))


class _Task(object):
    def __init__(self, options=None):
        self.options = options or {}
        self.executor = _Executor()
        self.calls = []
        self.npoc_service_target_set = {"http://example.com:8080"}

    def _get_stage_executor(self):
        return self.executor

    def port_scan(self):
        self.calls.append("port_scan")

    def ssl_cert(self):
        self.calls.append("ssl_cert")

    def find_site(self):
        self.calls.append("find_site")

    def _enable_protocol_detection(self):
        return False

    def save_service_info(self):
        self.calls.append("save_service_info")

    def brute_config(self):
        self.calls.append("brute_config")


class TestIPStageServices(unittest.TestCase):
    def test_network_service_keeps_three_stage_order(self):
        task = _Task({"port_scan": True, "ssl_cert": True})

        result = IPNetworkStageService(task).run()

        self.assertEqual(["port_scan", "ssl_cert", "find_site"], task.executor.names)
        self.assertEqual(["port_scan", "ssl_cert", "find_site"], task.calls)
        self.assertEqual({"port_scan": None, "ssl_cert": None, "find_site": None}, result)

    def test_post_process_service_keeps_optional_risk_stages(self):
        task = _Task({"port_scan": True, "poc_config": True, "brute_config": True})
        web_site_fetch = _WebSiteFetch()

        IPPostProcessStageService(task, web_site_fetch).run()

        self.assertEqual(["poc_run", "weak_brute"], task.executor.names)
        self.assertEqual(["save_service_info", "brute_config"], task.calls)
        self.assertEqual([{"http://example.com:8080"}], web_site_fetch.calls)


if __name__ == "__main__":
    unittest.main()
