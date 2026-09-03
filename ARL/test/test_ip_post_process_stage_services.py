"""IP 后置具体 stage 服务回归测试。"""

import unittest
from types import SimpleNamespace

from app.services.ip_post_process_stage_services import (
    IPBruteConfigStageService,
    IPNPOCServiceDetectionStageService,
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
    def curr_date():
        return "now"

    def conn_db(self, _name):
        return self.collection


class TestIPPostProcessStageServices(unittest.TestCase):
    def test_npoc_stage_persists_targets_and_marks_source(self):
        utils_api = _Utils()
        task = SimpleNamespace(
            task_id="task-1",
            npoc_service_target_set=set(),
            _build_sniffer_targets=lambda full_port: (
                ["192.0.2.10:8080"],
                1,
                1,
                "smart",
            ),
            _apply_npoc_service_result=lambda result: 1,
        )
        calls = []

        result = IPNPOCServiceDetectionStageService(
            task,
            utils_module=utils_api,
            sniffer=lambda targets, skip_common_http_ports: (
                calls.append((targets, skip_common_http_ports))
                or [{"target": "http://192.0.2.10:8080", "scheme": "http"}]
            ),
        ).run(full_port=False)

        self.assertEqual(1, len(result))
        self.assertEqual([(["192.0.2.10:8080"], True)], calls)
        self.assertEqual({"http://192.0.2.10:8080"}, task.npoc_service_target_set)
        self.assertEqual("npoc_sniffer", utils_api.collection.items[0]["source"])
        self.assertEqual("task-1", utils_api.collection.items[0]["task_id"])

    def test_brute_stage_uses_enabled_plugins_and_writes_results(self):
        utils_api = _Utils()
        task = SimpleNamespace(
            task_id="task-1",
            options={
                "brute_config": [
                    {"enable": True, "plugin_name": "ssh"},
                    {"enable": False, "plugin_name": "ftp"},
                ]
            },
            site_list=["https://example.com"],
            npoc_service_target_set={"http://192.0.2.10:22"},
        )
        calls = []

        result = IPBruteConfigStageService(
            task,
            utils_module=utils_api,
            risk_runner=lambda targets, plugins: (
                calls.append((targets, plugins))
                or [{"target": "https://example.com", "name": "demo"}]
            ),
        ).run()

        self.assertEqual(1, len(result))
        self.assertEqual(
            (
                ["https://example.com", "http://192.0.2.10:22"],
                ["ssh"],
            ),
            calls[0],
        )
        self.assertEqual("now", utils_api.collection.items[0]["save_date"])


if __name__ == "__main__":
    unittest.main()
