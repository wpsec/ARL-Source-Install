"""WebSiteFetch 高层阶段编排测试。"""

import unittest

from app.modules import WebSiteFetchOption
from app.services.web_site_fetch_orchestrator import WebSiteFetchOrchestrator


class _Task(object):
    def __init__(self):
        self.task_id = "65f000000000000000000001"
        self.options = {}
        self.calls = []
        self._nuclei_deferred_retry_needed = False
        self._nuclei_final_skip = False

    def run_func(self, name, func):
        self.calls.append(("stage", name))
        func()

    def fetch_site(self):
        self.calls.append("fetch_site")

    def site_identify(self):
        self.calls.append("site_identify")

    def save_site_info(self):
        self.calls.append("save_site_info")

    def _save_waf_skip_summary(self):
        self.calls.append("waf_summary")


class TestWebSiteFetchOrchestrator(unittest.TestCase):
    def test_minimal_flow_keeps_fetch_identify_and_persist_order(self):
        task = _Task()
        WebSiteFetchOrchestrator(task).run()

        self.assertEqual(
            [
                ("stage", "fetch_site"),
                "fetch_site",
                ("stage", "site_identify"),
                "site_identify",
                "save_site_info",
                "waf_summary",
            ],
            task.calls,
        )

    def test_file_leak_option_adds_stage_without_changing_prefix(self):
        task = _Task()
        task.options[WebSiteFetchOption.FILE_LEAK] = True
        task.file_leak = lambda: task.calls.append("file_leak")

        WebSiteFetchOrchestrator(task).run()

        self.assertEqual(
            ["fetch_site", "site_identify", "save_site_info", "file_leak"],
            [item for item in task.calls if isinstance(item, str) and item != "waf_summary"],
        )


if __name__ == "__main__":
    unittest.main()
