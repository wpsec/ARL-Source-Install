"""WebSiteFetch 高层阶段编排测试。"""

import unittest
from unittest import mock

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


    def test_finalization_decision_exposed_for_host_owner(self):
        task = _Task()
        WebSiteFetchOrchestrator(task).run()
        decision = task.last_finalization
        # 站点即唯一宿主（独立 WebSiteFetch/预览/PoC/监控）：收尾照常执行。
        # 无发现上下文的站点任务：契约不适用，决策 skipped→done。
        self.assertEqual(decision["verdict"], "skipped")
        self.assertEqual(decision["terminal_status"], "done")

    def test_host_owned_nested_flow_skips_site_finalizer(self):
        # Review P0.4：域名/IP 宿主置位后，嵌套站点层不得二次 drain/显影。
        task = _Task()
        task.terminal_finalize_host_owned = True
        with mock.patch(
            "app.services.web_site_fetch_orchestrator.TaskFinalizer",
        ) as finalizer_cls:
            WebSiteFetchOrchestrator(task).run()
        finalizer_cls.assert_not_called()
        self.assertEqual(task.last_finalization, {})


if __name__ == "__main__":
    unittest.main()
