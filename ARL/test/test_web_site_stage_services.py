"""WebSiteFetch 阶段服务边界回归测试。"""

import unittest

from app.modules import WebSiteFetchOption
from app.services.web_site_stage_services import (
    WebSiteDiscoveryStageService,
    WebSiteExternalScanStageService,
    WebSiteIntelStageService,
    WebSitePostProcessStageService,
)


class _Task(object):
    def __init__(self, options=None):
        self.options = options or {}
        self.task_id = "task-demo"
        self.site_info_list = ["before"]
        self._nuclei_deferred_retry_needed = False
        self.calls = []

    def run_func(self, name, func):
        self.calls.append(("stage", name))
        return func()

    def fetch_site(self):
        self.calls.append("fetch_site")

    def update_page_url_set(self):
        self.calls.append("update_page_url_set")

    def site_spider(self):
        self.calls.append("site_spider")

    def site_identify(self):
        self.calls.append("site_identify")

    def save_site_info(self):
        self.calls.append("save_site_info")

    def site_screenshot(self):
        self.calls.append("site_screenshot")

    def file_leak(self):
        self.calls.append("file_leak")

    def run_ai_poc_scan_plan(self):
        self.calls.append("run_ai_poc_scan_plan")

    def _run_optional_ai_stage_best_effort(self, *args, **kwargs):
        self.calls.append("optional_ai_stage")
        return args[1]()

    def _handle_ai_poc_stage_degrade(self, *args, **kwargs):
        self.calls.append("handle_ai_poc_stage_degrade")

    def nuclei_scan(self):
        self.calls.append("nuclei_scan")

    def afrog_scan(self):
        self.calls.append("afrog_scan")

    def run_web_info_hunter(self):
        self.calls.append("run_web_info_hunter")

    def run_penetration_test(self):
        self.calls.append("run_penetration_test")

    def run_deferred_nuclei_scan(self):
        self.calls.append("run_deferred_nuclei_scan")

    def _save_waf_skip_summary(self):
        self.calls.append("save_waf_skip_summary")


class TestWebSiteStageServices(unittest.TestCase):
    def test_discovery_service_preserves_site_stage_order(self):
        task = _Task(
            {
                WebSiteFetchOption.SITE_SPIDER: True,
                WebSiteFetchOption.SITE_CAPTURE: True,
            }
        )

        WebSiteDiscoveryStageService(task).run()

        self.assertEqual(
            [
                "fetch_site",
                "update_page_url_set",
                "site_spider",
                "site_identify",
                "save_site_info",
                "site_screenshot",
            ],
            [item for item in task.calls if isinstance(item, str)],
        )
        self.assertEqual([], task.site_info_list)

    def test_external_scan_service_keeps_optional_stage_order(self):
        task = _Task(
            {
                WebSiteFetchOption.FILE_LEAK: True,
                WebSiteFetchOption.NUCLEI_SCAN: True,
                WebSiteFetchOption.AFROG_SCAN: True,
            }
        )

        WebSiteExternalScanStageService(task).run()

        self.assertEqual(
            [
                "file_leak",
                "optional_ai_stage",
                "run_ai_poc_scan_plan",
                "nuclei_scan",
                "afrog_scan",
            ],
            [item for item in task.calls if isinstance(item, str)],
        )

    def test_intel_then_post_process_preserves_deferred_retry_order(self):
        task = _Task({WebSiteFetchOption.Info_Hunter: True})
        WebSiteIntelStageService(task).run()
        task.options[WebSiteFetchOption.PENETRATION_TEST] = True
        task._nuclei_deferred_retry_needed = True
        WebSitePostProcessStageService(task).run()

        self.assertEqual(
            [
                "run_web_info_hunter",
                "run_penetration_test",
                "run_deferred_nuclei_scan",
                "save_waf_skip_summary",
            ],
            [item for item in task.calls if isinstance(item, str)],
        )


if __name__ == "__main__":
    unittest.main()
