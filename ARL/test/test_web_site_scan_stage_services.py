"""WebSiteFetch 具体阶段服务回归测试。"""

import unittest
from types import SimpleNamespace

from app.modules import WebSiteFetchOption
from app.services.web_site_scan_stage_services import (
    WebSiteFetchStageService,
    WebSiteFileLeakStageService,
    WebSiteIdentifyStageService,
    WebSiteScreenshotStageService,
    WebSiteSpiderStageService,
)


class _Services(object):
    def __init__(self):
        self.fetch_calls = []
        self.capture_call = None
        self.spider_call = None
        self.page_fetch_call = None
        self.file_leak_call = None
        self.analyze_call = None

    def fetch_site(self, sites, waf_guard=None):
        self.fetch_calls.append((sites, waf_guard))
        return [{"site": "https://example.com"}]

    def site_screenshot(self, sites, **kwargs):
        self.capture_call = (sites, kwargs)
        return {"captured": len(sites)}

    def site_spider_thread(self, entries, waf_guard=None):
        self.spider_call = (entries, waf_guard)
        return {
            "https://example.com": [
                "https://example.com/existing",
                "https://example.com/new.js",
            ]
        }

    def page_fetch(self, urls, **kwargs):
        self.page_fetch_call = (urls, kwargs)
        return {"https://example.com/new.js": {"status": 200}}

    def file_leak(self, sites, words, waf_guard=None, scan_profile="", **kwargs):
        self.file_leak_call = (sites, words, waf_guard)
        self.file_leak_scan_profile = scan_profile
        return [{"url": "https://example.com/.env", "status": 200}]

    def web_analyze(self, sites):
        self.analyze_call = sites
        return {"https://example.com": [{"name": "demo"}]}


class _URL(object):
    @staticmethod
    def normal_url(value):
        return value


class _Utils(object):
    url = _URL()

    @staticmethod
    def load_file(_path):
        return [".env", "robots.txt"]


class _Writer(object):
    def __init__(self):
        self.calls = []

    def insert_one(self, collection, item):
        self.calls.append(("insert_one", collection, item))

    def upsert_one(self, collection, key_document, document):
        self.calls.append(("upsert_one", collection, key_document, document))

    def delete_many(self, collection, query):
        self.calls.append(("delete_many", collection, query))


class _ResultItemService(object):
    @staticmethod
    def build_fileleak_document(page, site_scope_map):
        item = dict(page)
        item["site"] = site_scope_map["https://example.com"]
        return item


class TestWebSiteScanStageServices(unittest.TestCase):
    def test_identify_stage_filters_targets_before_fingerprint_call(self):
        task = SimpleNamespace(
            task_id="task-1",
            options={},
            web_analyze_map={},
            _build_site_identify_targets=lambda: [
                "https://example.com",
                "https://blocked.example.com",
            ],
            _filter_waf_blocked_targets=lambda targets, stage_name: [
                target for target in targets if "blocked" not in target
            ],
        )
        service_api = _Services()

        result = WebSiteIdentifyStageService(task, services_module=service_api).run()

        self.assertEqual({"https://example.com": [{"name": "demo"}]}, result)
        self.assertEqual(["https://example.com"], service_api.analyze_call)

    def test_fetch_stage_updates_site_info_and_available_sites(self):
        task = SimpleNamespace(
            sites=["https://seed.example.com"],
            waf_guard="guard",
            site_info_list=[],
            available_sites=[],
        )
        service_api = _Services()

        result = WebSiteFetchStageService(task, services_module=service_api).run()

        self.assertEqual([{"site": "https://example.com"}], result)
        self.assertEqual(["https://example.com"], task.available_sites)
        self.assertEqual(
            [(["https://seed.example.com"], "guard")],
            service_api.fetch_calls,
        )

    def test_spider_stage_deduplicates_urls_before_fetch_and_write(self):
        writer = _Writer()
        task = SimpleNamespace(
            task_id="task-1",
            available_sites=["https://example.com"],
            search_engines_result={"https://example.com": []},
            page_url_set={"https://example.com/existing"},
            waf_guard="guard",
            options={WebSiteFetchOption.Info_Hunter: True},
            _result_writer=writer,
        )
        service_api = _Services()

        result = WebSiteSpiderStageService(
            task,
            lambda url, task_id, source: {
                "url": url,
                "task_id": task_id,
                "source": source,
            },
            services_module=service_api,
        ).run()

        self.assertEqual(["https://example.com/new.js"], result)
        self.assertEqual(
            [("insert_one", "url", {
                "url": "https://example.com/new.js",
                "task_id": "task-1",
                "source": "site_spider",
                "status": 200,
            })],
            writer.calls,
        )
        self.assertIn("https://example.com/new.js", task.page_url_set)

    def test_file_leak_stage_preserves_scope_and_cleanup_write(self):
        writer = _Writer()
        task = SimpleNamespace(
            task_id="task-1",
            options={},
            poc_sites={"https://example.com"},
            waf_guard="guard",
            _result_writer=writer,
            _result_item_service=_ResultItemService(),
        )
        service_api = _Services()
        result = WebSiteFileLeakStageService(
            task,
            services_module=service_api,
            utils_module=_Utils(),
            config=SimpleNamespace(
                FILE_LEAK_TOP_2k="/tmp/default-dict",
                FILE_LEAK_TARGET_CONCURRENCY=4,
            ),
        ).run()

        self.assertEqual(1, len(result))
        self.assertEqual(
            (["https://example.com"], [".env", "robots.txt"], "guard"),
            service_api.file_leak_call,
        )
        self.assertEqual("fileleak", writer.calls[0][1])
        self.assertEqual("url", writer.calls[1][1])
        self.assertEqual(
            {"task_id": "task-1", "url": "https://example.com/.env"},
            writer.calls[1][2],
        )

    def test_screenshot_stage_keeps_task_scoped_output_directory(self):
        task = SimpleNamespace(
            task_id="task-1",
            available_sites=["https://example.com"],
        )
        service_api = _Services()

        result = WebSiteScreenshotStageService(
            task,
            services_module=service_api,
            config=SimpleNamespace(
                SCREENSHOT_DIR="/tmp/screenshots",
                SITE_SCREENSHOT_CONCURRENCY=3,
            ),
        ).run()

        self.assertEqual({"captured": 1}, result)
        self.assertEqual(
            (
                ["https://example.com"],
                {
                    "concurrency": 3,
                    "capture_dir": "/tmp/screenshots/task-1",
                    "task_id": "task-1",
                },
            ),
            service_api.capture_call,
        )


if __name__ == "__main__":
    unittest.main()
