"""爬虫与目录扫描接入共享发现上下文的回归测试。"""

import base64
import unittest
from unittest import mock

try:
    from app.services.discovery_context import DiscoveryContext
    from app.services import siteUrlSpider as spider_mod
    from app.services import fileLeak as leak_mod
    _IMPORT_ERROR = None
except Exception as exc:  # 运行依赖缺失时整体跳过，不误报失败
    DiscoveryContext = None
    spider_mod = None
    leak_mod = None
    _IMPORT_ERROR = exc


@unittest.skipIf(DiscoveryContext is None, "运行依赖未安装：{}".format(_IMPORT_ERROR))
class TestSiteSpiderDiscoveryContext(unittest.TestCase):
    """爬虫只消费/登记共享响应，不改写自身返回集合。"""

    class _FakeResponse:
        def __init__(self, status_code=200, headers=None, content=b""):
            self.status_code = status_code
            self.headers = headers or {}
            self.content = content

    def _dns_allow(self):
        return mock.patch.object(spider_mod.utils, "check_dns_policy_for_url", return_value=(True, {}))

    def test_cached_page_skips_network_and_registers_candidates(self):
        context = DiscoveryContext("task-1")
        html = b'<html><body><a href="/admin/login"></a><a href="https://other.com/x"></a></body></html>'
        context.put_response(
            "https://example.com/",
            request_profile="html_get",
            status_code=200,
            headers={"Content-Type": "text/html"},
            body=html,
            source="fetch_site",
            consumer="fetch_site",
        )

        with mock.patch.object(spider_mod.utils, "http_req") as http_req, self._dns_allow():
            spider = spider_mod.SiteURLSpider(
                ["https://example.com/"],
                deep_num=1,
                discovery_context=context,
            )
            result = spider._work("https://example.com/")

        self.assertEqual(0, http_req.call_count)
        crawl_urls = [info.crawl_url for info in result]
        self.assertIn("https://example.com/admin/login", crawl_urls)
        self.assertNotIn("https://other.com/x", crawl_urls)

        candidates = context.iter_candidates(candidate_type="url")
        self.assertEqual(1, len(candidates))
        self.assertEqual({"site_spider"}, candidates[0].sources)
        self.assertEqual(1, context.event_counts.get("UrlCandidateDiscovered", 0))
        # 消费 fetch_site 已登记的响应应命中缓存计数。
        self.assertGreaterEqual(context.metrics_snapshot()["cache_hit_count"], 1)

    def test_fresh_fetch_is_cached_for_other_strategies(self):
        context = DiscoveryContext("task-1")
        html = b'<html><head><title>t</title></head><body><a href="/about"></a></body></html>'
        fake = self._FakeResponse(200, {"Content-Type": "text/html"}, html)

        with mock.patch.object(spider_mod.utils, "http_req", return_value=fake) as http_req, self._dns_allow():
            spider = spider_mod.SiteURLSpider(
                ["https://example.com/"],
                deep_num=1,
                discovery_context=context,
            )
            spider._work("https://example.com/")

        self.assertEqual(1, http_req.call_count)
        cached = context.get_response(
            "https://example.com/",
            request_profile="html_get",
            consumer="urlfinder_extract",
        )
        self.assertIsNotNone(cached)
        self.assertEqual(200, cached.status_code)
        self.assertIn("site_spider", cached.consumers)

    def test_duplicate_links_register_single_candidate(self):
        context = DiscoveryContext("task-1")
        html = b'<html><body><a href="/x"></a><a href="/x">again</a><a href="/x">more</a></body></html>'
        fake = self._FakeResponse(200, {"Content-Type": "text/html"}, html)

        with mock.patch.object(spider_mod.utils, "http_req", return_value=fake), self._dns_allow():
            spider = spider_mod.SiteURLSpider(
                ["https://example.com/"],
                deep_num=1,
                discovery_context=context,
            )
            spider._work("https://example.com/")

        self.assertEqual(1, len(context.candidate_registry))
        self.assertEqual(1, context.event_counts.get("UrlCandidateDiscovered", 0))

    def test_skip_header_response_is_not_cached(self):
        context = DiscoveryContext("task-1")
        fake = self._FakeResponse(444, {"X-ARL-WAF-SMART-SKIP": "1"}, b"")

        with mock.patch.object(spider_mod.utils, "http_req", return_value=fake), self._dns_allow():
            spider = spider_mod.SiteURLSpider(
                ["https://example.com/"],
                deep_num=1,
                discovery_context=context,
            )
            result = spider._work("https://example.com/")

        self.assertEqual(0, len(result))
        self.assertEqual(0, len(context.response_registry))


@unittest.skipIf(leak_mod is None, "运行依赖未安装")
class TestFileLeakResponseReuse(unittest.TestCase):
    """目录扫描只消费同 profile 已完成覆盖的响应。"""

    def test_cached_response_consumed_without_network(self):
        body = b"User-agent: *\nDisallow: /private/"
        cache = {
            leak_mod.normal_url("https://example.com/robots.txt"): {
                "status_code": 200,
                "headers": {"Content-Type": "text/plain"},
                "body_b64": base64.b64encode(body).decode("ascii"),
            }
        }
        req = leak_mod.HTTPReq(
            leak_mod.URL("https://example.com/robots.txt", "robots.txt"),
            response_cache=cache,
        )

        with mock.patch.object(leak_mod.utils, "http_req", side_effect=AssertionError("must not hit network")) as http_req:
            status_code, content = req.req()

        self.assertEqual(200, status_code)
        self.assertEqual(body, content)
        http_req.assert_not_called()

    def test_skip_header_cache_entry_is_not_consumed(self):
        cache = {
            leak_mod.normal_url("https://example.com/backup.zip"): {
                "status_code": 444,
                "headers": {"X-ARL-WAF-SMART-SKIP": "1"},
                "body_b64": base64.b64encode(b"x").decode("ascii"),
            }
        }
        req = leak_mod.HTTPReq(
            leak_mod.URL("https://example.com/backup.zip", "backup.zip"),
            response_cache=cache,
        )
        self.assertIsNone(req._cached_conn())

    def test_response_cache_builder_only_exports_matching_urls(self):
        context = DiscoveryContext("task-1")
        context.put_response(
            "https://example.com/sitemap.xml",
            request_profile="html_get",
            status_code=200,
            headers={"Content-Type": "application/xml"},
            body=b"<urlset></urlset>",
            source="site_spider",
            consumer="site_spider",
        )
        target_urls = [
            leak_mod.URL("https://example.com/sitemap.xml", "sitemap.xml"),
            leak_mod.URL("https://example.com/never-fetched.sql", "never-fetched.sql"),
        ]

        cache = leak_mod._build_file_leak_response_cache(context, target_urls)

        self.assertIn(leak_mod.normal_url("https://example.com/sitemap.xml"), cache)
        self.assertEqual(1, len(cache))
        self.assertEqual(
            b"<urlset></urlset>",
            base64.b64decode(cache[leak_mod.normal_url("https://example.com/sitemap.xml")]["body_b64"]),
        )

    def test_directory_queue_block_skips_watchdog_target(self):
        context = DiscoveryContext("task-1")
        context.record_waf_signal("https://example.com/x", "directory", reason="child_block", force=True)
        urls = [leak_mod.URL("https://example.com/backup.zip", "backup.zip")]

        result = leak_mod._run_file_leak_site_with_watchdog(
            "https://example.com",
            urls,
            concurrency=2,
            site_timeout_sec=10,
            no_progress_timeout_sec=10,
            waf_guard=None,
            # popen 触发即失败：证明目录队列暂停发生在派生子进程之前。
            popen_factory=lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("must not spawn")),
            discovery_context=context,
        )

        metrics = getattr(result, "metrics", {}) or {}
        self.assertEqual("directory_waf_block", metrics.get("end_reason"))
        self.assertEqual(len(urls), metrics.get("pending_count"))


if __name__ == "__main__":
    unittest.main()
