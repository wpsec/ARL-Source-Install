"""页面语义证据采集与恢复增强(新子域目录分发、Nuclei 账本)的回归测试。"""

import unittest
from types import SimpleNamespace

try:
    from app.services.page_semantics import (
        build_semantic_tags,
        enrich_page_item,
        extract_body_excerpt,
    )
    from app.services.discovery_context import DiscoveryContext
except Exception:
    build_semantic_tags = None


@unittest.skipIf(build_semantic_tags is None, "运行依赖未安装")
class TestPageSemantics(unittest.TestCase):
    def test_excerpt_strips_markup_and_caps_length(self):
        body = ("<script>var x=1</script>" + "<div>hello   world</div>" * 300).encode()
        excerpt = extract_body_excerpt(body, limit=120)
        self.assertLessEqual(len(excerpt), 120)
        self.assertNotIn("<div>", excerpt)
        self.assertNotIn("var x", excerpt)
        self.assertIn("hello world", excerpt)

    def test_binary_body_returns_empty_excerpt(self):
        self.assertEqual("", extract_body_excerpt(b"\x00\x01\x02binary"))

    def test_tags_are_weak_evidence_only(self):
        self.assertIn("auth_wall", build_semantic_tags(status_code=401))
        self.assertIn("not_found", build_semantic_tags(status_code=404))
        self.assertIn("server_error", build_semantic_tags(status_code=502))
        self.assertIn("login_page", build_semantic_tags(status_code=200, title="系统登录"))
        self.assertIn("static_asset", build_semantic_tags(content_type="image/png"))
        self.assertIn("api_json", build_semantic_tags(content_type="application/json", excerpt='{"a":1}'))
        self.assertIn("placeholder_page", build_semantic_tags(status_code=200, excerpt="Welcome to nginx!"))
        self.assertIn("empty_body", build_semantic_tags(status_code=200, excerpt=""))
        # 正常业务页不应产生任何形态标签
        self.assertEqual([], build_semantic_tags(status_code=200, title="订单管理", excerpt="共 12 条记录"))

    def test_enrich_preserves_existing_fields(self):
        item = {"title": "t", "url": "u", "content_length": 5, "status_code": 403}
        before = dict(item)

        enriched = enrich_page_item(item, body=b"<html>forbidden</html>", headers={"Content-Type": "text/html"})

        for key, value in before.items():
            self.assertEqual(value, enriched[key])
        self.assertEqual("forbidden", enriched["body_excerpt"])
        self.assertIn("auth_wall", enriched["semantic_tags"])

    def test_enrich_does_not_overwrite_existing_excerpt(self):
        item = {"status": 200, "body_excerpt": "kept", "semantic_tags": ["custom"]}

        enrich_page_item(item, body=b"ignored")

        self.assertEqual("kept", item["body_excerpt"])
        self.assertEqual(["custom"], item["semantic_tags"])

    def test_page_fetch_cached_shape_matches_live_shape(self):
        from app.services.pageFetch import PageFetch

        response = SimpleNamespace(
            body=b"<html><title>demo</title><div>login required</div></html>",
            status_code=200,
            headers={"Content-Type": "text/html"},
        )

        cached = PageFetch._cached_page_data("https://example.com/x", response)

        self.assertEqual(200, cached["status_code"])
        self.assertEqual("demo", cached["title"])
        self.assertEqual(len(response.body), cached["content_length"])
        self.assertIn("body_excerpt", cached)
        self.assertIn("login_page", cached["semantic_tags"])


@unittest.skipIf(build_semantic_tags is None, "运行依赖未安装")
class TestFileLeakDumpSemantics(unittest.TestCase):
    def test_dump_json_carries_evidence_fields(self):
        from app.services.fileLeak import Page, HTTPReq, URL

        req = HTTPReq(URL("https://example.com/.env", ".env"))
        req.status_code = 200
        req.content = b"APP_KEY=abc\nDB_PASSWORD=x"
        req.conn = SimpleNamespace(headers={"Content-Type": "application/octet-stream"})
        page = Page(req)

        item = page.dump_json()

        self.assertEqual("https://example.com/.env", item["url"])
        self.assertIn("body_excerpt", item)
        self.assertIn("APP_KEY", item["body_excerpt"])

    def test_site_document_semantics_via_fetch_like_flow(self):
        # fetchSite 在 item 组装处补字段；这里直接验证 enrich 对 site 字段形状（status 键）的兼容。
        item = {"site": "https://example.com", "status": 403, "title": "Forbidden", "body_length": 20}
        enrich_page_item(item, body=b"<html>403 forbidden</html>", headers={"Content-Type": "text/html"})
        self.assertIn("auth_wall", item["semantic_tags"])
        self.assertNotIn("status_code", item)


@unittest.skipIf(build_semantic_tags is None, "运行依赖未安装")
class TestNewHostDirectoryDispatch(unittest.TestCase):
    def _service(self, poc_sites, hosts, scope_domain=None, cap=10):
        from app.services.web_site_scan_stage_services import WebSiteFileLeakStageService
        from app.config import Config

        context = DiscoveryContext("task-1", allowed_hosts=scope_domain or ["example.com"])
        for host in hosts:
            context.register_candidate(
                event_type="NewHostDiscovered",
                candidate=host,
                candidate_type="host",
                source="page_intel",
            )
        task = SimpleNamespace(
            task_id="task-1",
            poc_sites=set(poc_sites),
            sites=scope_domain or ["example.com"],
            scope_domain=scope_domain or ["example.com"],
            discovery_context=context,
            _host_in_task_scope=lambda value: str(value or "").endswith("example.com"),
        )
        saved = {}
        for key in ("FILE_LEAK_NEW_HOST_ENABLE", "FILE_LEAK_NEW_HOST_MAX"):
            saved[key] = getattr(Config, key, None)
        setattr(Config, "FILE_LEAK_NEW_HOST_ENABLE", True)
        setattr(Config, "FILE_LEAK_NEW_HOST_MAX", cap)
        self._saved_config = saved
        return WebSiteFileLeakStageService(task), context

    def tearDown(self):
        from app.config import Config

        for key, value in getattr(self, "_saved_config", {}).items():
            if value is None:
                try:
                    delattr(Config, key)
                except AttributeError:
                    pass
            else:
                setattr(Config, key, value)

    def test_new_hosts_merged_once_and_capped(self):
        service, context = self._service(
            ["https://api.example.com"],
            ["www.example.com", "db.example.com", "evil.other.com"],
            cap=1,
        )

        merged = service._merge_new_host_targets(["https://api.example.com"])

        new_targets = [m for m in merged if m != "https://api.example.com"]
        # 候选按优先级/新鲜度排序，cap=1 时只能有一个同域新主机进入队列。
        self.assertEqual(1, len(new_targets))
        self.assertIn(new_targets[0], ("https://www.example.com", "https://db.example.com"))
        self.assertNotIn("https://evil.other.com", merged)  # 超范围

        # cap 未消费的 discovered 候选在下一轮合法补入；全部消费后输入原样透传。
        merged_again = service._merge_new_host_targets(merged)
        self.assertEqual(3, len(merged_again))
        self.assertIn("https://api.example.com", merged_again)
        self.assertIn("https://www.example.com", merged_again)
        self.assertIn("https://db.example.com", merged_again)
        merged_third = service._merge_new_host_targets(merged_again)
        self.assertEqual(merged_again, merged_third)

    def test_existing_host_not_duplicated(self):
        service, _ = self._service(["https://www.example.com"], ["www.example.com"])
        merged = service._merge_new_host_targets(["https://www.example.com"])
        self.assertEqual(["https://www.example.com"], list(merged))


@unittest.skipIf(build_semantic_tags is None, "运行依赖未安装")
class TestNucleiLedger(unittest.TestCase):
    class _Result(list):
        def __init__(self, values, metrics=None):
            super().__init__(values or [])
            self.metrics = dict(metrics or {})

    def _service(self, scan_metrics):
        from app.services.web_site_poc_stage_services import WebSiteNucleiScanStageService

        context = DiscoveryContext("task-1")
        calls = {"count": 0}
        targets = [{"target": "https://a.example.com", "finger": []}]

        def fake_scan(_targets, scan_profile=None):
            calls["count"] += 1
            return self._Result([{"target": "https://a.example.com", "info": 1}], metrics=scan_metrics)

        task = SimpleNamespace(
            task_id="task-1",
            discovery_context=context,
            _scan_result_in_task_scope=lambda item, target_keys=None: True,
            _result_item_service=SimpleNamespace(build_nuclei_document=lambda item: {"doc": 1}),
            _result_writer=SimpleNamespace(insert_one=lambda *args: None),
        )
        service = WebSiteNucleiScanStageService(task, scanner_factory=fake_scan)
        service.build_targets = lambda: list(targets)
        return service, context, calls, targets

    def test_success_marks_covered_and_rerun_skips(self):
        service, context, calls, targets = self._service({"status": "success", "end_reason": "completed"})

        service.run()
        service.run()

        self.assertEqual(1, calls["count"])
        self.assertIn("nuclei_scan", str(list(context.ledger._items.values())[0].idempotency_key))

    def test_partial_result_does_not_mark_covered(self):
        service, _context, calls, _targets = self._service({"status": "partial", "end_reason": "batch_degraded"})

        service.run()
        service.run()

        self.assertEqual(2, calls["count"])

    def test_no_discovery_context_runs_unconditionally(self):
        service, _context, calls, _targets = self._service({"status": "success"})
        service.task.discovery_context = None

        service.run()
        service.run()

        self.assertEqual(2, calls["count"])


if __name__ == "__main__":
    unittest.main()
