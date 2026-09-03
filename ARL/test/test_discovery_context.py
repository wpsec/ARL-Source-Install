"""任务级发现上下文回归测试。"""

import time
import unittest

from app.services.discovery_context import (
    DiscoveryContext,
    ResponseRegistry,
    register_intel_candidate,
    traffic_class_for_module,
)


class TestDiscoveryContext(unittest.TestCase):
    def test_response_is_reused_across_strategies(self):
        context = DiscoveryContext("task-1", allowed_hosts=["example.com"])
        context.put_response(
            "https://EXAMPLE.com:443/page#fragment",
            status_code=200,
            content_type="text/html",
            body="<html>",
            source="fetch_site",
            consumer="fetch_site",
        )

        response = context.get_response(
            "https://example.com/page",
            consumer="crawler",
        )

        self.assertIsNotNone(response)
        self.assertEqual("https://example.com/page", response.normalized_url)
        self.assertEqual(b"<html>", response.body)
        self.assertEqual(1, context.metrics_snapshot()["cache_hit_count"])
        self.assertEqual(1, context.metrics_snapshot()["cross_strategy_reuse_count"])

    def test_candidate_sources_merge_without_duplicate_event(self):
        context = DiscoveryContext("task-1", allowed_hosts=["example.com"])
        events = []
        context.subscribe("UrlCandidateDiscovered", events.append)

        first = context.register_candidate(
            "UrlCandidateDiscovered",
            "https://example.com/admin#section",
            "url",
            "site_spider",
        )
        second = context.register_candidate(
            "UrlCandidateDiscovered",
            "https://example.com/admin",
            "url",
            "urlfinder_js",
        )

        self.assertEqual(first.candidate_key, second.candidate_key)
        self.assertEqual({"site_spider", "urlfinder_js"}, second.sources)
        self.assertEqual(1, len(events))
        self.assertEqual(1, context.metrics_snapshot()["candidate_source_merge_count"])

    def test_ledger_claim_is_idempotent_and_failed_work_can_retry(self):
        context = DiscoveryContext("task-1")
        key = context.idempotency_key(
            "crawler",
            "https://example.com/page",
            scan_profile="normal",
            input_signature="hash-1",
        )

        self.assertTrue(context.ledger.claim(key, input_count=1))
        self.assertFalse(context.ledger.claim(key, input_count=1))
        context.ledger.finish(key, "failed", input_count=1, error=RuntimeError("test"))
        self.assertTrue(context.ledger.claim(key, input_count=1))

    def test_directory_waf_breaker_does_not_block_crawler(self):
        context = DiscoveryContext("task-1", waf_threshold=2)
        context.record_waf_signal("https://example.com/a", "directory", "blocked")
        context.record_waf_signal("https://example.com/b", "directory", "blocked")

        self.assertFalse(context.waf_policy.allow("https://example.com/c", "directory"))
        self.assertTrue(context.waf_policy.allow("https://example.com/c", "crawler"))

        context.record_waf_signal("https://example.com/d", "crawler", "host block", host_wide=True)
        self.assertFalse(context.waf_policy.allow("https://example.com/e", "crawler"))
        self.assertFalse(context.waf_policy.allow("https://example.com/e", "wih"))

    def test_scheduler_isolates_traffic_class_capacity(self):
        context = DiscoveryContext("task-1")
        context.request_scheduler = context.request_scheduler.__class__(
            context,
            limits={"normal": 1, "directory": 1},
            per_host_limit=2,
        )

        normal_lease = context.request_scheduler.acquire("https://example.com", "normal")
        self.assertIsNotNone(normal_lease)
        self.assertIsNone(context.request_scheduler.acquire("https://example.com/2", "normal"))
        directory_lease = context.request_scheduler.acquire("https://example.com/admin", "directory")
        self.assertIsNotNone(directory_lease)

        normal_lease.release()
        directory_lease.release()
        self.assertIsNotNone(context.request_scheduler.acquire("https://example.com/3", "normal"))


    def test_page_fetched_event_emitted_once_per_response(self):
        context = DiscoveryContext("task-1")
        events = []
        context.subscribe("PageFetched", events.append)

        context.put_response(
            "https://example.com/a",
            status_code=200,
            body="<html>a</html>",
            source="fetch_site",
            consumer="fetch_site",
        )
        context.put_response(
            "https://example.com/a",
            status_code=200,
            body="<html>a</html>",
            source="site_spider",
            consumer="site_spider",
        )

        self.assertEqual(1, len(events))
        self.assertEqual(1, context.event_counts.get("PageFetched", 0))

    def test_waf_signal_event_and_force_block_scoped_to_class(self):
        context = DiscoveryContext("task-1")
        events = []
        context.subscribe("WafSignalDetected", events.append)

        result = context.record_waf_signal("https://example.com/x", "directory", reason="child_block", force=True)

        self.assertTrue(result["blocked"])
        self.assertEqual(1, len(events))
        self.assertFalse(context.waf_policy.allow("https://example.com/any", "directory"))
        self.assertTrue(context.waf_policy.allow("https://example.com/any", "crawler"))
        self.assertEqual(1, context.metrics_snapshot()["waf_block_count"])

    def test_acquire_wait_times_out_then_reports_over_limit(self):
        context = DiscoveryContext("task-1")
        context.request_scheduler = context.request_scheduler.__class__(
            context,
            limits={"crawler": 1},
            per_host_limit=1,
        )

        held, reason = context.acquire_request("https://example.com/a", "crawler")
        self.assertIsNotNone(held)
        self.assertEqual("granted", reason)

        started = time.monotonic()
        second, second_reason = context.acquire_request(
            "https://example.com/b",
            "crawler",
            wait_sec=0.2,
        )
        elapsed = time.monotonic() - started

        self.assertIsNone(second)
        self.assertEqual("over_limit", second_reason)
        self.assertGreaterEqual(elapsed, 0.15)
        self.assertEqual(1, context.metrics_snapshot()["over_limit_request_count"])

        # 释放后新请求应立即获得配额。
        held.release()
        third, third_reason = context.acquire_request("https://example.com/c", "crawler", wait_sec=1.0)
        self.assertIsNotNone(third)
        self.assertEqual("granted", third_reason)

    def test_acquire_wait_blocked_reports_blocked(self):
        context = DiscoveryContext("task-1")
        context.record_waf_signal("https://example.com/x", "wih", reason="probe_block", force=True)

        lease, reason = context.acquire_request("https://example.com/y", "wih", wait_sec=0.1)
        self.assertIsNone(lease)
        self.assertEqual("blocked", reason)

    def test_response_registry_total_body_budget_evicts_oldest(self):
        registry = ResponseRegistry(max_entries=100, max_body_bytes=1024, max_total_body_bytes=2048)
        for index in range(5):
            registry.put(
                "https://example.com/page{}".format(index),
                body=b"x" * 900,
                source="fetch_site",
            )

        self.assertLessEqual(len(registry), 2)
        self.assertIsNone(registry.get("https://example.com/page0"))
        self.assertIsNotNone(registry.get("https://example.com/page4"))

    def test_traffic_class_for_module_mapping(self):
        cases = {
            "file_leak": "directory",
            "site_spider": "crawler",
            "site_spider_probe": "crawler",
            "urlfinder_extract": "wih",
            "page_intel_scan": "wih",
            "js_intel_scan": "wih",
            "wih_endpoint_probe": "wih",
            "site_screenshot": "browser",
            "fetch_site": "normal",
            "": "normal",
        }
        for module_name, expected in cases.items():
            self.assertEqual(expected, traffic_class_for_module(module_name), msg=module_name)

    def test_candidate_registry_evicts_oldest_over_cap(self):
        context = DiscoveryContext("task-1", candidate_max_entries=150)
        for index in range(200):
            context.register_candidate(
                "UrlCandidateDiscovered",
                "https://example.com/p/{}".format(index),
                "url",
                "site_spider",
            )

        self.assertEqual(150, len(context.candidate_registry))
        self.assertEqual(50, context.metrics_snapshot()["candidate_evicted_count"])
        oldest_key = context.candidate_registry.key("https://example.com/p/0", "url")
        newest_key = context.candidate_registry.key("https://example.com/p/199", "url")
        self.assertIsNone(context.candidate_registry.get(oldest_key))
        self.assertIsNotNone(context.candidate_registry.get(newest_key))

    def test_source_merge_refreshes_eviction_order(self):
        context = DiscoveryContext("task-1", candidate_max_entries=100)
        for index in range(100):
            context.register_candidate(
                "UrlCandidateDiscovered",
                "https://example.com/p/{}".format(index),
                "url",
                "site_spider",
            )
        # 对最早候选做来源合并应刷新其驱逐顺位：新淘汰的是 p1 而不是 p0。
        context.register_candidate(
            "UrlCandidateDiscovered",
            "https://example.com/p/0",
            "url",
            "urlfinder_extract",
        )
        context.register_candidate(
            "UrlCandidateDiscovered",
            "https://example.com/p/100",
            "url",
            "urlfinder_extract",
        )

        self.assertIsNotNone(
            context.candidate_registry.get(context.candidate_registry.key("https://example.com/p/0", "url"))
        )
        self.assertIsNone(
            context.candidate_registry.get(context.candidate_registry.key("https://example.com/p/1", "url"))
        )

    def test_register_intel_candidate_maps_record_types(self):
        context = DiscoveryContext("task-1")
        events = []
        context.subscribe("*", events.append)

        register_intel_candidate(context, "domain", "sub.example.com", "page_intel", "https://example.com")
        register_intel_candidate(context, "urlfinder_url", "https://example.com/api/v1/list", "urlfinder_extract")
        register_intel_candidate(context, "api_doc_url", "https://example.com/swagger", "js_intel_scan")
        register_intel_candidate(context, "secret", "AKIA123", "urlfinder_extract")
        register_intel_candidate(None, "domain", "ignored.example.com", "page_intel")

        event_types = [event.event_type for event in events]
        self.assertEqual(
            ["NewHostDiscovered", "UrlCandidateDiscovered", "EndpointCandidateDiscovered"],
            event_types,
        )
        statuses = [item.status for item in context.iter_candidates()]
        self.assertEqual(3, len(statuses))

    def test_candidate_status_transitions_via_helpers(self):
        context = DiscoveryContext("task-1")
        context.register_candidate(
            "UrlCandidateDiscovered",
            "https://example.com/api/a",
            "url",
            "urlfinder_extract",
        )

        updated = context.mark_candidate_status("https://example.com/api/a", "url", "fetched")
        self.assertIsNotNone(updated)
        self.assertEqual("fetched", updated.status)

        missing = context.mark_candidate_status("https://example.com/none", "url", "covered")
        self.assertIsNone(missing)

        covered = context.iter_candidates(candidate_type="url", status="fetched")
        self.assertEqual(1, len(covered))


if __name__ == "__main__":
    unittest.main()
