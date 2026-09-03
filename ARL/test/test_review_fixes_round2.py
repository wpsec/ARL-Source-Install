"""第二轮 review 修复的回归测试。

覆盖：
- #20 NewHostQueue 事件订阅→队列→WIH 注入→WAF scope 扩展闭环
- #23 single-flight 并发 miss 合并、put 唤醒、leader 失败释放
- #25 stage 超预算 success 强制降级 partial（经 finish_stage 观测）
- #27 favicon 复用 page_body / 响应缓存，不再二次请求
- #27 endpoint probe 调度租约 blocked 跳过
"""

import threading
import time
import unittest
from types import SimpleNamespace

try:
    from app.services.discovery_context import DiscoveryContext
    from app.services.discovery_queue import NewHostQueue
    from app.services.waf_guard import WAFSmartSkipGuard
except Exception:
    DiscoveryContext = None


@unittest.skipIf(DiscoveryContext is None, "运行依赖未安装")
class TestNewHostQueueClosure(unittest.TestCase):
    def test_event_feeds_queue_scope_and_wih_take(self):
        context = DiscoveryContext("task-1", allowed_hosts=["example.com"])
        guard = WAFSmartSkipGuard(
            enabled=True, smart_skip_enabled=True, task_id="t",
            scope_sites=["https://example.com"],
        )
        # 构造即订阅（max_hosts>0）
        queue = NewHostQueue(context, waf_guard=guard, max_hosts=3,
                             allowed_hosts={"example.com"})

        context.register_candidate(
            "NewHostDiscovered", "https://api.example.com/secret", "host", "page_intel")
        context.register_candidate(
            "NewHostDiscovered", "api.example.com", "host", "urlfinder")  # host 去重
        context.register_candidate(
            "NewHostDiscovered", "evil.other.com", "host", "page_intel")  # 非允许域

        self.assertEqual(["api.example.com"], queue.pending_hosts())
        self.assertIn("api.example.com", guard.scope_hosts)

        self.assertEqual(["https://api.example.com"], queue.take_for_wih())
        self.assertEqual([], queue.take_for_wih())

    def test_queue_cap_and_disabled(self):
        context = DiscoveryContext("task-1")
        queue_off = NewHostQueue(context, max_hosts=0)
        self.assertFalse(queue_off.enabled)
        context.register_candidate("NewHostDiscovered", "a.example.com", "host", "x")
        self.assertEqual([], queue_off.pending_hosts())

        context2 = DiscoveryContext("task-1")
        queue2 = NewHostQueue(context2, max_hosts=2)
        for i in range(5):
            context2.register_candidate(
                "NewHostDiscovered", "h%d.example.com" % i, "host", "x")
        self.assertEqual(2, len(queue2.pending_hosts()))
        self.assertEqual(3, context2.metrics_snapshot().get("new_host_queue_dropped_count"))
        self.assertEqual(2, context2.metrics_snapshot().get("new_host_discovered_count"))

    def test_handler_error_is_isolated(self):
        context = DiscoveryContext("task-1")
        boom = NewHostQueue(context, max_hosts=5)

        def _explode(event):
            raise RuntimeError("handler boom")

        context.subscribe_candidate_event("TestEvent", _explode)
        from app.services.discovery_context import DiscoveryEvent
        context.publish(DiscoveryEvent(
            event_type="TestEvent", candidate="x", candidate_key="k", source="t"))
        self.assertEqual(1, context.metrics_snapshot().get("event_listener_error_count"))
        # 队列自身仍工作
        context.register_candidate("NewHostDiscovered", "q.example.com", "host", "x")
        self.assertIn("q.example.com", boom.pending_hosts())


@unittest.skipIf(DiscoveryContext is None, "运行依赖未安装")
class TestSingleFlight(unittest.TestCase):
    def test_concurrent_miss_fetches_once(self):
        context = DiscoveryContext("task-1")
        fetch_count = {"n": 0}
        barrier = threading.Barrier(2)
        results = {}
        lock = threading.Lock()

        def worker(name):
            barrier.wait()
            cached, follower = context.await_singleflight_leader(
                "https://example.com/x", request_profile="html_get")
            if cached is not None:
                with lock:
                    results[name] = "cache"
                return
            if follower:
                with lock:
                    results[name] = "refetch"
                return
            time.sleep(0.2)
            with lock:
                fetch_count["n"] += 1
            context.put_response(
                "https://example.com/x", request_profile="html_get",
                status_code=200, body=b"ok", source="leader")
            with lock:
                results[name] = "fetched"

        threads = [threading.Thread(target=worker, args=(n,)) for n in ("a", "b")]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10)

        self.assertEqual(1, fetch_count["n"])
        self.assertEqual({"a", "b"}, set(results))
        self.assertIn("fetched", results.values())

    def test_leader_failure_releases_slot(self):
        context = DiscoveryContext("task-1")
        waiter = context.acquire_fetch_slot("https://example.com/y", request_profile="html_get")
        self.assertIsNone(waiter)
        context.release_fetch_slot("https://example.com/y", request_profile="html_get")
        waiter2 = context.acquire_fetch_slot("https://example.com/y", request_profile="html_get")
        self.assertIsNone(waiter2)

    def test_put_response_wakes_waiters(self):
        context = DiscoveryContext("task-1")
        self.assertIsNone(
            context.acquire_fetch_slot("https://example.com/z", request_profile="html_get"))
        order = []

        def follower():
            cached, _ = context.await_singleflight_leader(
                "https://example.com/z", request_profile="html_get", wait_sec=5)
            order.append("hit" if cached is not None else "miss")

        t = threading.Thread(target=follower)
        t.start()
        time.sleep(0.1)
        context.put_response("https://example.com/z", request_profile="html_get",
                             status_code=200, body=b"x", source="leader")
        t.join(6)
        self.assertEqual(["hit"], order)


class _CapturingUpdate(object):
    def __init__(self):
        self.finish_calls = []

    def update_task_field(self, *args, **kwargs):
        pass

    def append_service(self, *args, **kwargs):
        pass

    def start_stage(self, *args, **kwargs):
        return {"token": args[0] if args else kwargs.get("name")}

    def finish_stage(self, stage_context=None, *args, **kwargs):
        self.finish_calls.append(kwargs)


@unittest.skipIf(DiscoveryContext is None, "运行依赖未安装")
class TestStageBudgetDowngrade(unittest.TestCase):
    def _executor(self):
        from app.services.stage_executor import StageExecutor
        update = _CapturingUpdate()
        executor = StageExecutor(
            "task-1",
            base_update_task=update,
            logger=SimpleNamespace(
                info=lambda *a, **k: None,
                warning=lambda *a, **k: None,
                error=lambda *a, **k: None),
            # 真实接线中由 CommonTask._stage_result_metadata 提供；测试等价注入。
            result_metadata_provider=lambda result: (
                len(result) if isinstance(result, (list, set, dict)) else None,
                dict(getattr(result, "metrics", {}) or {})),
        )
        return executor, update

    def test_over_budget_success_becomes_partial(self):
        executor, update = self._executor()

        class _Res(list):
            def __init__(self):
                super().__init__([])
                self.metrics = {"status": "success", "end_reason": "completed"}

        def _slow():
            time.sleep(0.05)
            return _Res()

        executor.execute("slow_stage", _slow, budget_sec=0.001, log_kind="internal")
        self.assertEqual(1, len(update.finish_calls))
        call = update.finish_calls[0]
        self.assertEqual("partial", call.get("status"))
        self.assertEqual("budget_exceeded", call.get("end_reason"))
        self.assertTrue((call.get("metrics") or {}).get("budget_exceeded"))

    def test_error_status_not_upgraded(self):
        executor, update = self._executor()

        class _Res(list):
            def __init__(self):
                super().__init__([])
                self.metrics = {"status": "error", "end_reason": "mongo_timeout"}

        def _slow():
            time.sleep(0.05)
            return _Res()

        executor.execute("slow_stage2", _slow, budget_sec=0.001, log_kind="internal")
        call = update.finish_calls[0]
        self.assertEqual("error", call.get("status"))
        self.assertEqual("mongo_timeout", call.get("end_reason"))


@unittest.skipIf(DiscoveryContext is None, "运行依赖未安装")
class TestFaviconBodyReuse(unittest.TestCase):
    def test_icon_parsed_from_page_body_without_extra_request(self):
        from app.services import fetchSite as fetch_site_mod

        html = b'<html><head><link rel="icon" href="/brand.ico"></head><body>x</body></html>'
        calls = []

        class _R(object):
            def __init__(self, url):
                ok = url.endswith("brand.ico")
                self.status_code = 200 if ok else 404
                self.headers = {"Content-Type": "image/x-icon"}
                self.content = b"\x00\x01" * 60

        original_http = fetch_site_mod.http_req
        original_dns = fetch_site_mod.utils.check_dns_policy_for_url
        fetch_site_mod.http_req = lambda url, *a, **k: calls.append(url) or _R(url)
        fetch_site_mod.utils.check_dns_policy_for_url = lambda url, cache_map=None: (True, {})
        try:
            f = fetch_site_mod.FetchFavicon(
                "https://example.com/", page_body=html, waf_guard=None)
            result = f.run()
        finally:
            fetch_site_mod.http_req = original_http
            fetch_site_mod.utils.check_dns_policy_for_url = original_dns
        # 只探测 favicon.ico 与 brand.ico，绝不重新请求 "/"
        self.assertEqual(
            ["https://example.com/favicon.ico", "https://example.com/brand.ico"], calls)
        self.assertTrue(str(result.get("url", "")).endswith("brand.ico"))

    def test_favicon_response_cache_hit_skips_network(self):
        from app.services import fetchSite as fetch_site_mod
        from app.services.discovery_context import DiscoveryContext

        context = DiscoveryContext("task-1")
        context.put_response("https://example.com/favicon.ico",
                             request_profile="favicon_get", status_code=200,
                             headers={"Content-Type": "image/x-icon"},
                             body=b"\x00\x01" * 60, source="fetch_favicon")

        def fake_http(url, *a, **k):
            raise AssertionError("network must not be hit: " + str(url))

        original_http = fetch_site_mod.http_req
        original_dns = fetch_site_mod.utils.check_dns_policy_for_url
        fetch_site_mod.http_req = fake_http
        fetch_site_mod.utils.check_dns_policy_for_url = lambda url, cache_map=None: (True, {})
        try:
            f = fetch_site_mod.FetchFavicon(
                "https://example.com/", page_body=b"<html><body>y</body></html>",
                discovery_context=context)
            result = f.run()
        finally:
            fetch_site_mod.http_req = original_http
            fetch_site_mod.utils.check_dns_policy_for_url = original_dns
        self.assertTrue(str(result.get("url", "")).endswith("favicon.ico"))


@unittest.skipIf(DiscoveryContext is None, "运行依赖未安装")
class TestEndpointProbeScheduler(unittest.TestCase):
    def test_blocked_lease_skips_probe(self):
        from app.services import wih_endpoint_probe as probe_mod
        from app.services.discovery_context import DiscoveryContext

        context = DiscoveryContext("task-1")
        context.record_waf_signal("http://a.example.com/api", "wih", reason="unit", force=True)

        def _boom(*a, **k):
            raise AssertionError("network must not be hit")

        original = probe_mod.requests.request
        probe_mod.requests.request = _boom
        try:
            out = probe_mod._probe_one(
                {"url": "http://a.example.com/api", "method": "GET"},
                waf_guard=None, dns_policy_cache={}, discovery_context=context)
        finally:
            probe_mod.requests.request = original
        self.assertEqual("skipped", out.get("verification_status"))

    def test_probe_signature_default_context_none(self):
        import inspect
        from app.services import wih_endpoint_probe as probe_mod
        sig = inspect.signature(probe_mod._probe_one)
        self.assertIn("discovery_context", sig.parameters)
        self.assertIsNone(sig.parameters["discovery_context"].default)


if __name__ == "__main__":
    unittest.main()
