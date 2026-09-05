"""计划 6 第 2 批：API 请求复用 shadow 观测回归。

验证三件事：
- peek 无副作用（不动 consumers/LRU、不产生指标）；
- shadow 计数正确（总/唯一/重复/缓存命中/跨策略复用/期望网络）；
- 观测接线不改变现行输出：同一文档跨 Scanner 实例只发一次网络请求，
  记录集合与单次运行一致。
"""

import contextlib
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

ARL_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ARL_ROOT / "test" / "fixtures" / "api_unified"

if str(ARL_ROOT) not in sys.path:
    sys.path.insert(0, str(ARL_ROOT))

from test._api_unified_bootstrap import load_unified_modules  # noqa: E402

# 模块级(收集期)捕获真实引用:部分既有用例在 collection 期注入 fake app.utils 且不还原,
# 测试方法运行期再 import 会取到被污染的模块。
# bootstrap 在临时桩窗口内加载子模块(绕过 app.services 真实 __init__ 的 NPoC 等
# 重依赖),完成后还原 app / app.services 槽位,不留空壳桩污染
# `from app.services import X` 的既有用例(task_orchestrator 等)。
_captured = load_unified_modules()

utils = _captured["app.utils"]
_api_doc_module = _captured["app.services.api_doc_scan"]
shadow = _captured["app.services.api_unified_shadow"]
_probe_module = _captured["app.services.wih_endpoint_probe"]
DiscoveryContext = _captured["app.services.discovery_context"].DiscoveryContext

@contextlib.contextmanager
def _safe_domain_fns():
    """防既有用例遗留 fake app.utils 导致的 domain 函数内部重导入失败。"""

    with mock.patch.object(
        utils, "is_valid_domain", lambda value: "." in str(value or "")
    ), mock.patch.object(utils, "get_fld", lambda host: "example.com"):
        yield


DOC_URL = "https://api.example.com/v3/api-docs"
OPENAPI_TEXT = (FIXTURES / "openapi3_petstore.json").read_text(encoding="utf-8")


class _FakeResponse(object):
    def __init__(self, status_code=200, content=b"", headers=None):
        self.status_code = status_code
        self.content = content
        self.headers = headers or {"Content-Type": "application/json"}
        self.reason = "OK"
        self.encoding = "utf-8"


def _allow_dns(*_args, **_kwargs):
    return True, {"reason": ""}


class PeekTest(unittest.TestCase):
    def test_peek_has_no_side_effects(self):
        context = DiscoveryContext(task_id="peek-1")
        before = context.metrics_snapshot()
        self.assertIsNone(context.peek_response("https://a.example.com/x"))
        self.assertEqual(context.metrics_snapshot(), before, "peek miss 不得产生指标")

        context.put_response(
            url="https://a.example.com/x",
            request_profile="html_get",
            status_code=200,
            body=b"hello",
            source="page_fetch",
            consumer="page_fetch",
        )
        before_put = context.metrics_snapshot()
        snapshot = context.peek_response("https://a.example.com/x", request_profile="html_get")
        self.assertIsNotNone(snapshot)
        self.assertEqual(snapshot.consumers, {"page_fetch"})
        context.peek_response("https://a.example.com/x", request_profile="html_get")
        self.assertEqual(context.metrics_snapshot(), before_put, "peek 不得计入 hit/miss")
        # consumers 不因观测扩张：真实 get 才会登记。
        registry_item = context.response_registry.get(
            "https://a.example.com/x", request_profile="html_get"
        )
        self.assertEqual(registry_item.consumers, {"page_fetch"})
        context.get_response(
            "https://a.example.com/x", request_profile="html_get", consumer="api_doc_scan"
        )
        self.assertEqual(registry_item.consumers, {"page_fetch", "api_doc_scan"})
        # peek 快照与活记录解耦：后续 consumers 变化不回写快照。
        self.assertEqual(snapshot.consumers, {"page_fetch"})


class ShadowCounterTest(unittest.TestCase):
    def test_document_counters_and_cross_strategy(self):
        context = DiscoveryContext(task_id="shadow-doc-1")
        shadow.shadow_document_fetch_start(context, DOC_URL)
        metrics = context.metrics_snapshot()
        self.assertEqual(metrics["api_document_fetch_total"], 1)
        self.assertEqual(metrics["api_document_unique_total"], 1)
        self.assertEqual(metrics["api_document_expected_network_total"], 1)
        self.assertEqual(metrics.get("api_document_cache_hit_total", 0), 0)

        # 模拟页面链路先抓过同一文档：文档扫描的第二次尝试应为跨策略复用。
        context.put_response(
            url=DOC_URL,
            request_profile=shadow.LEGACY_SHARED_PROFILE,
            status_code=200,
            body=OPENAPI_TEXT.encode("utf-8"),
            source="page_fetch",
            consumer="page_fetch",
        )
        shadow.shadow_document_fetch_start(context, DOC_URL + "#frag")
        metrics = context.metrics_snapshot()
        self.assertEqual(metrics["api_document_fetch_total"], 2)
        self.assertEqual(metrics["api_document_repeat_total"], 1)
        self.assertEqual(metrics["api_document_cache_hit_total"], 1)
        self.assertEqual(metrics["api_document_cross_strategy_reuse_total"], 1)
        self.assertEqual(metrics["api_document_expected_network_total"], 1)

        # 统一 api_doc 桶落响应后：作为第 3 批切换生效的对照锚点。
        context.put_response(
            url=DOC_URL, request_profile=shadow.DOCUMENT_PROFILE, status_code=200, body=b"{}"
        )
        shadow.shadow_document_fetch_start(context, DOC_URL)
        metrics = context.metrics_snapshot()
        self.assertEqual(metrics["api_document_cross_bucket_hit_total"], 1)

        shadow.shadow_document_fetch_result(context, DOC_URL, ok=False)
        self.assertEqual(context.metrics_snapshot()["api_document_fetch_empty_total"], 1)

    def test_probe_counters(self):
        context = DiscoveryContext(task_id="shadow-probe-1")
        url = "https://api.example.com/v1/pets"
        shadow.shadow_probe_start(context, url, "GET", shadow.LEGACY_SHARED_PROFILE)
        metrics = context.metrics_snapshot()
        self.assertEqual(metrics["api_probe_total"], 1)
        self.assertEqual(metrics["api_probe_unique_total"], 1)
        self.assertEqual(metrics["api_probe_expected_network_total"], 1)

        context.put_response(
            url=url,
            request_profile=shadow.LEGACY_SHARED_PROFILE,
            status_code=200,
            body=b"ok",
            source="page_fetch",
            consumer="page_fetch",
        )
        shadow.shadow_probe_start(context, url, "GET", shadow.LEGACY_SHARED_PROFILE)
        metrics = context.metrics_snapshot()
        self.assertEqual(metrics["api_probe_repeat_total"], 1)
        self.assertEqual(metrics["api_probe_cache_hit_total"], 1)
        self.assertEqual(metrics["api_probe_cross_strategy_reuse_total"], 1)

        shadow.shadow_probe_failed(context)
        self.assertEqual(context.metrics_snapshot()["api_probe_failed_total"], 1)

    def test_none_and_broken_context_never_raise(self):
        shadow.shadow_document_fetch_start(None, DOC_URL)
        shadow.shadow_document_fetch_result(None, DOC_URL, ok=True)
        shadow.shadow_probe_start(None, DOC_URL)
        shadow.shadow_probe_failed(None)

        class _Broken(object):
            def record_metric(self, *_args, **_kwargs):
                raise RuntimeError("observer must not break scans")

            def peek_response(self, *_args, **_kwargs):
                raise RuntimeError("observer must not break scans")

        shadow.shadow_document_fetch_start(_Broken(), DOC_URL)
        shadow.shadow_probe_start(_Broken(), DOC_URL)
        shadow.shadow_probe_failed(_Broken())


class _NetworkCounter(object):
    def __init__(self, response_factory):
        self.calls = []
        self._response_factory = response_factory

    def __call__(self, url, method="get", **_kwargs):
        self.calls.append((url, method))
        return self._response_factory(url)


class ApiDocShadowWiringTest(unittest.TestCase):
    """同一文档跨 Scanner 实例（同一 context）只发一次真实请求，输出不变。"""

    def _make_scanner(self, context):
        with _safe_domain_fns():
            scanner = _api_doc_module.ApiDocScanner(
                sites=["https://api.example.com"],
                wih_records=[],
                waf_guard=None,
                discovery_context=context,
            )
        scanner._collect_seed_candidates = lambda: [DOC_URL]
        return scanner

    def test_shared_document_fetched_once(self):
        context = DiscoveryContext(task_id="wire-doc-1")
        counter = _NetworkCounter(
            lambda url: _FakeResponse(content=OPENAPI_TEXT.encode("utf-8"))
        )
        with mock.patch.object(utils, "http_req", counter), \
                mock.patch.object(utils, "check_dns_policy_for_url", _allow_dns):
            with _safe_domain_fns():
                first = self._make_scanner(context).run()
            with _safe_domain_fns():
                second = self._make_scanner(context).run()

        self.assertEqual(len(counter.calls), 1, "文档第二次运行必须走缓存")
        metrics = context.metrics_snapshot()
        self.assertEqual(metrics["api_document_fetch_total"], 2)
        self.assertEqual(metrics["api_document_unique_total"], 1)
        self.assertEqual(metrics["api_document_repeat_total"], 1)
        self.assertEqual(metrics["api_document_cache_hit_total"], 1)
        self.assertEqual(metrics["api_document_expected_network_total"], 1)
        self.assertEqual(metrics["network_request_count"], 1)

        dump_key = lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False)
        first_dump = sorted((record.dump_json() for record in first), key=dump_key)
        second_dump = sorted((record.dump_json() for record in second), key=dump_key)
        self.assertEqual(first_dump, second_dump, "shadow 观测不得改变输出记录集合")
        self.assertTrue(any(r.recordType == "api_doc_url" for r in first))

    def test_metrics_survive_without_context(self):
        # discovery_context=None 的旧路径行为不变（无 context 不计数、不报错）。
        counter = _NetworkCounter(
            lambda url: _FakeResponse(content=OPENAPI_TEXT.encode("utf-8"))
        )
        with mock.patch.object(utils, "http_req", counter), \
                mock.patch.object(utils, "check_dns_policy_for_url", _allow_dns):
            with _safe_domain_fns():
                records = self._make_scanner(None).run()
        self.assertEqual(len(counter.calls), 1)
        self.assertTrue(records)


class EndpointProbeShadowWiringTest(unittest.TestCase):
    """同 URL 两次探测：第二次复用缓存响应，shadow 计数正确，探测结果字段一致。"""

    def test_same_endpoint_probed_once(self):
        probe = _probe_module
        context = DiscoveryContext(task_id="wire-probe-1")
        calls = []

        def fake_request(method, url, **_kwargs):
            calls.append((method, url))
            return _FakeResponse(status_code=200, content=b'{"ok":true}')

        item = {"url": "https://api.example.com/v1/pets", "method": "GET"}
        with mock.patch.object(probe.requests, "request", fake_request), \
                mock.patch.object(probe.utils, "check_dns_policy_for_url", _allow_dns):
            first = probe._probe_one(dict(item), discovery_context=context)
            second = probe._probe_one(dict(item), discovery_context=context)

        self.assertEqual(len(calls), 1)
        self.assertEqual(first["verification_status"], "probed")
        self.assertEqual(second["verification_status"], "probed")
        self.assertIn("复用", second.get("verification_note", ""))
        metrics = context.metrics_snapshot()
        self.assertEqual(metrics["api_probe_total"], 2)
        self.assertEqual(metrics["api_probe_unique_total"], 1)
        self.assertEqual(metrics["api_probe_repeat_total"], 1)
        self.assertEqual(metrics["api_probe_cache_hit_total"], 1)

    def test_probe_failure_counted(self):
        probe = _probe_module
        context = DiscoveryContext(task_id="wire-probe-2")

        def boom(method, url, **_kwargs):
            raise OSError("connection refused")

        item = {"url": "https://api.example.com/v1/flaky", "method": "GET"}
        with mock.patch.object(probe.requests, "request", boom), \
                mock.patch.object(probe.utils, "check_dns_policy_for_url", _allow_dns):
            result = probe._probe_one(item, discovery_context=context)

        self.assertEqual(result["verification_status"], "error")
        self.assertEqual(context.metrics_snapshot()["api_probe_failed_total"], 1)


if __name__ == "__main__":
    unittest.main()
