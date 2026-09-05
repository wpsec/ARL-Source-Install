"""计划 6 第 3 批：ApiCandidateRegistry + ApiDocumentQueue 回归。

验证口径（计划 6 §7.2/§8.1/§11.2、附录A §4.5 证据锚）：
- 注册表：URL 级去重与 sources 聚合（G8 替代面）、状态机合法边强制、
  Endpoint 资产同 URL 不同 method 不合并；
- 队列：JS/记录/候选图回流在当前任务内消费、单文档失败隔离、
  深度/数量/阶段时限预算闸、账本 covered 重投跳过、残余候选保持
  开放态供 finalizer 下一轮周期显影；
- 获取面：api_doc profile 桶 + html_get 镜像、*_cross_bucket_hit 转正、
  html_get 已有响应不再发第二次网络请求；
- 兼容面：flag 开/关记录集合与 legacy 一致（§十三.2 双写）、整体异常回退 legacy。
"""

import contextlib
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

ARL_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ARL_ROOT / "test" / "fixtures" / "api_unified"

if str(ARL_ROOT) not in sys.path:
    sys.path.insert(0, str(ARL_ROOT))


def _ensure_app_package():
    """仅防御 app 被既有用例换成无 __path__ 的 fake。

    不得桩 app.services：空壳包会让 __init__ 不执行，后续
    `from app.services import X` 全部失败（unknown location）。
    """
    app = sys.modules.get("app")
    if app is None or not hasattr(app, "__path__"):
        app = types.ModuleType("app")
        app.__path__ = [str(ARL_ROOT / "app")]
        sys.modules["app"] = app


_ensure_app_package()

# 收集期捕获真实模块引用，免疫既有用例注入 fake app.utils 不还原的污染。
from app import utils  # noqa: E402
from app.services import api_candidate_registry as reg  # noqa: E402
from app.services import api_doc_scan as _api_doc_module  # noqa: E402
from app.services import web_info_intel_utils as _intel_utils  # noqa: E402
from app.services.api_doc_scan import ApiDocScanner  # noqa: E402
from app.services.api_unified_models import (  # noqa: E402
    UNIFIED_API_CONFIG_DEFAULTS,
    UnifiedApiEndpoint,
)
from app.services.api_unified_shadow import shadow_document_fetch_start  # noqa: E402
from app.services.discovery_context import (  # noqa: E402
    DiscoveryContext,
    LedgerEntry,
    normalize_url,
)

DOC_URL = "https://api.example.com/v3/api-docs"
SITE = "https://api.example.com"
OPENAPI_TEXT = (FIXTURES / "openapi3_petstore.json").read_text(encoding="utf-8")


def _full_config(**overrides):
    config = dict(UNIFIED_API_CONFIG_DEFAULTS)
    config["API_UNIFIED_ENABLE"] = True
    config["API_UNIFIED_FALLBACK_ENABLE"] = True
    config.update(overrides)
    return config


@contextlib.contextmanager
def _safe_domain_fns():
    with mock.patch.object(
        utils, "is_valid_domain", lambda value: "." in str(value or "")
    ), mock.patch.object(utils, "get_fld", lambda host: "example.com"):
        yield


def _make_queue(context=None, fetch_map=None, sites=None, records=None, config=None):
    """构造注入 fetch 的队列：fetch_map[规范化URL] -> 正文；缺省空响应。"""

    scanner = ApiDocScanner(
        sites=sites or [SITE],
        wih_records=records or [],
        waf_guard=None,
        discovery_context=context,
    )
    registry = reg.ApiCandidateRegistry(task_id="t3", context=context)
    calls = []

    def fetch_fn(doc):
        calls.append(doc.url)
        return (fetch_map or {}).get(normalize_url(doc.url), "") or ""

    queue = reg.ApiDocumentQueue(
        scanner=scanner,
        registry=registry,
        context=context,
        config=_full_config(**(config or {})),
        fetch_fn=fetch_fn,
    )
    return queue, calls


def _record_tuple(record):
    return (
        str(getattr(record, "recordType", "") or getattr(record, "record_type", "")),
        str(getattr(record, "content", "") or ""),
    )


class RegistryTest(unittest.TestCase):
    def test_dedup_and_source_merge(self):
        context = DiscoveryContext(task_id="reg-1")
        registry = reg.ApiCandidateRegistry(task_id="reg-1", context=context)
        with _safe_domain_fns():
            doc_a, created_a = registry.register_document(DOC_URL, source="seed")
            doc_b, created_b = registry.register_document(DOC_URL, source="js_intel")
        self.assertTrue(created_a)
        self.assertFalse(created_b, "同一规范化 URL 不得产生第二消费单元")
        self.assertIs(doc_a, doc_b)
        self.assertEqual(doc_a.sources, {"seed", "js_intel"})
        self.assertEqual(registry.merged_source_count, 1)
        self.assertEqual(context.event_counts.get("ApiDocumentCandidateDiscovered", 0), 1)

    def test_transition_table_enforced(self):
        registry = reg.ApiCandidateRegistry(task_id="reg-2")
        with _safe_domain_fns():
            registry.register_document(DOC_URL, source="seed")
            self.assertIsNone(
                registry.mark_document(DOC_URL, "parsed"),
                "discovered→parsed 非合法边必须拒绝",
            )
            self.assertEqual(registry.document(DOC_URL).status, "discovered")
            for status in ("queued", "fetching", "fetched", "parsed"):
                self.assertIsNotNone(registry.mark_document(DOC_URL, status))
            self.assertEqual(registry.document(DOC_URL).status, "parsed")
            self.assertIsNone(registry.mark_document(DOC_URL, "queued"), "parsed 为终态")

    def test_pending_priority_order(self):
        registry = reg.ApiCandidateRegistry(task_id="reg-3")
        with _safe_domain_fns():
            registry.register_document("https://a.example.com/swagger.json", source="seed")
            registry.register_document(
                "https://b.example.com/swagger.json",
                source="js_intel",
                priority=reg._DOC_PRIORITY_EVIDENCE,
            )
        pending = registry.pending_documents()
        self.assertEqual(pending[0].url, "https://b.example.com/swagger.json")

    def test_endpoint_assets_method_distinct_and_sources(self):
        registry = reg.ApiCandidateRegistry(task_id="reg-4")
        ep_get = UnifiedApiEndpoint(url=DOC_URL, method="GET", source="doc1", parent_document="doc1")
        ep_post = UnifiedApiEndpoint(url=DOC_URL, method="POST", source="doc1", parent_document="doc1")
        ep_get2 = UnifiedApiEndpoint(url=DOC_URL, method="GET", source="doc2", parent_document="doc2")
        self.assertTrue(registry.register_endpoint(ep_get)[1])
        self.assertTrue(registry.register_endpoint(ep_post)[1], "同 URL 不同 method 必须独立资产")
        merged, created = registry.register_endpoint(ep_get2)
        self.assertFalse(created)
        self.assertEqual(merged.sources, {"doc1", "doc2"})
        self.assertEqual(registry.endpoint_deduplicated_count, 1)


class QueueTest(unittest.TestCase):
    def test_record_backflow_fetch_once_and_endpoints_emitted(self):
        context = DiscoveryContext(task_id="q-1")
        from app.modules import WihRecord

        doc_record = WihRecord(
            record_type="api_doc_url",
            content=DOC_URL,
            source="https://app.example.com/app.js",
            site="api.example.com",
            fnv_hash=0,
        )
        queue, calls = _make_queue(
            context=context,
            fetch_map={DOC_URL: OPENAPI_TEXT},
            records=[doc_record],
        )
        with _safe_domain_fns():
            records = queue.run(wih_records=[doc_record])
        self.assertEqual(calls.count(DOC_URL), 1, "seed+记录双来源必须只获取一次")
        doc = queue.registry.document(DOC_URL)
        self.assertEqual(doc.status, "parsed")
        self.assertIn("https://app.example.com/app.js", doc.sources)
        types_set = {_record_tuple(item)[0] for item in records}
        self.assertIn("api_doc_endpoint", types_set)
        self.assertIn("api_doc_url", types_set)
        self.assertGreater(queue.registry.endpoint_created_count, 0)
        self.assertGreater(context.metrics["api_document_parse_success_total"], 0)

    def test_graph_backflow_channel(self):
        context = DiscoveryContext(task_id="q-2")
        context.register_candidate(
            "EndpointCandidateDiscovered",
            DOC_URL,
            "endpoint",
            source="js_intel",
            metadata={"intel_record_type": "api_doc_url"},
        )
        queue, calls = _make_queue(context=context, fetch_map={DOC_URL: OPENAPI_TEXT})
        with _safe_domain_fns():
            queue.run(wih_records=[])
        self.assertEqual(calls.count(DOC_URL), 1)
        doc = queue.registry.document(DOC_URL)
        self.assertIn("js_intel", doc.sources)
        self.assertEqual(doc.priority, reg._DOC_PRIORITY_EVIDENCE)

    def test_per_document_failure_isolation(self):
        good_url = "https://api.example.com/openapi.json"
        bad_url = DOC_URL

        def fetch_fn(doc):
            url = normalize_url(doc.url)
            if url == normalize_url(bad_url):
                raise RuntimeError("boom")
            return OPENAPI_TEXT if url == normalize_url(good_url) else ""

        scanner = ApiDocScanner(sites=[SITE], wih_records=[], discovery_context=None)
        registry = reg.ApiCandidateRegistry(task_id="q-3")
        queue = reg.ApiDocumentQueue(
            scanner=scanner,
            registry=registry,
            context=None,
            config=_full_config(API_DOCUMENT_MAX_TARGETS=100),
            fetch_fn=fetch_fn,
        )
        with _safe_domain_fns():
            records = queue.run()
        self.assertEqual(queue.parse_failed_count, 1)
        self.assertEqual(queue.parse_success_count, 1)
        self.assertEqual(registry.document(bad_url).status, "failed")
        self.assertEqual(registry.document(good_url).status, "parsed")
        self.assertTrue(any(_record_tuple(item)[0] == "api_doc_endpoint" for item in records))

    def test_depth_budget_gate(self):
        seed_doc = "https://api.example.com/swagger.json"
        depth1 = "https://api.example.com/deep/api-docs.json"
        depth2 = "https://api.example.com/deeper/api-docs.json"
        html1 = "<html><body>window.url = '{}'</body></html>".format(depth1)
        html2 = "<html><body>window.url = '{}'</body></html>".format(depth2)
        queue, calls = _make_queue(
            fetch_map={seed_doc: html1, depth1: html2, depth2: OPENAPI_TEXT},
            config={"API_DOCUMENT_MAX_DEPTH": 1, "API_DOCUMENT_MAX_TARGETS": 100},
        )
        with _safe_domain_fns():
            queue.run()
        self.assertEqual(calls.count(normalize_url(seed_doc)), 1)
        self.assertEqual(calls.count(normalize_url(depth1)), 1, "max_depth=1 允许一层引用")
        self.assertNotIn(normalize_url(depth2), calls, "二层引用必须被深度闸拦截")
        self.assertGreaterEqual(queue.skipped_budget_count, 1)

    def test_targets_budget_gate(self):
        queue, calls = _make_queue(
            fetch_map={},
            config={"API_DOCUMENT_MAX_TARGETS": 2},
        )
        with _safe_domain_fns():
            queue.run()
        self.assertLessEqual(len(calls), 2)
        self.assertGreaterEqual(queue.skipped_budget_count, 1, "16 个种子路径只放行 2 个")

    def test_stage_timeout_leaves_residual_open(self):
        ticks = iter([0.0, 10 ** 9, 10 ** 9, 10 ** 9])
        scanner = ApiDocScanner(sites=[SITE], wih_records=[])
        registry = reg.ApiCandidateRegistry(task_id="q-5")
        queue = reg.ApiDocumentQueue(
            scanner=scanner,
            registry=registry,
            context=None,
            config=_full_config(API_DOCUMENT_STAGE_TIMEOUT_SEC=5),
            fetch_fn=lambda doc: "",
            clock=lambda: next(ticks),
        )
        with _safe_domain_fns():
            queue.run()
        self.assertTrue(queue.stage_timeout_stopped)
        self.assertEqual(queue.fetch_count, 0)
        self.assertGreater(len(registry.pending_documents()), 0, "预算耗尽不得伪造消费")

    def test_ledger_covered_resumed_skip(self):
        context = DiscoveryContext(task_id="q-6")
        key = context.idempotency_key("api_doc", DOC_URL, "api_doc", "")
        context.ledger.upsert(LedgerEntry(idempotency_key=key, status="covered"))
        queue, calls = _make_queue(context=context, fetch_map={DOC_URL: OPENAPI_TEXT})
        with _safe_domain_fns():
            queue.run()
        self.assertNotIn(DOC_URL, calls, "重投时已 covered 文档不得二次获取")
        self.assertEqual(queue.resumed_skip_count, 1)
        self.assertEqual(queue.registry.document(DOC_URL).status, "skipped")

    def test_ledger_url_unique_contract_locked(self):
        """Review P1.2 契约锁定：任务窗口内 URL 唯一、正文变化不重验。

        文档获取固定单 profile=`api_doc`、GET、无认证差异；重投轮次对已
        covered 的 URL 不再获取，即使正文已变化。改变该语义必须同步修订
        06-附录A §4.7 并改用 (profile, body-hash) 组合键。
        """
        other_text = (FIXTURES / "openapi3_petstore.yaml").read_text(encoding="utf-8")
        context = DiscoveryContext(task_id="q-7")
        queue_one, calls_one = _make_queue(context=context, fetch_map={DOC_URL: OPENAPI_TEXT})
        with _safe_domain_fns():
            queue_one.run()
        self.assertIn(DOC_URL, calls_one)
        key = context.idempotency_key("api_doc", DOC_URL, "api_doc", "")
        self.assertEqual(
            key, "q-7|api_doc|{}|api_doc|".format(DOC_URL),
            "键形态即契约：stage/target/profile 固定、input_signature 段恒空",
        )
        entry = context.ledger.get(key)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.status, "covered")

        queue_two, calls_two = _make_queue(context=context, fetch_map={DOC_URL: other_text})
        with _safe_domain_fns():
            queue_two.run()
        self.assertNotIn(
            DOC_URL, calls_two,
            "同 task_id 重投轮次不得因正文变化重验（契约边界，漂移由新任务周期覆盖）",
        )

    def test_output_floor_and_format_vs_legacy(self):
        """第 4 批口径：统一输出为 legacy 记录面超集（G1 只增不减），格式逐字段一致。

        第 3 批（legacy 解析复用）时两者严格相等；统一 Parser 接管后，
        新增面只允许是模板端点类补充记录（附录A §4.8）。
        """
        fetch_map = {DOC_URL: OPENAPI_TEXT}

        def fake_fetch_text(url, **_kwargs):
            return fetch_map.get(normalize_url(url), ""), None

        with _safe_domain_fns():
            with mock.patch.object(_api_doc_module, "fetch_text", fake_fetch_text):
                legacy = ApiDocScanner(sites=[SITE], wih_records=[]).run()
            queue, _calls = _make_queue(fetch_map=fetch_map)
            unified = queue.run()
        legacy_set = {_record_tuple(item) for item in legacy}
        unified_set = {_record_tuple(item) for item in unified}
        self.assertTrue(
            legacy_set.issubset(unified_set),
            "统一输出不得低于 legacy 基线: 缺 {}".format(sorted(legacy_set - unified_set)),
        )
        extra = unified_set - legacy_set
        self.assertTrue(all("{" in content for _, content in extra),
                        "增量面只允许 G1 模板端点补充")
        self.assertFalse(
            [c for t, c in unified_set if t == "urlfinder_url" and "{" in c],
            "模板 URL 不得流入 urlfinder_url",
        )


class FetchProfileTest(unittest.TestCase):
    class _FakeResponse:
        def __init__(self, status_code=200, content=b"", headers=None):
            self.status_code = status_code
            self.content = content
            self.headers = headers or {"Content-Type": "application/json"}

    def _allow_dns(*_args, **_kwargs):
        return True, {"reason": ""}

    def test_api_doc_bucket_with_html_get_mirror(self):
        context = DiscoveryContext(task_id="fp-1")
        calls = []

        def fake_http_req(url, method, **kwargs):
            calls.append(url)
            return self._FakeResponse(200, OPENAPI_TEXT.encode("utf-8"))

        with mock.patch.object(_intel_utils.utils, "http_req", fake_http_req), \
                mock.patch.object(_intel_utils.utils, "check_dns_policy_for_url", self._allow_dns):
            text, _ = _intel_utils.fetch_text(
                DOC_URL, discovery_context=context,
                request_profile="api_doc", mirror_html_get=True,
            )
        self.assertTrue(text)
        self.assertEqual(len(calls), 1)
        self.assertIsNotNone(context.response_registry.peek(DOC_URL, "GET", "api_doc"))
        self.assertIsNotNone(context.response_registry.peek(DOC_URL, "GET", "html_get"))
        self.assertEqual(context.event_counts.get("PageFetched", 0), 1, "镜像直写不得重复发布事件")

        with mock.patch.object(_intel_utils.utils, "http_req", fake_http_req), \
                mock.patch.object(_intel_utils.utils, "check_dns_policy_for_url", self._allow_dns):
            text2, _ = _intel_utils.fetch_text(
                DOC_URL, discovery_context=context,
                request_profile="api_doc", mirror_html_get=True,
            )
        self.assertTrue(text2)
        self.assertEqual(len(calls), 1, "统一桶命中不得二次发起网络请求")

    def test_html_get_only_cache_reused_without_request(self):
        context = DiscoveryContext(task_id="fp-2")
        context.put_response(
            url=DOC_URL, method="GET", request_profile="html_get",
            status_code=200, body=OPENAPI_TEXT.encode("utf-8"), source="crawler",
        )
        calls = []

        def fake_http_req(url, method, **kwargs):
            calls.append(url)
            return self._FakeResponse(200, b"never")

        with mock.patch.object(_intel_utils.utils, "http_req", fake_http_req), \
                mock.patch.object(_intel_utils.utils, "check_dns_policy_for_url", self._allow_dns):
            text, _ = _intel_utils.fetch_text(
                DOC_URL, discovery_context=context,
                request_profile="api_doc", mirror_html_get=True,
            )
        self.assertTrue(text)
        self.assertEqual(calls, [])
        self.assertIsNotNone(
            context.response_registry.peek(DOC_URL, "GET", "api_doc"),
            "html_get 复用结果必须回填统一桶供后续 profile 命中",
        )

    def test_cross_bucket_hit_anchor_flips(self):
        context = DiscoveryContext(task_id="fp-3")
        context.response_registry.put(
            url=DOC_URL, method="GET", request_profile="api_doc",
            status_code=200, body=b"{}", source="api_doc_scan",
        )
        before = int(context.metrics.get("api_document_cross_bucket_hit_total", 0) or 0)
        shadow_document_fetch_start(context, DOC_URL)
        after = int(context.metrics.get("api_document_cross_bucket_hit_total", 0) or 0)
        self.assertEqual(after - before, 1, "第 3 批接管获取后 api_doc 桶命中必须转正")

    def test_default_profile_behavior_unchanged(self):
        context = DiscoveryContext(task_id="fp-4")
        calls = []

        def fake_http_req(url, method, **kwargs):
            calls.append((url, method))
            return self._FakeResponse(200, b"hello")

        with mock.patch.object(_intel_utils.utils, "http_req", fake_http_req), \
                mock.patch.object(_intel_utils.utils, "check_dns_policy_for_url", self._allow_dns):
            text, _ = _intel_utils.fetch_text(DOC_URL, discovery_context=context)
        self.assertEqual(text, "hello")
        self.assertIsNotNone(context.peek_response(DOC_URL, "GET", "html_get"))
        self.assertIsNone(context.peek_response(DOC_URL, "GET", "api_doc"))


class PipelineTest(unittest.TestCase):
    def test_disabled_delegates_to_legacy(self):
        context = DiscoveryContext(task_id="p-1")
        legacy_calls = []

        def fake_run_api_doc_scan(*args, **kwargs):
            legacy_calls.append(args)
            return []

        config = dict(UNIFIED_API_CONFIG_DEFAULTS)
        config["API_UNIFIED_ENABLE"] = False
        with mock.patch.object(_api_doc_module, "run_api_doc_scan", fake_run_api_doc_scan):
            result = reg.run_api_document_pipeline(
                [SITE], [], discovery_context=context, config=config)
        self.assertEqual(result, [])
        self.assertEqual(len(legacy_calls), 1, "flag 关闭必须原样委托 legacy 链路")
        self.assertFalse(hasattr(context, "api_candidate_registry"))

    def test_fallback_on_unified_crash(self):
        context = DiscoveryContext(task_id="p-2")
        legacy_records = ["LEGACY"]

        def fake_run_api_doc_scan(*args, **kwargs):
            return list(legacy_records)

        config = _full_config()
        with mock.patch.object(_api_doc_module, "run_api_doc_scan", fake_run_api_doc_scan), \
                mock.patch.object(reg.ApiDocumentQueue, "run", side_effect=RuntimeError("queue crash")):
            result = reg.run_api_document_pipeline(
                [SITE], [], discovery_context=context, config=config)
        self.assertEqual(result, legacy_records)
        self.assertGreaterEqual(context.metrics.get("api_unified_fallback_total", 0), 1)

        config_no = _full_config(API_UNIFIED_FALLBACK_ENABLE=False)
        with mock.patch.object(_api_doc_module, "run_api_doc_scan", fake_run_api_doc_scan), \
                mock.patch.object(reg.ApiDocumentQueue, "run", side_effect=RuntimeError("queue crash")):
            with self.assertRaises(RuntimeError):
                reg.run_api_document_pipeline(
                    [SITE], [], discovery_context=context, config=config_no)

    def test_enabled_end_to_end_with_fetch_text(self):
        context = DiscoveryContext(task_id="p-3")
        fetch_map = {DOC_URL: OPENAPI_TEXT}

        def fake_fetch_text(url, **kwargs):
            text = fetch_map.get(normalize_url(url), "")
            profile = kwargs.get("request_profile", "html_get")
            if text:
                context.response_registry.put(
                    url=url, method="GET", request_profile=profile,
                    status_code=200, body=text.encode("utf-8"), source="api_doc_scan",
                )
            return text, None

        # _default_fetch 延迟导入 fetch_text，按模块属性 patch 生效。
        with mock.patch.object(_intel_utils, "fetch_text", fake_fetch_text), \
                _safe_domain_fns():
            records = reg.run_api_document_pipeline(
                [SITE], [], discovery_context=context, config=_full_config())
        self.assertTrue(any(_record_tuple(item)[0] == "api_doc_endpoint" for item in records))
        self.assertEqual(
            int(context.metrics.get("api_document_cross_bucket_hit_total", 0) or 0), 0,
            "首轮无历史桶，锚计数保持 0",
        )
        self.assertIsNotNone(getattr(context, "api_candidate_registry", None))


if __name__ == "__main__":
    unittest.main()
