"""计划 6 第 3 批：ApiCandidateRegistry + ApiDocumentQueue 回归。

验证口径（计划 6 §7.2/§8.1/§11.2、附录A §4.5 证据锚）：
- 注册表：URL 级去重与 sources 聚合（G8 替代面）、状态机合法边强制、
  Endpoint 资产同 URL 不同 method 不合并；
- 队列：JS/记录/候选图回流在当前任务内消费、单文档失败隔离、
  深度/数量/阶段时限预算闸、账本 covered 重投跳过、残余候选保持
  开放态供 finalizer 下一轮周期显影；
- 获取面：api_doc profile 桶 + html_get 镜像、*_cross_bucket_hit 转正、
  html_get 已有响应不再发第二次网络请求；
- 兼容面：flag 开/关记录集合与 legacy 一致（§十三.2 双写）、整体异常回退 legacy；
- 安全面（Review P0-01）：不可信文档越界 host 只作 out_of_scope_domain 证据
  计数（api_document_out_of_scope_domain_total），绝不触发 in-scope domain 记录；
- 计量面（Review P1-08）：fetch 异常 / 空响应 / Parser 显式 failed 三条失败路径
  全部计入 parse_failed_count + api_document_parse_failed_total；
- 回退开关（Review P1-09）：API_UNIFIED_FALLBACK_ENABLE 同时覆盖 stage 级整体
  异常与单文档 Parser 崩溃，False 时 Parser 崩溃不回退 legacy、文档标 failed；
- Schema 摘要双通道（Review P0-04 / P1-11，附录A §4.13 冻结契约）：
  graphql_schema_summary 进 registry 有界诊断面（逐条字节上限 + 总条数上限），
  metrics 只放整数计数；该类型不再触发 api_document_unbridged_candidate_total。
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

# 收集期捕获真实模块引用，免疫既有用例注入 fake app.utils 不还原的污染。
# bootstrap 在临时桩窗口内加载子模块（绕过 app.services 真实 __init__ 的 NPoC 等
# 重依赖），完成后还原 app / app.services 槽位，不留空壳桩。app.modules 由
# api_doc_scan 顶层导入链在桩窗口内自动带入缓存：运行期用例
# `from app.modules import WihRecord` 命中缓存条目，不再触发包 __init__。
_captured = load_unified_modules()

utils = _captured["app.utils"]
reg = _captured["app.services.api_candidate_registry"]
_api_doc_module = _captured["app.services.api_doc_scan"]
_parser_module = _captured["app.services.api_unified_parser"]
_intel_utils = _captured["app.services.web_info_intel_utils"]
ApiDocScanner = _api_doc_module.ApiDocScanner
_models = _captured["app.services.api_unified_models"]
UNIFIED_API_CONFIG_DEFAULTS = _models.UNIFIED_API_CONFIG_DEFAULTS
ApiDocumentCandidate = _models.ApiDocumentCandidate
ParseDiagnostics = _models.ParseDiagnostics
ParseResult = _models.ParseResult
UnifiedApiEndpoint = _models.UnifiedApiEndpoint
shadow_document_fetch_start = _captured[
    "app.services.api_unified_shadow"
].shadow_document_fetch_start
_discovery_context = _captured["app.services.discovery_context"]
DiscoveryContext = _discovery_context.DiscoveryContext
LedgerEntry = _discovery_context.LedgerEntry
normalize_url = _discovery_context.normalize_url

DOC_URL = "https://api.example.com/v3/api-docs"
SITE = "https://api.example.com"
OPENAPI_TEXT = (FIXTURES / "openapi3_petstore.json").read_text(encoding="utf-8")
# 含 "<html" 的正文在 _parse_one 入口即绕过统一 Parser 链（格式面判定冻结于
# registry 本身），用作"非目标种子文档"的正文可让计量用例不依赖 Parser 实现。
HTML_OK_TEXT = "<html><body>api docs placeholder</body></html>"
# 跨-Fld 越界文档：server 指向任务范围（example.com）之外的 host。
EVIL_OPENAPI_TEXT = json.dumps({
    "openapi": "3.0.0",
    "info": {"title": "scope", "version": "1.0"},
    "servers": [{"url": "https://evil.com/v1"}],
    "paths": {"/pets": {"get": {"responses": {"200": {"description": "ok"}}}}},
})


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


@contextlib.contextmanager
def _fld_domain_fns():
    """get_fld 取末两段：区分同-Fld（example.com）与跨-Fld（evil.com）越界。"""

    with mock.patch.object(
        utils, "is_valid_domain", lambda value: "." in str(value or "")
    ), mock.patch.object(
        utils, "get_fld", lambda host: ".".join(str(host or "").split(".")[-2:])
    ):
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


@contextlib.contextmanager
def _fake_unified_parsers(factory):
    """整链替换统一 Parser 为 fake 工厂。

    P1-08/P1-09 用例只依赖 registry 侧冻结的四个导入名与 ParseResult 形态，
    与被并行演进的 parser 具体实现解耦。
    """

    with contextlib.ExitStack() as stack:
        for name in ("UnifiedOpenApiParser", "UnifiedPostmanParser",
                     "UnifiedGraphqlParser", "UnifiedWsdlParser"):
            stack.enter_context(mock.patch.object(_parser_module, name, factory))
        yield


def _make_queue_fn(fetch_fn, context=None, config=None):
    """单目标计量用例的队列构造：fetch_fn 全权决定各文档正文/异常。"""

    scanner = ApiDocScanner(sites=[SITE], wih_records=[], discovery_context=context)
    registry = reg.ApiCandidateRegistry(task_id="t4", context=context)
    queue = reg.ApiDocumentQueue(
        scanner=scanner,
        registry=registry,
        context=context,
        config=_full_config(**(config or {})),
        fetch_fn=fetch_fn,
    )
    return queue


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
        # 旧口径（本用例修复前）断言 parse_failed_count == 1，把"非目标 seed
        # 空响应不计量"当成了预期行为——与 Review P1-08 探针（fetch_count=1 而
        # parse_failed_count=0）矛盾，属被证伪的旧口径而非有效基线。P1-08 收口
        # 后：被消费文档终态必落 success 或 failed 之一，异常与空响应都计入。
        self.assertEqual(queue.parse_success_count, 1)
        self.assertEqual(
            queue.parse_failed_count, queue.fetch_count - queue.parse_success_count,
            "每个被消费文档必须收敛到 success/failed 之一（统一失败收口）")
        self.assertGreater(
            queue.parse_failed_count, 1, "异常文档之外，空响应 seed 同样计入失败收口")
        self.assertEqual(registry.document(bad_url).status, "failed")
        self.assertEqual(registry.document(bad_url).error_type, "RuntimeError")
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
        missing = legacy_set - unified_set
        # Review P0-01 安全收窄（唯一允许的 legacy>unified 差异面）：legacy 会把
        # 不可信文档里的同-Fld 越界 host 写入 domain 资产；统一层降级为
        # out_of_scope_domain 证据只计数、不落记录。
        self.assertTrue(
            all(record_type == "domain" for record_type, _ in missing),
            "除越界 domain 证据化外，统一输出不得低于 legacy 基线: 缺 {}".format(
                sorted(missing)),
        )
        self.assertEqual(missing, {("domain", "blue.example.com")})
        extra = unified_set - legacy_set
        self.assertTrue(all("{" in content for _, content in extra),
                        "增量面只允许 G1 模板端点补充")
        self.assertFalse(
            [c for t, c in unified_set if t == "urlfinder_url" and "{" in c],
            "模板 URL 不得流入 urlfinder_url",
        )


class OutOfScopeDomainBridgeTest(unittest.TestCase):
    """Review P0-01：越界 host 只作证据计数，绝不触发 _append_record("domain",...)。"""

    def test_same_fld_out_of_scope_domain_is_evidence_only(self):
        # legacy 会把 blue.example.com（同-Fld 越界）写入 domain 记录；
        # 统一层必须证据化：无记录、只计 api_document_out_of_scope_domain_total。
        context = DiscoveryContext(task_id="p001-a")
        queue, _calls = _make_queue(context=context, fetch_map={DOC_URL: OPENAPI_TEXT})
        with _fld_domain_fns():
            records = queue.run()
        self.assertEqual(
            [p for p in map(_record_tuple, records) if p[0] == "domain"], [],
            "同-Fld 越界 host 不得进入 in-scope domain 资产面")
        self.assertGreaterEqual(
            int(context.metrics.get("api_document_out_of_scope_domain_total", 0) or 0), 1,
            "证据必须计数可观测，不得静默丢弃")

    def test_cross_fld_out_of_scope_domain_is_evidence_only(self):
        context = DiscoveryContext(task_id="p001-b")
        queue, _calls = _make_queue(context=context, fetch_map={DOC_URL: EVIL_OPENAPI_TEXT})
        with _fld_domain_fns():
            records = queue.run()
        self.assertEqual(
            [p for p in map(_record_tuple, records) if p[0] == "domain"], [],
            "跨-Fld 越界 host 不得进入 in-scope domain 资产面")
        self.assertEqual(
            queue.registry.snapshot_endpoints(), [],
            "跨-Fld 越界文档不得产生任何端点资产")
        self.assertGreaterEqual(
            int(context.metrics.get("api_document_out_of_scope_domain_total", 0) or 0), 1)

    def test_bridge_counts_every_candidate_and_never_appends_domain(self):
        # 直接驱动桥接层：out_of_scope_domain、防御性 domain、wsdl_xsd_import
        # 与未接线类型全部必须计数（P0-04：桥接不得静默丢弃未知 candidate）。
        # P0-04 接线后 graphql_schema_summary 改走诊断面（见
        # GraphqlSchemaSummaryBridgeTest），本用例以真正未知类型守住
        # unbridged 观测锚"其余未接线类型仍计数"的语义。
        context = DiscoveryContext(task_id="p001-c")
        queue, _calls = _make_queue(context=context, fetch_map={})
        doc = ApiDocumentCandidate(task_id="t3", url=DOC_URL, source="seed")
        result = ParseResult(
            parser="openapi_unified",
            candidates=[
                {"record_type": "out_of_scope_domain", "content": "evil.com", "source": DOC_URL},
                # 防御分支：旧形态 domain 候选必须走同一证据出口。
                {"record_type": "domain", "content": "blue.example.com", "source": DOC_URL},
                {"record_type": "wsdl_xsd_import", "content": "types.xsd", "source": DOC_URL},
                {"record_type": "future_unwired_type", "content": "placeholder", "source": DOC_URL},
            ],
            diagnostics=ParseDiagnostics(parser="openapi_unified"),
        )
        with _fld_domain_fns(), \
                mock.patch.object(queue.scanner, "_append_record") as append:
            queue._bridge_parse_result(doc, result)
        self.assertEqual(
            [call for call in append.call_args_list if call[0] and call[0][0] == "domain"],
            [], "任何 domain 形态候选都不得触发 in-scope domain 记录")
        metrics = context.metrics
        self.assertEqual(int(metrics.get("api_document_out_of_scope_domain_total", 0) or 0), 2)
        self.assertEqual(int(metrics.get("api_document_wsdl_xsd_import_total", 0) or 0), 1)
        self.assertEqual(
            int(metrics.get("api_document_unbridged_candidate_total", 0) or 0), 1,
            "未接线候选类型必须显式计数，不得静默丢弃")

    def test_invalid_and_template_host_candidates_never_bridged(self):
        # 非法 host / 模板 host / URL 形态 content：一律只计数，绝不落记录。
        context = DiscoveryContext(task_id="p001-d")
        queue, _calls = _make_queue(context=context, fetch_map={})
        doc = ApiDocumentCandidate(task_id="t3", url=DOC_URL, source="seed")
        result = ParseResult(
            parser="openapi_unified",
            candidates=[
                {"record_type": "out_of_scope_domain", "content": "{env}.example.com",
                 "source": DOC_URL},
                {"record_type": "out_of_scope_domain", "content": "in valid.example.com",
                 "source": DOC_URL},
                {"record_type": "out_of_scope_domain", "content": "https://evil.com/soap",
                 "source": DOC_URL},
            ],
            diagnostics=ParseDiagnostics(parser="openapi_unified"),
        )
        with _fld_domain_fns(), \
                mock.patch.object(queue.scanner, "_append_record") as append:
            queue._bridge_parse_result(doc, result)
        append.assert_not_called()
        self.assertEqual(
            int(context.metrics.get("api_document_out_of_scope_domain_total", 0) or 0), 3)


class GraphqlSchemaSummaryBridgeTest(unittest.TestCase):
    """Review P0-04 双通道 + P1-11 GraphQL 计数（附录A §4.13 冻结契约）。

    全部用合成 candidate 与 fake parser 驱动，不依赖 graphql parser 生产侧
    实现完成态：消费侧只按冻结的字段形态校验。措辞口径（用户决策）：
    "Schema 摘要进入当前任务 context 的有界诊断面；stage metrics 仅记录状态与
    计数；第 8 批再决定是否纳入 Endpoint Registry 资产面。"
    """

    @staticmethod
    def _summary_candidate(**overrides):
        """生产侧冻结契约形态（附录A §4.13）的合成样本。"""

        candidate = {
            "record_type": "graphql_schema_summary",
            "kind": "sdl",
            "status": "ok",
            "error_type": "",
            "schema_hash": "ab" * 16,
            "types": ["Query", "Mutation"],
            "enums": ["Role"],
            "inputs": ["PetInput"],
            "scalars": ["JSON"],
            "type_count": 5,
            "field_count": 12,
            "truncated": False,
            "summary_bytes": 256,
        }
        candidate.update(overrides)
        return candidate

    def _bridge(self, queue, candidate):
        doc = ApiDocumentCandidate(task_id="t3", url=DOC_URL, source="seed")
        queue._bridge_candidate(doc, candidate)

    def test_three_statuses_counted_and_diagnosed(self):
        context = DiscoveryContext(task_id="t3-schema-1")
        queue, _calls = _make_queue(context=context, fetch_map={})
        self._bridge(queue, self._summary_candidate())
        self._bridge(queue, self._summary_candidate(
            kind="introspection", status="degraded", truncated=True))
        self._bridge(queue, self._summary_candidate(
            status="failed", error_type="schema_invalid"))
        metrics = context.metrics
        self.assertEqual(int(metrics.get("graphql_schema_success_total", 0) or 0), 1)
        self.assertEqual(int(metrics.get("graphql_schema_degraded_total", 0) or 0), 1)
        self.assertEqual(int(metrics.get("graphql_schema_failed_total", 0) or 0), 1)
        self.assertEqual(
            int(metrics.get("api_document_unbridged_candidate_total", 0) or 0), 0,
            "轮 1 观测锚归零：schema summary 已接线，不再进 unbridged")
        diags = queue.registry.schema_diagnostics
        self.assertEqual(len(diags), 3)
        first = diags[0]
        for key in ("record_type", "kind", "status", "error_type", "schema_hash",
                    "types", "enums", "inputs", "scalars",
                    "type_count", "field_count", "truncated", "summary_bytes"):
            self.assertIn(key, first, "合法摘要契约字段必须完整落位诊断面")
        self.assertEqual(first["kind"], "sdl")
        self.assertEqual(first["type_count"], 5)
        self.assertFalse(first["truncated"])
        self.assertTrue(diags[1]["truncated"])
        self.assertEqual(diags[2]["error_type"], "schema_invalid",
                         "failed 态保留生产侧 error_type 供归因（不得伪装成功）")

    def test_contract_violation_counted_failed_never_silent(self):
        context = DiscoveryContext(task_id="t3-schema-2")
        queue, _calls = _make_queue(context=context, fetch_map={})
        missing_status = self._summary_candidate()
        del missing_status["status"]
        invalids = [
            missing_status,
            self._summary_candidate(kind="sdl_v2"),
            # skipped 属队列链状态语义，不在 schema 摘要生产侧枚举内。
            self._summary_candidate(status="skipped"),
            self._summary_candidate(type_count="5"),
            # bool 是 int 子类，但计数语义必须真整数。
            self._summary_candidate(field_count=True),
        ]
        for candidate in invalids:
            self._bridge(queue, candidate)
        metrics = context.metrics
        self.assertEqual(
            int(metrics.get("graphql_schema_failed_total", 0) or 0), len(invalids),
            "非法 candidate 一律计 failed，绝不静默成功")
        self.assertEqual(int(metrics.get("graphql_schema_success_total", 0) or 0), 0)
        self.assertEqual(
            int(metrics.get("api_document_unbridged_candidate_total", 0) or 0), 0,
            "已接线类型绝不再进 unbridged")
        diags = queue.registry.schema_diagnostics
        self.assertEqual(len(diags), len(invalids))
        for entry in diags:
            self.assertEqual(entry["error_type"], "schema_contract_violation")
            self.assertEqual(entry["status"], "failed")
            self.assertTrue(entry["summary_dropped"])
            for body_key in ("schema_hash", "types", "enums", "inputs", "scalars"):
                self.assertNotIn(
                    body_key, entry, "非法候选不得落诊断正文（防夹带原文外流）")

    def test_byte_cap_trims_entry_to_safe_header(self):
        context = DiscoveryContext(task_id="t3-schema-3")
        queue, _calls = _make_queue(
            context=context, fetch_map={},
            config={"GRAPHQL_SCHEMA_SUMMARY_MAX_BYTES": 512})
        huge = self._summary_candidate(
            types=["Type%04d" % i for i in range(120)],
            type_count=120, field_count=900, summary_bytes=99999, truncated=True)
        self._bridge(queue, huge)
        # 同配置下的小条目不得被误裁（证明按字节而非条目数判定）。
        self._bridge(queue, self._summary_candidate())
        diags = queue.registry.schema_diagnostics
        self.assertEqual(len(diags), 2)
        trimmed = diags[0]
        self.assertTrue(trimmed["summary_dropped"])
        self.assertTrue(trimmed["truncated"])
        self.assertNotIn("types", trimmed, "超限条目正文（类型名单）必须丢弃")
        self.assertNotIn("summary_bytes", trimmed)
        self.assertEqual(trimmed["kind"], "sdl")
        self.assertEqual(trimmed["status"], "ok")
        self.assertEqual(trimmed["schema_hash"], "ab" * 16)
        self.assertEqual(trimmed["type_count"], 120)
        self.assertEqual(trimmed["field_count"], 900)
        kept = diags[1]
        self.assertNotIn("summary_dropped", kept)
        self.assertIn("types", kept)
        self.assertEqual(
            int(context.metrics.get("graphql_schema_success_total", 0) or 0), 2,
            "裁剪只影响诊断正文，状态计数按契约 status 归属不变")

    def test_entry_count_cap_drops_oldest_and_counts(self):
        context = DiscoveryContext(task_id="t3-schema-4")
        queue, _calls = _make_queue(context=context, fetch_map={})
        for i in range(18):
            self._bridge(queue, self._summary_candidate(schema_hash="h%02d" % i))
        diags = queue.registry.schema_diagnostics
        self.assertEqual(len(diags), 16, "总条数上限 16")
        self.assertEqual(diags[0]["schema_hash"], "h02", "满则丢最旧")
        hashes = {entry["schema_hash"] for entry in diags}
        self.assertNotIn("h00", hashes)
        self.assertNotIn("h01", hashes)
        self.assertEqual(
            int(context.metrics.get("api_document_schema_diagnostics_dropped_total", 0) or 0),
            2, "丢最旧必须可观测")
        self.assertEqual(
            int(context.metrics.get("graphql_schema_success_total", 0) or 0), 18,
            "驻留裁剪不改变到达计数")

    def test_unbridged_zero_for_summary_nonzero_for_unknown(self):
        context = DiscoveryContext(task_id="t3-schema-5")
        queue, _calls = _make_queue(context=context, fetch_map={})
        self._bridge(queue, self._summary_candidate())
        self._bridge(queue, {"record_type": "future_unwired_type", "content": "x"})
        metrics = context.metrics
        self.assertEqual(
            int(metrics.get("api_document_unbridged_candidate_total", 0) or 0), 1,
            "其余未接线类型行为不变")
        self.assertEqual(
            int(metrics.get("graphql_schema_success_total", 0) or 0), 1)

    def test_graphql_request_total_counted_per_endpoint(self):
        context = DiscoveryContext(task_id="t3-schema-6")
        queue, _calls = _make_queue(context=context, fetch_map={})
        doc = ApiDocumentCandidate(task_id="t3", url=DOC_URL, source="seed")
        endpoints = [
            UnifiedApiEndpoint(
                url="https://api.example.com/graphql", method="POST",
                api_type="graphql", source=DOC_URL, parent_document=DOC_URL),
            UnifiedApiEndpoint(
                url="https://api.example.com/gql/second", method="POST",
                api_type="graphql", source=DOC_URL, parent_document=DOC_URL),
            UnifiedApiEndpoint(
                url=DOC_URL, method="GET",
                api_type="rest", source=DOC_URL, parent_document=DOC_URL),
        ]
        result = ParseResult(
            parser="graphql_unified",
            endpoints=endpoints,
            diagnostics=ParseDiagnostics(parser="graphql_unified", status="ok"),
        )
        with _fld_domain_fns(), mock.patch.object(queue.scanner, "_append_record"):
            queue._bridge_parse_result(doc, result)
        self.assertEqual(
            int(context.metrics.get("graphql_request_total", 0) or 0), 2,
            "端点桥接循环内按 api_type==graphql 逐条计数")

    def _run_all_skipped_chain(self, task_id, type_hint, schema_enable):
        """全链 skipped 的 _parse_one 直驱：验证 skipped 计数的 best-effort 边界。"""

        class _AllSkippedParser:
            def __init__(self, **kwargs):
                pass

            def parse(self, text, options):
                return ParseResult(
                    parser="fake",
                    diagnostics=ParseDiagnostics(parser="fake", status="skipped"),
                )

        context = DiscoveryContext(task_id=task_id)
        queue = _make_queue_fn(
            lambda doc: "", context=context,
            config={"GRAPHQL_SCHEMA_ENABLE": schema_enable})
        url = "https://api.example.com/graphql"
        doc, _created = queue.registry.register_document(
            url, source="seed", type_hint=type_hint)
        queue.registry.mark_document(url, "queued")
        queue.registry.mark_document(url, "fetching")
        with _safe_domain_fns(), _fake_unified_parsers(_AllSkippedParser), \
                mock.patch.object(queue.scanner, "parse_document", lambda *a: None):
            self.assertTrue(queue._parse_one(doc, '{"query":"{__typename}"}', "sig"))
        return int(context.metrics.get("graphql_schema_skipped_total", 0) or 0)

    def test_graphql_schema_skipped_best_effort(self):
        self.assertEqual(
            self._run_all_skipped_chain("t3-schema-7a", "graphql", False), 1,
            "schema 关闭 + 全链 skipped + graphql 弱证据 → 计 skipped")
        self.assertEqual(
            self._run_all_skipped_chain("t3-schema-7b", "unknown", False), 0,
            "type_hint 无 graphql 证据不得计数")
        self.assertEqual(
            self._run_all_skipped_chain("t3-schema-7c", "graphql", True), 0,
            "schema 开关开启时不走 skipped 观测（预算/失败语义归生产侧诊断）")

    def test_parse_options_carries_injected_depth(self):
        queue = _make_queue_fn(lambda doc: "", config={"GRAPHQL_SCHEMA_MAX_DEPTH": 7})
        self.assertEqual(queue._parse_options().graphql_schema_max_depth, 7,
                         "P0-03：GRAPHQL_SCHEMA_MAX_DEPTH 必须经 _parse_options 接线")
        default_queue = _make_queue_fn(lambda doc: "")
        self.assertEqual(
            default_queue._parse_options().graphql_schema_max_depth,
            UNIFIED_API_CONFIG_DEFAULTS["GRAPHQL_SCHEMA_MAX_DEPTH"])

    def test_diagnostics_never_carry_raw_schema_or_variables(self):
        # 白名单投影 + 违规不回显：契约外键（原文/变量值形态）与非法候选的
        # 字段值一律不得进入诊断面序列化（合成 marker 验证）。
        context = DiscoveryContext(task_id="t3-schema-8")
        queue, _calls = _make_queue(context=context, fetch_map={})
        self._bridge(queue, self._summary_candidate(
            raw_schema="type Query { leaked: String } # SECRET_RAW_SDL_MARKER",
            variables={"api_key": "SECRET_VAR_VALUE"},
            description="SECRET_DESC_MARKER"))
        violation = self._summary_candidate(kind="SECRET_KIND_MARKER")
        del violation["type_count"]
        self._bridge(queue, violation)
        context2 = DiscoveryContext(task_id="t3-schema-9")
        queue2, _calls2 = _make_queue(
            context=context2, fetch_map={},
            config={"GRAPHQL_SCHEMA_SUMMARY_MAX_BYTES": 256})
        self._bridge(queue2, self._summary_candidate(
            types=["SECRET_TYPE_" + str(i) for i in range(120)],
            type_count=120, field_count=900, summary_bytes=99999))
        self.assertTrue(queue2.registry.schema_diagnostics[0]["summary_dropped"])
        blob = json.dumps(queue.registry.schema_diagnostics, ensure_ascii=False)
        blob2 = json.dumps(queue2.registry.schema_diagnostics, ensure_ascii=False)
        for marker in ("SECRET_RAW_SDL_MARKER", "SECRET_VAR_VALUE",
                       "SECRET_DESC_MARKER", "SECRET_KIND_MARKER"):
            self.assertNotIn(marker, blob)
        self.assertNotIn("SECRET_TYPE_", blob2)
        self.assertEqual(
            blob.count("schema_contract_violation"), 1,
            "violation 诊断只留归因键，不留正文")

    def test_run_exposes_schema_diagnostics_count_metric(self):
        # 端到端最小闭环：ok 解析结果携带 schema candidate → 诊断驻留计数经
        # context 指标透出（metrics 只放整数计数，摘要本体不进 metrics）。
        class _SchemaEmittingParser:
            def __init__(self, **kwargs):
                self.doc_url = str(kwargs.get("doc_url") or "")

            def parse(self, text, options):
                if normalize_url(self.doc_url) == normalize_url(DOC_URL):
                    return ParseResult(
                        parser="fake",
                        candidates=[GraphqlSchemaSummaryBridgeTest._summary_candidate()],
                        diagnostics=ParseDiagnostics(
                            parser="fake", status="ok"),
                    )
                return ParseResult(
                    parser="fake",
                    diagnostics=ParseDiagnostics(parser="fake", status="skipped"),
                )

        context = DiscoveryContext(task_id="t3-schema-10")
        queue = _make_queue_fn(
            UnifiedFailureAccountingTest._fetch_for(
                DOC_URL, target_text=json.dumps({"openapi": "3.0.0", "paths": {}})),
            context=context)
        with _safe_domain_fns(), _fake_unified_parsers(_SchemaEmittingParser):
            queue.run()
        self.assertEqual(queue.registry.document(DOC_URL).status, "parsed")
        self.assertEqual(
            int(context.metrics.get("graphql_schema_success_total", 0) or 0), 1)
        self.assertEqual(
            int(context.metrics.get("api_document_schema_diagnostics_total", 0) or 0), 1,
            "诊断面驻留条数以整数计数透出")


class UnifiedFailureAccountingTest(unittest.TestCase):
    """Review P1-08：三条文档失败路径统一收口到同一 counter + 指标。

    旧口径只计 fetch 异常与 Parser failed，空响应（fetch 返回 ""）被
    `mark_document(failed/empty_response)` 后静默放行——Review 探针实证
    fetch_count=1 而 parse_failed_count=0，分母与获取数出现无法归因缺口。
    冻结口径：凡被消费（fetch_count +1）的文档，终态必落
    parse_success_count 或 parse_failed_count 之一，且 failed 侧同步计
    api_document_parse_failed_total。三条路径 error_type 词表保持区分
    （异常类名 / empty_response / Parser 显式 error_type）便于归因。
    """

    @staticmethod
    def _fetch_for(target, target_text=None, target_raises=False):
        target_key = normalize_url(target)

        def fetch_fn(doc):
            if normalize_url(doc.url) == target_key:
                if target_raises:
                    raise RuntimeError("fetch boom")
                return target_text
            return HTML_OK_TEXT

        return fetch_fn

    def _assert_single_unified_failure(self, context, queue, error_type):
        self.assertEqual(queue.parse_failed_count, 1, "目标文档失败必须计入统一失败计数")
        self.assertEqual(
            int(context.metrics.get("api_document_parse_failed_total", 0) or 0), 1,
            "统一失败计数必须同步上指标")
        doc = queue.registry.document(DOC_URL)
        self.assertEqual(doc.status, "failed")
        self.assertEqual(doc.error_type, error_type, "error_type 词表用于区分失败路径")
        self.assertEqual(queue.parse_success_count, queue.fetch_count - 1)
        self.assertEqual(
            int(context.metrics.get("api_unified_fallback_total", 0) or 0), 0,
            "单文档失败收口不得混入回退指标（P1-09 冻结语义）")

    def test_fetch_exception_counts_unified_failure(self):
        context = DiscoveryContext(task_id="p108-exc")
        queue = _make_queue_fn(
            self._fetch_for(DOC_URL, target_raises=True), context=context)
        with _safe_domain_fns():
            queue.run()
        self._assert_single_unified_failure(context, queue, "RuntimeError")

    def test_empty_response_counts_unified_failure(self):
        context = DiscoveryContext(task_id="p108-empty")
        queue = _make_queue_fn(
            self._fetch_for(DOC_URL, target_text=""), context=context)
        with _safe_domain_fns():
            queue.run()
        self._assert_single_unified_failure(context, queue, "empty_response")

    def test_parser_failed_status_counts_unified_failure(self):
        context = DiscoveryContext(task_id="p108-failed")
        target_key = normalize_url(DOC_URL)

        class _FailedParser:
            def __init__(self, **kwargs):
                self.doc_url = str(kwargs.get("doc_url") or "")

            def parse(self, text, options):
                if normalize_url(self.doc_url) == target_key:
                    return ParseResult(
                        parser="fake",
                        diagnostics=ParseDiagnostics(
                            parser="fake", status="failed", error_type="schema_invalid"),
                    )
                return ParseResult(
                    parser="fake",
                    diagnostics=ParseDiagnostics(parser="fake", status="skipped"),
                )

        # 目标文档正文非 html 才进统一链；failed 态按 G4 不回退 legacy。
        queue = _make_queue_fn(
            self._fetch_for(
                DOC_URL, target_text=json.dumps({"openapi": "3.0.0", "paths": {}})),
            context=context)
        with _safe_domain_fns(), _fake_unified_parsers(_FailedParser), \
                mock.patch.object(queue.scanner, "parse_document") as legacy_parse:
            queue.run()
        self._assert_single_unified_failure(context, queue, "schema_invalid")
        self.assertNotIn(
            target_key,
            {normalize_url(str(call.args[0])) for call in legacy_parse.call_args_list},
            "Parser 显式 failed 不得回退 legacy（G4 口径不变）")


class ParserCrashFallbackSwitchTest(unittest.TestCase):
    """Review P1-09：API_UNIFIED_FALLBACK_ENABLE 作用域覆盖单文档 Parser 崩溃。

    修复前该开关只被 stage 级整体异常检查（run_api_document_pipeline），
    _parse_one 的 Parser 崩溃却无条件回退 legacy + 计 fallback，同名两套
    语义。冻结口径：True 维持崩溃回退 legacy + api_unified_fallback_total；
    False 时不回退，文档标 failed（error_type 取异常类名，与 fetch 异常/
    legacy 解析崩溃的既有词表一致）并计入统一失败收口。
    """

    def _run_crash(self, fallback_enable, task_id):
        context = DiscoveryContext(task_id=task_id)

        class _CrashParser:
            def __init__(self, **kwargs):
                pass

            def parse(self, text, options):
                raise ValueError("parser boom")

        queue = _make_queue_fn(
            UnifiedFailureAccountingTest._fetch_for(
                DOC_URL, target_text=OPENAPI_TEXT),
            context=context,
            config={"API_UNIFIED_FALLBACK_ENABLE": fallback_enable},
        )
        with _safe_domain_fns(), _fake_unified_parsers(_CrashParser), \
                mock.patch.object(queue.scanner, "parse_document") as legacy_parse:
            records = queue.run()
        target_key = normalize_url(DOC_URL)
        legacy_target_called = any(
            normalize_url(str(call.args[0])) == target_key
            for call in legacy_parse.call_args_list)
        return queue, context, records, legacy_target_called

    def test_crash_with_fallback_enabled_still_falls_back(self):
        queue, context, _records, legacy_target_called = self._run_crash(True, "p109-on")
        self.assertTrue(legacy_target_called, "开关 True 时 Parser 崩溃维持回退 legacy")
        self.assertEqual(queue.registry.document(DOC_URL).status, "parsed")
        self.assertEqual(queue.parse_failed_count, 0)
        self.assertEqual(
            int(context.metrics.get("api_unified_fallback_total", 0) or 0), 1)

    def test_crash_with_fallback_disabled_no_legacy_and_failed(self):
        queue, context, _records, legacy_target_called = self._run_crash(False, "p109-off")
        self.assertFalse(legacy_target_called, "开关 False 时崩溃文档不得产出 legacy 记录")
        doc = queue.registry.document(DOC_URL)
        self.assertEqual(doc.status, "failed")
        self.assertEqual(doc.error_type, "ValueError", "异常类名口径（与 715/549 一致）")
        self.assertEqual(queue.parse_failed_count, 1)
        self.assertEqual(queue.parse_success_count, queue.fetch_count - 1)
        self.assertEqual(
            int(context.metrics.get("api_document_parse_failed_total", 0) or 0), 1)
        self.assertEqual(
            int(context.metrics.get("api_unified_fallback_total", 0) or 0), 0,
            "不回退即不产生 fallback 事件，指标不得重复计")


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


class EndpointConsumerSurfaceTest(unittest.TestCase):
    """第 8 批 T8-1：Endpoint 领取/状态机、候选图回流、P1-12 不吞并、观测计数。"""

    @staticmethod
    def _ep(url="https://api.example.com/pets", method="GET", api_type="rest",
            signature="sig-1", confidence=50, source="seed"):
        return UnifiedApiEndpoint(
            url=url, method=method, api_type=api_type,
            input_signature=signature, confidence=confidence,
            source=source, parent_document="https://api.example.com/openapi.json")

    def test_p1_12_api_type_assets_not_swallowed(self):
        registry = reg.ApiCandidateRegistry(task_id="t8a")
        results = [registry.register_endpoint(self._ep(api_type=t))
                   for t in ("rest", "graphql", "soap")]
        self.assertTrue(all(created for _e, created in results))
        self.assertEqual(registry.endpoint_created_count, 3)
        self.assertEqual(registry.endpoint_deduplicated_count, 0)
        self.assertEqual(
            registry.endpoint_by_type, {"rest": 1, "graphql": 1, "soap": 1})
        # method 维度计数同步（P1-12 后键含 url+method+api_type+signature）
        self.assertEqual(registry.endpoint_by_method, {"GET": 3})

    def test_three_sources_same_endpoint_merges_once(self):
        # P0-05 门禁资产面：js/page/browser 来源的同一 Endpoint 只保留一条资产、
        # 按 sources 合并，不改探测状态（§7.2）。
        registry = reg.ApiCandidateRegistry(task_id="t8b")
        first, created = registry.register_endpoint(self._ep(source="js_intel"))
        self.assertTrue(created)
        first.status = "probed"  # 模拟消费方领取后回报，再验合并不改态
        second, created2 = registry.register_endpoint(self._ep(source="page_intel"))
        third, created3 = registry.register_endpoint(self._ep(source="browser"))
        self.assertFalse(created2 or created3)
        self.assertIs(second, first)
        self.assertEqual(third.status, "probed", "新来源合并不得重置探测态")
        self.assertEqual(registry.endpoint_created_count, 1)
        self.assertEqual(registry.endpoint_deduplicated_count, 2)
        self.assertEqual(registry.endpoint_sources_merged_count, 2)
        self.assertTrue(
            {"js_intel", "page_intel", "browser"} <= first.sources)

    def test_state_machine_claim_and_pending(self):
        registry = reg.ApiCandidateRegistry(task_id="t8c")
        high = self._ep(url="https://api.example.com/a", signature="s-a", confidence=90)
        low = self._ep(url="https://api.example.com/b", signature="s-b", confidence=10)
        registry.register_endpoint(high)
        registry.register_endpoint(low)
        claimed = registry.claim_endpoints_for_probe(limit=5, min_confidence=50)
        self.assertEqual([item.url for item in claimed],
                         ["https://api.example.com/a"], "confidence 降序领取")
        self.assertEqual(high.status, "queued")
        self.assertEqual(
            registry.endpoint(low.scoped_idempotency_key("t8c")).status, "pending",
            "低优先级不得丢弃，显影为 pending（§9.2）")
        # 非法边拒绝：queued→covered、probed→queued
        self.assertIsNone(registry.mark_endpoint(high, "covered"))
        self.assertIsNotNone(registry.mark_endpoint(high, "probed"))
        self.assertIsNone(registry.mark_endpoint(high, "queued"))
        self.assertEqual(registry.mark_endpoint(high, "covered").status, "covered")
        # pending 资产下一轮（阈值回落）可再领取
        again = registry.claim_endpoints_for_probe(limit=5)
        self.assertEqual([item.url for item in again], ["https://api.example.com/b"])
        self.assertEqual(low.status, "queued")

    def test_probe_report_word_mapping(self):
        registry = reg.ApiCandidateRegistry(task_id="t8d")
        for url, status_in, status_out in (
                ("https://api.example.com/r", "probed", "covered"),
                ("https://api.example.com/o", "observed", "covered"),
                ("https://api.example.com/e", "error", "failed"),
                ("https://api.example.com/s", "skipped", "skipped")):
            ep, _ = registry.register_endpoint(
                self._ep(url=url, signature="sig-" + url[-1]))
            registry.claim_endpoints_for_probe(limit=1)
            reported = registry.probe_report(ep, status_in)
            self.assertEqual(reported.status, status_out, status_in)
        unknown = registry.register_endpoint(
            self._ep(url="https://api.example.com/u", signature="sig-u"))
        self.assertIsNone(registry.probe_report(unknown[0], "weird"))

    def test_register_publishes_endpoint_candidate_to_graph(self):
        context = DiscoveryContext(task_id="t8e")
        registry = reg.ApiCandidateRegistry(task_id="t8e", context=context)
        registry.register_endpoint(self._ep(api_type="graphql"))
        graph_entries = [
            item for item in context.candidate_registry.values()
            if getattr(item, "candidate_type", "") == "endpoint"
        ]
        self.assertEqual(len(graph_entries), 1)
        self.assertEqual(graph_entries[0].candidate, "https://api.example.com/pets")
        self.assertEqual(
            getattr(graph_entries[0], "request_profile", ""), "api_endpoint_probe",
            "与 wih 来源(default profile)图条目分离，不互相吞并")
        registry.register_endpoint(self._ep(source="page_intel"))
        self.assertEqual(len([
            item for item in context.candidate_registry.values()
            if getattr(item, "candidate_type", "") == "endpoint"]), 1,
            "重复来源不产生第二条图条目")

    def test_queue_run_flushes_endpoint_observability(self):
        context = DiscoveryContext(task_id="t8f")
        queue = _make_queue_fn(
            lambda doc: OPENAPI_TEXT if DOC_URL in doc.url else HTML_OK_TEXT,
            context=context)
        with _safe_domain_fns():
            queue.run()
        created = int(context.metrics.get("api_endpoint_discovered_total", 0) or 0)
        self.assertGreater(created, 0, "OPENAPI_TEXT 端点资产已直登")
        by_type = context.metrics.get("api_endpoint_by_type.rest")
        self.assertEqual(int(by_type or 0), created, "REST 面类型计数与创建数一致")
        self.assertIsNotNone(context.metrics.get("api_endpoint_by_method.GET"))
        self.assertIsNotNone(context.metrics.get("api_endpoint_sources_merged_total"))


class BrowserIngestGateTest(unittest.TestCase):
    """第 8 批 T8-4 / P0-05 门禁：浏览器运行时事件进统一 Registry、多来源合一。"""

    GQL_URL = "https://api.example.com/graphql"
    QUERY = "query GetPet($petId: ID!) { pet(id: $petId) { name } }"

    def _request_json(self):
        return json.dumps({
            "url": self.GQL_URL, "method": "POST",
            "request": {"query": self.QUERY, "operationName": "GetPet",
                        "variables": {"petId": "SECRET-PET-9527"}},
        })

    def _browser_graphql_endpoints(self):
        # 与浏览器运行时通道同一拆解路径（UnifiedGraphqlParser 请求文档形态）。
        parser = _parser_module.UnifiedGraphqlParser(
            task_id="browser-intel", doc_url=self.GQL_URL,
            allowed_hosts={"api.example.com"})
        result = parser.parse(self._request_json(), _models.ParseOptions())
        self.assertEqual(result.diagnostics.status, "ok")
        return result.endpoints

    def test_doc_and_browser_and_page_merge_into_single_asset(self):
        context = DiscoveryContext(task_id="t8g1", allowed_hosts={"api.example.com"})
        queue, _calls = _make_queue(
            context=context, fetch_map={self.GQL_URL: self._request_json()})
        queue.registry.register_document(
            self.GQL_URL, source="js_intel", type_hint="graphql")
        with _safe_domain_fns():
            queue.run()
        gql_assets = [e for e in queue.registry.snapshot_endpoints()
                      if e["api_type"] == "graphql"]
        self.assertEqual(1, len(gql_assets), "文档通道应产出 graphql 资产")
        self.assertEqual(gql_assets[0]["status"], "discovered")

        results = {"https://api.example.com": {"runtime_api_calls": [
            {"method": "POST", "url": self.GQL_URL, "body_kind": "graphql",
             "_graphql_endpoints": self._browser_graphql_endpoints()},
        ]}}
        created = reg.ingest_browser_runtime_events(queue.registry, results)
        self.assertEqual(0, created, "浏览器与文档同 operation 同键：不重复建资产")
        # 页面来源证据再合一（直接 register 同键资产）。
        queue.registry.register_endpoint(UnifiedApiEndpoint(
            url=self.GQL_URL, method="POST", api_type="graphql",
            source="page_intel",
            input_signature=gql_assets[0]["input_signature"]))
        assets = [e for e in queue.registry.snapshot_endpoints()
                  if e["api_type"] == "graphql"]
        self.assertEqual(1, len(assets), "三来源仍只有一条资产")
        asset = assets[0]
        self.assertIn("browser", asset["sources"])
        self.assertEqual(
            asset["status"], "covered", "运行期已捕获响应：观察收口，不再补探")
        blob = json.dumps(asset, ensure_ascii=False)
        self.assertNotIn("SECRET-PET-9527", blob, "P0-05：变量取值不得进资产面")

    def test_browser_rest_calls_ingested_as_covered_assets(self):
        context = DiscoveryContext(task_id="t8g2", allowed_hosts={"api.example.com"})
        registry = reg.ApiCandidateRegistry(task_id="t8g2", context=context)
        results = {"https://api.example.com": {"runtime_api_calls": [
            {"method": "GET", "url": "https://api.example.com/api/items"},
            {"method": "GET", "url": "https://evil.example.org/track"},  # 越界
            {"method": "GET", "url": "javascript:void(0)"},              # 非 HTTP
        ]}}
        created = reg.ingest_browser_runtime_events(registry, results)
        self.assertEqual(1, created)
        urls = {e["url"] for e in registry.snapshot_endpoints()}
        self.assertEqual(urls, {"https://api.example.com/api/items"})
        for e in registry.snapshot_endpoints():
            self.assertEqual(e["status"], "covered",
                             "浏览器观察过的请求不得再进补探领取")
        self.assertEqual(
            int(context.metrics.get("api_endpoint_browser_out_of_scope_total", 0) or 0), 1)

    def test_observed_shortcut_only_for_non_terminal(self):
        registry = reg.ApiCandidateRegistry(task_id="t8g3")
        ep, _ = registry.register_endpoint(UnifiedApiEndpoint(
            url="https://api.example.com/x", method="GET",
            input_signature="sig-x"))
        self.assertIs(registry.mark_endpoint_observed(ep), ep)
        self.assertEqual(ep.status, "covered")
        again = registry.mark_endpoint_observed(ep)
        self.assertIsNone(again, "终态不被观察事件回写")


class UrlRecordDocHintBackflowTest(unittest.TestCase):
    """第 8 批：页面/JS 的 urlfinder_url/page_link 记录按 URL 形态升级文档候选。

    GraphQL/WSDL 入口不再依赖 api_doc_url 记录生产者（js 关键字表与 Rust 面
    不改），统一队列按 document_type_hint 分类回流；非文档形态 URL 不进队。
    """

    GQL_URL = "https://api.example.com/graphql"
    GQL_TEXT = json.dumps({
        "url": "https://api.example.com/graphql", "method": "POST",
        "request": {"query": "query Ping { ping }"},
    })

    def _record(self, record_type, content):
        from app.modules import WihRecord
        return WihRecord(
            record_type=record_type, content=content,
            source="https://api.example.com/", site="api.example.com", fnv_hash=0)

    def test_page_link_and_urlfinder_graphql_backflow_fetch_once(self):
        context = DiscoveryContext(task_id="t85a")
        records = [
            self._record("urlfinder_url", self.GQL_URL),
            self._record("page_link", self.GQL_URL),
            self._record("urlfinder_url", "https://api.example.com/pet.png"),
            self._record("page_link", "https://api.example.com/soap/PetService.wsdl"),
        ]
        queue, calls = _make_queue(
            context=context, fetch_map={self.GQL_URL: self.GQL_TEXT}, records=records)
        with _safe_domain_fns():
            queue.run(wih_records=records)
        self.assertEqual(
            calls.count(self.GQL_URL), 1, "双记录同 URL 也只获取一次")
        doc = queue.registry.document(self.GQL_URL)
        self.assertIsNotNone(doc, "graphql 形态 URL 必须升级为文档候选")
        self.assertEqual(doc.type_hint, "graphql")
        self.assertEqual(doc.status, "parsed")
        assets = [e for e in queue.registry.snapshot_endpoints()
                  if e["api_type"] == "graphql"]
        self.assertEqual(len(assets), 1, "JS/页面来源经队列产出 graphql 资产")
        self.assertIsNone(
            queue.registry.document("https://api.example.com/pet.png"),
            "非文档形态 URL 不进队")

    def test_wsdl_bridge_counts_operation_metric(self):
        # 范围修正项（附录A §4.13）：wsdl_operation_total 在统一桥接面逐
        # operation 计数（第 7 批 fixture 的 getPet/listPets 两个 soap 端点）。
        context = DiscoveryContext(task_id="wsdlm")
        text = (FIXTURES / "wsdl_service.wsdl").read_text(encoding="utf-8")
        wsdl_url = "https://api.example.com/soap/PetService.wsdl"
        queue, _calls = _make_queue(context=context, fetch_map={wsdl_url: text})
        queue.registry.register_document(wsdl_url, source="seed", type_hint="wsdl")
        with _safe_domain_fns():
            queue.run()
        self.assertEqual(
            int(context.metrics.get("wsdl_operation_total", 0) or 0), 2)

    def test_api_doc_url_passthrough_unchanged(self):
        # 直通语义回归：api_doc_url 记录不依赖 URL 形态。
        odd_doc = "https://api.example.com/portal/doc.json"
        context = DiscoveryContext(task_id="t85b")
        rec = self._record("api_doc_url", odd_doc)
        queue, _calls = _make_queue(
            context=context, fetch_map={odd_doc: self.GQL_TEXT}, records=[rec])
        with _safe_domain_fns():
            queue.run(wih_records=[rec])
        self.assertIsNotNone(queue.registry.document(odd_doc))


if __name__ == "__main__":
    unittest.main()
