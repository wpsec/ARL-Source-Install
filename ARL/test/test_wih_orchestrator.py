"""WIH 编排器回归测试。"""

import importlib.util
import sys
import types
import unittest
from pathlib import Path


ARL_ROOT = Path(__file__).resolve().parents[1]
if str(ARL_ROOT) not in sys.path:
    sys.path.insert(0, str(ARL_ROOT))

from test._api_unified_bootstrap import load_modules  # noqa: E402

# 收集期预载真实 discovery_context 子模块（bootstrap 临时桩窗口，槽位还原、
# 缓存条目保留）：wih_orchestrator 顶层 `from app.services.discovery_context
# import register_intel_candidate, url_host` 在下方 fake app.services（非包）
# 注入后只能命中 sys.modules 缓存条目——Review P2-13 前本文件因缺该预载而
# 收集期 ImportError，属既有 bootstrap 缺陷而非环境问题。
_REAL_MODULES = load_modules(
    "app.services.discovery_context", "app.services.api_unified_models")
_REAL_DISCOVERY_CONTEXT = _REAL_MODULES["app.services.discovery_context"]

_MODULE_PATH = ARL_ROOT / "app" / "services" / "wih_orchestrator.py"
_SPEC = importlib.util.spec_from_file_location("wih_orchestrator_test_module", _MODULE_PATH)
_MODULE = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader


class _Logger(object):
    def info(self, _message):
        return None

    def debug(self, *_args, **_kwargs):
        return None

    def warning(self, *_args, **_kwargs):
        return None


class _Record(object):
    """对齐真实 WihRecord 的属性形态：构造参数叫 record_type，属性是 recordType。"""
    fnv_hash = "record-1"
    recordType = "domain"
    content = "api.example.test"
    source = "runtime"
    site = "https://example.test"

    def dump_json(self):
        return {"fnv_hash": self.fnv_hash}


class _InfoHunter(object):
    @staticmethod
    def normalize_wih_record(value):
        return _Record() if value == "raw-record" else None


class _Task(object):
    def __init__(self):
        self.task_id = "task-1"
        self.sites = ["https://example.test"]
        self.options = {}
        self.page_url_set = set()
        self.waf_guard = object()
        self.wih_record_set = set()
        self.stage_names = []
        self.saved_records = []

    def _filter_waf_blocked_targets(self, sites, stage_name=""):
        self.assertEqual("wih", stage_name)
        return sites

    def _apply_reused_wih_records(self, records):
        self.assertEqual([], records)
        return 0

    def _run_substage(self, name, func, **_kwargs):
        self.stage_names.append(name)
        return func()

    def _run_optional_ai_stage_best_effort(self, _name, func, **_kwargs):
        return func()

    def _save_wih_endpoints(self, _endpoints):
        raise AssertionError("test does not expect endpoint persistence")

    def _wih_record_in_task_scope(self, _record):
        return True

    def add_wih_domain_set(self, _record):
        return None

    def _save_wih_record(self, record):
        self.saved_records.append(record.fnv_hash)


_saved_modules = {
    name: sys.modules.get(name)
    for name in ("app", "app.services", "app.utils", "app.config", "app.services.infoHunter")
}
try:
    fake_services = types.ModuleType("app.services")
    fake_services.run_wih_periodic_reuse = lambda **_kwargs: {}
    fake_services.run_wih = lambda *_args, **_kwargs: (["raw-record"], [])
    fake_services.run_wih_endpoint_probe = lambda endpoints, **_kwargs: endpoints
    fake_services.run_wih_endpoint_ai_fill = lambda _task_id, endpoints, **_kwargs: endpoints
    fake_services.run_urlfinder_extract = lambda *_args, **_kwargs: []
    fake_services.run_page_intel_scan = lambda *_args, **_kwargs: []
    fake_services.run_api_doc_scan = lambda *_args, **_kwargs: []
    # 第 3 批统一层开关面：默认桩保持 flag-off 语义（wih_api_doc legacy 阶段位）；
    # 用例可用 patch.object(services, "api_unified_enabled", ...) 切到统一分支。
    fake_services.api_unified_enabled = lambda: False
    fake_services.run_api_document_pipeline = lambda *_args, **_kwargs: []
    fake_services.run_js_intel_scan = lambda *_args, **_kwargs: []
    fake_services.run_urlfinder_sensitive_scan = lambda *_args, **_kwargs: []
    fake_services.run_trufflehog_js = lambda *_args, **_kwargs: []
    fake_services.run_urlfinder_url_probe = lambda *_args, **_kwargs: []
    fake_utils = types.ModuleType("app.utils")
    fake_utils.get_logger = lambda: _Logger()
    fake_app = types.ModuleType("app")
    fake_app.services = fake_services
    fake_app.utils = fake_utils
    fake_config = types.ModuleType("app.config")
    fake_config.Config = types.SimpleNamespace(WIH_TOTAL_BUDGET_SEC=2700, URLFINDER_SENSITIVE_STAGE_TIMEOUT_SEC=1800)
    fake_info_hunter = types.ModuleType("app.services.infoHunter")
    fake_info_hunter.InfoHunter = _InfoHunter
    sys.modules.update({
        "app": fake_app,
        "app.services": fake_services,
        "app.utils": fake_utils,
        "app.config": fake_config,
        "app.services.infoHunter": fake_info_hunter,
        "app.services.discovery_context": _REAL_DISCOVERY_CONTEXT,
    })
    _SPEC.loader.exec_module(_MODULE)
finally:
    for name, module in _saved_modules.items():
        if module is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = module

WihOrchestrator = _MODULE.WihOrchestrator


class _FakeCandidate(object):
    def __init__(self, candidate, candidate_type="endpoint", status="discovered"):
        self.candidate = candidate
        self.candidate_type = candidate_type
        self.status = status


class _FakeRegistry(object):
    def __init__(self, items):
        self._items = items

    def values(self):
        return list(self._items)


class _FakeDiscoveryContext(object):
    ledger = None

    def __init__(self, candidates):
        self.candidate_registry = _FakeRegistry(candidates)
        self.registered = []
        self.marked = []

    def register_candidate(self, **kwargs):
        self.registered.append(kwargs)

    def mark_candidate_status(self, candidate, candidate_type, status, **_kwargs):
        self.marked.append((candidate, status))


class _EndpointTask(_Task):
    def __init__(self, discovery_context):
        _Task.__init__(self)
        self.discovery_context = discovery_context
        self.saved_endpoint_batches = []

    def _save_wih_endpoints(self, endpoints):
        self.saved_endpoint_batches.append(list(endpoints))


class _FakeEndpoint(object):
    def __init__(self, url, method):
        self.url = url
        self.method = method
        self.api_type = "rest"
        self.status = "queued"


class _FakeApiRegistry(object):
    """第 8 批 T8-3 编排消费面桩：只实现 followup 用到的三个方法。"""

    def __init__(self, claimable=()):
        self._claimable = list(claimable)
        self.registered = []
        self.reported = []

    def register_endpoint(self, endpoint):
        self.registered.append(endpoint)
        return endpoint, True

    def claim_endpoints_for_probe(self, limit, min_confidence=0):
        return self._claimable[:max(0, int(limit or 0))]

    def probe_report(self, endpoint, verification_status):
        self.reported.append((endpoint.url, endpoint.method, verification_status))
        return endpoint


class TestWihOrchestratorEndpointOrder(unittest.TestCase):
    def _run_with_endpoints(self, task, probe_spy):
        original_wih = fake_services.run_wih
        original_probe = fake_services.run_wih_endpoint_probe
        try:
            fake_services.run_wih = lambda *_a, **_k: (
                ["raw-record"],
                [{"url": "https://example.test/api/v1", "method": "GET"}],
            )
            fake_services.run_wih_endpoint_probe = probe_spy
            WihOrchestrator(task).run()
        finally:
            fake_services.run_wih = original_wih
            fake_services.run_wih_endpoint_probe = original_probe

    def test_endpoint_probe_runs_after_urlfinder_and_followup_consumes_candidates(self):
        ctx = _FakeDiscoveryContext([
            _FakeCandidate("https://example.test/api/v1"),       # 首轮已探测，排除
            _FakeCandidate("https://api.example.test/pet/list"),  # 新 API，应补探
            _FakeCandidate("https://api.example.test/old", status="covered"),
            _FakeCandidate("https://page.example.test/x", candidate_type="url"),
            _FakeCandidate("javascript:alert(1)"),
        ])
        task = _EndpointTask(ctx)
        task.assertEqual = self.assertEqual
        probed_batches = []

        def probe_spy(endpoints, **_kwargs):
            probed_batches.append([dict(e) for e in endpoints])
            return endpoints

        self._run_with_endpoints(task, probe_spy)

        self.assertEqual(
            [
                "wih_primary_scan",
                "wih_urlfinder_extract",
                "wih_endpoint_probe",
                "wih_endpoint_ai_fill",
                "wih_page_intel",
                "wih_api_doc",
                "wih_js_intel",
                "wih_endpoint_followup_probe",
                "wih_urlfinder_sensitive",
                "wih_trufflehog_js",
                "wih_url_probe",
            ],
            task.stage_names,
        )
        self.assertEqual(2, len(probed_batches))
        self.assertEqual("https://example.test/api/v1", probed_batches[0][0]["url"])
        self.assertEqual(
            [{"url": "https://api.example.test/pet/list", "method": "GET"}],
            probed_batches[1],
        )
        self.assertEqual(2, len(task.saved_endpoint_batches))
        self.assertEqual(("https://api.example.test/pet/list", "fetched"),
                         ctx.marked[-1])

    def test_registry_channel_replaces_graph_scan_when_attached(self):
        # 第 8 批 T8-3：context 挂载统一 Registry 后补探只消费 Registry，
        # 不再扫候选图（§7.3）；POST/已探测资产不外发请求。
        ctx = _FakeDiscoveryContext([
            _FakeCandidate("https://should-not-probe.test/x"),  # 图条目须被忽略
        ])
        registry = _FakeApiRegistry([
            _FakeEndpoint("https://api.example.test/g", "GET"),
            _FakeEndpoint("https://api.example.test/p", "POST"),
            _FakeEndpoint("https://example.test/api/v1", "GET"),  # 首轮已探测
        ])
        ctx.api_candidate_registry = registry
        task = _EndpointTask(ctx)
        task.assertEqual = self.assertEqual
        probed_batches = []

        def probe_spy(endpoints, **_kwargs):
            probed_batches.append([dict(e) for e in endpoints])
            for e in endpoints:
                e["verification_status"] = "probed"
            return endpoints

        original_wih = fake_services.run_wih
        original_probe = fake_services.run_wih_endpoint_probe
        try:
            fake_services.run_wih = lambda *_a, **_k: (
                ["raw-record"],
                [{"url": "https://example.test/api/v1", "method": "GET"}],
            )
            fake_services.run_wih_endpoint_probe = probe_spy
            WihOrchestrator(task).run()
        finally:
            fake_services.run_wih = original_wih
            fake_services.run_wih_endpoint_probe = original_probe

        # 候选图 fallback 不应触发：mark 未被调用。
        self.assertEqual([], ctx.marked)
        # probed_batches[0] 为首轮 Go 结果探测，[1] 为 Registry 补探。
        self.assertEqual(2, len(probed_batches))
        self.assertEqual(
            [{"url": "https://api.example.test/g", "method": "GET"}],
            probed_batches[1])
        # probe_report 记录的是编排层传入的回报词表（真实 Registry 的
        # 状态机映射由 test_api_candidate_registry 锁定）：POST→skipped、
        # 探测成功→probed、首轮已观察→observed。
        reported = {(url, method, status) for url, method, status in registry.reported}
        self.assertIn(("https://api.example.test/p", "POST", "skipped"), reported)
        self.assertIn(("https://api.example.test/g", "GET", "probed"), reported)
        self.assertIn(("https://example.test/api/v1", "GET", "observed"), reported)
        # 首轮结果双写为 covered 资产（§7.3 映射）。
        self.assertTrue(any(
            getattr(e, "url", "") == "https://example.test/api/v1"
            and getattr(e, "status", "") == "covered"
            for e in registry.registered))

    def test_legacy_channel_used_when_no_registry(self):
        # 未挂载统一 Registry（flag 关/管线回退）→ 走候选图 fallback，行为不变。
        ctx = _FakeDiscoveryContext([
            _FakeCandidate("https://api.example.test/pet/list"),
        ])
        task = _EndpointTask(ctx)
        task.assertEqual = self.assertEqual
        seen = []

        def probe_spy(endpoints, **_kwargs):
            seen.append(list(endpoints))
            return endpoints

        original_probe = fake_services.run_wih_endpoint_probe
        try:
            fake_services.run_wih_endpoint_probe = probe_spy
            WihOrchestrator(task).run()
        finally:
            fake_services.run_wih_endpoint_probe = original_probe
        self.assertTrue(seen, "fallback 通道应补探")
        self.assertTrue(ctx.marked, "候选图状态回写")

    def test_wih_records_reach_candidate_registry_with_recordType_attr(self):
        # WihRecord 属性名是 recordType，读成 record_type 不会抛错而是
        # 静默丢候选（新子域/新 API 无法分发）——用真实属性形态锁定。
        ctx = _FakeDiscoveryContext([])
        task = _Task()
        task.assertEqual = self.assertEqual
        task.discovery_context = ctx

        WihOrchestrator(task).run()

        self.assertTrue(ctx.registered, "WIH 记录必须登记进候选图")
        entry = ctx.registered[0]
        self.assertEqual("NewHostDiscovered", entry.get("event_type"))
        self.assertEqual("api.example.test", entry.get("candidate"))
        self.assertEqual("host", entry.get("candidate_type"))


class _FakeLedger(object):
    def __init__(self):
        self.finished = []

    def get(self, key):
        return None

    def finish(self, key, status, **_kwargs):
        self.finished.append((key, status))


class _FakePolicy(object):
    def __init__(self, blocked_hosts=()):
        self.blocked_hosts = tuple(blocked_hosts)

    def allow(self, target, traffic_class):
        return not any(h in str(target) for h in self.blocked_hosts)


class _FakeCtx(_FakeDiscoveryContext):
    def __init__(self, blocked_hosts=()):
        _FakeDiscoveryContext.__init__(self, [])
        self.ledger = _FakeLedger()
        self.waf_policy = _FakePolicy(blocked_hosts)

    def idempotency_key(self, stage, target, scan_profile="default", input_signature=""):
        return "k|{}|{}".format(stage, target)


class _WihResult(list):
    """模拟 Go 结果对象：list 载荷 + metrics 全绿字段。"""
    metrics = {"end_reason": "completed"}


class TestWihCoveredGuard(unittest.TestCase):
    """真实环境教训：Go 引擎撞 403 墙也"成功返回"，covered 不能照记。"""

    def _run(self, run_wih_result, blocked_hosts=()):
        run_wih_result = (_WihResult(run_wih_result[0]), run_wih_result[1])
        original_wih = fake_services.run_wih
        try:
            fake_services.run_wih = lambda *_a, **_k: run_wih_result
            task = _Task()
            task.assertEqual = self.assertEqual
            ctx = _FakeCtx(blocked_hosts=blocked_hosts)
            task.discovery_context = ctx
            WihOrchestrator(task).run()
            return ctx
        finally:
            fake_services.run_wih = original_wih

    def test_zero_result_batch_not_marked_covered(self):
        ctx = self._run(([], []))
        self.assertEqual([], ctx.ledger.finished)

    def test_blocked_site_not_marked_covered(self):
        ctx = self._run((["raw-record"], []), blocked_hosts=["example.test"])
        self.assertEqual([], ctx.ledger.finished)

    def test_normal_batch_still_covered(self):
        ctx = self._run((["raw-record"], []))
        self.assertEqual(1, len(ctx.ledger.finished))
        self.assertTrue(all(status == "covered" for _k, status in ctx.ledger.finished))


class TestWihOrchestrator(unittest.TestCase):
    def test_preserves_wih_stage_order_and_saves_normalized_record(self):
        task = _Task()
        task.assertEqual = self.assertEqual

        WihOrchestrator(task).run()

        self.assertEqual(
            [
                "wih_primary_scan",
                "wih_urlfinder_extract",
                "wih_page_intel",
                "wih_api_doc",
                "wih_js_intel",
                "wih_urlfinder_sensitive",
                "wih_trufflehog_js",
                "wih_url_probe",
            ],
            task.stage_names,
        )
        self.assertEqual(["record-1"], task.saved_records)


if __name__ == "__main__":
    unittest.main()
