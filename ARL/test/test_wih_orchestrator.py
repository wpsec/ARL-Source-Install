"""WIH 编排器回归测试。"""

import importlib.util
import sys
import types
import unittest
from pathlib import Path


_MODULE_PATH = Path(__file__).resolve().parents[1] / "app" / "services" / "wih_orchestrator.py"
_SPEC = importlib.util.spec_from_file_location("wih_orchestrator_test_module", _MODULE_PATH)
_MODULE = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader


class _Logger(object):
    def info(self, _message):
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
