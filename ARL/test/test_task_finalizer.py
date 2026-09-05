"""统一任务收尾器回归(报告§4 前置2)。

用真实 DiscoveryContext/NewHostQueue(纯 stdlib)+ 假任务对象验证:
有界 drain、残余显式 pending、skipped/partial/ok 状态语义、
holder 解析与配置开关;不依赖 xing/Mongo/Celery。
"""

import sys
import types
import unittest
from pathlib import Path
from unittest import mock

ARL_ROOT = Path(__file__).resolve().parents[1]
if str(ARL_ROOT) not in sys.path:
    sys.path.insert(0, str(ARL_ROOT))


def _stub_packages():
    app = sys.modules.get("app")
    if app is None or not hasattr(app, "__path__"):
        app = types.ModuleType("app")
        app.__path__ = [str(ARL_ROOT / "app")]
        sys.modules["app"] = app
    services = sys.modules.get("app.services")
    if services is None:
        services = types.ModuleType("app.services")
        services.__path__ = [str(ARL_ROOT / "app" / "services")]
        sys.modules["app.services"] = services


_stub_packages()

from app.services import task_finalizer as _tf  # noqa: E402
from app.services.discovery_context import DiscoveryContext  # noqa: E402
from app.services.discovery_queue import NewHostQueue  # noqa: E402
from app.services.domain_stage_services import _run_measured_stage  # noqa: E402
from app.services.task_finalizer import TaskFinalizer  # noqa: E402

# Config 引用必须取自生产模块本身:全量收集期 app.config 可能被其他用例替换为 fake,
# patch 自己捕获的副本不会作用于被测代码的读取路径。


def _make_holder(context):
    queue = NewHostQueue(
        context,
        waf_guard=None,
        max_hosts=10,
        allowed_hosts={"example.com"},
    )

    class _Holder(object):
        task_id = "finalizer-test"

        def __init__(self):
            self.discovery_context = context
            self.new_host_queue = queue
            self.wih_calls = 0
            self.raise_on_hunter = False

        def web_info_hunter(self):
            self.wih_calls += 1
            if self.raise_on_hunter:
                raise RuntimeError("hunter boom")
            self.new_host_queue.take_for_wih()

    return _Holder()


def _publish_host(context, host):
    context.register_candidate(
        event_type="NewHostDiscovered",
        candidate=host,
        candidate_type="host",
        source="page_intel",
    )


class NewHostQueueUntakenTest(unittest.TestCase):
    def test_has_untaken_tracks_take(self):
        context = DiscoveryContext(task_id="q-1")
        holder = _make_holder(context)
        self.assertFalse(holder.new_host_queue.has_untaken())
        _publish_host(context, "sub.example.com")
        self.assertTrue(holder.new_host_queue.has_untaken())
        holder.new_host_queue.take_for_wih()
        self.assertFalse(holder.new_host_queue.has_untaken())

    def test_out_of_scope_host_not_queued(self):
        context = DiscoveryContext(task_id="q-2")
        holder = _make_holder(context)
        _publish_host(context, "other.testdomain.invalid")
        self.assertFalse(holder.new_host_queue.has_untaken())


class DrainTest(unittest.TestCase):
    def test_drain_consumes_pending_hosts_once_per_round(self):
        context = DiscoveryContext(task_id="d-1")
        holder = _make_holder(context)
        _publish_host(context, "a.example.com")
        _publish_host(context, "b.example.com")

        result = TaskFinalizer(holder).drain_new_hosts(holder)
        self.assertEqual(result["drain_rounds"], 1)
        self.assertEqual(result["hosts_before"], 2)
        self.assertEqual(result["hosts_after"], 0)
        self.assertEqual(holder.wih_calls, 1)
        self.assertFalse(holder.new_host_queue.has_untaken())

    def test_drain_disabled_by_rounds_zero(self):
        context = DiscoveryContext(task_id="d-2")
        holder = _make_holder(context)
        _publish_host(context, "a.example.com")
        with mock.patch.object(_tf.Config, "TASK_FINALIZER_DRAIN_ROUNDS", 0, create=True):
            result = TaskFinalizer(holder).drain_new_hosts(holder)
        self.assertEqual(result["drain_rounds"], 0)
        self.assertEqual(holder.wih_calls, 0)

    def test_hunter_exception_does_not_propagate(self):
        context = DiscoveryContext(task_id="d-3")
        holder = _make_holder(context)
        holder.raise_on_hunter = True
        _publish_host(context, "a.example.com")
        result = TaskFinalizer(holder).drain_new_hosts(holder)
        self.assertEqual(result["hosts_after"], 1)


class PendingEvidenceTest(unittest.TestCase):
    def test_residual_hosts_recorded_pending_in_ledger(self):
        context = DiscoveryContext(task_id="p-1")
        holder = _make_holder(context)
        _publish_host(context, "late.example.com")
        holder.new_host_queue.take_for_wih()
        _publish_host(context, "residual.example.com")

        written = TaskFinalizer(holder).persist_pending_hosts(holder)
        self.assertEqual(written, 1)
        self.assertIsNone(
            holder.discovery_context.ledger.get("pending_backlog|wih|late.example.com")
        )
        entry = holder.discovery_context.ledger.get("pending_backlog|wih|residual.example.com")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.status, "pending")
        self.assertEqual(entry.payload.get("task_id"), "finalizer-test")
        # 幂等:重复收尾不再写第二条
        self.assertEqual(TaskFinalizer(holder).persist_pending_hosts(holder), 0)


class FinalizerRunTest(unittest.TestCase):
    def test_run_ok_when_no_backlog(self):
        context = DiscoveryContext(task_id="r-1")
        holder = _make_holder(context)
        result = TaskFinalizer(holder).run()
        self.assertEqual(result["metrics"]["status"], "ok")
        self.assertEqual(result["metrics"]["residual_total"], 0)

    def test_run_partial_when_candidate_backlog(self):
        context = DiscoveryContext(task_id="r-2")
        holder = _make_holder(context)
        context.register_candidate(
            event_type="UrlCandidateDiscovered",
            candidate="https://leftover.example.com/api",
            candidate_type="url",
            source="urlfinder",
        )
        result = TaskFinalizer(holder).run()
        metrics = result["metrics"]
        self.assertEqual(metrics["status"], "partial")
        self.assertGreaterEqual(metrics["backlog_candidate_discovered"], 1)

    def test_run_skipped_without_discovery_context(self):
        class _Bare(object):
            task_id = "r-3"

        result = TaskFinalizer(_Bare()).run()
        self.assertEqual(result["metrics"]["status"], "skipped")

    def test_config_gate_skips(self):
        context = DiscoveryContext(task_id="r-4")
        holder = _make_holder(context)
        with mock.patch.object(_tf.Config, "TASK_FINALIZER_ENABLE", False, create=True):
            result = TaskFinalizer(holder).run()
        self.assertEqual(result["metrics"]["status"], "skipped")
        self.assertEqual(result["metrics"]["end_reason"], "disabled_by_config")

    def test_holder_resolution_prefers_web_site_fetch(self):
        context = DiscoveryContext(task_id="r-5")
        holder = _make_holder(context)

        class _Outer(object):
            task_id = "r-5"
            web_site_fetch = holder

        result = TaskFinalizer(_Outer()).run()
        self.assertEqual(result["metrics"]["status"], "ok")

    def test_executor_route_used_when_available(self):
        context = DiscoveryContext(task_id="r-6")
        holder = _make_holder(context)
        seen = {}

        def fake_internal_stage(name, func):
            seen["name"] = name
            return func()

        holder._run_internal_stage = fake_internal_stage
        result = TaskFinalizer(holder).run()
        self.assertEqual(seen["name"], "task_finalization")
        self.assertEqual(result["metrics"]["status"], "ok")


class MeasuredStageTest(unittest.TestCase):
    """阶段统一经执行器产出独立指标;无执行器的轻量任务回退手工语义。"""

    def test_executor_path(self):
        calls = []

        class _Task(object):
            def _run_internal_stage(self, name, func):
                calls.append(name)
                return func()

        TaskFinalizer  # noqa: B018 保持引用清晰

        _run_measured_stage(_Task(), "domain_brute", lambda: {"output_count": 1})
        self.assertEqual(calls, ["domain_brute"])

    def test_fallback_manual_path(self):
        events = []

        class _LightTask(object):
            def update_task_field(self, field, value):
                events.append(("field", field, value))

            def update_services(self, name, elapsed, metrics=None):
                events.append(("services", name))

        _run_measured_stage(_LightTask(), "arl_search", lambda: None)
        self.assertIn(("field", "status", "arl_search"), events)
        self.assertIn(("services", "arl_search"), events)


if __name__ == "__main__":
    unittest.main()
