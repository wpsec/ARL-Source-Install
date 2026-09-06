"""统一任务收尾器回归(报告§4 前置2)。

用真实 DiscoveryContext/NewHostQueue(纯 stdlib)+ 假任务对象验证:
有界 drain、残余显式 pending、skipped/partial/ok 状态语义、
holder 解析与配置开关;不依赖 xing/Mongo/Celery。
"""

import sys
import unittest
from pathlib import Path
from unittest import mock

ARL_ROOT = Path(__file__).resolve().parents[1]
if str(ARL_ROOT) not in sys.path:
    sys.path.insert(0, str(ARL_ROOT))


# 测试卫生（计划 1 未完成项收敛，Review P2-13 规范）：旧实现注入 app.services
# 空壳桩后不还原，同进程后续 bootstrap 红线断言（assert_no_shell_pollution）
# 被引爆。改用共用 bootstrap 的"临时桩窗口 + finally 还原"模式，模块级常量
# 持有真实引用，免疫其它用例的槽位污染。
from test._api_unified_bootstrap import (  # noqa: E402
    assert_no_shell_pollution,
    load_modules,
)

_captured = load_modules(
    "app.services.task_finalizer",
    "app.services.discovery_context",
    "app.services.discovery_queue",
    "app.services.domain_stage_services",
)
assert_no_shell_pollution()

_tf = _captured["app.services.task_finalizer"]
DiscoveryContext = _captured["app.services.discovery_context"].DiscoveryContext
NewHostQueue = _captured["app.services.discovery_queue"].NewHostQueue
_run_measured_stage = _captured["app.services.domain_stage_services"]._run_measured_stage
TaskFinalizer = _tf.TaskFinalizer

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


class DrainEntryResolutionTest(unittest.TestCase):
    """收尾 drain 必须重入生产入口 run_web_info_hunter(Review 20260905 修复轮)。"""

    class _ProductionHolder(object):
        task_id = "entry-prod"

        def __init__(self, context):
            self.discovery_context = context
            self.new_host_queue = NewHostQueue(
                context, waf_guard=None, max_hosts=10, allowed_hosts={"example.com"}
            )
            self.hunter_calls = 0

        def run_web_info_hunter(self):
            self.hunter_calls += 1
            self.new_host_queue.take_for_wih()

    def test_production_entry_name_is_used(self):
        context = DiscoveryContext(task_id="e-1")
        holder = self._ProductionHolder(context)
        _publish_host(context, "a.example.com")
        result = TaskFinalizer(holder).drain_new_hosts(holder)
        self.assertEqual(result["drain_rounds"], 1)
        self.assertEqual(holder.hunter_calls, 1)
        self.assertEqual(result["hosts_after"], 0)

    def test_missing_hunter_entry_degrades_to_residual(self):
        context = DiscoveryContext(task_id="e-2")

        class _NoHunter(object):
            task_id = "e-2"

            def __init__(self):
                self.discovery_context = context
                self.new_host_queue = NewHostQueue(
                    context, waf_guard=None, max_hosts=10, allowed_hosts={"example.com"}
                )

        holder = _NoHunter()
        _publish_host(context, "a.example.com")
        finalizer = TaskFinalizer(holder)
        finalizer.run()
        # 无法 drain 时残余必须显影并把终态降级为 done_pending，绝不伪装干净完成
        self.assertEqual(finalizer.decision["terminal_status"], "done_pending")
        self.assertEqual(finalizer.decision["blocking_residual"], 1)


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


class PolicyPendingLedgerTest(unittest.TestCase):
    """策略级 pending 显影账本(Review 20260905 §4 重要项2)。"""

    def test_directory_policy_inactive_without_option(self):
        context = DiscoveryContext(task_id="pd-1")
        holder = _make_holder(context)
        holder.options = {}
        _publish_host(context, "late.example.com")
        result = TaskFinalizer(holder).run()
        metrics = result["metrics"]
        self.assertEqual(metrics["pending_directory"], 0)

    def test_url_api_and_other_policy_buckets(self):
        context = DiscoveryContext(task_id="pd-2")
        holder = _make_holder(context)
        holder.options = {}
        context.register_candidate(
            event_type="UrlCandidateDiscovered",
            candidate="https://u.example.com/api",
            candidate_type="url",
            source="urlfinder",
        )
        context.register_candidate(
            event_type="EndpointCandidateDiscovered",
            candidate="https://u.example.com/swagger",
            candidate_type="endpoint",
            source="api_doc",
        )
        context.register_candidate(
            event_type="UrlCandidateDiscovered",
            candidate="https://u.example.com/a.js",
            candidate_type="js",
            source="urlfinder",
        )
        result = TaskFinalizer(holder).run()
        metrics = result["metrics"]
        self.assertEqual(metrics["pending_url_probe"], 1)
        self.assertEqual(metrics["pending_api"], 1)
        self.assertEqual(metrics["open_other_candidates"], 1)
        # 非阻断策略不改变 done 终态(Review §4 重要项1：只有 WIH 队列残余阻断)
        self.assertEqual(metrics["terminal_status"], "done")
        entry = context.ledger.get(
            "pending_backlog|url_probe|https://u.example.com/api"
        )
        self.assertIsNotNone(entry)
        self.assertEqual(entry.status, "pending")
        self.assertEqual(entry.payload.get("policy"), "url_probe")
        self.assertIsNone(
            context.ledger.get("pending_backlog|url_probe|https://u.example.com/a.js")
        )

    def test_queue_overflow_host_shown_as_wih_overflow(self):
        """容量丢弃且目录契约未激活的主机必须显影 wih_overflow（自查轮补口径）。"""

        context = DiscoveryContext(task_id="pd-4")
        queue = NewHostQueue(
            context, waf_guard=None, max_hosts=1, allowed_hosts={"example.com"}
        )

        class _Holder(object):
            task_id = "pd-4"

            def __init__(self):
                self.discovery_context = context
                self.new_host_queue = queue
                self.options = {}

            def run_web_info_hunter(self):
                queue.take_for_wih()

        holder = _Holder()
        _publish_host(context, "first.example.com")
        _publish_host(context, "dropped.example.com")
        self.assertTrue(queue.is_queued("first.example.com"))
        self.assertFalse(queue.is_queued("DROPPED.example.com"))

        finalizer = TaskFinalizer(holder)
        result = finalizer.run()
        metrics = result["metrics"]
        # 队列主机被 drain 消费；容量丢弃主机不阻断终态但必须显影
        self.assertEqual(metrics["pending_wih"], 0)
        self.assertEqual(metrics["pending_wih_overflow"], 1)
        self.assertEqual(metrics["status"], "partial")
        self.assertEqual(finalizer.terminal_status(), "done")
        entry = context.ledger.get("pending_backlog|wih_overflow|dropped.example.com")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.status, "pending")

    def test_directory_pending_with_consumed_ledger_skip(self):
        context = DiscoveryContext(task_id="pd-3")
        holder = _make_holder(context)
        holder.options = {"file_leak": True}
        _publish_host(context, "a.example.com")
        _publish_host(context, "b.example.com")
        context.ledger.finish(
            context.idempotency_key("file_leak", "https://a.example.com"),
            "covered",
        )
        result = TaskFinalizer(holder).run()
        metrics = result["metrics"]
        # a 已被目录消费账本证明消费；b 是晚到候选显影为 pending
        self.assertEqual(metrics["pending_directory"], 1)
        entry = context.ledger.get("pending_backlog|directory|b.example.com")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.payload.get("reason"), "finalizer_next_cycle")


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

    def test_run_marks_external_boundary_metrics(self):
        context = DiscoveryContext(task_id="r-7")
        holder = _make_holder(context)
        context.record_metric("external_network_wih_go", 3)
        context.record_metric("external_network_trufflehog", 2)
        result = TaskFinalizer(holder).run()
        metrics = result["metrics"]
        self.assertEqual(metrics["external_network_wih_go"], 3)
        self.assertEqual(metrics["external_network_trufflehog"], 2)
        # 零计数/无关指标不得混入
        self.assertNotIn("cache_miss_count", metrics)

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


class FinalizerDecisionTest(unittest.TestCase):
    """终态决策与兼容映射(Review 20260905 §4 重要项1)。"""

    def test_clean_decision_maps_to_done(self):
        context = DiscoveryContext(task_id="fd-1")
        holder = _make_holder(context)
        finalizer = TaskFinalizer(holder)
        finalizer.run()
        self.assertEqual(finalizer.terminal_status(), "done")
        self.assertEqual(finalizer.decision["verdict"], "clean")

    def test_queue_residual_maps_to_done_pending(self):
        context = DiscoveryContext(task_id="fd-2")
        holder = _make_holder(context)
        _publish_host(context, "residual.example.com")
        finalizer = TaskFinalizer(holder)
        with mock.patch.object(_tf.Config, "TASK_FINALIZER_DRAIN_ROUNDS", 0, create=True):
            result = finalizer.run()
        self.assertEqual(finalizer.terminal_status(), "done_pending")
        self.assertEqual(result["metrics"]["terminal_status"], "done_pending")
        self.assertEqual(result["metrics"]["status"], "partial")
        self.assertEqual(result["metrics"]["pending_wih"], 1)
        self.assertEqual(result["metrics"]["blocking_residual"], 1)

    def test_nonblocking_pending_keeps_done_but_records_partial(self):
        context = DiscoveryContext(task_id="fd-3")
        holder = _make_holder(context)
        context.register_candidate(
            event_type="UrlCandidateDiscovered",
            candidate="https://late.example.com/next",
            candidate_type="url",
            source="urlfinder",
        )
        finalizer = TaskFinalizer(holder)
        result = finalizer.run()
        # 晚到 URL 候选按下一轮周期语义显影 pending，不阻断 done（契约只承诺队列清空）
        self.assertEqual(finalizer.terminal_status(), "done")
        self.assertEqual(result["metrics"]["status"], "partial")
        self.assertEqual(result["metrics"]["pending_url_probe"], 1)
        self.assertEqual(result["metrics"]["blocking_residual"], 0)

    def test_degraded_run_maps_to_done_degraded(self):
        context = DiscoveryContext(task_id="fd-4")
        holder = _make_holder(context)
        finalizer = TaskFinalizer(holder)
        with mock.patch.object(
            TaskFinalizer, "_core", side_effect=RuntimeError("boom")
        ):
            result = finalizer.run()
        self.assertEqual(finalizer.terminal_status(), "done_degraded")
        self.assertEqual(result["terminal_status"], "done_degraded")

    def test_external_boundary_metrics_surfaced(self):
        context = DiscoveryContext(task_id="fd-5")
        holder = _make_holder(context)
        context.record_metric("external_network_wih_go", 7)
        context.record_metric("external_network_trufflehog", 2)
        context.record_metric("cache_hit_count", 99)
        result = TaskFinalizer(holder).run()
        metrics = result["metrics"]
        self.assertEqual(metrics["external_network_wih_go"], 7)
        self.assertEqual(metrics["external_network_trufflehog"], 2)
        self.assertNotIn("cache_hit_count", metrics)


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
