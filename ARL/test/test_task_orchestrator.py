"""任务高层编排器测试。"""

import unittest
from unittest.mock import patch

from app.config import Config
from app.services.task_orchestrator import DomainTaskOrchestrator


class _Task(object):
    def __init__(self):
        self.task_id = "65f000000000000000000001"
        self.options = {}
        self._last_ip_query_metrics = {}
        self.calls = []

    def update_task_field(self, field, value):
        self.calls.append(("update", field, value))

    def _seed_base_domain(self):
        self.calls.append("seed")

    def _run_discovery_preview(self):
        self.calls.append("preview")

    def _load_saved_domain_info(self):
        self.calls.append("load")

    def domain_fetch(self):
        self.calls.append("domain_fetch")

    def search_engines(self):
        self.calls.append("search_engines")

    def start_ip_fetch(self):
        self.calls.append("start_ip_fetch")

    def start_site_fetch(self):
        self.calls.append("start_site_fetch")

    def start_find_vhost(self):
        self.calls.append("start_find_vhost")

    def start_poc_run(self):
        self.calls.append("start_poc_run")

    def start_wih_domain_update(self):
        self.calls.append("start_wih_domain_update")

    def common_run(self):
        self.calls.append("common_run")

    def update_services(self, *args, **kwargs):
        self.calls.append(("update_services", args, kwargs))


class TestDomainTaskOrchestrator(unittest.TestCase):
    def test_discovery_and_deep_keep_stage_order(self):
        task = _Task()
        with patch.object(Config, "IP_PIVOT_QUERY_ENABLE", False), \
                patch("app.services.task_orchestrator.push_task_finish_notify") as notify:
            DomainTaskOrchestrator(task).run_discovery(include_preview=True)
            DomainTaskOrchestrator(task).run_deep()

        self.assertEqual("seed", task.calls[1])
        self.assertEqual("preview", task.calls[2])
        deep_calls = [item for item in task.calls if isinstance(item, str)]
        self.assertEqual(
            [
                "seed",
                "preview",
                "load",
                "domain_fetch",
                "search_engines",
                "start_ip_fetch",
                "start_site_fetch",
                "start_find_vhost",
                "start_poc_run",
                "start_wih_domain_update",
                "common_run",
            ],
            deep_calls,
        )
        self.assertEqual("done", task.calls[-2][2])
        notify.assert_called_once_with(task.task_id)


class _FakeFinalizer(object):
    """替换 TaskFinalizer：只提供终态决策，drain 细节由 task_finalizer 测试覆盖。"""

    def __init__(self, terminal_status, task=None):
        self._terminal_status = terminal_status
        self.ran = 0
        self.task = task

    def run(self):
        self.ran += 1
        if self.task is not None:
            self.task.calls.append("finalizer")
        return {"metrics": {"terminal_status": self._terminal_status}}

    def terminal_status(self):
        return self._terminal_status


class _IPFakeBaseUpdate(object):
    def __init__(self):
        self.calls = []

    def update_task_field(self, field, value):
        self.calls.append(("update", field, value))


class _IPFakeTask(object):
    def __init__(self):
        self.task_id = "65f000000000000000000002"
        self.task_tag = "task"
        self.site_list = []
        self.options = {}
        self.base_update_task = _IPFakeBaseUpdate()


class _FakeWebSiteFetch(object):
    instances = []

    def __init__(self, task_id=None, sites=None, options=None):
        self.task_id = task_id
        self.calls = []
        _FakeWebSiteFetch.instances.append(self)

    def run(self):
        # 记录 run 时刻的终态归属标记，锁定"置位在 run 之前"。
        self.calls.append(("run", getattr(self, "terminal_finalize_host_owned", False)))


class TestDomainOrchestratorTerminalStatus(unittest.TestCase):
    def _run_deep(self, terminal_status):
        task = _Task()
        finalizer = _FakeFinalizer(terminal_status, task=task)
        with patch.object(Config, "IP_PIVOT_QUERY_ENABLE", False), \
                patch("app.services.task_orchestrator.TaskFinalizer", return_value=finalizer), \
                patch("app.services.task_orchestrator.push_task_finish_notify") as notify:
            DomainTaskOrchestrator(task).run_deep()
        return task, finalizer, notify

    def test_clean_done_writes_done(self):
        task, finalizer, notify = self._run_deep("done")
        self.assertEqual(finalizer.ran, 1)
        self.assertEqual("done", task.calls[-2][2])
        notify.assert_called_once_with(task.task_id)

    def test_queue_residual_writes_done_pending(self):
        task, finalizer, _ = self._run_deep("done_pending")
        status_calls = [c for c in task.calls if c[0] == "update" and c[1] == "status"]
        self.assertEqual(status_calls[-1][2], "done_pending")
        # 收尾决策必须发生在 common_run 统计之前、终态写入之前
        idx_finalizer = task.calls.index("finalizer")
        idx_common = task.calls.index("common_run")
        idx_status = next(
            i for i, c in enumerate(task.calls)
            if isinstance(c, tuple) and c[0] == "update" and c[1] == "status" and c[2] == "done_pending"
        )
        self.assertLess(idx_finalizer, idx_common)
        self.assertLess(idx_common, idx_status)

    def test_degraded_writes_done_degraded(self):
        task, _, _ = self._run_deep("done_degraded")
        status_calls = [c for c in task.calls if c[0] == "update" and c[1] == "status"]
        self.assertEqual(status_calls[-1][2], "done_degraded")


class TestIPTaskOrchestrator(unittest.TestCase):
    def _run(self, terminal_status):
        import app.services.task_orchestrator as to

        task = _IPFakeTask()
        finalizer = _FakeFinalizer(terminal_status)
        _FakeWebSiteFetch.instances = []
        with patch.object(to, "IPNetworkStageService"), \
                patch.object(to, "IPPostProcessStageService"), \
                patch.object(to, "TaskLifecycleService"), \
                patch.object(to, "WebSiteFetch", _FakeWebSiteFetch), \
                patch.object(to, "TaskFinalizer", return_value=finalizer), \
                patch.object(to, "push_task_finish_notify") as notify:
            to.IPTaskOrchestrator(task).run()
        return task, finalizer, notify

    def test_terminal_status_follows_finalizer_decision(self):
        for terminal_status in ("done", "done_pending", "done_degraded"):
            with self.subTest(status=terminal_status):
                task, finalizer, notify = self._run(terminal_status)
                self.assertEqual(finalizer.ran, 1)
                # 收尾决策后必须把 web_site_fetch 挂回任务供 holder 解析路径一致性验证
                self.assertIs(task.web_site_fetch, _FakeWebSiteFetch.instances[0])
                self.assertEqual(
                    _FakeWebSiteFetch.instances[0].calls, [("run", True)],
                    "IP 宿主必须在站点实例 run 前置位终态所有权",
                )
                status_calls = [
                    c for c in task.base_update_task.calls
                    if c[0] == "update" and c[1] == "status"
                ]
                self.assertEqual(status_calls[-1][2], terminal_status)
                notify.assert_called_once_with(task.task_id)


if __name__ == "__main__":
    unittest.main()
