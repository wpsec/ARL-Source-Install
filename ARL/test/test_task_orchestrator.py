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


if __name__ == "__main__":
    unittest.main()
