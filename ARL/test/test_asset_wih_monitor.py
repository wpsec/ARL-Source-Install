"""WIH 资产监控入口用固定 stage 响应验证编排。"""

import unittest
from unittest.mock import patch

import app.services.asset_wih_monitor as wih_monitor
from app.helpers.asset_wih_monitor import submit_asset_wih_monitor_job


class TestAssetWihMonitor(unittest.TestCase):
    def test_empty_fixture_results_do_not_persist_or_scan(self):
        sites = ["https://target.fixture.invalid"]
        with patch.object(
            wih_monitor, "get_scope_by_scope_id",
            return_value={"name": "fixture scope", "scope_type": "domain", "scope_array": []},
        ), patch.object(wih_monitor.asset_site, "find_site_by_scope_id", return_value=sites), \
                patch.object(wih_monitor, "run_wih", return_value=[]) as run_wih, \
                patch.object(wih_monitor, "run_urlfinder_extract", return_value=[]), \
                patch.object(wih_monitor, "run_page_intel_scan", return_value=[]), \
                patch.object(wih_monitor, "api_unified_enabled", return_value=False), \
                patch.object(wih_monitor, "run_api_doc_scan", return_value=[]), \
                patch.object(wih_monitor, "run_js_intel_scan", return_value=[]), \
                patch.object(wih_monitor, "run_urlfinder_sensitive_scan", return_value=[]), \
                patch.object(wih_monitor.asset_wih, "get_wih_record_fnv_hash", return_value=set()):
            results = wih_monitor.asset_wih_monitor("fixture-scope")

        self.assertEqual([], results)
        run_wih.assert_called_once_with(sites)

    def test_monitor_job_submits_task_data(self):
        with patch("app.helpers.task.submit_task") as submit:
            submit_asset_wih_monitor_job(
                scope_id="fixture-scope",
                name="fixture monitor",
                scheduler_id="fixture-scheduler",
            )

        task_data = submit.call_args.args[0]
        self.assertEqual("fixture-scope", task_data["options"]["scope_id"])
        self.assertEqual("fixture-scheduler", task_data["options"]["scheduler_id"])


if __name__ == "__main__":
    unittest.main()
