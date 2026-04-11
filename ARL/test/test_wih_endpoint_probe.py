import types
import unittest
from unittest.mock import patch

IMPORT_ERROR = None
try:
    import app.services.commonTask as common_task_module
    from app.services.commonTask import WebSiteFetch
except Exception as exc:
    common_task_module = None
    WebSiteFetch = None
    IMPORT_ERROR = exc


@unittest.skipIf(IMPORT_ERROR is not None, "requires commonTask dependencies: {}".format(IMPORT_ERROR))
class TestWihEndpointProbeIntegration(unittest.TestCase):
    def test_run_web_info_hunter_enriches_endpoint_status_before_save(self):
        task = WebSiteFetch.__new__(WebSiteFetch)
        task.task_id = "task-1"
        task.sites = ["https://zsbgs.scwxzyxy.cn"]
        task.options = {}
        task.waf_guard = None
        task.page_url_set = set()
        task.wih_record_set = set()
        task.wih_domain_set = set()
        task.scope_domain = []
        task.base_update_task = types.SimpleNamespace(
            update_task_field=lambda *args, **kwargs: None,
            append_service=lambda *args, **kwargs: None,
        )
        task._filter_waf_blocked_targets = lambda sites, stage_name="": list(sites or [])
        task._run_substage = lambda name, func, detail="": func()
        task._url_in_task_scope = lambda value: True
        task._wih_record_in_task_scope = lambda record: True
        task.add_wih_domain_set = lambda record: None

        saved_endpoints = []
        task._save_wih_endpoints = lambda endpoints: saved_endpoints.extend(list(endpoints or []))

        raw_endpoints = [
            {
                "target": "https://zsbgs.scwxzyxy.cn",
                "page_url": "https://zsbgs.scwxzyxy.cn/p/0/?StId=st_app_news_i_x93QtRs5gli9KJp3aBk",
                "url": "https://zsbgs.scwxzyxy.cn/p/0/",
                "method": "POST",
                "status_code": None,
                "response_size": None,
                "request_template": {
                    "body": {"StId": "st_app_news_i_x93QtRs5gli9KJp3aBk"},
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                },
            }
        ]
        enriched_endpoints = [
            {
                **raw_endpoints[0],
                "status_code": 200,
                "response_status": 200,
                "response_size": 512,
            }
        ]
        ai_filled_endpoints = [
            {
                **enriched_endpoints[0],
                "ai_fill_status": "tested",
                "ai_fill_source": "heuristic",
                "ai_fill_params": [{"name": "StId", "location": "body", "value": "st_app_news_i_x93QtRs5gli9KJp3aBk"}],
                "ai_fill_response_summary": "JSON键: ok",
            }
        ]

        with patch.object(common_task_module.services, "run_wih", return_value=([], raw_endpoints)), \
             patch.object(common_task_module.services, "run_wih_endpoint_probe", return_value=enriched_endpoints) as mock_probe, \
             patch.object(common_task_module.services, "run_wih_endpoint_ai_fill", return_value=ai_filled_endpoints) as mock_ai_fill, \
             patch.object(common_task_module.services, "run_urlfinder_extract", return_value=[]), \
             patch.object(common_task_module.services, "run_page_intel_scan", return_value=[]), \
             patch.object(common_task_module.services, "run_api_doc_scan", return_value=[]):
            task.run_web_info_hunter()

        mock_probe.assert_called_once()
        mock_ai_fill.assert_called_once()
        self.assertEqual(1, len(saved_endpoints))
        self.assertEqual(200, saved_endpoints[0].get("status_code"))
        self.assertEqual(512, saved_endpoints[0].get("response_size"))
        self.assertEqual("tested", saved_endpoints[0].get("ai_fill_status"))


if __name__ == "__main__":
    unittest.main()
