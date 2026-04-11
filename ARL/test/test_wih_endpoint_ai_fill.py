import unittest
from unittest.mock import patch


IMPORT_ERROR = None
try:
    from app.services import wih_endpoint_ai_fill as fill_module
except Exception as exc:
    fill_module = None
    IMPORT_ERROR = exc


class _FakeResponse(object):
    def __init__(self, status_code=200, headers=None, body=b'{"ok":true,"token":"demo-token","user":"tester"}'):
        self.status_code = status_code
        self.headers = headers or {"Content-Type": "application/json"}
        self.encoding = "utf-8"
        self._body = body

    def iter_content(self, chunk_size=4096, decode_unicode=False):
        if self._body:
            yield self._body

    def close(self):
        return None


@unittest.skipIf(IMPORT_ERROR is not None, "requires wih_endpoint_ai_fill dependencies: {}".format(IMPORT_ERROR))
class TestWihEndpointAiFill(unittest.TestCase):
    def _runtime(self):
        return {
            "enabled": True,
            "ai_available": False,
            "prompt_id": "default_ai_fill_wih_endpoint",
            "prompt_name": "默认AI填充-WIH接口",
            "prompt_content": "",
            "ai_config": {},
            "active_profile": {},
            "request_delay_ms": 0,
            "api_console": None,
        }

    def test_fill_form_urlencoded_packet_and_probe(self):
        packet = (
            "POST /_rest/st/ajax_st_app_news.ashx HTTP/1.1\r\n"
            "Host: zsbgs.scwxzyxy.cn\r\n"
            "Accept: application/json, text/plain, */*\r\n"
            "Connection: close\r\n"
            "Content-Length: 73\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "User-Agent: Mozilla/5.0\r\n"
            "\r\n"
            "FolderId=<value>&TabId=<value>&action=ToSearchUrl&kw=<value>&said=<value>"
        )
        endpoint = {
            "target": "https://zsbgs.scwxzyxy.cn",
            "page_url": "https://zsbgs.scwxzyxy.cn/p/0/?StId=st_app_news_i_x93QtRs5gli9KJp3aBk",
            "url": "https://zsbgs.scwxzyxy.cn/_rest/st/ajax_st_app_news.ashx",
            "method": "POST",
            "request_packet": packet,
            "request_template": {},
            "status_code": None,
            "response_size": None,
        }

        with patch.object(fill_module, "_load_ai_fill_runtime", return_value=self._runtime()), \
             patch.object(fill_module.utils, "check_dns_policy_for_url", return_value=(True, {})), \
             patch.object(fill_module.Config, "WIH_ENDPOINT_AI_FILL_MAX_TARGETS", 10), \
             patch.object(fill_module.Config, "WIH_ENDPOINT_AI_FILL_CONCURRENCY", 1), \
             patch.object(fill_module.requests, "request", return_value=_FakeResponse()) as mock_request:
            results = fill_module.run_wih_endpoint_ai_fill("task-1", [endpoint])

        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("tested", result.get("ai_fill_status"))
        self.assertEqual("heuristic", result.get("ai_fill_source"))
        self.assertTrue(result.get("ai_fill_tested"))
        self.assertIn("JSON键", str(result.get("ai_fill_response_summary") or ""))
        self.assertIn("token", str(result.get("ai_fill_response_summary") or ""))
        self.assertIn("HTTP/1.1 200", str(result.get("ai_fill_response_packet") or ""))
        self.assertIn("\"ok\":true", str(result.get("ai_fill_response_packet") or ""))

        param_map = {
            "{}:{}".format(str(item.get("location") or ""), str(item.get("name") or "")): str(item.get("value") or "")
            for item in list(result.get("ai_fill_params") or [])
            if isinstance(item, dict)
        }
        self.assertEqual("1", param_map.get("body:FolderId"))
        self.assertEqual("1", param_map.get("body:TabId"))
        self.assertEqual("ToSearchUrl", param_map.get("body:action"))
        self.assertEqual("test", param_map.get("body:kw"))
        self.assertEqual("1", param_map.get("body:said"))

        mock_request.assert_called_once()
        self.assertEqual("POST", mock_request.call_args.args[0])
        self.assertEqual("https://zsbgs.scwxzyxy.cn/_rest/st/ajax_st_app_news.ashx", mock_request.call_args.args[1])
        self.assertEqual("ToSearchUrl", mock_request.call_args.kwargs["data"]["action"])
        self.assertEqual("test", mock_request.call_args.kwargs["data"]["kw"])

    def test_delete_method_only_returns_hint_without_active_probe(self):
        endpoint = {
            "target": "https://portal.example.com",
            "page_url": "https://portal.example.com/admin/user",
            "url": "https://portal.example.com/api/admin/user/1",
            "method": "DELETE",
            "request_template": {
                "path": {"id": "<value>"},
                "body": {"userId": "<value>"},
                "headers": {"Content-Type": "application/json"},
            },
        }

        with patch.object(fill_module, "_load_ai_fill_runtime", return_value=self._runtime()), \
             patch.object(fill_module.Config, "WIH_ENDPOINT_AI_FILL_MAX_TARGETS", 10), \
             patch.object(fill_module.Config, "WIH_ENDPOINT_AI_FILL_CONCURRENCY", 1), \
             patch.object(fill_module.requests, "request") as mock_request:
            results = fill_module.run_wih_endpoint_ai_fill("task-2", [endpoint])

        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("hint_only", result.get("ai_fill_status"))
        self.assertTrue(result.get("ai_fill_hint_only"))
        self.assertFalse(result.get("ai_fill_tested"))
        self.assertIn("DELETE", str(result.get("ai_fill_note") or ""))
        mock_request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
