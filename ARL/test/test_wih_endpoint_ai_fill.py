import unittest
from unittest.mock import patch

import requests


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

    def test_ai_transport_error_falls_back_to_heuristic_fill(self):
        packet = (
            "POST /_rest/st/ajax_st_app_news.ashx HTTP/1.1\r\n"
            "Host: zsbgs.scwxzyxy.cn\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "\r\n"
            "FolderId=<value>&TabId=<value>&action=ToSearchUrl&kw=<value>&said=<value>"
        )
        endpoint = {
            "target": "https://zsbgs.scwxzyxy.cn",
            "page_url": "https://zsbgs.scwxzyxy.cn/p/0/",
            "url": "https://zsbgs.scwxzyxy.cn/_rest/st/ajax_st_app_news.ashx",
            "method": "POST",
            "request_packet": packet,
            "request_template": {},
            "status_code": None,
            "response_size": None,
        }

        class _FakeApiConsole(object):
            AI_WIH_ENDPOINT_FILL_SCENE = "ai_fill_wih_endpoint"
            AI_WIH_ENDPOINT_FILL_MODULE_ID = "wih_endpoint_fill"

            @staticmethod
            def _normalize_ai_provider_id(value):
                return str(value or "openai")

            @staticmethod
            def _normalize_ai_model_name(provider_id, model_name):
                return str(model_name or "deepseek-chat")

            @staticmethod
            def _build_ai_proxy_dict(proxy_url):
                return None

            @staticmethod
            def _safe_int(value, default=0, min_value=None):
                try:
                    number = int(value)
                except Exception:
                    number = default
                if min_value is not None and number < min_value:
                    return min_value
                return number

            @staticmethod
            def _safe_float(value, default=0.0, min_value=None):
                try:
                    number = float(value)
                except Exception:
                    number = default
                if min_value is not None and number < min_value:
                    return min_value
                return number

            @staticmethod
            def _normalize_ai_usage_dict(value):
                return {}

            @staticmethod
            def _is_ai_model_unavailable_error(message):
                return False

            @staticmethod
            def _pick_ai_retry_model(provider_id, current_model):
                return ""

            @staticmethod
            def _write_ai_usage_log(**kwargs):
                return None

            @staticmethod
            def _extract_json_object_from_text(value):
                return None

        runtime = {
            "enabled": True,
            "ai_available": True,
            "prompt_id": "default_ai_fill_wih_endpoint",
            "prompt_name": "默认AI填充-WIH接口",
            "prompt_content": "你是 WIH 接口参数补全助手，请返回结构化 JSON。",
            "ai_config": {},
            "active_profile": {
                "provider": "deepseek",
                "model": "deepseek-chat",
                "base_url": "https://api.deepseek.com/v1",
                "api_key": "demo-key",
                "timeout_sec": 40,
                "temperature": 0.1,
                "max_tokens": 1600,
                "proxy": "",
                "name": "DeepSeek",
            },
            "request_delay_ms": 0,
            "api_console": _FakeApiConsole(),
        }

        with patch.object(fill_module, "_load_ai_fill_runtime", return_value=runtime), \
             patch.object(fill_module.utils, "check_dns_policy_for_url", return_value=(True, {})), \
             patch.object(fill_module.Config, "WIH_ENDPOINT_AI_FILL_MAX_TARGETS", 10), \
             patch.object(fill_module.Config, "WIH_ENDPOINT_AI_FILL_CONCURRENCY", 1), \
             patch.object(fill_module.utils, "http_req", side_effect=requests.exceptions.ConnectionError("api.deepseek.com connect failed")) as mock_ai_req, \
             patch.object(fill_module.requests, "request", return_value=_FakeResponse()) as mock_probe_req:
            results = fill_module.run_wih_endpoint_ai_fill("task-3", [endpoint])

        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("tested", result.get("ai_fill_status"))
        self.assertEqual("heuristic", result.get("ai_fill_source"))
        self.assertTrue(result.get("ai_fill_tested"))
        self.assertIn("已回退启发式补全", str(result.get("ai_fill_note") or ""))
        self.assertIn("ConnectionError", str(result.get("ai_fill_note") or ""))
        self.assertGreaterEqual(mock_ai_req.call_count, 2)
        mock_probe_req.assert_called_once()

    def test_probe_timeout_marks_test_failed(self):
        packet = (
            "POST /_rest/st/ajax_st_app_news.ashx HTTP/1.1\r\n"
            "Host: yhxy.scwxzyxy.cn\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "\r\n"
            "FolderId=<value>&TabId=<value>&action=ToSearchUrl&kw=<value>&said=<value>"
        )
        endpoint = {
            "target": "https://yhxy.scwxzyxy.cn",
            "page_url": "https://yhxy.scwxzyxy.cn/",
            "url": "https://yhxy.scwxzyxy.cn/_rest/st/ajax_st_app_news.ashx",
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
             patch.object(fill_module.requests, "request", side_effect=requests.exceptions.ReadTimeout("timed out")):
            results = fill_module.run_wih_endpoint_ai_fill("task-4", [endpoint])

        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("test_failed", result.get("ai_fill_status"))
        self.assertFalse(result.get("ai_fill_tested"))
        self.assertEqual("heuristic", result.get("ai_fill_source"))
        self.assertIn("填充后测试失败", str(result.get("ai_fill_note") or ""))
        self.assertIn("ReadTimeout", str(result.get("ai_fill_note") or ""))
        self.assertIsNone(result.get("status_code"))
        self.assertIsNone(result.get("response_size"))

    def test_zero_max_targets_means_unlimited(self):
        endpoints = []
        for index in range(3):
            endpoints.append(
                {
                    "target": "https://api{}.example.com".format(index),
                    "page_url": "https://api{}.example.com/docs".format(index),
                    "url": "https://api{}.example.com/v1/users".format(index),
                    "method": "GET",
                    "request_template": {
                        "query": {"id": "<value>"},
                    },
                    "status_code": None,
                    "response_size": None,
                }
            )

        with patch.object(fill_module, "_load_ai_fill_runtime", return_value=self._runtime()), \
             patch.object(fill_module.utils, "check_dns_policy_for_url", return_value=(True, {})), \
             patch.object(fill_module.Config, "WIH_ENDPOINT_AI_FILL_MAX_TARGETS", 0), \
             patch.object(fill_module.Config, "WIH_ENDPOINT_AI_FILL_CONCURRENCY", 1), \
             patch.object(fill_module.requests, "request", return_value=_FakeResponse()):
            results = fill_module.run_wih_endpoint_ai_fill("task-5", endpoints)

        self.assertEqual(3, len(results))
        self.assertTrue(all(item.get("ai_fill_status") != "skipped" for item in results))
        self.assertTrue(all(item.get("ai_fill_source") != "skipped" for item in results))


if __name__ == "__main__":
    unittest.main()
