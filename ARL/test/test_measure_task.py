import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).resolve().parents[1] / "app" / "services" / "measure_task.py"
MODULE_SPEC = importlib.util.spec_from_file_location("measure_task_test_module", MODULE_PATH)
measure_task_module = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(measure_task_module)

fetch_measure_query_ips = measure_task_module.fetch_measure_query_ips
normalize_measure_provider = measure_task_module.normalize_measure_provider
normalize_measure_queries = measure_task_module.normalize_measure_queries
normalize_measure_query_for_provider = measure_task_module.normalize_measure_query_for_provider
run_measure_query_test = measure_task_module.run_measure_query_test
ZOOMEYE_HOST_SEARCH_URL = measure_task_module.ZOOMEYE_HOST_SEARCH_URL
ZOOMEYE_WEB_SEARCH_URL = measure_task_module.ZOOMEYE_WEB_SEARCH_URL


class FakeResponse:
    def __init__(self, status_code=200, data=None, text="", json_error=None):
        self.status_code = status_code
        self._data = data if data is not None else {}
        self.text = text
        self._json_error = json_error

    def json(self):
        if self._json_error:
            raise self._json_error
        return self._data


class TestMeasureTaskService(unittest.TestCase):
    def test_normalize_measure_provider_supports_alias(self):
        self.assertEqual(normalize_measure_provider("fofa"), "fofa")
        self.assertEqual(normalize_measure_provider("hunter"), "hunter_qax")
        self.assertEqual(normalize_measure_provider("quake"), "quake_360")

    def test_normalize_measure_queries_dedup_lines(self):
        items = normalize_measure_queries(' app="nginx" \n\napp="nginx"\r\n country="CN" ')
        self.assertEqual(items, ['app="nginx"', 'country="CN"'])

    def test_normalize_measure_query_for_provider_converts_simple_ip_equals(self):
        self.assertEqual(normalize_measure_query_for_provider("shodan", 'ip="203.0.113.10"'), "ip:203.0.113.10")
        self.assertEqual(normalize_measure_query_for_provider("zoomeye", 'ip="203.0.113.10"'), 'ip="203.0.113.10"')
        self.assertEqual(normalize_measure_query_for_provider("quake_360", 'ip="203.0.113.10"'), 'ip:"203.0.113.10"')
        self.assertEqual(
            normalize_measure_query_for_provider("shodan", 'ip="203.0.113.10" port:443'),
            'ip="203.0.113.10" port:443',
        )

    def test_normalize_measure_query_for_provider_converts_host_and_domain(self):
        self.assertEqual(
            normalize_measure_query_for_provider("shodan", 'host:"example.com"'),
            'hostname:"example.com"',
        )
        self.assertEqual(
            normalize_measure_query_for_provider("shodan", 'domain="example.com"'),
            'hostname:"example.com"',
        )
        self.assertEqual(
            normalize_measure_query_for_provider("zoomeye", 'domain="example.com"'),
            'domain="example.com"',
        )

    def test_resolve_zoomeye_sub_type(self):
        self.assertEqual(measure_task_module._resolve_zoomeye_sub_type('domain="example.com"'), "web")
        self.assertEqual(measure_task_module._resolve_zoomeye_sub_type('ip:"203.0.113.10"'), "v4")

    @patch("app.services.measure_task._request_query")
    def test_run_measure_query_test_aggregates_multi_lines(self, mock_request_query):
        mock_request_query.side_effect = [
            {"total": 2, "matches": [{"ip_str": "203.0.113.11"}]},
            {"total": 3, "matches": [{"ip_str": "198.51.100.12"}]},
        ]

        result = run_measure_query_test("shodan", "title:test\nhostname:test")

        self.assertEqual(result["provider"], "shodan")
        self.assertEqual(result["size"], 5)
        self.assertEqual(result["query_count"], 2)
        self.assertEqual(result["items"][0]["size"], 2)
        self.assertEqual(result["items"][1]["size"], 3)

    @patch("app.services.measure_task._request_query")
    def test_fetch_measure_query_ips_extracts_fofa_ips(self, mock_request_query):
        mock_request_query.return_value = {
            "size": 3,
            "results": [
                ["https://a.example.com", "192.0.2.11"],
                ["https://b.example.com", "198.51.100.13"],
                ["203.0.113.14", "203.0.113.14"],
            ],
        }

        result = fetch_measure_query_ips("fofa", 'app="nginx"')

        self.assertEqual(result["size"], 3)
        self.assertEqual(result["ips"], ["192.0.2.11", "198.51.100.13", "203.0.113.14"])

    @patch("app.services.measure_task._request_query")
    def test_fetch_measure_query_ips_extracts_hunter_ips(self, mock_request_query):
        mock_request_query.return_value = {
            "code": 200,
            "data": {
                "total": 2,
                "arr": [
                    {"ip": "192.0.2.15"},
                    {"url": "https://198.51.100.16:8443/login"},
                ],
            },
        }

        result = fetch_measure_query_ips("hunter_qax", 'web.title="test"')

        self.assertEqual(result["ips"], ["192.0.2.15", "198.51.100.16"])

    @patch("app.services.measure_task._request_query")
    def test_fetch_measure_query_ips_extracts_shodan_ips(self, mock_request_query):
        mock_request_query.return_value = {
            "total": 2,
            "matches": [
                {"ip_str": "192.0.2.17"},
                {"ip": 117901063},
            ],
        }

        result = fetch_measure_query_ips("shodan", "product:nginx")

        self.assertEqual(result["ips"], ["192.0.2.17"])

    @patch("app.services.measure_task._request_query")
    def test_fetch_measure_query_ips_extracts_zoomeye_ips(self, mock_request_query):
        mock_request_query.return_value = {
            "total": 2,
            "matches": [
                {"ip": "192.0.2.18"},
                {"site": {"ip": "203.0.113.18"}},
            ],
        }

        result = fetch_measure_query_ips("zoomeye", 'app:"nginx"')

        self.assertEqual(result["ips"], ["192.0.2.18", "203.0.113.18"])

    @patch("app.services.measure_task._request_query")
    def test_fetch_measure_query_ips_extracts_zoomeye_v2_ips(self, mock_request_query):
        mock_request_query.return_value = {
            "total": 2,
            "data": [
                {"ip": "192.0.2.26"},
                {"portinfo": {"host": "203.0.113.26:443"}},
            ],
        }

        result = fetch_measure_query_ips("zoomeye", 'domain="example.com"')

        self.assertEqual(result["ips"], ["192.0.2.26", "203.0.113.26"])

    @patch("app.services.measure_task._request_query")
    def test_fetch_measure_query_ips_extracts_quake_ips(self, mock_request_query):
        mock_request_query.return_value = {
            "code": 0,
            "meta": {"total": 2},
            "data": [
                {"ip": "192.0.2.19"},
                {"service": {"ip": "198.51.100.20"}},
            ],
        }

        result = fetch_measure_query_ips("quake_360", 'service:"nginx"')

        self.assertEqual(result["ips"], ["192.0.2.19", "198.51.100.20"])

    @patch.object(measure_task_module, "refresh_runtime_config_best_effort", return_value=None)
    @patch.object(measure_task_module.Config, "QUERY_PLUGIN_CONFIG", {"shodan": {"api_key": "shodan-key"}})
    @patch("app.services.measure_task.utils.http_req")
    def test_request_query_wraps_non_json_response(self, mock_http_req, _refresh):
        mock_http_req.return_value = FakeResponse(
            status_code=403,
            text="<html>Forbidden</html>",
            json_error=ValueError("Expecting value: line 1 column 1 (char 0)"),
        )

        with self.assertRaises(RuntimeError) as context:
            measure_task_module._request_query("shodan", "ip:203.0.113.21")

        message = str(context.exception)
        self.assertIn("Shodan 返回非 JSON 响应，HTTP 403", message)
        self.assertIn("Forbidden", message)

    @patch.object(measure_task_module, "refresh_runtime_config_best_effort", return_value=None)
    @patch.object(measure_task_module.Config, "QUERY_PLUGIN_CONFIG", {"shodan": {"api_key": "shodan-key"}})
    @patch("app.services.measure_task.utils.http_req")
    def test_request_query_reports_shodan_cloudflare_page(self, mock_http_req, _refresh):
        mock_http_req.return_value = FakeResponse(
            status_code=403,
            text="<html>Just a moment... Cloudflare</html>",
            json_error=ValueError("Expecting value: line 1 column 1 (char 0)"),
        )

        with self.assertRaises(RuntimeError) as context:
            measure_task_module._request_query("shodan", 'hostname:"example.com"')

        message = str(context.exception)
        self.assertIn("Shodan 返回非 JSON 响应，HTTP 403", message)
        self.assertIn("API 请求被防护页拦截", message)

    @patch.object(measure_task_module, "refresh_runtime_config_best_effort", return_value=None)
    @patch.object(measure_task_module.Config, "QUERY_PLUGIN_CONFIG", {"shodan": {"api_key": "shodan-key"}})
    @patch("app.services.measure_task.utils.http_req")
    def test_request_query_uses_shodan_json_headers(self, mock_http_req, _refresh):
        mock_http_req.return_value = FakeResponse(data={"total": 0, "matches": []})

        data = measure_task_module._request_query("shodan", 'hostname:"example.com"')

        self.assertEqual(data, {"total": 0, "matches": []})
        headers = mock_http_req.call_args.kwargs["headers"]
        self.assertEqual(headers["Accept"], "application/json")
        self.assertEqual(headers["User-Agent"], "ARL/measure-task")

    @patch.object(measure_task_module, "refresh_runtime_config_best_effort", return_value=None)
    @patch.object(measure_task_module.Config, "QUERY_PLUGIN_CONFIG", {"zoomeye": {"api_key": "zoomeye-key"}})
    @patch("app.services.measure_task.utils.http_req")
    def test_request_query_uses_zoomeye_v1_get(self, mock_http_req, _refresh):
        mock_http_req.return_value = FakeResponse(data={"total": 0, "matches": []})

        data = measure_task_module._request_query("zoomeye", 'domain="example.com"')

        self.assertEqual(data, {"total": 0, "matches": []})
        self.assertEqual(mock_http_req.call_args[0][0], ZOOMEYE_WEB_SEARCH_URL)
        self.assertEqual(mock_http_req.call_args[0][1], "get")
        params = mock_http_req.call_args.kwargs["params"]
        self.assertEqual(params["query"], 'domain="example.com"')
        self.assertNotIn("qbase64", params)
        self.assertNotIn("json", mock_http_req.call_args.kwargs)
        headers = mock_http_req.call_args.kwargs["headers"]
        self.assertEqual(headers["API-KEY"], "zoomeye-key")

    @patch.object(measure_task_module, "refresh_runtime_config_best_effort", return_value=None)
    @patch.object(measure_task_module.Config, "QUERY_PLUGIN_CONFIG", {"zoomeye": {"api_key": "zoomeye-key"}})
    @patch("app.services.measure_task.utils.http_req")
    def test_request_query_uses_zoomeye_v1_host_search_for_v4(self, mock_http_req, _refresh):
        mock_http_req.return_value = FakeResponse(data={"total": 0, "matches": []})

        measure_task_module._request_query("zoomeye", 'app:"nginx"')

        self.assertEqual(mock_http_req.call_args[0][0], ZOOMEYE_HOST_SEARCH_URL)
        self.assertEqual(mock_http_req.call_args[0][1], "get")

    def test_extract_quake_total_from_nested_pagination(self):
        total = measure_task_module._extract_total_size(
            "quake_360",
            {"code": 0, "meta": {"pagination": {"total": 7}}, "data": []},
        )

        self.assertEqual(total, 7)

    def test_extract_total_size_falls_back_to_result_list_length(self):
        total = measure_task_module._extract_total_size(
            "quake_360",
            {"code": 0, "meta": {}, "data": [{"ip": "203.0.113.23"}]},
        )

        self.assertEqual(total, 1)

    def test_extract_quake_ips_from_nested_service_fields(self):
        ips = measure_task_module._extract_quake_ips({
            "code": 0,
            "data": [
                {"service": {"host": "203.0.113.24:443"}},
                {"components": [{"ip": "203.0.113.25"}]},
            ],
        })

        self.assertEqual(ips, ["203.0.113.24", "203.0.113.25"])


if __name__ == "__main__":
    unittest.main()
