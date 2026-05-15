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
run_measure_query_test = measure_task_module.run_measure_query_test


class TestMeasureTaskService(unittest.TestCase):
    def test_normalize_measure_provider_supports_alias(self):
        self.assertEqual(normalize_measure_provider("fofa"), "fofa")
        self.assertEqual(normalize_measure_provider("hunter"), "hunter_qax")
        self.assertEqual(normalize_measure_provider("quake"), "quake_360")

    def test_normalize_measure_queries_dedup_lines(self):
        items = normalize_measure_queries(' app="nginx" \n\napp="nginx"\r\n country="CN" ')
        self.assertEqual(items, ['app="nginx"', 'country="CN"'])

    @patch("app.services.measure_task._request_query")
    def test_run_measure_query_test_aggregates_multi_lines(self, mock_request_query):
        mock_request_query.side_effect = [
            {"total": 2, "matches": [{"ip_str": "1.1.1.1"}]},
            {"total": 3, "matches": [{"ip_str": "2.2.2.2"}]},
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
                ["https://a.example.com", "1.1.1.1"],
                ["https://b.example.com", "2.2.2.2"],
                ["3.3.3.3", "3.3.3.3"],
            ],
        }

        result = fetch_measure_query_ips("fofa", 'app="nginx"')

        self.assertEqual(result["size"], 3)
        self.assertEqual(result["ips"], ["1.1.1.1", "2.2.2.2", "3.3.3.3"])

    @patch("app.services.measure_task._request_query")
    def test_fetch_measure_query_ips_extracts_hunter_ips(self, mock_request_query):
        mock_request_query.return_value = {
            "code": 200,
            "data": {
                "total": 2,
                "arr": [
                    {"ip": "4.4.4.4"},
                    {"url": "https://5.5.5.5:8443/login"},
                ],
            },
        }

        result = fetch_measure_query_ips("hunter_qax", 'web.title="test"')

        self.assertEqual(result["ips"], ["4.4.4.4", "5.5.5.5"])

    @patch("app.services.measure_task._request_query")
    def test_fetch_measure_query_ips_extracts_shodan_ips(self, mock_request_query):
        mock_request_query.return_value = {
            "total": 2,
            "matches": [
                {"ip_str": "6.6.6.6"},
                {"ip": 117901063},
            ],
        }

        result = fetch_measure_query_ips("shodan", "product:nginx")

        self.assertEqual(result["ips"], ["6.6.6.6"])

    @patch("app.services.measure_task._request_query")
    def test_fetch_measure_query_ips_extracts_zoomeye_ips(self, mock_request_query):
        mock_request_query.return_value = {
            "total": 2,
            "matches": [
                {"ip": "7.7.7.7"},
                {"site": {"ip": "8.8.8.8"}},
            ],
        }

        result = fetch_measure_query_ips("zoomeye", 'app:"nginx"')

        self.assertEqual(result["ips"], ["7.7.7.7", "8.8.8.8"])

    @patch("app.services.measure_task._request_query")
    def test_fetch_measure_query_ips_extracts_quake_ips(self, mock_request_query):
        mock_request_query.return_value = {
            "code": 0,
            "meta": {"total": 2},
            "data": [
                {"ip": "9.9.9.9"},
                {"service": {"ip": "10.10.10.10"}},
            ],
        }

        result = fetch_measure_query_ips("quake_360", 'service:"nginx"')

        self.assertEqual(result["ips"], ["10.10.10.10", "9.9.9.9"])


if __name__ == "__main__":
    unittest.main()
