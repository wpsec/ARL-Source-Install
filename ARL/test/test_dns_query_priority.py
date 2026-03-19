import unittest
from unittest.mock import patch

from app.config import Config
from app.services.dns_query import run_query_plugin


class FakePlugin:
    def __init__(self, source_name, results=None, call_trace=None):
        self.source_name = source_name
        self.results = list(results or [])
        self.query_calls = []
        self.init_kwargs = None
        self.call_trace = call_trace

    def init_key(self, **kwargs):
        self.init_kwargs = kwargs

    def query(self, target):
        self.query_calls.append(target)
        if isinstance(self.call_trace, list):
            self.call_trace.append(self.source_name)
        return list(self.results)


class TestDnsQueryPriority(unittest.TestCase):
    def setUp(self):
        self.original_query_plugin_config = Config.QUERY_PLUGIN_CONFIG
        self.original_fofa_email = Config.FOFA_EMAIL
        self.original_fofa_key = Config.FOFA_KEY

    def tearDown(self):
        Config.QUERY_PLUGIN_CONFIG = self.original_query_plugin_config
        Config.FOFA_EMAIL = self.original_fofa_email
        Config.FOFA_KEY = self.original_fofa_key

    def test_auto_mode_runs_all_enabled_sources_but_executes_fofa_and_shodan_first(self):
        Config.FOFA_EMAIL = "user@example.com"
        Config.FOFA_KEY = "fofa-key"
        Config.QUERY_PLUGIN_CONFIG = {
            "fofa": {"enable": True},
            "shodan": {"enable": True, "api_key": "shodan-key"},
            "quake_360": {"enable": True, "quake_token": "quake-token"},
            "hunter_how": {"enable": True, "api_key": "hunter-key"},
        }

        call_trace = []
        fofa_plugin = FakePlugin("fofa", ["a.example.com"], call_trace=call_trace)
        shodan_plugin = FakePlugin("shodan", ["b.example.com"], call_trace=call_trace)
        quake_plugin = FakePlugin("quake_360", ["c.example.com"], call_trace=call_trace)
        hunter_plugin = FakePlugin("hunter_how", ["d.example.com"], call_trace=call_trace)

        with patch("app.services.dns_query.utils.load_query_plugins", return_value=[
            quake_plugin,
            hunter_plugin,
            shodan_plugin,
            fofa_plugin,
        ]):
            results = run_query_plugin("example.com", [])

        self.assertEqual(fofa_plugin.query_calls, ["example.com"])
        self.assertEqual(shodan_plugin.query_calls, ["example.com"])
        self.assertEqual(quake_plugin.query_calls, ["example.com"])
        self.assertEqual(hunter_plugin.query_calls, ["example.com"])
        self.assertEqual(call_trace[:2], ["fofa", "shodan"])
        self.assertEqual(
            {(item["domain"], item["source"]) for item in results},
            {
                ("a.example.com", "fofa"),
                ("b.example.com", "shodan"),
                ("c.example.com", "quake_360"),
                ("d.example.com", "hunter_how"),
            },
        )

    def test_auto_mode_without_preferred_credentials_still_runs_enabled_sources(self):
        Config.FOFA_EMAIL = ""
        Config.FOFA_KEY = ""
        Config.QUERY_PLUGIN_CONFIG = {
            "fofa": {"enable": True},
            "shodan": {"enable": True, "api_key": ""},
            "quake_360": {"enable": True, "quake_token": "quake-token"},
            "hunter_how": {"enable": True, "api_key": "hunter-key"},
        }

        fofa_plugin = FakePlugin("fofa")
        shodan_plugin = FakePlugin("shodan")
        quake_plugin = FakePlugin("quake_360", ["c.example.com"])
        hunter_plugin = FakePlugin("hunter_how", ["d.example.com"])

        with patch("app.services.dns_query.utils.load_query_plugins", return_value=[
            shodan_plugin,
            hunter_plugin,
            quake_plugin,
            fofa_plugin,
        ]):
            results = run_query_plugin("example.com", [])

        self.assertEqual(hunter_plugin.query_calls, ["example.com"])
        self.assertEqual(quake_plugin.query_calls, ["example.com"])
        self.assertEqual(fofa_plugin.query_calls, [])
        self.assertEqual(shodan_plugin.query_calls, [])
        self.assertEqual(
            {(item["domain"], item["source"]) for item in results},
            {
                ("c.example.com", "quake_360"),
                ("d.example.com", "hunter_how"),
            },
        )

    def test_explicit_sources_still_allow_running_lower_priority_measurement_provider(self):
        Config.FOFA_EMAIL = "user@example.com"
        Config.FOFA_KEY = "fofa-key"
        Config.QUERY_PLUGIN_CONFIG = {
            "fofa": {"enable": True},
            "shodan": {"enable": True, "api_key": "shodan-key"},
            "quake_360": {"enable": True, "quake_token": "quake-token"},
        }

        quake_plugin = FakePlugin("quake_360", ["quake.example.com"])
        fofa_plugin = FakePlugin("fofa", ["fofa.example.com"])

        with patch("app.services.dns_query.utils.load_query_plugins", return_value=[
            quake_plugin,
            fofa_plugin,
        ]):
            results = run_query_plugin("example.com", ["quake_360"])

        self.assertEqual(quake_plugin.query_calls, ["example.com"])
        self.assertEqual(fofa_plugin.query_calls, [])
        self.assertEqual(results, [{"domain": "quake.example.com", "source": "quake_360"}])


if __name__ == "__main__":
    unittest.main()
