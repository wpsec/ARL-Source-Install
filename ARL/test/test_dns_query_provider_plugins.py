import base64
import unittest
from unittest.mock import patch

from app.services.dns_query_plugin.hunter_how import Query as HunterHowQuery
from app.services.dns_query_plugin.shodan import Query as ShodanQuery


class TestHunterHowQuery(unittest.TestCase):
    @patch("app.services.dns_query_plugin.hunter_how.time.sleep", return_value=None)
    def test_sub_domains_builds_domain_and_suffix_queries(self, _sleep):
        plugin = HunterHowQuery()
        plugin.init_key(api_key="test-key", page_size=100, max_page=1)

        captured_queries = []

        def fake_search_page(params, headers, target, curr_page):
            self.assertGreater(int(params["start_time"]), 0)
            decoded = base64.urlsafe_b64decode(params["query"]).decode("utf-8")
            captured_queries.append(decoded)
            if decoded == 'domain="google.com"':
                return 200, {"data": {"arr": [{"domain": "www.google.com"}]}}
            return 200, {"data": {"arr": [{"url": "https://mail.google.com/inbox"}]}}

        with patch.object(plugin, "_search_page", side_effect=fake_search_page):
            results = plugin.sub_domains("google.com")

        self.assertIn('domain="google.com"', captured_queries)
        self.assertIn('domain.suffix=="google.com"', captured_queries)
        self.assertEqual(set(results), {"www.google.com", "mail.google.com"})

    @patch("app.services.dns_query_plugin.hunter_how.time.sleep", return_value=None)
    def test_sub_domains_by_ip_uses_ip_equals_query(self, _sleep):
        plugin = HunterHowQuery()
        plugin.init_key(api_key="test-key", page_size=100, max_page=1)

        captured_queries = []

        def fake_search_page(params, headers, target, curr_page):
            decoded = base64.urlsafe_b64decode(params["query"]).decode("utf-8")
            captured_queries.append(decoded)
            return 200, {
                "data": {
                    "arr": [
                        {"domain": "a.example.com"},
                        {"host": "1.1.1.1"},
                        {"url": "https://b.example.com/login"},
                    ]
                }
            }

        with patch.object(plugin, "_search_page", side_effect=fake_search_page):
            results = plugin.sub_domains_by_ip("1.1.1.1")

        self.assertEqual(captured_queries, ['ip=="1.1.1.1"'])
        self.assertEqual(set(results), {"a.example.com", "b.example.com"})


class TestShodanQuery(unittest.TestCase):
    @patch("app.services.dns_query_plugin.shodan.time.sleep", return_value=None)
    def test_sub_domains_combines_dns_and_search_queries(self, _sleep):
        plugin = ShodanQuery()
        plugin.init_key(api_key="test-key", max_page=1)

        search_queries = []

        def fake_dns_page(target, curr_page):
            return 200, {"subdomains": ["api"], "more": False}

        def fake_search_page(search, curr_page):
            search_queries.append(search)
            return 200, {
                "matches": [
                    {"domains": ["mail.test.com"], "hostnames": ["vpn.test.com"]},
                ],
                "total": 1,
            }

        with patch.object(plugin, "_request_dns_page", side_effect=fake_dns_page):
            with patch.object(plugin, "_request_search_page", side_effect=fake_search_page):
                results = plugin.sub_domains("test.com")

        self.assertIn("domain:test.com", search_queries)
        self.assertIn("hostname:test.com", search_queries)
        self.assertEqual(set(results), {"api.test.com", "mail.test.com", "vpn.test.com"})

    @patch("app.services.dns_query_plugin.shodan.time.sleep", return_value=None)
    def test_sub_domains_by_ip_uses_ip_filter(self, _sleep):
        plugin = ShodanQuery()
        plugin.init_key(api_key="test-key", max_page=1)

        search_queries = []

        def fake_search_page(search, curr_page):
            search_queries.append(search)
            return 200, {
                "matches": [
                    {
                        "domains": ["a.example.com"],
                        "hostnames": ["b.example.com", "1.1.1.1"],
                        "ssl": {"cert": {"subject": {"CN": "c.example.com"}}},
                    }
                ],
                "total": 1,
            }

        with patch.object(plugin, "_request_search_page", side_effect=fake_search_page):
            results = plugin.sub_domains_by_ip("1.1.1.1")

        self.assertEqual(search_queries, ["ip:1.1.1.1"])
        self.assertEqual(set(results), {"a.example.com", "b.example.com", "c.example.com"})

    @patch("app.services.dns_query_plugin.shodan.time.sleep", return_value=None)
    def test_sub_domains_by_cert_builds_subject_fingerprint_and_serial_queries(self, _sleep):
        plugin = ShodanQuery()
        plugin.init_key(api_key="test-key", max_page=1)

        search_queries = []
        cert = {
            "subject": {"common_name": "*.test.com"},
            "fingerprint": {"sha1": "AA:BB:CC"},
            "serial_number": "12345",
        }

        def fake_search_page(search, curr_page):
            search_queries.append(search)
            return 200, {
                "matches": [
                    {"domains": ["portal.test.com"], "hostnames": ["admin.test.com"]},
                ],
                "total": 1,
            }

        with patch.object(plugin, "_request_search_page", side_effect=fake_search_page):
            results = plugin.sub_domains_by_cert(cert)

        self.assertIn('ssl.cert.subject.cn:"test.com"', search_queries)
        self.assertIn('ssl.cert.fingerprint:"aabbcc"', search_queries)
        self.assertIn("ssl.cert.serial:12345", search_queries)
        self.assertEqual(set(results), {"portal.test.com", "admin.test.com"})


if __name__ == "__main__":
    unittest.main()
