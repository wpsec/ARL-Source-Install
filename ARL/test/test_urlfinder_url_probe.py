import unittest
from unittest.mock import patch

from app.modules import CollectSource, WihRecord
from app.services.urlfinder_url_probe import run_urlfinder_url_probe


class _FakeUrlCollection:
    def __init__(self, existing_urls=None):
        self._existing_urls = set(existing_urls or [])
        self.inserted = []

    def distinct(self, field_name, query):
        if field_name != "url":
            return []
        urls = query.get("url", {}).get("$in", [])
        return [url for url in urls if url in self._existing_urls]

    def insert_one(self, item):
        self.inserted.append(item)


class TestUrlfinderUrlProbe(unittest.TestCase):
    @patch("app.services.urlfinder_url_probe.page_fetch")
    @patch("app.services.urlfinder_url_probe.utils.check_dns_policy_for_url")
    @patch("app.services.urlfinder_url_probe.utils.conn_db")
    def test_probe_insert_and_filter(self, mock_conn_db, mock_dns_policy, mock_page_fetch):
        fake_collection = _FakeUrlCollection(existing_urls=["https://example.com/already"])
        mock_conn_db.return_value = fake_collection

        def _dns_policy(url, cache_map=None):
            if "blocked" in url:
                return False, {"reason": "dns_drift_no_overlap", "resolver_ips": [], "system_ips": []}
            return True, {"reason": "pass", "resolver_ips": ["1.1.1.1"], "system_ips": ["1.1.1.1"]}

        mock_dns_policy.side_effect = _dns_policy
        mock_page_fetch.return_value = {
            "https://example.com/api/user": {
                "url": "https://example.com/api/user",
                "title": "ok",
                "content_length": 12,
                "status_code": 200,
            }
        }

        records = [
            WihRecord("urlfinder_url", "https://example.com/api/user", "https://example.com", "https://example.com", 1),
            WihRecord("urlfinder_url", "https://example.com/blocked", "https://example.com", "https://example.com", 2),
            WihRecord("urlfinder_url", "https://example.com/a.js", "https://example.com", "https://example.com", 3),
            WihRecord("urlfinder_url", "https://other.com/api", "https://example.com", "https://example.com", 4),
            WihRecord("domain", "sub.example.com", "https://example.com", "https://example.com", 5),
        ]

        page_url_set = {"https://example.com/already"}
        inserted_count = run_urlfinder_url_probe(
            task_id="task_1",
            sites=["https://example.com"],
            wih_records=records,
            page_url_set=page_url_set,
        )

        self.assertEqual(inserted_count, 1)
        self.assertEqual(len(fake_collection.inserted), 1)
        self.assertEqual(fake_collection.inserted[0]["source"], CollectSource.WIH_URL_PROBE)
        self.assertIn("https://example.com/api/user", page_url_set)
        mock_page_fetch.assert_called_once_with(
            ["https://example.com/api/user"],
            concurrency=6,
            waf_guard=None,
            waf_module="urlfinder_url_probe",
        )

    @patch("app.services.urlfinder_url_probe.page_fetch")
    @patch("app.services.urlfinder_url_probe.utils.check_dns_policy_for_url")
    @patch("app.services.urlfinder_url_probe.utils.conn_db")
    def test_probe_filters_template_static_and_annotation_noise(self, mock_conn_db, mock_dns_policy, mock_page_fetch):
        fake_collection = _FakeUrlCollection()
        mock_conn_db.return_value = fake_collection
        mock_dns_policy.return_value = (True, {"reason": "pass", "resolver_ips": ["1.1.1.1"], "system_ips": ["1.1.1.1"]})
        mock_page_fetch.return_value = {
            "https://example.com/api/user": {
                "url": "https://example.com/api/user",
                "title": "ok",
                "content_length": 12,
                "status_code": 200,
            }
        }

        records = [
            WihRecord("path_url", "https://example.com/api/user (path_probe status=200)", "https://example.com/a.js", "https://example.com", 11),
            WihRecord("path_url", "https://example.com/static/app.css (path_probe status=200)", "https://example.com/a.js", "https://example.com", 12),
            WihRecord("path_url", "https://example.com/announcement/{id}/detail|get (path_probe status=200)", "https://example.com/a.js", "https://example.com", 13),
            WihRecord("path_url", "https://example.com/head (path_probe status=200)", "https://example.com/a.js", "https://example.com", 14),
        ]

        inserted_count = run_urlfinder_url_probe(
            task_id="task_3",
            sites=["https://example.com"],
            wih_records=records,
        )

        self.assertEqual(inserted_count, 1)
        self.assertEqual(len(fake_collection.inserted), 1)
        self.assertEqual(fake_collection.inserted[0]["url"], "https://example.com/api/user")
        mock_page_fetch.assert_called_once_with(
            ["https://example.com/api/user"],
            concurrency=6,
            waf_guard=None,
            waf_module="urlfinder_url_probe",
        )

    @patch("app.services.urlfinder_url_probe.utils.conn_db")
    def test_probe_skip_when_disabled(self, mock_conn_db):
        records = [
            WihRecord("urlfinder_url", "https://example.com/api/user", "https://example.com", "https://example.com", 100)
        ]

        with patch("app.services.urlfinder_url_probe.Config.URLFINDER_URL_PROBE_ENABLE", False):
            inserted_count = run_urlfinder_url_probe(
                task_id="task_2",
                sites=["https://example.com"],
                wih_records=records,
            )

        self.assertEqual(inserted_count, 0)
        mock_conn_db.assert_not_called()


if __name__ == "__main__":
    unittest.main()
