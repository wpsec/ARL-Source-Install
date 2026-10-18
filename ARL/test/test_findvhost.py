import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app.services.findVhost import Page, brute_vhost, find_vhost


class TestFindVhost(unittest.TestCase):
    def test_brute_vhost_filters_reference_pages(self):
        not_found = b"<html><title>not found</title></html>"
        hosted = (
            b"<html><title>Hosted App</title><body>"
            + b"x" * 180
            + b" found.example</body></html>"
        )

        def fake_request(url, headers, timeout):
            if headers["Host"] == "found.example":
                return SimpleNamespace(
                    content=hosted,
                    headers={"Content-Type": "text/html"},
                    status_code=200,
                )
            return SimpleNamespace(
                content=not_found,
                headers={"Content-Type": "text/html"},
                status_code=404,
            )

        with patch("app.services.findVhost.http_req", side_effect=fake_request) as request:
            results = brute_vhost(
                "192.0.2.10",
                (["found.example", "missing.example"], "https"),
            )

        self.assertEqual(["found.example"], [page.domain for page in results])
        self.assertEqual(6, request.call_count)
        self.assertTrue(all(call.kwargs["timeout"] == (3, 6) for call in request.call_args_list))

    def test_find_vhost_deduplicates_matching_pages_across_ips(self):
        def page(ip, domain):
            title = "Shared App" if domain == "shared.example" else "Other App"
            body = "shared response" if domain == "shared.example" else "distinct response " + ("x" * 100)
            return Page(
                url="http://" + ip,
                domain=domain,
                content=("<html><title>{}</title><body>{}</body></html>".format(title, body)).encode(),
                status_code=200,
                content_type="text/html",
            )

        responses = [
            {
                "192.0.2.10": {page("192.0.2.10", "shared.example")},
                "192.0.2.11": {
                    page("192.0.2.11", "shared.example"),
                    page("192.0.2.11", "other.example"),
                },
            },
            {},
        ]

        with patch("app.services.findVhost.thread_map", side_effect=responses):
            results = find_vhost(
                ["192.0.2.10", "192.0.2.11"],
                ["shared.example", "other.example"],
            )

        self.assertEqual(
            {"shared.example", "other.example"},
            {result["domain"] for result in results},
        )
        self.assertEqual(2, len(results))


if __name__ == "__main__":
    unittest.main()
