import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app.services import probe_http,check_http


class TestProbeHTTP(unittest.TestCase):
    def setUp(self):
        self.dns_policy = patch(
            "app.utils.check_dns_policy_for_url",
            return_value=(True, {"reason": "fixture", "resolver_ips": [], "system_ips": []}),
        )
        self.connect_kwargs = patch("app.utils.build_http_connect_kwargs_for_url", return_value={})
        self.http_request = patch(
            "app.utils.http_req",
            return_value=SimpleNamespace(
                status_code=200,
                headers={"Content-Type": "text/html"},
                content=b"",
                close=lambda: None,
            ),
        )
        for patcher in (self.dns_policy, self.connect_kwargs, self.http_request):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_probe_http_uses_fixture_response(self):
        urls = probe_http(["target.fixture.invalid"])

        self.assertEqual(["https://target.fixture.invalid"], urls)

    def test_check_http_uses_fixture_response(self):
        urls = ["http://target.fixture.invalid"]
        sites = check_http(urls)
        self.assertEqual({urls[0]: {"status": 200, "content-type": "text/html"}}, sites)
