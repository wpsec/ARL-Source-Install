import sys
import types
import unittest
from unittest.mock import patch


def _ensure_stub_modules():
    try:
        import bson  # noqa: F401
    except Exception:
        bson_module = types.ModuleType("bson")

        class ObjectId(str):
            pass

        bson_module.ObjectId = ObjectId
        sys.modules["bson"] = bson_module

    try:
        import pymongo  # noqa: F401
    except Exception:
        pymongo_module = types.ModuleType("pymongo")

        class MongoClient(object):
            def __init__(self, *args, **kwargs):
                pass

        pymongo_module.MongoClient = MongoClient
        sys.modules["pymongo"] = pymongo_module

    try:
        import tld  # noqa: F401
    except Exception:
        tld_module = types.ModuleType("tld")

        class _FakeTLDResult(object):
            def __init__(self, text):
                parts = [x for x in str(text or "").split(".") if x]
                self.subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""
                self.domain = parts[-2] if len(parts) >= 2 else str(text or "")
                self.fld = ".".join(parts[-2:]) if len(parts) >= 2 else str(text or "")

        def get_tld(text, fix_protocol=True, as_object=True):
            return _FakeTLDResult(text)

        tld_module.get_tld = get_tld
        sys.modules["tld"] = tld_module

    try:
        import pyquery  # noqa: F401
    except Exception:
        pyquery_module = types.ModuleType("pyquery")

        class PyQuery(object):
            def __init__(self, *args, **kwargs):
                pass

            def __call__(self, *args, **kwargs):
                return self

            def items(self):
                return []

        pyquery_module.PyQuery = PyQuery
        sys.modules["pyquery"] = pyquery_module

    try:
        import mmh3  # noqa: F401
    except Exception:
        mmh3_module = types.ModuleType("mmh3")
        mmh3_module.hash = lambda _data: 0
        sys.modules["mmh3"] = mmh3_module


_ensure_stub_modules()

from app import utils
from app.config import Config
from app.services.buildDomainInfo import BuildDomainInfo, build_domain_info
from app.services.checkHTTP import CheckHTTP
from app.services.fetchSite import FetchSite

TEST_SPLIT_DOMAIN = "portal.example.test"
TEST_PUBLIC_IP = "203.0.113.44"
TEST_PRIVATE_IP = "10.10.10.10"


class DummyResponse(object):
    def __init__(self, status_code=200, headers=None, content=b"ok", reason="OK"):
        self.status_code = status_code
        self.headers = headers or {}
        self.content = content
        self.reason = reason

    def close(self):
        return None


class TestDNSSplitHorizon(unittest.TestCase):
    @patch("app.services.buildDomainInfo.utils.get_cname", return_value=[])
    @patch(
        "app.services.buildDomainInfo.utils.check_dns_policy_for_host",
        return_value=(True, {"preferred_ips": [TEST_PUBLIC_IP]}),
    )
    def test_domain_info_reuses_shared_dns_policy_cache(self, mock_policy, _mock_cname):
        policy_cache = {}

        first = build_domain_info(
            ["a.example.test"],
            concurrency=1,
            dns_policy_cache=policy_cache,
        )
        second = build_domain_info(
            ["a.example.test"],
            concurrency=1,
            dns_policy_cache=policy_cache,
        )

        self.assertEqual(len(first), 1)
        self.assertEqual(len(second), 1)
        self.assertEqual(mock_policy.call_count, 1)

    @patch("app.utils.get_ip_socket", return_value=[TEST_PUBLIC_IP])
    @patch("app.utils.get_ip_system", return_value=[TEST_PUBLIC_IP])
    @patch("app.utils.get_ip", return_value=[TEST_PUBLIC_IP])
    @patch.object(Config, "DNS_RESOLVERS", ["8.8.8.8"])
    def test_dns_policy_collects_custom_system_and_socket_views(self, mock_get_ip, mock_system, mock_socket):
        allow_scan, detail = utils.check_dns_policy_for_host(TEST_SPLIT_DOMAIN)

        self.assertTrue(allow_scan)
        self.assertEqual(detail["resolver_ips"], [TEST_PUBLIC_IP])
        self.assertEqual(detail["system_ips"], [TEST_PUBLIC_IP])
        self.assertEqual(detail["socket_ips"], [TEST_PUBLIC_IP])
        mock_get_ip.assert_called_once_with(TEST_SPLIT_DOMAIN, log_flag=False)
        mock_system.assert_called_once_with(TEST_SPLIT_DOMAIN, log_flag=False)
        mock_socket.assert_called_once_with(TEST_SPLIT_DOMAIN, log_flag=False)

    @patch.object(Config, "DNS_RESOLVERS", ["8.8.8.8"])
    @patch("app.utils.get_ip_socket", return_value=[TEST_PRIVATE_IP])
    @patch("app.utils.get_ip_system", return_value=[TEST_PRIVATE_IP])
    @patch("app.utils.get_ip", return_value=[TEST_PUBLIC_IP])
    @patch("app.utils.get_ip_type")
    def test_check_dns_policy_allow_split_horizon_public(self, mock_get_ip_type, *_args):
        mock_get_ip_type.side_effect = lambda ip: "PUBLIC" if str(ip) == TEST_PUBLIC_IP else "PRIVATE"

        allow_scan, detail = utils.check_dns_policy_for_host(TEST_SPLIT_DOMAIN)

        self.assertTrue(allow_scan)
        self.assertEqual(detail.get("preferred_ips"), [TEST_PUBLIC_IP])
        self.assertTrue(str(detail.get("reason", "")).startswith("split_horizon"))

    def test_build_http_connect_kwargs_for_url(self):
        detail = {
            "preferred_ips": [TEST_PUBLIC_IP],
        }

        kwargs = utils.build_http_connect_kwargs_for_url(
            "https://{}:8443/demo".format(TEST_SPLIT_DOMAIN),
            policy_detail=detail,
        )

        self.assertEqual(kwargs["connect_ip"], TEST_PUBLIC_IP)
        self.assertEqual(kwargs["server_hostname"], TEST_SPLIT_DOMAIN)
        self.assertEqual(kwargs["host_header"], "{}:8443".format(TEST_SPLIT_DOMAIN))

    @patch("app.services.buildDomainInfo.utils.get_cname", return_value=[])
    @patch("app.services.buildDomainInfo.utils.get_ip", side_effect=AssertionError("should not fallback get_ip"))
    @patch(
        "app.services.buildDomainInfo.utils.check_dns_policy_for_host",
        return_value=(True, {"preferred_ips": [TEST_PUBLIC_IP]}),
    )
    def test_build_domain_info_prefers_policy_ips(self, _mock_policy, _mock_get_ip, _mock_get_cname):
        worker = BuildDomainInfo([], concurrency=1)
        worker.work(TEST_SPLIT_DOMAIN)

        self.assertEqual(len(worker.domain_info_list), 1)
        self.assertEqual(worker.domain_info_list[0].ip_list, [TEST_PUBLIC_IP])

    @patch(
        "app.services.checkHTTP.utils.check_dns_policy_for_url",
        return_value=(True, {"preferred_ips": [TEST_PUBLIC_IP], "resolver_ips": [TEST_PUBLIC_IP]}),
    )
    @patch("app.services.checkHTTP.utils.http_req")
    def test_check_http_uses_direct_connect_kwargs(self, mock_http_req, _mock_policy):
        mock_http_req.return_value = DummyResponse(
            status_code=200,
            headers={"Content-Type": "text/html"},
            content=b"hello",
        )

        checker = CheckHTTP([], concurrency=1)
        checker.check("https://{}:8443/demo".format(TEST_SPLIT_DOMAIN))

        kwargs = mock_http_req.call_args.kwargs
        self.assertEqual(kwargs["connect_ip"], TEST_PUBLIC_IP)
        self.assertEqual(kwargs["server_hostname"], TEST_SPLIT_DOMAIN)
        self.assertEqual(kwargs["host_header"], "{}:8443".format(TEST_SPLIT_DOMAIN))

    @patch(
        "app.services.checkHTTP.utils.check_dns_policy_for_url",
        return_value=(
            False,
            {
                "reason": "dns_drift_no_overlap",
                "resolver_ips": ["8.8.8.8"],
                "system_ips": ["1.1.1.1"],
                "preferred_ips": ["8.8.8.8"],
            },
        ),
    )
    @patch("app.services.checkHTTP.utils.http_req")
    def test_check_http_allows_prevalidated_public_dns_drift(self, mock_http_req, _mock_policy):
        mock_http_req.return_value = DummyResponse(
            status_code=200,
            headers={"Content-Type": "text/html"},
            content=b"hello",
        )

        checker = CheckHTTP(
            [],
            concurrency=1,
            prevalidated_dns_domains={TEST_SPLIT_DOMAIN},
        )
        result = checker.check("https://{}/".format(TEST_SPLIT_DOMAIN))

        self.assertEqual(result["status"], 200)
        mock_http_req.assert_called_once()

    @patch(
        "app.services.checkHTTP.utils.check_dns_policy_for_url",
        return_value=(
            False,
            {
                "reason": "dns_drift_no_overlap",
                "resolver_ips": ["10.10.10.10"],
                "system_ips": ["192.168.1.10"],
                "preferred_ips": ["10.10.10.10"],
            },
        ),
    )
    @patch("app.services.checkHTTP.utils.http_req")
    def test_check_http_does_not_override_private_dns_drift(self, mock_http_req, _mock_policy):
        checker = CheckHTTP(
            [],
            concurrency=1,
            prevalidated_dns_domains={TEST_SPLIT_DOMAIN},
        )

        self.assertIsNone(checker.check("https://{}/".format(TEST_SPLIT_DOMAIN)))
        mock_http_req.assert_not_called()

    @patch("app.services.fetchSite.load_fingerprint", return_value=[])
    @patch(
        "app.services.fetchSite.utils.check_dns_policy_for_url",
        return_value=(True, {"preferred_ips": [TEST_PUBLIC_IP], "resolver_ips": [TEST_PUBLIC_IP]}),
    )
    @patch("app.services.fetchSite.fetch_favicon", return_value={})
    @patch("app.services.fetchSite.utils.get_title", return_value="Demo")
    @patch("app.services.fetchSite.utils.get_headers", return_value="HTTP/1.1 200 OK")
    @patch("app.services.fetchSite.FetchSite.fetch_fingerprint", return_value=None)
    @patch("app.services.fetchSite.utils.http_req")
    def test_fetch_site_records_direct_connect_ip(
        self,
        mock_http_req,
        _mock_fetch_fingerprint,
        _mock_get_headers,
        _mock_get_title,
        _mock_fetch_favicon,
        _mock_policy,
        _mock_load_fingerprint,
    ):
        mock_http_req.return_value = DummyResponse(
            status_code=200,
            headers={"Server": "nginx"},
            content=b"<title>Demo</title>",
        )

        worker = FetchSite([], concurrency=1)
        worker.work("https://{}/demo".format(TEST_SPLIT_DOMAIN))

        self.assertEqual(len(worker.site_info_list), 1)
        self.assertEqual(worker.site_info_list[0]["ip"], TEST_PUBLIC_IP)
        kwargs = mock_http_req.call_args.kwargs
        self.assertEqual(kwargs["connect_ip"], TEST_PUBLIC_IP)
        self.assertEqual(kwargs["server_hostname"], TEST_SPLIT_DOMAIN)
        self.assertEqual(kwargs["host_header"], TEST_SPLIT_DOMAIN)


if __name__ == "__main__":
    unittest.main()
