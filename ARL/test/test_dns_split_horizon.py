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
from app.services.buildDomainInfo import BuildDomainInfo
from app.services.checkHTTP import CheckHTTP
from app.services.fetchSite import FetchSite


class DummyResponse(object):
    def __init__(self, status_code=200, headers=None, content=b"ok", reason="OK"):
        self.status_code = status_code
        self.headers = headers or {}
        self.content = content
        self.reason = reason

    def close(self):
        return None


class TestDNSSplitHorizon(unittest.TestCase):
    @patch.object(Config, "DNS_RESOLVERS", ["8.8.8.8"])
    @patch("app.utils.get_ip_socket", return_value=["192.168.166.69"])
    @patch("app.utils.get_ip_system", return_value=["192.168.166.69"])
    @patch("app.utils.get_ip", return_value=["47.100.89.44"])
    @patch("app.utils.get_ip_type")
    def test_check_dns_policy_allow_split_horizon_public(self, mock_get_ip_type, *_args):
        mock_get_ip_type.side_effect = lambda ip: "PUBLIC" if str(ip).startswith("47.") else "PRIVATE"

        allow_scan, detail = utils.check_dns_policy_for_host("firstr.eytax.com.cn")

        self.assertTrue(allow_scan)
        self.assertEqual(detail.get("preferred_ips"), ["47.100.89.44"])
        self.assertTrue(str(detail.get("reason", "")).startswith("split_horizon"))

    def test_build_http_connect_kwargs_for_url(self):
        detail = {
            "preferred_ips": ["47.100.89.44"],
        }

        kwargs = utils.build_http_connect_kwargs_for_url(
            "https://firstr.eytax.com.cn:8443/demo",
            policy_detail=detail,
        )

        self.assertEqual(kwargs["connect_ip"], "47.100.89.44")
        self.assertEqual(kwargs["server_hostname"], "firstr.eytax.com.cn")
        self.assertEqual(kwargs["host_header"], "firstr.eytax.com.cn:8443")

    @patch("app.services.buildDomainInfo.utils.get_cname", return_value=[])
    @patch("app.services.buildDomainInfo.utils.get_ip", side_effect=AssertionError("should not fallback get_ip"))
    @patch(
        "app.services.buildDomainInfo.utils.check_dns_policy_for_host",
        return_value=(True, {"preferred_ips": ["47.100.89.44"]}),
    )
    def test_build_domain_info_prefers_policy_ips(self, _mock_policy, _mock_get_ip, _mock_get_cname):
        worker = BuildDomainInfo([], concurrency=1)
        worker.work("firstr.eytax.com.cn")

        self.assertEqual(len(worker.domain_info_list), 1)
        self.assertEqual(worker.domain_info_list[0].ip_list, ["47.100.89.44"])

    @patch(
        "app.services.checkHTTP.utils.check_dns_policy_for_url",
        return_value=(True, {"preferred_ips": ["47.100.89.44"], "resolver_ips": ["47.100.89.44"]}),
    )
    @patch("app.services.checkHTTP.utils.http_req")
    def test_check_http_uses_direct_connect_kwargs(self, mock_http_req, _mock_policy):
        mock_http_req.return_value = DummyResponse(
            status_code=200,
            headers={"Content-Type": "text/html"},
            content=b"hello",
        )

        checker = CheckHTTP([], concurrency=1)
        checker.check("https://firstr.eytax.com.cn:8443/demo")

        kwargs = mock_http_req.call_args.kwargs
        self.assertEqual(kwargs["connect_ip"], "47.100.89.44")
        self.assertEqual(kwargs["server_hostname"], "firstr.eytax.com.cn")
        self.assertEqual(kwargs["host_header"], "firstr.eytax.com.cn:8443")

    @patch("app.services.fetchSite.load_fingerprint", return_value=[])
    @patch(
        "app.services.fetchSite.utils.check_dns_policy_for_url",
        return_value=(True, {"preferred_ips": ["47.100.89.44"], "resolver_ips": ["47.100.89.44"]}),
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
        worker.work("https://firstr.eytax.com.cn/demo")

        self.assertEqual(len(worker.site_info_list), 1)
        self.assertEqual(worker.site_info_list[0]["ip"], "47.100.89.44")
        kwargs = mock_http_req.call_args.kwargs
        self.assertEqual(kwargs["connect_ip"], "47.100.89.44")
        self.assertEqual(kwargs["server_hostname"], "firstr.eytax.com.cn")
        self.assertEqual(kwargs["host_header"], "firstr.eytax.com.cn")


if __name__ == "__main__":
    unittest.main()
