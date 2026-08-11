"""
泛解析画像与复验逻辑单元测试
"""
import importlib.util
import pathlib
import sys
import types
import unittest
from unittest.mock import patch

ROOT_DIR = pathlib.Path(__file__).resolve().parents[1]


class _DomainInfo:
    def __init__(self, domain, record=None, record_type="A", ips=None):
        self.domain = domain
        self.record_list = list(record or [])
        self.type = record_type
        self.ip_list = list(ips or [])


def _normalize_domain(value):
    return str(value or "").strip().lower().strip(".")


def _cut_first_name(domain):
    parts = _normalize_domain(domain).split(".")
    if len(parts) <= 2:
        return _normalize_domain(domain)
    return ".".join(parts[1:])


def _load_module(module_name, file_path):
    spec = importlib.util.spec_from_file_location(module_name, str(file_path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _bootstrap_test_module():
    app_pkg = types.ModuleType("app")
    app_pkg.__path__ = [str(ROOT_DIR / "app")]
    sys.modules["app"] = app_pkg

    services_pkg = types.ModuleType("app.services")
    services_pkg.__path__ = [str(ROOT_DIR / "app" / "services")]
    sys.modules["app.services"] = services_pkg
    app_pkg.services = services_pkg

    config_module = types.ModuleType("app.config")

    class Config:
        WILDCARD_PROBE_COUNT = 4
        WILDCARD_VERIFY_ROUNDS = 2
        WILDCARD_MAX_LEVELS = 2

    config_module.Config = Config
    sys.modules["app.config"] = config_module
    app_pkg.config = config_module

    utils_module = types.ModuleType("app.utils")
    utils_module.normalize_domain = _normalize_domain
    utils_module.random_choices = lambda size=8: "probeunit"
    utils_module.get_ip = lambda domain, log_flag=False: []
    utils_module.get_cname = lambda domain, log_flag=False: []
    utils_module.domain = types.SimpleNamespace(cut_first_name=_cut_first_name)
    sys.modules["app.utils"] = utils_module
    app_pkg.utils = utils_module

    wildcard_module = _load_module("app.services.wildcardDomain", ROOT_DIR / "app" / "services" / "wildcardDomain.py")
    services_pkg.wildcardDomain = wildcard_module
    return wildcard_module


wildcard_module = _bootstrap_test_module()


class TestWildcardProfileUnit(unittest.TestCase):
    def test_build_wildcard_probe_roots_cover_branch_and_parent(self):
        roots = wildcard_module.build_wildcard_probe_roots(
            ["api.dev.example.com"],
            max_levels=2,
        )

        self.assertEqual(roots, ["dev.example.com", "example.com"])

    @patch("app.services.wildcardDomain.utils.random_choices", side_effect=["probea001", "probeb002"])
    @patch("app.services.wildcardDomain.utils.get_cname")
    @patch("app.services.wildcardDomain.utils.get_ip")
    def test_collect_wildcard_profiles_merge_multi_round_results(self, mock_get_ip, mock_get_cname, _mock_random):
        mock_get_ip.side_effect = lambda domain, log_flag=False: {
            "probea001.example.com": ["1.1.1.1"],
            "probeb002.example.com": ["2.2.2.2"],
        }.get(domain, [])
        mock_get_cname.side_effect = lambda domain, log_flag=False: {
            "probea001.example.com": ["wild.edge.example.net"],
        }.get(domain, [])

        profiles = wildcard_module.collect_wildcard_profiles_from_domains(
            ["example.com"],
            probe_count=2,
            max_levels=1,
            verify_rounds=1,
        )

        profile = profiles["example.com"]
        self.assertEqual(profile["records"], {"1.1.1.1", "2.2.2.2", "wild.edge.example.net"})
        self.assertIn(("1.1.1.1", "wild.edge.example.net"), profile["signatures"])
        self.assertIn(("2.2.2.2",), profile["signatures"])

    @patch("app.services.wildcardDomain.utils.random_choices", return_value="probea001")
    @patch("app.services.wildcardDomain.utils.get_cname", return_value=[])
    @patch("app.services.wildcardDomain.utils.get_ip", return_value=["9.9.9.9"])
    def test_collect_wildcard_profiles_from_roots_keep_branch_root(self, _mock_get_ip, _mock_get_cname, _mock_random):
        profiles = wildcard_module.collect_wildcard_profiles_from_roots(
            ["dev.example.com"],
            probe_count=1,
            verify_rounds=1,
        )

        self.assertIn("dev.example.com", profiles)
        self.assertNotIn("example.com", profiles)

    @patch("app.services.wildcardDomain.utils.get_cname", return_value=[])
    @patch("app.services.wildcardDomain.utils.get_ip", return_value=["3.3.3.3"])
    def test_domain_info_hits_wildcard_profile_by_exact_rrset(self, _mock_get_ip, _mock_get_cname):
        wildcard_profile_map = {
            "dev.example.com": {
                "root": "dev.example.com",
                "records": {"3.3.3.3"},
                "a_records": {"3.3.3.3"},
                "cname_records": set(),
                "signatures": {("3.3.3.3",)},
                "record_counter": {"3.3.3.3": 3},
                "signature_counter": {("3.3.3.3",): 3},
                "probe_domains": {"probea.dev.example.com"},
                "sample_count": 3,
            }
        }
        info = _DomainInfo("foo.dev.example.com", record=["3.3.3.3"], record_type="A", ips=["3.3.3.3"])

        self.assertTrue(
            wildcard_module.domain_info_hits_wildcard_profile(
                info,
                wildcard_profile_map,
                verify_rounds=2,
                max_levels=1,
            )
        )

    def test_domain_info_hits_wildcard_profile_by_cname_overlap(self):
        wildcard_profile_map = {
            "example.com": {
                "root": "example.com",
                "records": {"wild.edge.example.net"},
                "a_records": set(),
                "cname_records": {"wild.edge.example.net"},
                "signatures": {("wild.edge.example.net",)},
                "record_counter": {"wild.edge.example.net": 2},
                "signature_counter": {("wild.edge.example.net",): 2},
                "probe_domains": {"probea.example.com"},
                "sample_count": 2,
            }
        }
        info = _DomainInfo(
            "bar.example.com",
            record=["wild.edge.example.net"],
            record_type="CNAME",
            ips=[],
        )

        self.assertTrue(
            wildcard_module.domain_info_hits_wildcard_profile(
                info,
                wildcard_profile_map,
                verify_rounds=1,
                max_levels=1,
            )
        )


if __name__ == "__main__":
    unittest.main()
