import unittest
from unittest.mock import patch

IMPORT_ERROR = None

try:
    from app import modules
    from app.services.wildcardDomain import (
        build_wildcard_probe_domains,
        collect_wildcard_records_from_domains,
    )
    from app.tasks.domain import DomainTask
except Exception as exc:
    IMPORT_ERROR = exc


@unittest.skipIf(IMPORT_ERROR is not None, "requires domain task dependencies: {}".format(IMPORT_ERROR))
class TestWildcardDomain(unittest.TestCase):
    @patch("app.services.wildcardDomain.utils.random_choices", return_value="probezzzz")
    def test_build_wildcard_probe_domains_keep_same_level(self, _mock_random):
        probe_domains = build_wildcard_probe_domains(
            ["mail.weread.qq.com", "example.com"],
            probe_count=1,
        )

        self.assertIn("probezzzz.weread.qq.com", probe_domains)
        self.assertIn("probezzzz.example.com", probe_domains)

    @patch("app.services.wildcardDomain.utils.get_cname")
    @patch("app.services.wildcardDomain.utils.get_ip")
    @patch(
        "app.services.wildcardDomain.utils.random_choices",
        side_effect=["probea111", "probeb222", "probec333"],
    )
    def test_collect_wildcard_records_from_domains_merge_multi_probe_results(
        self,
        _mock_random,
        mock_get_ip,
        mock_get_cname,
    ):
        mock_get_ip.side_effect = lambda domain, log_flag=False: {
            "probea111.example.com": ["1.1.1.1"],
            "probeb222.example.com": ["2.2.2.2"],
            "probec333.example.com": ["3.3.3.3"],
        }.get(domain, [])
        mock_get_cname.side_effect = lambda domain, log_flag=False: {
            "probeb222.example.com": ["wildcard.edge.example.net"],
        }.get(domain, [])

        records = collect_wildcard_records_from_domains(["example.com"], probe_count=3)

        self.assertEqual(
            records,
            {"1.1.1.1", "2.2.2.2", "3.3.3.3", "wildcard.edge.example.net"},
        )


@unittest.skipIf(IMPORT_ERROR is not None, "requires domain task dependencies: {}".format(IMPORT_ERROR))
class TestDomainTaskWildcardFilter(unittest.TestCase):
    @patch("app.tasks.domain.utils.check_dns_policy_for_host", return_value=(True, {}))
    def test_clear_domain_info_by_record_match_secondary_ip(self, _mock_policy):
        task = DomainTask(
            base_domain="example.com",
            task_id="64b7d749c97bead7f83d0de4",
            options={},
        )
        task._wildcard_domain_records = ["2.2.2.2"]

        wildcard_info = modules.DomainInfo(
            domain="api.example.com",
            record=["1.1.1.1"],
            type="A",
            ips=["9.9.9.9", "2.2.2.2"],
        )
        normal_info = modules.DomainInfo(
            domain="www.example.com",
            record=["8.8.8.8"],
            type="A",
            ips=["8.8.8.8"],
        )

        filtered = task.clear_domain_info_by_record([wildcard_info, normal_info])

        self.assertEqual([item.domain for item in filtered], ["www.example.com"])

    @patch(
        "app.tasks.domain.collect_wildcard_profiles_from_roots",
        side_effect=lambda roots: {
            root: {"root": root, "records": {"1.1.1.1"}}
            for root in roots
        },
    )
    def test_clear_domain_info_prewarm_wildcard_profiles_by_batch(self, mock_collect):
        task = DomainTask(
            base_domain="example.com",
            task_id="64b7d749c97bead7f83d0de4",
            options={},
        )
        info = modules.DomainInfo(
            domain="api.dev.example.com",
            record=["2.2.2.2"],
            type="A",
            ips=["2.2.2.2"],
        )

        task._prewarm_wildcard_profiles([info])

        mock_collect.assert_called_once()
        self.assertEqual(
            set(mock_collect.call_args.args[0]),
            {"dev.example.com", "example.com"},
        )
        self.assertEqual(
            set(task._wildcard_profile_cache),
            {"dev.example.com", "example.com"},
        )


if __name__ == "__main__":
    unittest.main()
