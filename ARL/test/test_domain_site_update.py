import unittest

IMPORT_ERROR = None

try:
    from app import modules
    from app.services.domainSiteUpdate import DomainSiteUpdate
except Exception as exc:
    IMPORT_ERROR = exc


@unittest.skipIf(IMPORT_ERROR is not None, "requires domain site update dependencies: {}".format(IMPORT_ERROR))
class TestDomainSiteUpdate(unittest.TestCase):
    def test_clear_wildcard_domain_info_matches_secondary_ip(self):
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

        filtered, drop_count = DomainSiteUpdate._clear_wildcard_domain_info(
            [wildcard_info, normal_info],
            {"2.2.2.2"},
        )

        self.assertEqual(drop_count, 1)
        self.assertEqual([item.domain for item in filtered], ["www.example.com"])

    def test_clear_wildcard_domain_info_matches_cname_record(self):
        wildcard_info = modules.DomainInfo(
            domain="mail.example.com",
            record=["wildcard.edge.example.net"],
            type="CNAME",
            ips=["3.3.3.3"],
        )
        normal_info = modules.DomainInfo(
            domain="open.example.com",
            record=["4.4.4.4"],
            type="A",
            ips=["4.4.4.4"],
        )

        filtered, drop_count = DomainSiteUpdate._clear_wildcard_domain_info(
            [wildcard_info, normal_info],
            {"wildcard.edge.example.net"},
        )

        self.assertEqual(drop_count, 1)
        self.assertEqual([item.domain for item in filtered], ["open.example.com"])


if __name__ == "__main__":
    unittest.main()
