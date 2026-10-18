import unittest
from unittest.mock import patch

from app.utils.cdn import get_cdn_name_by_ip, get_cdn_name_by_cname
import app.utils.cdn as cdn


class TestCDNName(unittest.TestCase):
    def setUp(self):
        self._patched = patch.multiple(
            cdn,
            cdn_info=[{
                "name": "Fixture CDN",
                "ip_cidr": ["203.0.113.0/24"],
                "cname_domain": ["edge.fixture.invalid"],
            }],
            cdn_ip_cidr_list=["203.0.113.0/24"],
            cdn_cname_list=["edge.fixture.invalid"],
        )
        self._patched.start()
        self.addCleanup(self._patched.stop)

    def test_cdn_ip(self):
        self.assertEqual("", get_cdn_name_by_ip("198.51.100.2"))
        self.assertEqual("Fixture CDN", get_cdn_name_by_ip("203.0.113.2"))

    def test_cdn_cname(self):
        self.assertEqual("", get_cdn_name_by_cname("origin.fixture.invalid"))
        self.assertEqual("Fixture CDN", get_cdn_name_by_cname("www.edge.fixture.invalid"))

if __name__ == '__main__':
    unittest.main()
