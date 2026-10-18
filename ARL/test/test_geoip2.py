import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app.utils import get_ip_city, get_ip_asn
import app.utils.ip as ip_utils


class TestGeoIP2(unittest.TestCase):
    def test_get_ip_city(self):
        reader = SimpleNamespace(city=lambda _ip: SimpleNamespace(
            city=SimpleNamespace(name="Fixture City"),
            location=SimpleNamespace(latitude=1.5, longitude=2.5),
            country=SimpleNamespace(name="Fixture Country", iso_code="FC"),
            subdivisions=SimpleNamespace(most_specific=SimpleNamespace(
                name="Fixture Region", iso_code="FR"
            )),
        ))
        with patch.object(ip_utils, "_get_city_reader", return_value=reader):
            result = get_ip_city("203.0.113.1")

        self.assertEqual("Fixture City", result["city"])
        self.assertEqual("Fixture Region", result["region_name"])
        self.assertEqual("FC", result["country_code"])

    def test_get_ip_asn(self):
        reader = SimpleNamespace(asn=lambda _ip: SimpleNamespace(
            autonomous_system_number=64512,
            autonomous_system_organization="Fixture Network",
        ))
        with patch.object(ip_utils, "_get_asn_reader", return_value=reader):
            result = get_ip_asn("203.0.113.1")

        self.assertEqual(64512, result["number"])
        self.assertEqual("Fixture Network", result["organization"])


if __name__ == '__main__':
    unittest.main()
