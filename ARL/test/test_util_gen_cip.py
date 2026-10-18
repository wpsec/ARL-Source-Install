import unittest
from unittest.mock import patch

from app.utils.arl import gen_cip_map
import app.utils.arl as arl_utils


class TestTaskHelpers(unittest.TestCase):
    def test_gen_cip_map_ip(self):
        with patch.object(arl_utils, "conn_db") as conn_db:
            conn_db.return_value.find.return_value = iter([
                {"ip": "203.0.113.12", "domain": ["a.fixture.invalid"]},
                {"ip": "203.0.113.44", "domain": ["b.fixture.invalid"]},
            ])
            cip_map = gen_cip_map("fixture-task-id-with-24-characters")

        self.assertEqual(1, len(cip_map))
        entry = next(iter(cip_map.values()))
        self.assertEqual({"203.0.113.12", "203.0.113.44"}, entry["ip_set"])
        self.assertEqual({"a.fixture.invalid", "b.fixture.invalid"}, entry["domain_set"])

    def test_gen_cip_map_domain(self):
        with patch.object(arl_utils, "conn_db") as conn_db:
            conn_db.return_value.find.return_value = iter([
                {"ip": "198.51.100.10", "domain": ["site.fixture.invalid"]},
            ])
            cip_map = gen_cip_map("fixture-task-id-with-24-characters")

        self.assertEqual(1, len(cip_map))
        self.assertEqual({"198.51.100.10"}, next(iter(cip_map.values()))["ip_set"])


if __name__ == '__main__':
    unittest.main()
