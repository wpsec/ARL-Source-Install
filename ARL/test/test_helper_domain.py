import unittest
from unittest.mock import patch

from app.helpers.domain import find_private_domain_by_task_id, find_public_ip_by_task_id
from app.helpers.domain import find_domain_by_task_id


class _Collection(object):
    def find(self, query):
        self.query = query
        return iter([
            {"domain": ["internal-a.fixture.invalid", "internal-b.fixture.invalid"]},
            {"domain": []},
        ])

    def distinct(self, field, query):
        self.query = query
        return {
            ("ip", "PUBLIC"): ["198.51.100.10", "203.0.113.11"],
            ("domain", None): ["a.fixture.invalid", "b.fixture.invalid"],
        }.get((field, query.get("ip_type")), [])


class TestHelperDomain(unittest.TestCase):
    def setUp(self):
        self.conn_db = patch("app.helpers.domain.utils.conn_db", side_effect=lambda *_args: _Collection())
        self.cached_call = patch(
            "app.helpers.domain.cached_call",
            side_effect=lambda _key, loader, **_kwargs: loader(),
        )
        self.conn_db.start()
        self.cached_call.start()
        self.addCleanup(self.conn_db.stop)
        self.addCleanup(self.cached_call.stop)

    def test_private_domain(self):
        domains = find_private_domain_by_task_id("fixture-task")
        self.assertEqual({"internal-a.fixture.invalid", "internal-b.fixture.invalid"}, set(domains))

    def test_public_ip(self):
        ips = find_public_ip_by_task_id("fixture-task")
        self.assertEqual(["198.51.100.10", "203.0.113.11"], ips)

    def test_domain(self):
        domains = find_domain_by_task_id("fixture-task")
        self.assertEqual(["a.fixture.invalid", "b.fixture.invalid"], domains)


if __name__ == '__main__':
    unittest.main()
