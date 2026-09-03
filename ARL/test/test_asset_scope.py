import unittest

from app.modules import AssetScopeType, ErrorMsg
from app.routes.assetScope import normalize_black_scope_items, normalize_scope_items
from app.utils.ip import ip_in_scope


class TestAssetScopeNormalize(unittest.TestCase):
    def test_normalize_domain_scope_deduplicates_and_validates(self):
        items, error_msg, error_data = normalize_scope_items(
            "https://Example.com/path\napi.example.com example.com",
            AssetScopeType.DOMAIN,
        )

        self.assertIsNone(error_msg)
        self.assertIsNone(error_data)
        self.assertEqual(items, ["example.com", "api.example.com"])

    def test_normalize_ip_scope_supports_ip_cidr_and_range(self):
        items, error_msg, error_data = normalize_scope_items(
            "192.0.2.10\n192.0.2.0/24 192.0.2.10-192.0.2.20",
            AssetScopeType.IP,
        )

        self.assertIsNone(error_msg)
        self.assertIsNone(error_data)
        self.assertEqual(items, ["192.0.2.10", "192.0.2.0/24", "192.0.2.10-192.0.2.20"])

    def test_normalize_ip_scope_rejects_invalid_item(self):
        items, error_msg, error_data = normalize_scope_items("not-an-ip", AssetScopeType.IP)

        self.assertIsNone(items)
        self.assertEqual(error_msg, ErrorMsg.ScopeTypeIsNotIP)
        self.assertEqual(error_data, {"scope": "not-an-ip"})

    def test_normalize_ip_scope_rejects_reversed_range(self):
        items, error_msg, error_data = normalize_scope_items("192.0.2.20-192.0.2.10", AssetScopeType.IP)

        self.assertIsNone(items)
        self.assertEqual(error_msg, ErrorMsg.ScopeTypeIsNotIP)

    def test_normalize_black_domain_scope(self):
        items = normalize_black_scope_items("https://Test.Example.com/path test.example.com", AssetScopeType.DOMAIN)

        self.assertEqual(items, ["test.example.com"])


class TestIpInScope(unittest.TestCase):
    """非对齐段与常规条目的成员判定。"""

    def test_unaligned_range_matches_by_interval(self):
        scope = ["192.0.2.10-192.0.2.20"]
        self.assertTrue(ip_in_scope("192.0.2.10", scope))
        self.assertTrue(ip_in_scope("192.0.2.15", scope))
        self.assertTrue(ip_in_scope("192.0.2.20", scope))
        self.assertFalse(ip_in_scope("192.0.2.21", scope))
        self.assertFalse(ip_in_scope("192.0.2.9", scope))

    def test_cidr_single_and_blacklist_semantics_unchanged(self):
        self.assertTrue(ip_in_scope("192.0.2.5", ["192.0.2.0/24"]))
        self.assertTrue(ip_in_scope("192.0.2.5", ["192.0.2.5"]))
        self.assertTrue(ip_in_scope("192.0.2.30", ["192.0.2.0/28", "192.0.2.16-192.0.2.31"]))
        self.assertFalse(ip_in_scope("10.0.0.1", ["192.0.2.0/24"]))
        self.assertFalse(ip_in_scope("not-an-ip", ["192.0.2.0/24"]))
        self.assertFalse(ip_in_scope("192.0.2.5", ["broken-entry"]))


if __name__ == "__main__":
    unittest.main()
