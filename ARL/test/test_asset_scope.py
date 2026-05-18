import unittest

from app.modules import AssetScopeType, ErrorMsg
from app.routes.assetScope import normalize_black_scope_items, normalize_scope_items


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

    def test_normalize_black_domain_scope(self):
        items = normalize_black_scope_items("https://Test.Example.com/path test.example.com", AssetScopeType.DOMAIN)

        self.assertEqual(items, ["test.example.com"])


if __name__ == "__main__":
    unittest.main()
