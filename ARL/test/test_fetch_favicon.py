import unittest
from app.services import fetch_favicon
try:
    from test._network_test_guard import legacy_network_test
except ImportError:
    from _network_test_guard import legacy_network_test


@legacy_network_test
class TestFavicon(unittest.TestCase):
    def test_favicon_error(self):
        data = fetch_favicon("https://106.55.91.130/")
        self.assertFalse(data)

    def test_favicon(self):
        data = fetch_favicon("https://www.qq.com/")
        self.assertTrue(data["hash"] == 1787932733)


if __name__ == '__main__':
    unittest.main()
