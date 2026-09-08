import unittest
from app import services
try:
    from test._network_test_guard import legacy_network_test
except ImportError:
    from _network_test_guard import legacy_network_test


@legacy_network_test
class TestWebInfoHunter(unittest.TestCase):
    def test_run_wih(self):
        sites = ["https://www.freebuf.com", "https://www.qq.com/"]
        results = services.run_wih(sites)

        for result in results:
            print(result)

        self.assertTrue(len(results) > 2)
