import unittest
from app.services.nuclei_scan import nuclei_scan
try:
    from test._network_test_guard import legacy_network_test
except ImportError:
    from _network_test_guard import legacy_network_test


@legacy_network_test
class TestCDNName(unittest.TestCase):
    def test_nuclei_scan(self):
        result = nuclei_scan(["http://www.baidu.com"])
        print("Result: ", result)


if __name__ == '__main__':
    unittest.main()
