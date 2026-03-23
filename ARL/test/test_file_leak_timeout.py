"""
目录扫描自适应超时回归测试。
"""
import unittest
from unittest.mock import patch

try:
    from app.services.fileLeak import _calc_adaptive_timeout, _calc_file_leak_target_timeouts
except ModuleNotFoundError:
    _calc_adaptive_timeout = None
    _calc_file_leak_target_timeouts = None


@unittest.skipIf(
    _calc_adaptive_timeout is None or _calc_file_leak_target_timeouts is None,
    "运行依赖未安装，跳过目录扫描超时回归",
)
class TestFileLeakTimeout(unittest.TestCase):
    """
    验证目录扫描超时预算计算逻辑。
    """

    def test_calc_adaptive_timeout_base_only(self):
        value = _calc_adaptive_timeout(base_sec=900, per_1000_urls_sec=180, max_sec=7200, url_count=500)
        self.assertEqual(900, value)

    def test_calc_adaptive_timeout_scale_and_cap(self):
        value = _calc_adaptive_timeout(base_sec=900, per_1000_urls_sec=300, max_sec=1200, url_count=4500)
        self.assertEqual(1200, value)

    def test_calc_adaptive_timeout_disable_when_base_zero(self):
        value = _calc_adaptive_timeout(base_sec=0, per_1000_urls_sec=300, max_sec=3600, url_count=5000)
        self.assertEqual(0, value)

    def test_calc_file_leak_target_timeouts(self):
        with patch("app.services.fileLeak.Config.FILE_LEAK_SITE_TIMEOUT_SEC", 900), \
                patch("app.services.fileLeak.Config.FILE_LEAK_SITE_TIMEOUT_PER_1000_URLS_SEC", 180), \
                patch("app.services.fileLeak.Config.FILE_LEAK_SITE_TIMEOUT_MAX_SEC", 7200), \
                patch("app.services.fileLeak.Config.FILE_LEAK_NO_PROGRESS_TIMEOUT_SEC", 120), \
                patch("app.services.fileLeak.Config.FILE_LEAK_NO_PROGRESS_TIMEOUT_PER_1000_URLS_SEC", 30), \
                patch("app.services.fileLeak.Config.FILE_LEAK_NO_PROGRESS_TIMEOUT_MAX_SEC", 600):
            site_timeout, no_progress_timeout = _calc_file_leak_target_timeouts(2500)

        self.assertEqual(1260, site_timeout)
        self.assertEqual(180, no_progress_timeout)


if __name__ == "__main__":
    unittest.main()
