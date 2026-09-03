"""验证多架构镜像不会静默关闭 MassDNS 相关任务选项。"""
import unittest

from app.helpers.task import apply_arch_compat_options


class TestArchCompatOptions(unittest.TestCase):
    def test_massdns_options_are_preserved(self):
        options = {
            "domain_brute": True,
            "alt_dns": True,
            "domain_brute_type": "test",
        }

        normalized, notices = apply_arch_compat_options(options)

        self.assertEqual(options, normalized)
        self.assertEqual([], notices)


if __name__ == "__main__":
    unittest.main()
