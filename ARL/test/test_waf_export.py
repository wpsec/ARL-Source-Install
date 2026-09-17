"""WAF XLSX 导出字段兼容回归测试。"""

import unittest
from unittest.mock import patch

try:
    from app.routes.export import _extract_waf_rows
except Exception:
    _extract_waf_rows = None


@unittest.skipIf(_extract_waf_rows is None, "运行依赖未安装，跳过 WAF 导出回归")
class TestWafExport(unittest.TestCase):
    def test_extract_rows_reads_new_and_legacy_summary_fields(self):
        with patch(
            "app.routes.export.get_task_data",
            side_effect=[
                {
                    "waf_skip_summary": {
                        "detected_hosts": [
                            {
                                "host": "new.example.com",
                                "last_url": "https://new.example.com/",
                                "waf_name": "Cloudflare",
                                "detection_sources": ["wafw00f"],
                                "wafw00f_status": "detected",
                                "wafw00f_active_risk_blocked": True,
                            }
                        ]
                    }
                },
                {
                    "waf_skip_summary": {
                        "blocked_hosts": [
                            {
                                "host": "old.example.com",
                                "last_url": "http://old.example.com/",
                                "waf_name": "legacy-waf",
                            }
                        ]
                    }
                },
            ],
        ):
            rows = _extract_waf_rows(["new-task", "old-task"])

        self.assertEqual(2, len(rows))
        self.assertEqual("wafw00f", rows[0][13])
        self.assertEqual("detected", rows[0][16])
        self.assertEqual("legacy-waf", rows[1][3])


if __name__ == "__main__":
    unittest.main()
