"""
指纹缓存与打分逻辑单元测试
"""
import unittest
from unittest.mock import patch

IMPORT_ERROR = None
try:
    from app.services.fingerprint import FingerPrint
    from app.services.fingerprint_cache import estimate_human_rule_confidence, finger_db_identify_detail
except Exception as exc:
    FingerPrint = None
    estimate_human_rule_confidence = None
    finger_db_identify_detail = None
    IMPORT_ERROR = exc


@unittest.skipIf(IMPORT_ERROR is not None, "requires fingerprint test dependencies: {}".format(IMPORT_ERROR))
class TestFingerprintCacheUnit(unittest.TestCase):
    """
    验证指纹详情聚合与置信度估算逻辑
    """

    def test_estimate_human_rule_confidence(self):
        """
        强特征规则的置信度应高于弱特征规则
        """
        self.assertGreater(
            estimate_human_rule_confidence('icon_hash=="116323821"'),
            estimate_human_rule_confidence('body="Welcome"'),
        )
        self.assertGreater(
            estimate_human_rule_confidence('header="Server: nginx" || body="Welcome"'),
            estimate_human_rule_confidence('header="Server: nginx"'),
        )

    @patch("app.services.fingerprint_cache.finger_db_cache.get_data")
    def test_identify_detail_keeps_highest_confidence(self, mock_get_data):
        """
        同名应用命中多条规则时应保留置信度最高的一条
        """
        mock_get_data.return_value = [
            FingerPrint("禅道", 'url="/zentao/user"'),
            FingerPrint("禅道", 'icon_hash=="116323821"'),
            FingerPrint("Nginx", 'header="server: nginx"'),
        ]

        variables = {
            "body": "",
            "header": "server: nginx",
            "title": "",
            "icon_hash": "116323821",
            "response": "server: nginx\n",
            "url": "https://demo.local/zentao/user-login.html",
        }

        results = finger_db_identify_detail(variables)
        self.assertEqual(results[0]["name"], "禅道")
        self.assertGreaterEqual(results[0]["confidence"], 95)
        self.assertIn("icon_hash", results[0]["match_fields"])


if __name__ == "__main__":
    unittest.main()
