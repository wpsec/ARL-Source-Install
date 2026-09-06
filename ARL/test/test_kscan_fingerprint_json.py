"""
kscan 指纹 JSON 加载兼容测试
"""
import json
import os
import tempfile
import unittest
from unittest.mock import patch

IMPORT_ERROR = None
try:
    from app.services import kscan_fingerprint as kscan_module
except Exception as exc:
    kscan_module = None
    IMPORT_ERROR = exc


@unittest.skipIf(IMPORT_ERROR is not None, "requires kscan fingerprint test dependencies: {}".format(IMPORT_ERROR))
class TestKscanFingerprintJson(unittest.TestCase):
    """
    验证运行时对标准化 JSON 指纹的兼容能力
    """

    def test_load_standard_json_rules(self):
        """
        标准化 JSON 指纹应能在运行时转换为 human_rule
        """
        payload = {
            "fingerprint": [
                {"name": "禅道", "method": "url", "keyword": ["/zentao/user"]},
                {"name": "禅道", "method": "faviconhash", "keyword": ["116323821"]},
                {"name": "Nginx", "method": "header", "keyword": "Server: nginx"},
            ]
        }

        fd, file_path = tempfile.mkstemp(suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fp:
                json.dump(payload, fp, ensure_ascii=False)

            old_cache = dict(kscan_module._CACHE)
            old_missing_logged = kscan_module._MISSING_LOGGED
            try:
                kscan_module._CACHE = {
                    "file_path": "",
                    "mtime": -1,
                    "signature": (),
                    "rules": [],
                    "stats": {},
                }
                kscan_module._MISSING_LOGGED = False

                with patch.object(kscan_module.Config, "KSCAN_FINGERPRINT_ENABLE", True), \
                        patch.object(kscan_module.Config, "KSCAN_FINGERPRINT_FILE", file_path):
                    rules = kscan_module.load_kscan_fingerprint_rules()
            finally:
                kscan_module._CACHE = old_cache
                kscan_module._MISSING_LOGGED = old_missing_logged

            # loader 设计=同名多条目（fingerprint_cache 按名合并消费）；
            # 聚合全部条目再断言，避免同名后写覆盖假失败。
            rule_map = {}
            for item in rules:
                rule_map[item["name"]] = "{} || {}".format(
                    rule_map.get(item["name"], ""), item["human_rule"]).strip(" |")
            self.assertIn('url="/zentao/user"', rule_map["禅道"])
            self.assertIn('icon_hash=="116323821"', rule_map["禅道"])
            self.assertEqual(rule_map["Nginx"], 'header="Server: nginx"')
        finally:
            if os.path.exists(file_path):
                os.unlink(file_path)


if __name__ == "__main__":
    unittest.main()
