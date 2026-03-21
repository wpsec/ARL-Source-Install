"""
指纹导入脚本回归测试
"""
import json
import os
import tempfile
import unittest

from app.tools.import_fingerprint import parse_finger_json


class TestImportFingerprint(unittest.TestCase):
    """
    覆盖历史指纹、标准 JSON 指纹和预编译规则三种导入格式
    """

    def parse_payload(self, payload):
        """
        将临时 JSON 文件交给导入解析器并返回结果
        """
        fd, file_path = tempfile.mkstemp(suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fp:
                json.dump(payload, fp, ensure_ascii=False)
            return parse_finger_json(file_path)
        finally:
            if os.path.exists(file_path):
                os.unlink(file_path)

    def test_parse_legacy_schema(self):
        """
        历史 cms/method/location/keyword 格式仍应保持兼容
        """
        payload = {
            "fingerprint": [
                {
                    "cms": "Nginx",
                    "method": "keyword",
                    "location": "header",
                    "keyword": ["Server: nginx", "Server: nginx"],
                },
                {
                    "cms": "WordPress",
                    "method": "keyword",
                    "location": "body",
                    "keyword": ["wp-content"],
                },
            ]
        }

        finger_map = self.parse_payload(payload)
        self.assertEqual(finger_map["Nginx"], 'header="Server: nginx"')
        self.assertEqual(finger_map["WordPress"], 'body="wp-content"')

    def test_parse_standard_schema(self):
        """
        标准化 name/method/keyword 格式应能自动映射到 ARL 表达式
        """
        payload = {
            "fingerprint": [
                {
                    "name": "禅道",
                    "method": "url",
                    "keyword": ["/zentao/user", "/zentao/user"],
                },
                {
                    "name": "禅道",
                    "method": "faviconhash",
                    "keyword": ["116323821"],
                },
                {
                    "name": "Nginx",
                    "method": "header",
                    "keyword": "Server: nginx",
                },
            ]
        }

        finger_map = self.parse_payload(payload)
        self.assertIn('url="/zentao/user"', finger_map["禅道"])
        self.assertIn('icon_hash=="116323821"', finger_map["禅道"])
        self.assertEqual(finger_map["Nginx"], 'header="Server: nginx"')

    def test_parse_precompiled_schema(self):
        """
        预编译 human_rule 列表应保持原样聚合并去重
        """
        payload = [
            {"name": "Nginx", "human_rule": 'header="Server: nginx"'},
            {"name": "Nginx", "human_rule": 'header="Server: nginx"'},
            {"name": "Nginx", "human_rule": 'body="Welcome to nginx"'},
        ]

        finger_map = self.parse_payload(payload)
        self.assertEqual(
            finger_map["Nginx"],
            'body="Welcome to nginx" || header="Server: nginx"',
        )


if __name__ == "__main__":
    unittest.main()
