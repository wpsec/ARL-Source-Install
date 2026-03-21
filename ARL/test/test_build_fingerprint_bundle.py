"""
单文件指纹库构建测试
"""
import json
import os
import tempfile
import unittest

from app.tools.build_fingerprint_bundle import build_fingerprint_bundle


class TestBuildFingerprintBundle(unittest.TestCase):
    """
    验证多指纹源合并时的去重与限量行为
    """

    def create_json_file(self, payload):
        """
        写入临时 JSON 文件并返回路径
        """
        fd, file_path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as fp:
            json.dump(payload, fp, ensure_ascii=False)
        return file_path

    def test_build_bundle_merges_and_deduplicates(self):
        """
        多来源同名规则应去重后聚合到单一 human_rule
        """
        base_path = self.create_json_file(
            {
                "fingerprint": [
                    {"name": "Nginx", "human_rule": 'header="Server: nginx"'},
                    {"name": "禅道", "human_rule": 'url="/zentao/user"'},
                ]
            }
        )
        extra_path = self.create_json_file(
            {
                "fingerprint": [
                    {"name": "禅道", "method": "faviconhash", "keyword": ["116323821"]},
                    {"name": "Nginx", "human_rule": 'header="Server: nginx"'},
                ]
            }
        )

        try:
            items, stats = build_fingerprint_bundle(
                [base_path, extra_path],
                max_rules_per_name=30,
                max_total_rules=12000,
            )
        finally:
            os.unlink(base_path)
            os.unlink(extra_path)

        rule_map = {item["name"]: item["human_rule"] for item in items}
        self.assertEqual(rule_map["Nginx"], 'header="Server: nginx"')
        self.assertIn('url="/zentao/user"', rule_map["禅道"])
        self.assertIn('icon_hash=="116323821"', rule_map["禅道"])
        self.assertEqual(stats.get("source_file", 0), 2)


if __name__ == "__main__":
    unittest.main()
