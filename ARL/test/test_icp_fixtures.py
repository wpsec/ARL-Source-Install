"""ICP 上游响应脱敏样例的结构回归测试。"""

import json
import pathlib
import unittest


FIXTURE_DIR = pathlib.Path(__file__).resolve().parent / "data" / "icp"
FIXTURE_NAMES = (
    "web_success.json",
    "app_success.json",
    "app_detail_success.json",
    "black_web_success.json",
)


def _iter_keys(value):
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key)
            yield from _iter_keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_keys(child)


class TestIcpFixtures(unittest.TestCase):
    def test_fixture_files_are_json_and_do_not_contain_credentials(self):
        sensitive_names = {"token", "sign", "cookie", "authorization", "password", "secret"}
        for name in FIXTURE_NAMES:
            with self.subTest(name=name):
                payload = json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))
                self.assertIsInstance(payload, dict)
                self.assertEqual(200, payload["code"])
                self.assertTrue(payload["success"])
                self.assertFalse(
                    sensitive_names.intersection(key.lower() for key in _iter_keys(payload))
                )

    def test_fixture_shapes_cover_normal_detail_and_blacklist_responses(self):
        web = json.loads((FIXTURE_DIR / "web_success.json").read_text(encoding="utf-8"))
        app = json.loads((FIXTURE_DIR / "app_success.json").read_text(encoding="utf-8"))
        detail = json.loads((FIXTURE_DIR / "app_detail_success.json").read_text(encoding="utf-8"))
        black = json.loads((FIXTURE_DIR / "black_web_success.json").read_text(encoding="utf-8"))

        self.assertIsInstance(web["params"]["list"], list)
        self.assertIsInstance(app["params"]["list"], list)
        self.assertIsInstance(detail["params"], dict)
        self.assertIsInstance(black["params"], list)


if __name__ == "__main__":
    unittest.main()
