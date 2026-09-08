"""计划 7 跨目标画像 golden corpus 回归。"""

import importlib.util
import json
import sys
import unittest
from pathlib import Path


ARL_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ARL_ROOT / "app" / "services" / "target_profile.py"
FIXTURE_PATH = ARL_ROOT / "test" / "fixtures" / "wih_profiles" / "golden.json"
SPEC = importlib.util.spec_from_file_location("plan7_wih_profile_golden", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class WihProfileGoldenTest(unittest.TestCase):
    def test_all_supported_shapes_have_stable_profile(self):
        corpus = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        resolver = MODULE.TargetProfileResolver()
        self.assertEqual("wih-profile-golden-v1", corpus["version"])
        for case in corpus["cases"]:
            with self.subTest(case=case["name"]):
                profile = resolver.resolve(
                    pages=case.get("pages", []),
                    scripts=case.get("scripts", []),
                    runtime_events=case.get("runtime_events", []),
                )
                self.assertEqual(case["expected_profile"], profile.profile)
                self.assertLessEqual(len(profile.evidence), 16)


if __name__ == "__main__":
    unittest.main()
