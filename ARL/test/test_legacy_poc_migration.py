"""历史 40 个漏洞插件的 YAML 正反向等价验证快照回归。"""

import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ARL-NPoC"))
sys.path.insert(0, str(ROOT / "ARL-NPoC" / "tools"))

from tools import verify_legacy_pocs


class LegacyPocMigrationTest(unittest.TestCase):
    def test_all_legacy_pocs_match_recorded_python_snapshot_on_fixtures(self):
        results = verify_legacy_pocs.verify_all()
        self.assertEqual(len(results), 40)
        self.assertTrue(all(item["matched"] for item in results.values()), results)
        for rule_id, result in results.items():
            self.assertEqual(result["positive"]["python"], result["positive"]["yaml"], rule_id)
            self.assertEqual(result["negative"]["python"], result["negative"]["yaml"], rule_id)


if __name__ == "__main__":
    unittest.main()
