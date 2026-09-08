"""计划 7 自适应候选调度测试。"""

import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "app" / "services" / "wih_adaptive_scheduler.py"
SPEC = importlib.util.spec_from_file_location("plan7_wih_adaptive_scheduler", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class WihAdaptiveSchedulerTest(unittest.TestCase):
    def test_selects_high_gain_candidates_with_budget_and_host_cap(self):
        plan = MODULE.schedule_candidates(
            [
                {"candidate_id": "slow", "host": "c.test", "expected_evidence": 90, "confidence": 90, "request_cost": 8, "time_cost": 8},
                {"candidate_id": "fast", "host": "a.test", "expected_evidence": 80, "confidence": 90, "request_cost": 0.5, "time_cost": 0.5},
                {"candidate_id": "second-host", "host": "b.test", "expected_evidence": 70, "confidence": 80, "request_cost": 0.5, "time_cost": 0.5},
            ],
            budget=3,
            max_per_host=1,
        )

        self.assertEqual(("fast", "second-host"), tuple(item.candidate_id for item in plan.selected))
        self.assertEqual(MODULE.STOP_BUDGET, plan.stop_reason)
        self.assertIn(("slow", "budget_exhausted"), plan.skipped)

    def test_covered_candidates_are_not_reselected(self):
        plan = MODULE.schedule_candidates(
            [{"candidate_id": "covered", "covered": True, "expected_evidence": 100}],
        )
        self.assertEqual((), plan.selected)
        self.assertEqual((("covered", "already_covered"),), plan.skipped)

    def test_waf_or_low_gain_stops_without_deleting_candidates(self):
        plan = MODULE.schedule_candidates(
            [{"candidate_id": "one", "expected_evidence": 80}],
            waf_block_count=3,
        )
        self.assertEqual(MODULE.STOP_WAF, plan.stop_reason)
        self.assertEqual(("one",), tuple(item.candidate_id for item in plan.pending))


if __name__ == "__main__":
    unittest.main()
