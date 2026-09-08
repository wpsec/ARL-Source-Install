"""计划 7 自适应采集策略契约测试。"""

import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "app" / "services" / "wih_strategy.py"
SPEC = importlib.util.spec_from_file_location("plan7_wih_strategy", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class WihStrategyTest(unittest.TestCase):
    def test_unknown_keeps_low_cost_defaults(self):
        plan = MODULE.build_wih_strategy_plan(
            {
                "profile": "unknown",
                "confidence": "low",
                "recommended_collectors": ["http"],
                "optional_collectors": ["browser_runtime"],
                "skipped_collectors": [],
            }
        )

        self.assertIn("http", plan.selected_collectors)
        self.assertIn("endpoint_probe", plan.selected_collectors)
        self.assertNotIn("browser_runtime", plan.selected_collectors)
        self.assertIn("browser_runtime", plan.skipped_collectors)
        self.assertEqual("requires_explicit_enable", plan.to_dict()["reasons"]["browser_runtime"])

    def test_spa_selects_browser_only_when_explicitly_enabled(self):
        profile = {
            "profile": "spa",
            "confidence": "high",
            "recommended_collectors": ["http", "html", "script"],
            "optional_collectors": ["browser_runtime"],
            "skipped_collectors": [],
        }

        disabled = MODULE.build_wih_strategy_plan(profile, browser_enabled=False)
        enabled = MODULE.build_wih_strategy_plan(profile, browser_enabled=True)

        self.assertNotIn("browser_runtime", disabled.selected_collectors)
        self.assertIn("browser_runtime", enabled.selected_collectors)
        self.assertEqual(
            "explicit_feature_enabled",
            enabled.to_dict()["reasons"]["browser_runtime"],
        )

    def test_budget_or_low_gain_stops_l1_optional_expansion(self):
        profile = {
            "profile": "api_only",
            "confidence": "high",
            "recommended_collectors": ["http", "api_document"],
            "optional_collectors": [],
            "skipped_collectors": [],
        }

        plan = MODULE.build_wih_strategy_plan(
            profile,
            metrics={"no_gain_count": 3},
        )

        self.assertEqual("low_information_gain", plan.stop_reason)
        self.assertNotIn("endpoint_probe", plan.selected_collectors)
        self.assertIn("endpoint_probe", plan.skipped_collectors)

    def test_l2_is_never_selected_without_explicit_flag(self):
        plan = MODULE.build_wih_strategy_plan(
            {"profile": "api_only", "recommended_collectors": ["http"]},
            auth_boundary_enabled=False,
        )

        self.assertNotIn("auth_boundary", plan.selected_collectors)
        self.assertIn("auth_boundary", plan.skipped_collectors)
        self.assertEqual(MODULE.LEVEL_L1, plan.max_level)


if __name__ == "__main__":
    unittest.main()
