"""计划 7 L0-L3 受控验证策略测试。"""

import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "app"
    / "services"
    / "controlled_verification_policy.py"
)
SPEC = importlib.util.spec_from_file_location("plan7_controlled_policy", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class ControlledVerificationPolicyTest(unittest.TestCase):
    def setUp(self):
        self.policy = MODULE.ControlledVerificationPolicy()

    def test_get_and_head_are_l1_read_only(self):
        for method in ("GET", "HEAD"):
            decision = self.policy.decide(
                {"url": "https://example.invalid/api", "method": method}
            )
            self.assertTrue(decision.allowed)
            self.assertEqual(MODULE.LEVEL_L1, decision.level)
            self.assertEqual(MODULE.STATUS_QUEUED, decision.status)

    def test_post_requires_explicit_read_only_allowlist(self):
        item = {
            "url": "https://example.invalid/api",
            "method": "POST",
            "body_kind": "json",
            "safe_read": True,
        }
        self.assertFalse(self.policy.decide(item).allowed)
        allowlisted = MODULE.ControlledVerificationPolicy(allowlisted_post=True)
        self.assertTrue(allowlisted.decide(item).allowed)

    def test_dangerous_method_is_l3_only(self):
        decision = self.policy.decide(
            {"url": "https://example.invalid/api", "method": "DELETE"}
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(MODULE.LEVEL_L3, decision.level)
        self.assertEqual("method_is_write_or_specialized", decision.reason_code)

    def test_l2_requires_allowlisted_auth_profile_and_is_pending(self):
        item = {
            "url": "https://example.invalid/api",
            "method": "GET",
            "auth_profile": "anonymous",
        }
        self.assertFalse(self.policy.decide(item, requested_level="L2").allowed)
        policy = MODULE.ControlledVerificationPolicy(l2_enabled=True)
        decision = policy.decide(item, requested_level="L2")
        self.assertFalse(decision.allowed)
        self.assertEqual(MODULE.STATUS_PENDING, decision.status)
        self.assertEqual("requires_auth_boundary_stage", decision.reason_code)

    def test_observed_response_is_l0_and_never_reprobed(self):
        decision = self.policy.decide(
            {
                "url": "https://example.invalid/api",
                "method": "POST",
                "status_code": 200,
            }
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(MODULE.LEVEL_L0, decision.level)
        self.assertEqual(MODULE.STATUS_OBSERVED, decision.status)


if __name__ == "__main__":
    unittest.main()
