"""计划 7 认证边界结果和敏感信息边界测试。"""

import importlib.util
import json
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "app" / "services" / "wih_auth_boundary.py"
SPEC = importlib.util.spec_from_file_location("plan7_wih_auth_boundary", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class WihAuthBoundaryTest(unittest.TestCase):
    def test_same_public_shape_is_manual_review_candidate(self):
        result = MODULE.compare_auth_boundary(
            {
                "anonymous": {"status_code": 200, "content_type": "application/json", "structure_hash": "same", "body_length": 100},
                "invalid_auth": {"status_code": 200, "content_type": "application/json", "structure_hash": "same", "body_length": 100},
                "authorized": {"status_code": 200, "content_type": "application/json", "structure_hash": "private", "body_length": 200},
            }
        )
        self.assertEqual(MODULE.AUTH_ANOMALY_CANDIDATE, result.verification_status)
        self.assertTrue(result.manual_review_required)
        self.assertIn("invalid_auth_same_shape", result.reason_codes)

    def test_unauthorized_status_does_not_create_candidate(self):
        result = MODULE.compare_auth_boundary(
            {
                "anonymous": {"status_code": 401, "content_type": "application/json", "structure_hash": "error"},
                "invalid_auth": {"status_code": 403, "content_type": "application/json", "structure_hash": "error"},
            }
        )
        self.assertNotEqual(MODULE.AUTH_ANOMALY_CANDIDATE, result.verification_status)
        self.assertFalse(result.manual_review_required)

    def test_jobs_and_projection_never_contain_credentials_or_body(self):
        jobs = MODULE.build_auth_boundary_jobs(
            {"url": "https://example.test/api", "method": "GET", "token": "secret"},
            enabled=True,
        )
        result = MODULE.compare_auth_boundary(
            {"anonymous": {"status_code": 200, "content_type": "application/json", "body": "secret"}},
            sibling_requires_auth=True,
        )
        projected = MODULE.apply_auth_boundary_result({"url": "https://example.test/api"}, result)
        serialized = json.dumps({"jobs": jobs, "result": projected}, ensure_ascii=False)
        self.assertNotIn("secret", serialized)
        self.assertNotIn("body", json.dumps(result.to_dict(), ensure_ascii=False))

    def test_disabled_jobs_are_explicitly_pending(self):
        jobs = MODULE.build_auth_boundary_jobs({}, enabled=False)
        self.assertEqual(1, len(jobs))
        self.assertEqual(MODULE.AUTH_PENDING, jobs[0]["status"])
        self.assertEqual("l2_requires_explicit_enable", jobs[0]["reason_code"])


if __name__ == "__main__":
    unittest.main()
