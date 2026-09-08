"""计划 7 独立 API 验证协调器测试。"""

import json
import sys
import unittest
from pathlib import Path
from unittest import mock


ARL_ROOT = Path(__file__).resolve().parents[1]
if str(ARL_ROOT) not in sys.path:
    sys.path.insert(0, str(ARL_ROOT))

from test._api_unified_bootstrap import load_modules  # noqa: E402


_BUNDLE = load_modules(
    "app.services.api_unified_models",
    "app.services.controlled_verification_policy",
    "app.services.wih_adaptive_scheduler",
    "app.services.wih_endpoint_probe",
    "app.services.wih_api_verify",
)
MODULE = _BUNDLE["app.services.wih_api_verify"]
ENDPOINT_PROBE = _BUNDLE["app.services.wih_endpoint_probe"]
run_api_verify = MODULE.run_api_verify


class WihApiVerifyTest(unittest.TestCase):
    def test_default_without_executor_is_pending_and_does_not_request(self):
        result = run_api_verify(
            [{"endpoint_id": "ep-1", "url": "https://example.test/api", "method": "GET"}]
        )
        self.assertEqual("pending", result["items"][0]["verification_status"])
        self.assertEqual("verify_executor_not_configured", result["items"][0]["verification_reason_codes"][0])

    def test_dangerous_methods_are_skipped_before_executor(self):
        called = []
        result = run_api_verify(
            [{"endpoint_id": "ep-1", "url": "https://example.test/api", "method": "DELETE"}],
            verify_fn=lambda item: called.append(item) or {"status_code": 200},
        )
        self.assertEqual([], called)
        self.assertEqual("skipped", result["items"][0]["verification_status"])

    def test_executor_result_is_reduced_to_safe_fields(self):
        result = run_api_verify(
            [{
                "endpoint_id": "ep-1",
                "url": "https://example.test/api?token=secret",
                "method": "GET",
                "token": "secret",
                "request_template": {"headers": {"Authorization": "Bearer secret"}, "body": "secret"},
            }],
            verify_fn=lambda item: {
                "status_code": 200,
                "response_size": 10,
                "response_body": "secret",
                "verification_reason_codes": ["ok"],
            },
        )
        serialized = json.dumps(result, ensure_ascii=False)
        self.assertNotIn("secret", serialized)
        self.assertEqual("verified_read", result["items"][0]["verification_status"])
        self.assertEqual(200, result["items"][0]["status_code"])

    def test_public_result_drops_nested_sensitive_keys_and_query_values(self):
        result = run_api_verify(
            [{
                "endpoint_id": "ep-1",
                "url": "https://example.test/api",
                "auth_token": "secret-auth",
                "query": {"name": "secret-query"},
                "metadata": {"password_hash": "secret-hash", "safe": "kept"},
            }]
        )
        serialized = json.dumps(result, ensure_ascii=False)
        self.assertNotIn("secret-auth", serialized)
        self.assertNotIn("secret-query", serialized)
        self.assertNotIn("secret-hash", serialized)
        self.assertIn("kept", serialized)

    def test_l2_uses_injected_auth_boundary_executor(self):
        result = run_api_verify(
            [{
                "endpoint_id": "ep-l2",
                "url": "https://example.test/private?token=secret",
                "method": "GET",
                "auth_profile": "anonymous",
                "verification_level": "L2",
            }],
            policy=MODULE.ControlledVerificationPolicy(l2_enabled=True),
            auth_boundary_fn=lambda _item: {
                "anonymous": {
                    "status_code": 200,
                    "content_type": "application/json",
                    "structure_hash": "same",
                    "body_length": 100,
                    "body": "secret",
                },
                "invalid_auth": {
                    "status_code": 200,
                    "content_type": "application/json",
                    "structure_hash": "same",
                    "body_length": 100,
                },
                "authorized": {
                    "status_code": 200,
                    "content_type": "application/json",
                    "structure_hash": "private",
                    "body_length": 200,
                },
            },
        )
        item = result["items"][0]
        self.assertEqual("auth_anomaly_candidate", item["verification_status"])
        self.assertTrue(item["manual_review_required"])
        self.assertNotIn("secret", json.dumps(result, ensure_ascii=False))

    def test_l2_without_executor_stays_pending(self):
        result = run_api_verify(
            [{
                "endpoint_id": "ep-l2",
                "url": "https://example.test/private",
                "method": "GET",
                "auth_profile": "anonymous",
                "verification_level": "L2",
            }],
            policy=MODULE.ControlledVerificationPolicy(l2_enabled=True),
        )
        self.assertEqual("pending", result["items"][0]["verification_status"])
        self.assertEqual(
            "auth_boundary_executor_not_configured",
            result["items"][0]["verification_reason_codes"][0],
        )

    def test_l1_executor_adapts_existing_probe_without_leaking_packet(self):
        with mock.patch.object(
            ENDPOINT_PROBE,
            "_probe_one",
            return_value={
                "verification_status": "probed",
                "status_code": 200,
                "response_size": 128,
                "verification_response_packet": "Authorization: secret",
            },
        ) as probe:
            executor = MODULE.build_l1_executor()
            result = run_api_verify(
                [{"endpoint_id": "ep-l1", "url": "https://example.test/api", "method": "GET"}],
                verify_fn=executor,
            )
        probe.assert_called_once()
        self.assertEqual("verified_read", result["items"][0]["verification_status"])
        self.assertEqual(200, result["items"][0]["status_code"])
        self.assertNotIn("Authorization", json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    unittest.main()
