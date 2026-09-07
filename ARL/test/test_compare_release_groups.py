import importlib.util
import json
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[2] / "scripts" / "compare-release-groups.py"
SPEC = importlib.util.spec_from_file_location("compare_release_groups", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def _target(index, suffix="same"):
    return {
        "target_id": "synthetic-target-{}".format(index),
        "terminal_status": "completed",
        "waf": {"api_doc": 0, "endpoint_probe": 0},
        "endpoints": [
            {
                "endpoint_key": "target-{}|rest|GET|/v1/items|{}".format(index, suffix),
                "url": "https://synthetic.invalid/v1/items",
                "method": "GET",
                "api_type": "rest",
                "status": "probed",
                "sources": ["synthetic"],
            }
        ],
    }


def _payload():
    targets = [_target(index) for index in range(40)]
    return {
        "schema_version": 1,
        "metadata": {
            "revision": "test-revision",
            "image_digest": "sha256:test-image",
            "config_fingerprint": "test-config",
            "target_set_sha256": "test-target-set",
        },
        "groups": {
            "legacy": {"targets": targets},
            "unified_shadow": {"targets": json.loads(json.dumps(targets))},
            "stage_gated_rust": {"targets": json.loads(json.dumps(targets))},
        },
        "allowed_legacy_missing": [],
    }


class CompareReleaseGroupsTest(unittest.TestCase):
    def test_three_equal_groups_pass(self):
        report = MODULE.compare_release_groups(_payload())

        self.assertTrue(report["ok"])
        self.assertEqual(40, report["groups"]["legacy"]["target_count"])
        self.assertEqual(0, report["shadow_vs_legacy"]["missing_count"])
        self.assertEqual(0, report["rust_vs_shadow"]["mismatch_count"])

    def test_shadow_missing_endpoint_requires_explicit_allowance(self):
        payload = _payload()
        removed = payload["groups"]["unified_shadow"]["targets"][0]["endpoints"].pop()
        payload["groups"]["stage_gated_rust"]["targets"][0]["endpoints"].pop()
        target_id_hash = MODULE._digest(payload["groups"]["legacy"]["targets"][0]["target_id"])
        endpoint_hash = MODULE._digest(MODULE._endpoint_record(removed, "legacy", target_id_hash))

        report = MODULE.compare_release_groups(payload)
        self.assertFalse(report["ok"])
        self.assertEqual(1, report["shadow_vs_legacy"]["missing_count"])

        payload["allowed_legacy_missing"] = [{
            "target_id_sha256": target_id_hash,
            "endpoint_sha256": endpoint_hash,
            "reason": "synthetic allowed evidence-only delta",
        }]
        report = MODULE.compare_release_groups(payload)
        self.assertTrue(report["ok"])
        self.assertEqual(1, report["shadow_vs_legacy"]["allowed_missing_count"])

    def test_rust_mismatch_fails_without_exposing_raw_target(self):
        payload = _payload()
        payload["groups"]["stage_gated_rust"]["targets"][0]["waf"]["endpoint_probe"] = 1

        report = MODULE.compare_release_groups(payload)
        rendered = json.dumps(report, ensure_ascii=False)

        self.assertFalse(report["ok"])
        self.assertEqual(1, report["rust_vs_shadow"]["mismatch_count"])
        self.assertNotIn("synthetic-target-0", rendered)
        self.assertNotIn("synthetic.invalid", rendered)

    def test_metadata_mismatch_is_a_gate_failure(self):
        payload = _payload()
        del payload["metadata"]["image_digest"]

        report = MODULE.compare_release_groups(payload)

        self.assertFalse(report["ok"])
        self.assertIn("metadata 缺少 image_digest", report["errors"])

    def test_export_without_endpoint_key_keeps_api_type_in_identity(self):
        target_hash = MODULE._digest("synthetic-target")
        rest = MODULE._endpoint_record(
            {
                "url": "https://synthetic.invalid/graphql",
                "method": "POST",
                "api_type": "rest",
                "status": "probed",
            },
            "legacy",
            target_hash,
        )
        graphql = MODULE._endpoint_record(
            {
                "url": "https://synthetic.invalid/graphql",
                "method": "POST",
                "api_type": "graphql",
                "status": "probed",
            },
            "shadow",
            target_hash,
        )

        self.assertNotEqual(rest["endpoint_key"], graphql["endpoint_key"])


if __name__ == "__main__":
    unittest.main()
