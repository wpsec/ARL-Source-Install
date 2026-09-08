"""ResponseRegistry 诊断摘要契约测试。"""

import importlib.util
import json
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "app" / "services" / "discovery_context.py"
SPEC = importlib.util.spec_from_file_location("plan7_discovery_context_snapshot", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class ResponseRegistrySnapshotTest(unittest.TestCase):
    def test_metadata_snapshot_excludes_body_and_headers(self):
        registry = MODULE.ResponseRegistry()
        registry.put(
            "resource-1",
            method="GET",
            request_profile="html_get",
            status_code=200,
            headers={"X-Debug": "header-marker"},
            content_type="text/html",
            body="private-marker",
            source="page_intel",
            consumer="urlfinder",
        )

        snapshot = registry.snapshot_metadata()
        serialized = json.dumps(snapshot)

        self.assertEqual(len(snapshot), 1)
        self.assertEqual(snapshot[0]["status_code"], 200)
        self.assertEqual(snapshot[0]["consumers"], ["urlfinder"])
        self.assertNotIn("private-marker", serialized)
        self.assertNotIn("header-marker", serialized)
        self.assertIn("body_hash", snapshot[0])

    def test_metadata_snapshot_respects_registry_bound(self):
        registry = MODULE.ResponseRegistry(max_entries=1)
        registry.put("resource-1", body="first")
        registry.put("resource-2", body="second")

        snapshot = registry.snapshot_metadata()

        self.assertEqual(len(snapshot), 1)
        self.assertEqual(snapshot[0]["normalized_url"], "resource-2")


if __name__ == "__main__":
    unittest.main()
