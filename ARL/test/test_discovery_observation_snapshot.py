"""DiscoveryContext 证据图诊断摘要测试。"""

import importlib.util
import sys
import types
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "app" / "services" / "discovery_context.py"
SPEC = importlib.util.spec_from_file_location("plan7_discovery_context_observation", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class DiscoveryObservationSnapshotTest(unittest.TestCase):
    def test_graph_counts_are_diagnostic_only(self):
        context = MODULE.DiscoveryContext("task-observation")
        context.evidence_graph = types.SimpleNamespace(node_count=3, edge_count=2)

        snapshot = context.observation_snapshot()

        self.assertEqual(snapshot["evidence_graph"], {"nodes": 3, "edges": 2})
        self.assertEqual(snapshot["task_id"], "task-observation")
        self.assertNotIn("nodes", snapshot)
        self.assertNotIn("edges", snapshot)


if __name__ == "__main__":
    unittest.main()
