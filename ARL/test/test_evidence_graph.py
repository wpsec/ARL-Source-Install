"""计划 7 第一批 EvidenceGraph 契约测试。"""

import importlib.util
import json
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "app" / "services" / "evidence_graph.py"
SPEC = importlib.util.spec_from_file_location("plan7_evidence_graph", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class EvidenceGraphTest(unittest.TestCase):
    def test_nodes_merge_by_opaque_deterministic_id(self):
        graph = MODULE.EvidenceGraph()
        node_id = graph.add_node(
            "endpoint",
            "sensitive-internal-identity",
            sources=["api_document", "api_document"],
            attributes={"http_method": "GET", "status_code": 200, "ignored": "value"},
        )
        same_id = graph.add_node(
            "endpoint",
            "sensitive-internal-identity",
            sources=["browser_runtime"],
            attributes={"parser": "openapi"},
        )

        self.assertEqual(node_id, same_id)
        self.assertEqual(graph.node_count, 1)
        snapshot = graph.snapshot()
        self.assertEqual(snapshot["nodes"][0]["sources"], ["api_document", "browser_runtime"])
        self.assertEqual(snapshot["nodes"][0]["attributes"]["status_code"], "200")
        self.assertNotIn("sensitive-internal-identity", json.dumps(snapshot))

    def test_edges_are_idempotent_and_merge_evidence(self):
        graph = MODULE.EvidenceGraph()
        source = graph.add_node("page", "page-1")
        target = graph.add_node("endpoint", "endpoint-1")

        self.assertTrue(graph.add_edge(source, target, "contains", evidence=["html", "html"]))
        self.assertFalse(graph.add_edge(source, target, "contains", evidence=["runtime"]))
        self.assertEqual(graph.edge_count, 1)
        self.assertEqual(graph.snapshot()["edges"][0]["evidence"], ["html", "runtime"])

    def test_unknown_edge_endpoint_is_rejected(self):
        graph = MODULE.EvidenceGraph()
        node_id = graph.add_node("page", "page-1")

        with self.assertRaises(KeyError):
            graph.add_edge(node_id, "ev_missing", "contains")

    def test_sensitive_sources_are_opaque_and_sensitive_attributes_are_dropped(self):
        graph = MODULE.EvidenceGraph()
        node_id = graph.add_node(
            "observation",
            "identity-1",
            sources=["https://internal.invalid/path?token=secret-value"],
            attributes={"request_profile": "Authorization: Bearer secret-value", "transport": "https"},
        )

        output = json.dumps(graph.snapshot())
        self.assertNotIn("secret-value", output)
        self.assertNotIn("internal.invalid", output)
        self.assertEqual(graph.node_count, 1)
        self.assertTrue(node_id.startswith("ev_"))

    def test_node_and_edge_budgets_are_enforced(self):
        graph = MODULE.EvidenceGraph(max_nodes=1, max_edges=1)
        first = graph.add_node("page", "page-1")

        with self.assertRaises(OverflowError):
            graph.add_node("endpoint", "endpoint-2")
        self.assertEqual(graph.node_count, 1)
        self.assertEqual(first, graph.snapshot()["nodes"][0]["node_id"])

        edge_graph = MODULE.EvidenceGraph(max_nodes=2, max_edges=1)
        source = edge_graph.add_node("page", "page-1")
        target = edge_graph.add_node("endpoint", "endpoint-1")
        edge_graph.add_edge(source, target, "contains")
        with self.assertRaises(OverflowError):
            edge_graph.add_edge(target, source, "references")


if __name__ == "__main__":
    unittest.main()
