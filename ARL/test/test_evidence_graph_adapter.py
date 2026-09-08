"""计划 7 EvidenceGraph 与既有 Registry 的适配测试。"""

import importlib.util
import json
import sys
import types
import unittest
from pathlib import Path


ARL_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_NAME = "plan7_evidence_graph_adapter"
PACKAGE = types.ModuleType(PACKAGE_NAME)
PACKAGE.__path__ = []
sys.modules[PACKAGE_NAME] = PACKAGE
GRAPH_SPEC = importlib.util.spec_from_file_location(
    PACKAGE_NAME + ".evidence_graph", ARL_ROOT / "app" / "services" / "evidence_graph.py"
)
GRAPH_MODULE = importlib.util.module_from_spec(GRAPH_SPEC)
sys.modules[GRAPH_SPEC.name] = GRAPH_MODULE
GRAPH_SPEC.loader.exec_module(GRAPH_MODULE)

ADAPTER_SPEC = importlib.util.spec_from_file_location(
    PACKAGE_NAME + ".adapter", ARL_ROOT / "app" / "services" / "evidence_graph_adapter.py"
)
ADAPTER_MODULE = importlib.util.module_from_spec(ADAPTER_SPEC)
sys.modules[ADAPTER_SPEC.name] = ADAPTER_MODULE
ADAPTER_SPEC.loader.exec_module(ADAPTER_MODULE)


class _Candidate:
    def __init__(self, key, value, candidate_type, parent_target=""):
        self.candidate_key = key
        self.candidate = value
        self.candidate_type = candidate_type
        self.parent_target = parent_target
        self.status = "discovered"
        self.request_profile = "default"
        self.sources = {"page_intel", "page_intel"}
        self.metadata = {"method": "GET", "confidence": 70}


class _CandidateRegistry:
    def __init__(self, values):
        self._values = values

    def values(self):
        return list(self._values)


class _ApiRegistry:
    def snapshot_documents(self):
        return [
            {
                "url": "document-1",
                "status": "discovered",
                "source": "js_intel",
                "type_hint": "openapi",
                "parent_target": "target-1",
            }
        ]

    def snapshot_endpoints(self):
        return [
            {
                "endpoint_id": "endpoint-id-1",
                "url": "endpoint-1",
                "method": "GET",
                "api_type": "rest",
                "status": "covered",
                "confidence": 90,
                "source": "api_unified",
                "parent_document": "document-1",
                "parent_target": "target-1",
            }
        ]


class _RichApiRegistry(_ApiRegistry):
    def snapshot_documents(self):
        return []

    def snapshot_endpoints(self):
        return [
            {
                "endpoint_id": "endpoint-rich",
                "url": "endpoint-rich",
                "method": "GET",
                "api_type": "graphql",
                "status": "covered",
                "confidence": 90,
                "source": "browser",
                "auth_hint": "bearer",
                "manual_review_required": True,
                "path_template": "/users/{id}",
                "operation_id": "getUser",
                "evidence_ids": ["runtime-observation-1"],
                "parameters": [
                    {"name": "userId", "location": "query", "type_summary": "string"},
                ],
            }
        ]

class _ResponseRegistry:
    def snapshot_metadata(self):
        return [
            {
                "normalized_url": "endpoint-1",
                "method": "GET",
                "request_profile": "html_get",
                "status_code": 200,
                "content_type": "text/html",
                "source": "page_intel",
                "consumers": ["urlfinder"],
            }
        ]

class _Context:
    def __init__(self):
        self.candidate_registry = _CandidateRegistry(
            [_Candidate("candidate-key-1", "endpoint-1", "endpoint", "target-1")]
        )
        self.api_candidate_registry = _ApiRegistry()
        self.response_registry = _ResponseRegistry()
        self.metrics = {}

    def record_metric(self, name, amount=1):
        self.metrics[name] = int(self.metrics.get(name, 0) or 0) + int(amount or 0)


class EvidenceGraphAdapterTest(unittest.TestCase):
    def test_sync_is_idempotent_and_merges_registry_sources(self):
        context = _Context()
        graph = ADAPTER_MODULE.get_or_create_evidence_graph(context)

        first = ADAPTER_MODULE.sync_discovery_context(context, graph=graph)
        second = ADAPTER_MODULE.sync_discovery_context(context, graph=graph)

        self.assertEqual(first["skipped"], 0)
        self.assertEqual(second["skipped"], 0)
        self.assertEqual(graph.node_count, 5)
        self.assertEqual(graph.edge_count, 5)
        self.assertEqual(context.metrics["evidence_graph_sync_total"], 2)
        self.assertGreater(context.metrics["evidence_graph_node_sync_total"], 0)

    def test_snapshot_never_contains_candidate_or_registry_raw_identity(self):
        context = _Context()
        graph = ADAPTER_MODULE.sync_discovery_context(context)
        serialized = json.dumps(context.evidence_graph.snapshot(), ensure_ascii=True)

        self.assertNotIn("candidate-key-1", serialized)
        self.assertNotIn("endpoint-id-1", serialized)
        self.assertNotIn("document-1", serialized)
        self.assertNotIn("endpoint-1", serialized)
        self.assertNotIn("endpoint-1", serialized)
        self.assertEqual(graph["skipped"], 0)

    def test_graph_budget_is_soft_for_scan_pipeline(self):
        context = _Context()
        graph = GRAPH_MODULE.EvidenceGraph(max_nodes=1, max_edges=1)

        summary = ADAPTER_MODULE.sync_discovery_context(context, graph=graph)

        self.assertGreater(summary["skipped"], 0)
        self.assertLessEqual(graph.node_count, 1)

    def test_missing_registry_is_a_safe_noop(self):
        context = types.SimpleNamespace()

        summary = ADAPTER_MODULE.sync_discovery_context(context)

        self.assertEqual(summary, {"nodes_added": 0, "edges_added": 0, "skipped": 0})

    def test_endpoint_details_become_parameter_and_auth_edges(self):
        context = _Context()
        context.api_candidate_registry = _RichApiRegistry()
        graph = ADAPTER_MODULE.sync_discovery_context(context)
        snapshot = context.evidence_graph.snapshot()
        kinds = {node["kind"] for node in snapshot["nodes"]}
        relations = {edge["relation"] for edge in snapshot["edges"]}

        self.assertEqual(0, graph["skipped"])
        self.assertIn("parameter", kinds)
        self.assertIn("identity", kinds)
        self.assertIn("has_parameter", relations)
        self.assertIn("auth_boundary", relations)
        self.assertIn("calls", relations)
        self.assertIn("references", relations)

    def test_document_relation_uses_graph_contract_name(self):
        context = _Context()
        graph = ADAPTER_MODULE.sync_discovery_context(context)
        relations = {edge["relation"] for edge in context.evidence_graph.snapshot()["edges"]}

        self.assertEqual(0, graph["skipped"])
        self.assertIn("documents", relations)
        self.assertNotIn("describes", relations)

    def test_page_candidate_is_recorded_as_endpoint_caller(self):
        context = _Context()
        context.candidate_registry._values[0].candidate_type = "page"
        graph = ADAPTER_MODULE.sync_discovery_context(context)
        relations = {edge["relation"] for edge in context.evidence_graph.snapshot()["edges"]}

        self.assertEqual(0, graph["skipped"])
        self.assertIn("calls", relations)

    def test_endpoint_candidate_is_not_treated_as_endpoint_caller(self):
        context = _Context()
        context.candidate_registry._values[0].candidate = "endpoint-rich"
        context.api_candidate_registry = _RichApiRegistry()
        ADAPTER_MODULE.sync_discovery_context(context)
        snapshot = context.evidence_graph.snapshot()
        node_kinds = {node["node_id"]: node["kind"] for node in snapshot["nodes"]}

        for edge in snapshot["edges"]:
            if edge["relation"] == "calls":
                self.assertNotEqual("endpoint", node_kinds[edge["source_id"]])

    def test_protocol_registry_becomes_safe_protocol_nodes(self):
        context = _Context()
        context.protocol_registry = types.SimpleNamespace(snapshot=lambda: [{
            "protocol_id": "protocol-id-1",
            "protocol": "websocket",
            "url": "wss://example.test/socket?token=secret",
            "host": "example.test",
            "event": "handshake",
            "status": "observed",
            "confidence": 75,
            "sources": ["browser"],
        }])
        graph = ADAPTER_MODULE.sync_discovery_context(context)
        snapshot = context.evidence_graph.snapshot()
        self.assertEqual(0, graph["skipped"])
        self.assertIn("protocol", {node["kind"] for node in snapshot["nodes"]})
        self.assertIn("observes", {edge["relation"] for edge in snapshot["edges"]})
        self.assertNotIn("secret", json.dumps(snapshot, ensure_ascii=False))


if __name__ == "__main__":
    unittest.main()
