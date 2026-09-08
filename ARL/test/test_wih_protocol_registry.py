"""计划 7 协议观察 Registry 测试。"""

import json
import sys
import unittest
from pathlib import Path


ARL_ROOT = Path(__file__).resolve().parents[1]
if str(ARL_ROOT) not in sys.path:
    sys.path.insert(0, str(ARL_ROOT))

from test._api_unified_bootstrap import load_modules  # noqa: E402


_BUNDLE = load_modules(
    "app.services.api_unified_models",
    "app.services.api_candidate_registry",
    "app.services.discovery_context",
    "app.services.wih_protocol_registry",
)
MODULE = _BUNDLE["app.services.wih_protocol_registry"]
API_REGISTRY = _BUNDLE["app.services.api_candidate_registry"]
DISCOVERY_CONTEXT = _BUNDLE["app.services.discovery_context"]


class WihProtocolRegistryTest(unittest.TestCase):
    def test_merges_observations_and_preserves_only_safe_metadata(self):
        registry = MODULE.ProtocolRegistry(allowed_hosts={"example.test"})
        result = MODULE.ingest_protocol_events(
            registry,
            [
                {
                    "url": "wss://example.test/socket?token=secret",
                    "protocol": "websocket",
                    "event": "handshake",
                    "source": "browser",
                    "operation": "subscribe",
                    "evidence_ids": ["ev-1"],
                },
                {
                    "url": "wss://example.test/socket?token=secret",
                    "protocol": "websocket",
                    "event": "handshake",
                    "source": "har",
                    "evidence_ids": ["ev-2"],
                },
            ],
        )
        self.assertEqual(
            {
                "created": 1,
                "merged": 1,
                "out_of_scope": 0,
                "capacity": 0,
                "skipped": 0,
            },
            result,
        )
        serialized = json.dumps(registry.snapshot(), ensure_ascii=False)
        self.assertNotIn("secret", serialized)
        self.assertIn("browser", serialized)
        self.assertIn("har", serialized)

    def test_scope_and_invalid_protocol_fail_closed(self):
        registry = MODULE.ProtocolRegistry(allowed_hosts={"example.test"})
        result = MODULE.ingest_protocol_events(
            registry,
            [
                {"url": "wss://other.test/socket", "protocol": "websocket"},
                {"url": "https://example.test/api", "protocol": "unknown"},
            ],
        )
        self.assertEqual(0, len(registry))
        self.assertEqual(1, result["out_of_scope"])
        self.assertEqual(1, result["skipped"])

    def test_unsupported_url_scheme_is_rejected(self):
        registry = MODULE.ProtocolRegistry(allowed_hosts={"example.test"})
        result = MODULE.ingest_protocol_events(
            registry,
            [{"url": "javascript:alert(1)", "protocol": "websocket"}],
        )
        self.assertEqual(0, len(registry))
        self.assertEqual(1, result["skipped"])

    def test_browser_runtime_events_flow_into_protocol_registry(self):
        context = DISCOVERY_CONTEXT.DiscoveryContext(
            task_id="protocol-runtime", allowed_hosts={"example.test"})
        registry = API_REGISTRY.ApiCandidateRegistry(
            task_id="protocol-runtime", context=context)
        created = API_REGISTRY.ingest_browser_runtime_events(
            registry,
            {"https://example.test": {"runtime_api_calls": [
                {"protocol": "websocket", "event": "handshake",
                 "url": "wss://example.test/socket?token=secret"},
                {"protocol": "websocket", "event": "frame_received",
                 "url": "wss://example.test/socket?token=secret"},
                {"protocol": "websocket", "event": "handshake",
                 "url": "wss://example.test/socket?token=secret",
                 "source": "har"},
            ]}},
        )
        self.assertEqual(0, created)
        observations = getattr(context, "protocol_registry").snapshot()
        self.assertEqual(2, len(observations))
        self.assertTrue(all(item["protocol"] == "websocket" for item in observations))
        self.assertNotIn("secret", json.dumps(observations, ensure_ascii=False))
        self.assertEqual(2, context.metrics.get("protocol_observation_created_total"))
        self.assertEqual(1, context.metrics.get("protocol_observation_merged_total"))

    def test_registry_bounds_observation_count_and_merged_sources(self):
        registry = MODULE.ProtocolRegistry(
            allowed_hosts={"example.test"}, max_observations=1
        )
        first = MODULE.ProtocolObservation(
            url="wss://example.test/socket",
            protocol="websocket",
            sources={"source-{:03d}".format(index) for index in range(80)},
            evidence_ids={"evidence-{:03d}".format(index) for index in range(80)},
        )
        registry.register(first)
        merged = MODULE.ProtocolObservation(
            url="wss://example.test/socket",
            protocol="websocket",
            source="later",
            evidence_ids={"later-evidence"},
        )
        registry.register(merged)
        _stored, outcome = registry.register(
            MODULE.ProtocolObservation(
                url="wss://example.test/other",
                protocol="websocket",
            )
        )
        self.assertEqual("capacity", outcome)
        self.assertEqual(1, len(registry))
        item = registry.snapshot()[0]
        self.assertLessEqual(len(item["sources"]), 32)
        self.assertLessEqual(len(item["evidence_ids"]), 32)


if __name__ == "__main__":
    unittest.main()
