"""统一资产关联阶段的边界测试。"""

import unittest
from unittest.mock import patch

from test._api_unified_bootstrap import load_modules


_captured = load_modules(
    "app.services.asset_pivot_stage_services",
    "app.services.domain_stage_services",
)
_service = _captured["app.services.asset_pivot_stage_services"]
_domain_stage_services = _captured["app.services.domain_stage_services"]
Config = _service.Config
UnifiedAssetDiscoveryStageService = _service.UnifiedAssetDiscoveryStageService
validate_domain_binding = _service.validate_domain_binding


class _Writer(object):
    def __init__(self):
        self.documents = []

    def upsert_one(self, collection, key, document):
        self.documents.append((collection, key, document))


class _ProviderResult(list):
    def __init__(self, values=None, metrics=None):
        super().__init__(values or [])
        self.metrics = metrics or {}


class _Task(object):
    task_id = "task-asset-pivot"

    def __init__(self):
        self.options = {"dns_query_plugin": True}
        self.ip_set = {"203.0.113.10"}
        self.ip_info_list = []
        self.cert_map = {}
        self.site_list = []
        self._result_writer = _Writer()
        self.ssl_cert_calls = 0

    def ssl_cert(self):
        self.ssl_cert_calls += 1


class _Port(object):
    def __init__(self, port_id):
        self.port_id = port_id


class _IPInfo(object):
    ip = "203.0.113.10"
    port_info_list = [_Port(443), _Port(8080)]


class _BruteDomain(object):
    def __init__(self, domain):
        self.domain = domain


class TestAssetPivotStageServices(unittest.TestCase):
    def test_provider_metrics_preserve_raw_and_unique_counts(self):
        task = _Task()
        resolver_calls = []
        provider_result = _ProviderResult(
            values=[
                {
                    "domain": "dedupe.example.com",
                    "source": "fofa",
                    "pivot_ip": "203.0.113.10",
                },
                {
                    "domain": "dedupe.example.com",
                    "source": "fofa",
                    "pivot_ip": "203.0.113.10",
                },
            ],
            metrics={
                "source_result_count": 4,
                "unique_result_count": 2,
                "failed_count": 1,
                "degraded_count": 1,
            }
        )

        with patch.object(_service, "run_query_plugin_by_ip", return_value=provider_result), \
                patch.object(_service, "run_query_plugin_by_cert", return_value=[]):
            old_enable = getattr(Config, "ASSET_DISCOVERY_DOMAIN_BRUTE_ENABLE", True)
            Config.ASSET_DISCOVERY_DOMAIN_BRUTE_ENABLE = False
            try:
                metrics = UnifiedAssetDiscoveryStageService(
                    task,
                    resolver=lambda domain: resolver_calls.append(domain)
                    or ["203.0.113.10"],
                ).run()
            finally:
                Config.ASSET_DISCOVERY_DOMAIN_BRUTE_ENABLE = old_enable

        self.assertEqual(4, metrics["provider_raw_results"])
        self.assertEqual(2, metrics["provider_unique_results"])
        self.assertEqual(1, metrics["provider_failed"])
        self.assertEqual(1, metrics["provider_degraded"])
        self.assertEqual(["dedupe.example.com"], resolver_calls)

    def test_binding_accepts_any_matching_a_or_aaaa_record(self):
        resolver = lambda domain: {
            "api.example.com": ["198.51.100.9", "203.0.113.10"],
        }.get(domain, [])

        result = validate_domain_binding(
            "api.example.com",
            pivot_ips=["203.0.113.10"],
            resolver=resolver,
        )

        self.assertEqual("accepted", result["status"])
        self.assertEqual(["203.0.113.10"], result["matched_ips"])

    def test_binding_keeps_dns_mismatch_as_evidence_only(self):
        result = validate_domain_binding(
            "drift.example.com",
            pivot_ips=["203.0.113.10"],
            resolver=lambda _domain: ["198.51.100.9"],
        )

        self.assertEqual("evidence_only", result["status"])
        self.assertEqual("dns_not_match_pivot_ip", result["reason"])

    def test_dns_failure_is_degraded_and_invalid_certificate_name_is_rejected(self):
        degraded = validate_domain_binding(
            "temporary.example.com",
            pivot_ips=["203.0.113.10"],
            resolver=lambda _domain: (_ for _ in ()).throw(OSError("resolver down")),
        )
        rejected = validate_domain_binding(
            "*.example.com",
            pivot_ips=["203.0.113.10"],
            resolver=lambda _domain: ["203.0.113.10"],
        )
        public_suffix = validate_domain_binding(
            "co.uk",
            pivot_ips=["203.0.113.10"],
            resolver=lambda _domain: ["203.0.113.10"],
        )
        private_suffix = validate_domain_binding(
            "github.io",
            pivot_ips=["203.0.113.10"],
            resolver=lambda _domain: ["203.0.113.10"],
        )

        self.assertEqual("degraded", degraded["status"])
        self.assertEqual("dns_error", degraded["reason"])
        self.assertEqual("rejected", rejected["status"])
        self.assertEqual("rejected", public_suffix["status"])
        self.assertEqual("rejected", private_suffix["status"])

    def test_ip_pivot_only_injects_dns_confirmed_domain_to_web_sites(self):
        task = _Task()
        task.ip_info_list = [_IPInfo()]
        resolver = lambda domain: (
            ["203.0.113.10"]
            if domain == "web.example.com"
            else ["198.51.100.9"]
        )
        provider_results = [
            {
                "domain": "web.example.com",
                "source": "fofa",
                "pivot_ip": "203.0.113.10",
            },
            {
                "domain": "drift.example.com",
                "source": "fofa",
                "pivot_ip": "203.0.113.10",
            },
        ]

        with patch.object(_service, "run_query_plugin_by_ip", return_value=provider_results), \
                patch.object(_service, "run_query_plugin_by_cert", return_value=[]), \
                patch.object(_service, "should_skip_cdn_waf", return_value=False):
            old_enable = getattr(Config, "ASSET_DISCOVERY_DOMAIN_BRUTE_ENABLE", True)
            Config.ASSET_DISCOVERY_DOMAIN_BRUTE_ENABLE = False
            try:
                metrics = UnifiedAssetDiscoveryStageService(
                    task,
                    resolver=resolver,
                ).run()
            finally:
                Config.ASSET_DISCOVERY_DOMAIN_BRUTE_ENABLE = old_enable

        self.assertEqual(1, metrics["new_domains"])
        self.assertEqual(1, metrics["evidence_only"])
        self.assertIn("https://web.example.com", task.site_list)
        self.assertIn("http://web.example.com:8080", task.site_list)
        self.assertNotIn("http://drift.example.com", task.site_list)
        self.assertGreaterEqual(task.ssl_cert_calls, 1)
        decisions = [
            item[2]["decision"]
            for item in task._result_writer.documents
            if item[0] == "asset_pivot_evidence"
        ]
        self.assertIn("accepted", decisions)
        self.assertIn("evidence_only", decisions)

    def test_evidence_key_keeps_provider_sources_separate(self):
        task = _Task()
        decision = {
            "domain": "shared.example.com",
            "status": "evidence_only",
            "reason": "dns_not_match_pivot_ip",
            "resolved_ips": ["198.51.100.9"],
            "matched_ips": [],
        }
        _service.write_pivot_evidence(
            task,
            candidate_type="domain",
            value="shared.example.com",
            source="fofa_ip_pivot",
            decision=decision,
            pivot_ip="203.0.113.10",
        )
        _service.write_pivot_evidence(
            task,
            candidate_type="domain",
            value="shared.example.com",
            source="hunter_ip_pivot",
            decision=decision,
            pivot_ip="203.0.113.10",
        )

        evidence = [
            item for item in task._result_writer.documents
            if item[0] == "asset_pivot_evidence"
        ]
        self.assertEqual(2, len(evidence))

    def test_ip_pivot_supports_runtime_dictionary_results(self):
        task = _Task()
        task.ip_info_list = [{
            "ip": "203.0.113.10",
            "port_info": [
                {"port_id": 443, "service_name": "https"},
                {"port_id": 8080, "service_name": "http"},
            ],
            "domain": [],
            "cdn_name": "",
        }]
        resolver = lambda _domain: ["203.0.113.10"]
        provider_results = [{
            "domain": "runtime.example.com",
            "source": "fofa",
            "pivot_ip": "203.0.113.10",
        }]

        with patch.object(_service, "run_query_plugin_by_ip", return_value=provider_results), \
                patch.object(_service, "run_query_plugin_by_cert", return_value=[]), \
                patch.object(_service, "should_skip_cdn_waf", return_value=False):
            old_enable = getattr(Config, "ASSET_DISCOVERY_DOMAIN_BRUTE_ENABLE", True)
            Config.ASSET_DISCOVERY_DOMAIN_BRUTE_ENABLE = False
            try:
                UnifiedAssetDiscoveryStageService(task, resolver=resolver).run()
            finally:
                Config.ASSET_DISCOVERY_DOMAIN_BRUTE_ENABLE = old_enable

        self.assertEqual(["runtime.example.com"], task.ip_info_list[0]["domain"])
        self.assertIn("https://runtime.example.com", task.site_list)
        self.assertIn("http://runtime.example.com:8080", task.site_list)

    def test_certificate_cn_san_is_used_after_source_ip_binding(self):
        task = _Task()
        task.options["dns_query_plugin"] = False
        task.ip_info_list = [_IPInfo()]
        task.cert_map = {
            "203.0.113.10:443": {
                "subject": {"common_name": "tls.example.com"},
                "extensions": {
                    "subjectAltName": "DNS:tls.example.com,DNS:*.example.com",
                },
                "_scan_meta": {"endpoint": "203.0.113.10:443"},
            }
        }
        resolver = lambda domain: (
            ["203.0.113.10"] if domain == "tls.example.com" else []
        )

        with patch.object(_service, "run_query_plugin_by_ip", return_value=[]) as ip_query, \
                patch.object(_service, "run_query_plugin_by_cert", return_value=[]) as cert_query, \
                patch.object(_service, "should_skip_cdn_waf", return_value=False):
            old_enable = getattr(Config, "ASSET_DISCOVERY_DOMAIN_BRUTE_ENABLE", True)
            Config.ASSET_DISCOVERY_DOMAIN_BRUTE_ENABLE = False
            try:
                metrics = UnifiedAssetDiscoveryStageService(
                    task,
                    resolver=resolver,
                ).run()
            finally:
                Config.ASSET_DISCOVERY_DOMAIN_BRUTE_ENABLE = old_enable

        self.assertEqual(1, metrics["new_domains"])
        self.assertIn("https://tls.example.com", task.site_list)
        self.assertNotIn("https://*.example.com", task.site_list)
        ip_query.assert_not_called()
        cert_query.assert_not_called()

    def test_certificate_provider_keeps_endpoint_and_certificate_identity(self):
        task = _Task()
        task.ip_info_list = [{
            "ip": "203.0.113.10",
            "port_info": [{"port_id": 443, "service_name": "https"}],
            "domain": [],
            "cdn_name": "",
        }]
        task.cert_map = {
            "203.0.113.10:443": {
                "serial_number": "ABC123",
                "subject": {"common_name": "source.example.com"},
                "extensions": {"subjectAltName": "DNS:source.example.com"},
                "_scan_meta": {"endpoint": "203.0.113.10:443"},
            }
        }
        provider_results = [{
            "domain": "pivot.example.com",
            "source": "hunter",
            "pivot_cert": "sn:ABC123",
        }]

        with patch.object(_service, "run_query_plugin_by_ip", return_value=[]), \
                patch.object(_service, "run_query_plugin_by_cert", return_value=provider_results), \
                patch.object(_service, "should_skip_cdn_waf", return_value=False):
            old_enable = getattr(Config, "ASSET_DISCOVERY_DOMAIN_BRUTE_ENABLE", True)
            Config.ASSET_DISCOVERY_DOMAIN_BRUTE_ENABLE = False
            try:
                metrics = UnifiedAssetDiscoveryStageService(
                    task,
                    resolver=lambda _domain: ["203.0.113.10"],
                ).run()
            finally:
                Config.ASSET_DISCOVERY_DOMAIN_BRUTE_ENABLE = old_enable

        self.assertEqual(2, metrics["new_domains"])
        evidence = [
            item[2] for item in task._result_writer.documents
            if item[0] == "asset_pivot_evidence"
            and item[2]["source"] == "hunter_cert_pivot"
        ]
        self.assertEqual(1, len(evidence))
        self.assertEqual("203.0.113.10:443", evidence[0]["pivot_endpoint"])
        self.assertEqual("sn:ABC123", evidence[0]["pivot_cert_key"])

    def test_provider_failure_degrades_stage_without_aborting(self):
        task = _Task()
        with patch.object(
            _service,
            "run_query_plugin_by_ip",
            side_effect=TimeoutError("provider timeout"),
        ), patch.object(_service, "run_query_plugin_by_cert", return_value=[]):
            old_enable = getattr(Config, "ASSET_DISCOVERY_DOMAIN_BRUTE_ENABLE", True)
            Config.ASSET_DISCOVERY_DOMAIN_BRUTE_ENABLE = False
            try:
                metrics = UnifiedAssetDiscoveryStageService(
                    task,
                    resolver=lambda _domain: [],
                ).run()
            finally:
                Config.ASSET_DISCOVERY_DOMAIN_BRUTE_ENABLE = old_enable

        self.assertEqual("partial", metrics["status"])
        self.assertEqual("provider_failed", metrics["end_reason"])
        self.assertEqual(1, metrics["provider_failed"])

    def test_confirmed_domain_runs_bounded_brute_and_rechecks_ip_binding(self):
        task = _Task()
        task.ip_info_list = [_IPInfo()]
        resolver_map = {
            "web.example.com": ["203.0.113.10"],
            "admin.example.com": ["203.0.113.10"],
            "drift.example.com": ["198.51.100.9"],
        }
        provider_results = [{
            "domain": "web.example.com",
            "source": "fofa",
            "pivot_ip": "203.0.113.10",
        }]

        with patch.object(_service, "run_query_plugin_by_ip", return_value=provider_results), \
                patch.object(_service, "run_query_plugin_by_cert", return_value=[]), \
                patch.object(_service, "should_skip_cdn_waf", return_value=False), \
                patch.object(
                    _domain_stage_services,
                    "domain_brute",
                    return_value=[
                        _BruteDomain("admin.example.com"),
                        _BruteDomain("drift.example.com"),
                    ],
                ) as brute:
            old_rounds = getattr(Config, "ASSET_DISCOVERY_MAX_ROUNDS", 3)
            try:
                Config.ASSET_DISCOVERY_MAX_ROUNDS = 1
                metrics = UnifiedAssetDiscoveryStageService(
                    task,
                    resolver=lambda domain: resolver_map.get(domain, []),
                ).run()
            finally:
                Config.ASSET_DISCOVERY_MAX_ROUNDS = old_rounds

        brute.assert_called_once()
        self.assertEqual(2, metrics["new_domains"])
        self.assertIn("https://admin.example.com", task.site_list)
        self.assertNotIn("https://drift.example.com", task.site_list)
        self.assertGreaterEqual(metrics["evidence_only"], 1)

    def test_multiple_rounds_do_not_repeat_provider_for_same_ip(self):
        task = _Task()
        task.ip_info_list = [_IPInfo()]
        provider_results = [{
            "domain": "once.example.com",
            "source": "fofa",
            "pivot_ip": "203.0.113.10",
        }]
        with patch.object(_service, "run_query_plugin_by_ip", return_value=provider_results) as ip_query, \
                patch.object(_service, "run_query_plugin_by_cert", return_value=[]), \
                patch.object(_service, "should_skip_cdn_waf", return_value=False):
            old_rounds = getattr(Config, "ASSET_DISCOVERY_MAX_ROUNDS", 3)
            old_enable = getattr(Config, "ASSET_DISCOVERY_DOMAIN_BRUTE_ENABLE", True)
            Config.ASSET_DISCOVERY_MAX_ROUNDS = 3
            Config.ASSET_DISCOVERY_DOMAIN_BRUTE_ENABLE = False
            try:
                metrics = UnifiedAssetDiscoveryStageService(
                    task,
                    resolver=lambda _domain: ["203.0.113.10"],
                ).run()
            finally:
                Config.ASSET_DISCOVERY_MAX_ROUNDS = old_rounds
                Config.ASSET_DISCOVERY_DOMAIN_BRUTE_ENABLE = old_enable

        ip_query.assert_called_once_with(
            ip_list=["203.0.113.10"],
            target_domain="",
            max_domains=int(Config.IP_PIVOT_QUERY_MAX_DOMAINS or 0),
        )
        self.assertEqual(2, metrics["rounds"])
        self.assertEqual([1, 0], metrics["round_new_domains"])


if __name__ == "__main__":
    unittest.main()
