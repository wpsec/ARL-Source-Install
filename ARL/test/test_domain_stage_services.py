"""域名阶段服务的边界回归测试。"""

import sys
import types
import unittest
from unittest.mock import patch

from test._api_unified_bootstrap import load_modules


_captured = load_modules("app.services.domain_stage_services")
_domain_stage_services = _captured["app.services.domain_stage_services"]
Config = _domain_stage_services.Config
DomainDiscoveryStageService = _domain_stage_services.DomainDiscoveryStageService
DomainNetworkStageService = _domain_stage_services.DomainNetworkStageService
DomainPostProcessStageService = _domain_stage_services.DomainPostProcessStageService
DomainSiteStageService = _domain_stage_services.DomainSiteStageService


class _Executor(object):
    def __init__(self):
        self.names = []

    def execute(self, name, func, **kwargs):
        self.names.append(name)
        return func()


class _Task(object):
    def __init__(self, options=None):
        self.base_domain = "example.com"
        self.task_id = "task-1"
        self.task_tag = "monitor"
        self.options = options or {}
        self.domain_info_list = []
        self.discovery_context = None
        self._last_dns_query_metrics = {}
        self.executor = _Executor()
        self.calls = []

    def _get_stage_executor(self):
        return self.executor

    def update_task_field(self, field, value):
        self.calls.append(("update", field, value))

    def update_services(self, name, elapsed, metrics=None):
        self.calls.append(("service", name, metrics or {}))

    def domain_brute(self):
        self.calls.append("domain_brute")

    def build_single_domain_info(self, domain):
        self.calls.append(("build", domain))
        return "base-domain-info"

    def add_domain_source_map(self, values, source):
        self.calls.append(("source", source))

    def add_domain_source_names(self, values, source):
        self.calls.append(("source_names", source))

    def build_domain_info(self, domains):
        self.calls.append(("build_domains", sorted(domains)))
        return []

    def clear_domain_info_by_record(self, values):
        self.calls.append("clear_domain_info")
        return values

    def save_domain_info_list(self, values, source=None):
        self.calls.append(("save_domain", source))

    def dns_query_plugin(self):
        self.calls.append("dns_query_plugin")

    def arl_search(self):
        self.calls.append("arl_search")

    def alt_dns(self):
        self.calls.append("alt_dns")

    def gen_ipv4_map(self):
        self.calls.append("gen_ipv4_map")

    def port_scan(self):
        self.calls.append("port_scan")

    def ssl_cert(self):
        self.calls.append("ssl_cert")

    def save_ip_info(self):
        self.calls.append("save_ip_info")

    def _enable_protocol_detection(self):
        return False

    def save_service_info(self):
        self.calls.append("save_service_info")

    def find_vhost_vuln(self):
        self.calls.append("find_vhost_vuln")


class TestDomainStageServices(unittest.TestCase):
    def test_discovery_service_owns_discovery_stage_order(self):
        task = _Task({"domain_brute": True, "dns_query_plugin": True, "arl_search": True, "alt_dns": True})

        with patch.object(
            DomainDiscoveryStageService,
            "run_dns_query_plugin",
            side_effect=lambda: task.calls.append("dns_query_plugin"),
        ):
            DomainDiscoveryStageService(task).run()

        self.assertEqual(
            ["domain_brute", "dns_query_plugin", "arl_search", "alt_dns"],
            [item for item in task.calls if isinstance(item, str)],
        )
        self.assertEqual(
            [("update", "status", "dns_query_plugin")],
            [item for item in task.calls if item == ("update", "status", "dns_query_plugin")],
        )
        self.assertEqual(["domain_brute", "dns_query_plugin", "arl_search", "alt_dns"], [
            item[1] for item in task.calls if isinstance(item, tuple) and item[0] == "service"
        ])

    def test_dns_query_service_preserves_metrics_sources_and_candidates(self):
        task = _Task({"dns_query_plugin": True})
        task.task_tag = "task"
        task.domain_source_map = {}
        task._resolve_dns_query_sources = lambda: ["fofa", "hunter_how"]

        class _DomainInfo(object):
            def __init__(self, domain):
                self.domain = domain

        class _Plugin(object):
            def __init__(self, source_name):
                self.source_name = source_name

        class _QueryResults(list):
            def __init__(self, values, metrics):
                super().__init__(values)
                self.metrics = metrics

        class _Context(object):
            def __init__(self):
                self.events = []

            def register_candidate(self, **kwargs):
                self.events.append(kwargs)

        context = _Context()
        task.discovery_context = context
        task.build_domain_info = lambda domains: [_DomainInfo(domain) for domain in domains]
        task.clear_domain_info_by_record = lambda values: values

        query_calls = []

        def run_query(_target, sources):
            query_calls.append(list(sources))
            metrics = {
                "input_count": len(sources),
                "output_count": 2 if sources == ["fofa"] else 1,
                "provider_count": len(sources),
                "provider_success_count": len(sources),
                "request_count": len(sources),
                "network_wait_sec": 0.125,
                "provider_status": [{"source": sources[0], "status": "success"}],
            }
            values = [
                {"domain": "a.example.com", "source": "fofa"},
                {"domain": "b.example.com", "source": "fofa"},
            ] if sources == ["fofa"] else [
                {"domain": "a.example.com", "source": "hunter_how"},
            ]
            return _QueryResults(values, metrics)

        def add_source_names(values, source):
            task.calls.append(("source_names", source))
            for value in values:
                domain = getattr(value, "domain", value)
                task.domain_source_map.setdefault(domain, set()).add(source)

        task.add_domain_source_names = add_source_names
        task.save_domain_info_list = lambda values, source=None: task.calls.append(
            ("save_domain", source, len(values))
        )

        class _NoopStageContext(object):
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        with patch.object(
            _domain_stage_services.utils,
            "load_query_plugins",
            return_value=[_Plugin("fofa"), _Plugin("hunter_how")],
        ), patch.object(
            _domain_stage_services,
            "run_query_plugin",
            side_effect=run_query,
        ), patch.object(
            _domain_stage_services,
            "stage_execution_context",
            return_value=_NoopStageContext(),
        ), patch.object(
            Config,
            "DOMAIN_DNS_QUERY_PLUGIN_SOURCE_BATCH_SIZE",
            1,
        ), patch.object(
            Config,
            "DNS_QUERY_PLUGIN_DOMAIN_BATCH_SIZE",
            100,
        ), patch.object(
            Config,
            "DNS_QUERY_PLUGIN_STAGE_TIMEOUT_SEC",
            0,
        ), patch.object(
            Config,
            "DNS_QUERY_PLUGIN_STAGE_TIMEOUT_PER_SOURCE_SEC",
            0,
        ):
            DomainDiscoveryStageService(task).run_dns_query_plugin()

        self.assertEqual([["fofa"], ["hunter_how"]], query_calls)
        self.assertEqual(
            {"a.example.com": {"fofa", "hunter_how"}, "b.example.com": {"fofa"}},
            task.domain_source_map,
        )
        self.assertEqual(2, len(task.domain_info_list))
        self.assertEqual(3, len(context.events))
        self.assertEqual(
            {"a.example.com", "b.example.com"},
            {event["candidate"] for event in context.events},
        )
        self.assertEqual(3, task._last_dns_query_metrics["output_count"])
        self.assertEqual(2, task._last_dns_query_metrics["unique_domain_count"])
        self.assertEqual(1, task._last_dns_query_metrics["domain_dedup_count"])
        self.assertEqual(0.25, task._last_dns_query_metrics["network_wait_sec"])

    def test_dns_query_source_resolver_filters_disabled_and_incomplete_sources(self):
        task = _Task()

        class _Plugin(object):
            def __init__(self, source_name):
                self.source_name = source_name

        with patch.object(
            _domain_stage_services.utils,
            "load_query_plugins",
            return_value=[
                _Plugin("fofa"),
                _Plugin("hunter_how"),
                _Plugin("shodan"),
                _Plugin("shodan"),
                _Plugin(""),
            ],
        ), patch.object(
            Config,
            "QUERY_PLUGIN_CONFIG",
            {
                "fofa": {"enable": False},
                "hunter_how": {"api_key": ""},
                "shodan": {"enable": True},
            },
        ):
            sources = DomainDiscoveryStageService(task)._resolve_dns_query_sources()

        self.assertEqual(["shodan"], sources)

    def test_dns_query_service_prefers_task_query_compat_hook(self):
        task = _Task({"dns_query_plugin": True})
        task._resolve_dns_query_sources = lambda: ["fofa"]
        calls = []

        class _QueryResults(list):
            metrics = {}

        def run_query_compat(target, sources):
            calls.append((target, list(sources)))
            return _QueryResults()

        task._run_query_plugin = run_query_compat
        with patch.object(
            _domain_stage_services,
            "run_query_plugin",
            side_effect=AssertionError("must use task compatibility hook"),
        ):
            DomainDiscoveryStageService(task).run_dns_query_plugin()

        self.assertEqual([("example.com", ["fofa"])], calls)

    def test_dns_query_service_preserves_timeout_context_and_exception(self):
        task = _Task({"dns_query_plugin": True})
        task._resolve_dns_query_sources = lambda: ["fofa", "hunter_how"]
        task._calc_dns_query_plugin_stage_timeout = lambda count: count + 10

        class _StageContext(object):
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        with patch.object(
            _domain_stage_services,
            "stage_execution_context",
            return_value=_StageContext(),
        ) as stage_context, patch.object(
            _domain_stage_services,
            "run_query_plugin",
            side_effect=RuntimeError("provider failed"),
        ):
            with self.assertRaises(RuntimeError):
                DomainDiscoveryStageService(task).run_dns_query_plugin()

        stage_context.assert_called_once_with("dns_query_plugin", 12)
        self.assertEqual({}, task._last_dns_query_metrics)

    def test_discovery_service_owns_search_engine_stage_and_page_context(self):
        task = _Task({"search_engines": True})
        inserted = []
        events = []

        class _SearchResults(list):
            metrics = {"provider_status": "success", "request_count": 1}

        class _Context(object):
            def register_candidate(self, **kwargs):
                events.append(kwargs)

        class _Collection(object):
            def insert_one(self, item):
                inserted.append(item)

        task.discovery_context = _Context()
        search_results = _SearchResults([
            "https://example.com/api/list",
            "https://sub.example.com/",
            "https://outside.example.net/ignored",
        ])
        fake_common_task = types.ModuleType("app.services.commonTask")
        fake_common_task.build_url_item = (
            lambda site, task_id, source: {
                "site": site,
                "task_id": task_id,
                "source": source,
            }
        )
        with patch.dict(
            sys.modules,
            {"app.services.commonTask": fake_common_task},
        ), patch.object(
            _domain_stage_services,
            "search_engines",
            return_value=search_results,
        ), patch.object(
            _domain_stage_services.services,
            "page_fetch",
            return_value={"https://example.com/api/list": {"status": 200}},
            create=True,
        ) as page_fetch, patch.object(
            _domain_stage_services.utils,
            "conn_db",
            return_value=_Collection(),
        ):
            DomainDiscoveryStageService(task).run_search_engines()

        self.assertEqual("search_engines", task.calls[0][2])
        self.assertEqual(
            [("build_domains", ["example.com", "sub.example.com"])],
            [item for item in task.calls if isinstance(item, tuple) and item[0] == "build_domains"],
        )
        page_fetch.assert_called_once_with(
            {"https://example.com/api/list"},
            discovery_context=task.discovery_context,
            traffic_class="crawler",
        )
        self.assertEqual(1, len(events))
        self.assertEqual("fetched", events[0]["status"])
        self.assertEqual(1, len(inserted))
        self.assertEqual("https://example.com/api/list", inserted[0]["site"])
        self.assertEqual(
            {"provider_status": "success", "request_count": 1},
            next(item[2] for item in task.calls if isinstance(item, tuple) and item[0] == "service"),
        )

    def test_network_service_keeps_port_and_certificate_as_separate_stages(self):
        task = _Task({"port_scan": True, "ssl_cert": True})
        with patch.object(Config, "CERT_PIVOT_QUERY_ENABLE", False):
            DomainNetworkStageService(task).run()

        self.assertEqual(["port_scan", "ssl_cert"], task.executor.names)
        self.assertEqual(["gen_ipv4_map", "port_scan", "ssl_cert", "save_ip_info"], task.calls)

    def test_post_process_service_does_not_run_disabled_stages(self):
        task = _Task({})

        DomainPostProcessStageService(task).run_poc()
        DomainPostProcessStageService(task).run_find_vhost()

        self.assertEqual([], task.calls)
        self.assertEqual([], task.executor.names)

    def test_site_service_marks_host_owned_terminal_finalize(self):
        # Review P0.4：域名深度流程的站点实例由宿主统一收尾，嵌套层不得二次执行。
        task = _Task()
        task.task_id = "65f0000000000000000000aa"
        task.site_list = ["https://www.example.com"]
        task.find_site = lambda: task.calls.append("find_site")

        class _FakeSiteFetch(object):
            instances = []

            def __init__(self, task_id=None, sites=None, options=None, scope_domain=None):
                self.scope_domain = scope_domain
                self.wih_domain_set = set()
                self.flag_at_run = None
                _FakeSiteFetch.instances.append(self)

            def run(self):
                self.flag_at_run = getattr(self, "terminal_finalize_host_owned", False)

        try:
            fake_common_task = types.ModuleType("app.services.commonTask")
            fake_common_task.WebSiteFetch = _FakeSiteFetch
            with patch.dict(sys.modules, {"app.services.commonTask": fake_common_task}):
                DomainSiteStageService(task).run()
            self.assertEqual(1, len(_FakeSiteFetch.instances))
            self.assertTrue(
                _FakeSiteFetch.instances[0].flag_at_run,
                "WebSiteFetch.run 之前必须已置位终态归属",
            )
            self.assertEqual([task.base_domain], _FakeSiteFetch.instances[0].scope_domain)
        finally:
            _FakeSiteFetch.instances = []


if __name__ == "__main__":
    unittest.main()
