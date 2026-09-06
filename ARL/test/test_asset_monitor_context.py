"""资产监控入口接入任务级发现上下文的回归(报告§4 前置3)。

监控器模块依赖重(app.services 包级导入拉 Mongo/NPoC),这里用假模块注入门面:
- AssetWihMonitor: 验证每轮 run 创建 monitor|scope|run 前缀的 DiscoveryContext,
  并贯穿传给 5 个可编排阶段;run_wih/trufflehog 不接(外部进程边界)。
- AssetSiteCompare: 验证站点抓取走 fetch_text+context,同站点二次比对只发一次
  真实请求(任务内响应复用)。
"""

import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

ARL_ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ARL_ROOT / "app"
SERVICES_DIR = APP_DIR / "services"

if str(ARL_ROOT) not in sys.path:
    sys.path.insert(0, str(ARL_ROOT))



# 测试卫生（计划 1 收敛项）：本文件在模块顶层向 sys.modules 注入 fake 包槽位且
# 旧版无还原，单文件独立运行后会把 fake 留给同进程后续用例（合跑顺序敏感）。
# 统一在守卫/钩子处快照并还原共享父槽位；子模块缓存（真实实现）按 bootstrap
# 理念保留。
_HYGIENE_SHARED_SLOTS = (
    "app", "app.utils", "app.config", "app.modules",
    "app.services", "app.services.fingerprints", "app.tools",
)
_HYGIENE_PRE = {n: sys.modules.get(n) for n in _HYGIENE_SHARED_SLOTS}


def tearDownModule():
    for _name, _original in _HYGIENE_PRE.items():
        if _original is None:
            sys.modules.pop(_name, None)
        else:
            sys.modules[_name] = _original

def _bootstrap_packages():
    """__path__ 桩包:绕开 app.services/__init__ 的重依赖链,只加载纯 stdlib 子模块。"""

    app = sys.modules.get("app")
    if app is None or not getattr(app, "__path__", None):
        app = types.ModuleType("app")
        app.__path__ = [str(APP_DIR)]
        sys.modules["app"] = app
    services = sys.modules.get("app.services")
    if services is None or not getattr(services, "__path__", None):
        services = types.ModuleType("app.services")
        services.__path__ = [str(SERVICES_DIR)]
        sys.modules["app.services"] = services


_bootstrap_packages()

from app import utils as _real_utils  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "app.services.discovery_context", SERVICES_DIR / "discovery_context.py"
)
_discovery_module = importlib.util.module_from_spec(_spec)
sys.modules["app.services.discovery_context"] = _discovery_module
_spec.loader.exec_module(_discovery_module)
DiscoveryContext = _discovery_module.DiscoveryContext


def _module_from_service(name: str):
    sys.modules.pop("app.services.{}".format(name), None)
    path = SERVICES_DIR / "{}.py".format(name)
    spec = importlib.util.spec_from_file_location("app.services.{}".format(name), path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["app.services.{}".format(name)] = module
    spec.loader.exec_module(module)
    return module


class _FakeDb(object):
    def __init__(self):
        self.inserted = []

    def find_one(self, *_args, **_kwargs):
        return None

    def insert_one(self, item):
        self.inserted.append(item)


class AssetWihMonitorContextTest(unittest.TestCase):
    def setUp(self):
        self.saved = {}
        app_pkg = sys.modules.get("app")
        if app_pkg is None or not getattr(app_pkg, "__path__", None):
            app_pkg = types.ModuleType("app")
            app_pkg.__path__ = [str(APP_DIR)]
        from app import utils as real_utils

        # 只覆盖必要属性并还原;对 fake 桩只回滚自己新增的属性,不删既有内容。
        self._utils_backup = {}

        def _patch_utils(name, value):
            had = name in vars(real_utils)
            self._utils_backup[name] = (had, getattr(real_utils, name, None))
            setattr(real_utils, name, value)

        _patch_utils("check_domain_black", lambda domain: False)
        _patch_utils("curr_date_obj", lambda: None)
        self.dbs = {}
        _patch_utils("conn_db", lambda name: self.dbs.setdefault(name, _FakeDb()))
        _patch_utils("get_logger", lambda: mock.MagicMock())

        helpers = types.ModuleType("app.helpers")
        asset_site = types.ModuleType("app.helpers.asset_site")
        asset_site.find_site_by_scope_id = lambda scope_id: [
            "https://a.example.com",
            "https://b.example.com",
        ]
        asset_wih = types.ModuleType("app.helpers.asset_wih")
        asset_wih.get_wih_record_fnv_hash = lambda scope_id: set()
        scope_mod = types.ModuleType("app.helpers.scope")
        scope_mod.get_scope_by_scope_id = lambda scope_id: {
            "name": "demo",
            "scope_type": "domain",
            "scope_array": ["example.com"],
        }
        app_pkg.helpers = helpers
        helpers.asset_site = asset_site
        helpers.asset_wih = asset_wih
        helpers.scope = scope_mod

        services_pkg = types.ModuleType("app.services")
        services_pkg.__path__ = [str(SERVICES_DIR)]
        self.stage_calls = {}

        def _stage(name, default=()):
            def _run(sites, records=None, waf_guard=None, discovery_context=None):
                self.stage_calls[name] = discovery_context
                self.contexts.append(discovery_context)
                return list(default)

            return _run

        self.contexts = []
        services_pkg.run_wih = lambda sites: []  # Go 边界:无 ctx 参数
        services_pkg.run_urlfinder_extract = _stage("urlfinder_extract")
        services_pkg.run_page_intel_scan = _stage("page_intel")
        services_pkg.run_api_doc_scan = _stage("api_doc")
        services_pkg.run_js_intel_scan = _stage("js_intel")
        services_pkg.run_urlfinder_sensitive_scan = _stage("urlfinder_sensitive")
        services_pkg.run_trufflehog_js = lambda sites, records, waf_guard=None: []
        # 第 8 批统一入口两符号（flag-off 默认：监控走 legacy 顺序）。
        services_pkg.api_unified_enabled = lambda: False
        services_pkg.run_api_document_pipeline = _stage("api_doc_unified")

        info_hunter = types.ModuleType("app.services.infoHunter")

        class _InfoHunter(object):
            @staticmethod
            def normalize_wih_record(value):
                return value

        info_hunter.InfoHunter = _InfoHunter
        # asset_wih_monitor 现为子模块直导（第 10 批 hygiene 修复：包级 re-export
        # 直绑在轻环境/收集期交错下必炸）：为每个被直导的子模块建 stub 并复用
        # services_pkg 上已定义的 stage 桩，_swap 统一登记还原。
        info_hunter.run_wih = services_pkg.run_wih
        _stage_stubs = {
            "app.services.api_candidate_registry": ("api_unified_enabled", "run_api_document_pipeline"),
            "app.services.api_doc_scan": ("run_api_doc_scan",),
            "app.services.js_intel_scan": ("run_js_intel_scan",),
            "app.services.page_intel_scan": ("run_page_intel_scan",),
            "app.services.trufflehog_scan": ("run_trufflehog_js",),
            "app.services.urlfinder_extract": ("run_urlfinder_extract",),
            "app.services.urlfinder_sensitive_scan": ("run_urlfinder_sensitive_scan",),
        }
        for _mod_name, _attrs in _stage_stubs.items():
            _stub = types.ModuleType(_mod_name)
            for _attr in _attrs:
                setattr(_stub, _attr, getattr(services_pkg, _attr))
            self._swap({_mod_name: _stub})
        services_pkg.infoHunter = info_hunter

        wih_record_mod = types.ModuleType("app.modules")

        class _WihRecord(object):
            pass

        wih_record_mod.WihRecord = _WihRecord

        self._swap({
            "app": app_pkg,
            "app.helpers": helpers,
            "app.helpers.asset_site": asset_site,
            "app.helpers.asset_wih": asset_wih,
            "app.helpers.scope": scope_mod,
            "app.services": services_pkg,
            "app.services.infoHunter": info_hunter,
            "app.modules": wih_record_mod,
        })
        self.monitor = _module_from_service("asset_wih_monitor")

    def tearDown(self):
        from app import utils as real_utils

        for name, (had, value) in self._utils_backup.items():
            if had:
                setattr(real_utils, name, value)
            elif getattr(real_utils, "__path__", None):
                delattr(real_utils, name)
        sys.modules.pop("app.services.asset_wih_monitor", None)
        for name, module in self.saved.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module

    def _swap(self, mapping):
        for name, module in mapping.items():
            self.saved.setdefault(name, sys.modules.get(name))
            sys.modules[name] = module

    def test_monitor_creates_and_propagates_context(self):
        results = self.monitor.AssetWihMonitor("scope-1").run()
        self.assertEqual(results, [])

        # run_wih 无 ctx 参数(Go 边界),其余五阶段必须收到同一个上下文。
        contexts = {
            name: ctx
            for name, ctx in self.stage_calls.items()
            if isinstance(ctx, DiscoveryContext)
        }
        self.assertEqual(
            set(contexts),
            {"urlfinder_extract", "page_intel", "api_doc", "js_intel", "urlfinder_sensitive"},
        )
        self.assertEqual(len(self.contexts), 5)
        distinct = {id(ctx) for ctx in self.contexts}
        self.assertEqual(len(distinct), 1, "同轮监控必须共享一个上下文")
        context = self.contexts[0]
        self.assertTrue(context.task_id.startswith("monitor|scope-1|"))
        self.assertEqual(context.allowed_hosts, {"a.example.com", "b.example.com"})

    def test_each_run_gets_fresh_context(self):
        self.monitor.AssetWihMonitor("scope-1").run()
        second = self.monitor.AssetWihMonitor("scope-1")
        second.run()
        ids = [ctx.task_id for ctx in self.contexts]
        self.assertEqual(len(set(ids)), 2, "run_id 必须区分监控轮次")


class AssetSiteCompareFetchTest(unittest.TestCase):
    def setUp(self):
        self.saved = {}
        app_pkg = sys.modules.get("app")
        if app_pkg is None or not getattr(app_pkg, "__path__", None):
            app_pkg = types.ModuleType("app")
            app_pkg.__path__ = [str(APP_DIR)]
        # 运行期 sys.modules["app.utils"] 可能已被其他用例替换为 fake;
        # web_info_intel_utils 在收集期捕获的真实 utils 对象才是 fetch_text 实际使用的。
        fetch_chain = sys.modules.get("app.services.web_info_intel_utils")
        if fetch_chain is None or not hasattr(fetch_chain, "fetch_text"):
            fetch_chain = _module_from_service("web_info_intel_utils")
        real_utils = fetch_chain.utils
        # `from app import utils` 会先命中包属性(可能是他用例留下的 fake),
        # 再命中 sys.modules——两处一起钉回真实对象。
        self._swap({"app.utils": real_utils})
        self._saved_pkg_utils = getattr(app_pkg, "utils", None)
        app_pkg.utils = real_utils

        # app.config 同样可能是运行期残留的 fake:换回真实 config 模块再加载被测文件。
        real_cfg = sys.modules.get("app.config")
        if real_cfg is None or not hasattr(getattr(real_cfg, "Config", None), "ASSET_SITE_MONITOR_CONCURRENCY"):
            spec = importlib.util.spec_from_file_location("app.config", APP_DIR / "config.py")
            real_cfg = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(real_cfg)
            self._swap({"app.config": real_cfg})

        self.real_http_req = real_utils.http_req
        self.http_calls = []

        def fake_http_req(url, method="get", **_kwargs):
            self.http_calls.append(url)
            return types.SimpleNamespace(
                status_code=200,
                content=b"<title>Asset Site</title>",
                headers={"Content-Type": "text/html"},
            )

        services_pkg = types.ModuleType("app.services")
        services_pkg.__path__ = [str(SERVICES_DIR)]

        fetch_site_mod = types.ModuleType("app.services.fetchSite")
        fetch_site_mod.fetch_site = lambda sites: []

        helpers = types.ModuleType("app.helpers")
        asset_site = types.ModuleType("app.helpers.asset_site")
        asset_site.find_site_by_scope_id = lambda scope_id: ["https://a.example.com"]
        asset_site.find_site_info_by_scope_id = lambda scope_id: []
        asset_domain = types.ModuleType("app.helpers.asset_domain")
        asset_monitor_helper = types.ModuleType("app.helpers.asset_site_monitor")
        asset_monitor_helper.is_black_asset_site = lambda site: False
        notify = types.ModuleType("app.helpers.message_notify")
        notify.push_email = lambda *a, **k: None
        notify.push_dingding = lambda *a, **k: None
        scope_mod = types.ModuleType("app.helpers.scope")
        scope_mod.get_scope_by_scope_id = lambda scope_id: {"name": "demo"}

        self._swap({
            "app": app_pkg,
            "app.utils": real_utils,
            "app.services": services_pkg,
            "app.services.fetchSite": fetch_site_mod,
            "app.helpers": helpers,
            "app.helpers.asset_site": asset_site,
            "app.helpers.asset_domain": asset_domain,
            "app.helpers.asset_site_monitor": asset_monitor_helper,
            "app.helpers.message_notify": notify,
            "app.helpers.scope": scope_mod,
        })
        self.real_dns_check = real_utils.check_dns_policy_for_url
        real_utils.http_req = fake_http_req
        real_utils.check_dns_policy_for_url = lambda url, cache_map=None: (True, {})
        self._fetch_chain_utils = real_utils
        self.compare_module = _module_from_service("asset_site_monitor")

    def tearDown(self):
        app_pkg = sys.modules.get("app")
        if app_pkg is not None and hasattr(self, "_saved_pkg_utils"):
            app_pkg.utils = self._saved_pkg_utils
        self._fetch_chain_utils.http_req = self.real_http_req
        self._fetch_chain_utils.check_dns_policy_for_url = self.real_dns_check
        sys.modules.pop("app.services.asset_site_monitor", None)
        sys.modules.pop("app.services.asset_site_monitor_ctx_probe", None)
        for name, module in self.saved.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module

    def _swap(self, mapping):
        for name, module in mapping.items():
            self.saved.setdefault(name, sys.modules.get(name))
            sys.modules[name] = module

    def test_compare_fetch_shares_context_and_reuses_response(self):
        compare = self.compare_module.AssetSiteCompare(scope_id="scope-9")
        self.assertTrue(compare.discovery_context.task_id.startswith("monitor|scope-9|"))

        site = "https://a.example.com"
        compare.work(site)
        compare.work(site)

        self.assertEqual(self.http_calls, [site], "同轮二次抓取必须命中任务内缓存")
        item = compare.new_site_info_map[site]
        self.assertEqual(item["status"], 200)
        self.assertIn("Asset Site", item["title"])
        metrics = compare.discovery_context.metrics_snapshot()
        self.assertGreaterEqual(metrics["network_request_count"], 1)
        self.assertGreaterEqual(metrics["cache_hit_count"], 1)




if __name__ == "__main__":
    unittest.main()
