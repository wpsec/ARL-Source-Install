#!/usr/bin/env python3
"""计划5 第6-7阶段：legacy vs unified 生效规则集对照报告（放行前置证据）。

为什么是规则集对照而非响应回放：site 集合不存响应 body，历史数据无法完整回放匹配。
本脚本对比两条链**实际生效的规则空间**：
  legacy  = finger_db_cache.get_data()（Mongo + kscan 内置文件，无 policy）
  unified = SiteFingerprintRegistry（仓库基线 gz[policy 化] + Mongo overlay）
输出 delta 及归因，核对两件事：
  1) 减少方向必须可归因（policy 拒绝的泛化噪声，附录B 清单交叉核对）；
  2) 新增方向必须可解释（faviconhash/webapp 进链、kscan_local 1760、用户规则 overlay）。
容器内执行（真实 Mongo）：
    docker cp scripts/fingerprint-ruleset-diff.py arl_web:/tmp/fpdiff.py
    docker exec -e FINGERPRINT_REAL_DB=1 arl_web python3 /tmp/fpdiff.py
本地执行（fake Mongo=空，仅文件面预览）：python3 scripts/fingerprint-ruleset-diff.py
报告首行标注数据来源（real/preview）。
"""
import importlib.util
import os
import pathlib
import sys
import types

ROOT = pathlib.Path(__file__).resolve().parent.parent
ARL = ROOT / "ARL"


def bootstrap():
    # 容器内真实链：直接 import app.*（xing/真实 Mongo 齐备），不 fake 任何模块
    if os.environ.get("FINGERPRINT_REAL_DB") == "1":
        # 容器工作布局 /code（arl_web 镜像根），本地开发布局 ARL/；取存在 app/ 的那个
        for cand in ("/code", str(ARL)):
            if (Path(cand) / "app" / "__init__.py").exists():
                sys.path.insert(0, cand)
                break
        else:
            sys.path.insert(0, str(ARL))
        import app.services.fingerprint_cache as cache
        import app.services.site_fingerprint_registry as registry
        from app.config import Config as _C
        source = "real"
        _ = getattr(_C, "SITE_FINGERPRINT_FILE", "")
        return cache, registry, source
    app_pkg = types.ModuleType("app")
    app_pkg.__path__ = [str(ARL / "app")]
    sys.modules["app"] = app_pkg
    svc = types.ModuleType("app.services")
    svc.__path__ = [str(ARL / "app" / "services")]
    sys.modules["app.services"] = svc
    app_pkg.services = svc
    tools = types.ModuleType("app.tools")
    tools.__path__ = [str(ARL / "app" / "tools")]
    sys.modules["app.tools"] = tools
    app_pkg.tools = tools
    utils = types.ModuleType("app.utils")
    utils.__path__ = [str(ARL / "app" / "utils")]

    class _L:
        def __getattr__(self, _n):
            return lambda *a, **k: None

    class _Coll:
        def find(self, *a, **k):
            return iter([])

        def find_one(self, *a, **k):
            return None

        def count_documents(self, *a, **k):
            return 0

    utils.get_logger = lambda *a, **k: _L()
    utils.conn_db = lambda *a, **k: _Coll()
    utils.load_file = lambda p: open(p, encoding="utf-8").readlines()
    sys.modules["app.utils"] = utils
    app_pkg.utils = utils
    config_module = types.ModuleType("app.config")

    class Config:
        REDIS_ENABLE = False
        REDIS_HOST = "127.0.0.1"
        REDIS_PORT = 6379
        REDIS_DB = 0
        REDIS_PASSWORD = ""
        REDIS_CACHE_EXPIRE = 0
        web_app_rule = str(ARL / "app/dicts/webapp.json")
        FINGERPRINT = str(ROOT / "tools/finger.json")
        KSCAN_FINGERPRINT_ENABLE = True
        KSCAN_FINGERPRINT_FILE = str(ARL / "app/dicts/kscan_fingerprint.json")  # legacy 用内置版
        KSCAN_FINGERPRINT_NAME_PREFIX = ""
        KSCAN_FINGERPRINT_REGEX_FALLBACK = "literal"
        KSCAN_FINGERPRINT_MIN_LITERAL_LEN = 5
        KSCAN_FINGERPRINT_MAX_RULES_PER_NAME = 30
        KSCAN_FINGERPRINT_MAX_TOTAL_RULES = 12000
        FINGER_CONFIDENCE_MIN = 85
        FINGER_CANDIDATE_CONFIDENCE_MIN = 70
        FINGER_LEGACY_RULE_CONFIDENCE = 72
        WAPPALYZER_CONFIDENCE_MIN = 70
        FINGER_CANDIDATE_MAX_ITEMS = 8
        SITE_FINGERPRINT_SOURCE = "unified"
        SITE_FINGERPRINT_FILE = str(ARL / "app/dicts/site_fingerprints.json.gz")

    config_module.Config = Config
    sys.modules["app.config"] = config_module
    app_pkg.config = config_module

    def _load(name, path):
        spec = importlib.util.spec_from_file_location(name, str(path))
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module

    _load("app.fp_common", ARL / "app/fp_common.py")
    svc.expr = _load("app.services.expr", ARL / "app/services/expr.py")
    svc.fingerprint = _load("app.services.fingerprint", ARL / "app/services/fingerprint.py")
    svc.kscan_fingerprint = _load("app.services.kscan_fingerprint", ARL / "app/services/kscan_fingerprint.py")
    cache = _load("app.services.fingerprint_cache", ARL / "app/services/fingerprint_cache.py")
    svc.fingerprint_cache = cache
    _load("app.tools.build_unified_fingerprints", ARL / "app/tools/build_unified_fingerprints.py")
    registry = _load("app.services.site_fingerprint_registry", ARL / "app/services/site_fingerprint_registry.py")
    return cache, registry, "preview"


def main():
    cache, registry_mod, source = bootstrap()
    print(f"数据来源: {source}{'（真实 Mongo，作放行依据）' if source == 'real' else '（本地空库预览，正式放行须容器内 real 重跑）'}")
    legacy_rules = cache.finger_db_cache.get_data() or []
    if source == "real":
        from app.config import Config as _C
        site_path = str(_C.SITE_FINGERPRINT_FILE)
    else:
        site_path = str(ARL / "app/dicts/site_fingerprints.json.gz")
    reg = registry_mod.SiteFingerprintRegistry(site_path).load()
    if not reg.ok:
        print("ERROR: unified registry unavailable:", reg.load_error)
        return 1

    legacy_names = {str(r.app_name).strip().casefold() for r in legacy_rules}
    unified_names = {str(r["name"]).strip().casefold() for r in reg.rules}
    only_unified = sorted(unified_names - legacy_names)
    only_legacy = sorted(legacy_names - unified_names)

    import gzip as _gz, json as _json
    with _gz.open(site_path if not site_path.endswith(".gz") else site_path, "rt", encoding="utf-8") as f:
        _meta = _json.load(f)["meta"]
    rejected_detail = {str(r.get("name", "")).strip().casefold(): r for r in _meta.get("rejected_rules_detail", [])}
    print(f"- 产物 meta: content_hash={_meta.get('content_hash', '')[:16]} 拒绝明细 {len(rejected_detail)} 条")
    print("# legacy vs unified 生效规则集对照")
    print(f"- legacy 规则数（应用名去重）: {len(legacy_names)}")
    print(f"- unified 规则数（含 overlay）: {len(unified_names)}  overlay_error={reg._overlay_error or '无'}")
    print(f"- 仅 unified 有: {len(only_unified)}（预期来源：faviconhash/webapp 进链、kscan_local 新增、用户规则）")
    for name in only_unified[:40]:
        print(f"  + {name}")
    if len(only_unified) > 40:
        print(f"  …共 {len(only_unified)}")
    print(f"- 仅 legacy 有: {len(only_legacy)}（放行阻断项：非 policy 可归因的减少）")
    unattributed = []
    for name in only_legacy:
        if name in rejected_detail:
            print(f"  - {name}  [归因：{rejected_detail[name]['reason']}，来源 {rejected_detail[name].get('sources')}]")
        else:
            unattributed.append(name)
    for name in unattributed[:60]:
        print(f"  - {name}  [未归因!!]")
    if len(unattributed) > 60:
        print(f"  …未归因共 {len(unattributed)}")
    print()
    if unattributed:
        print("结论：存在未归因的召回减少，禁止放行 unified。")
        return 2
    print("结论：减少全部可归因 policy 动作；放行仍需 x86 真实 Mongo 数据重跑本报告 + 观测期指标（05 第4阶段切换口径）。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
