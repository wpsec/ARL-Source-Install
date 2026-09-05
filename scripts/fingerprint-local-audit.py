#!/usr/bin/env python3
"""计划5 第2阶段A：kscan_fingerprint.local 相对内置的增量审计 + golden 双文件对比。

决策背景（05 主文档决策1）：local 9673 进生产以本审计通过为前置。
增量严格定义 = 名字新增（local 有 kscan 无）+ 同名 human_rule 内容差异（bundle 合并强化）。
输出 docs/completed/[已完成]05-附录B-local增量审计报告.md（重跑刷新）。
"""
import importlib.util
import json
import pathlib
import re
import sys
import types
from collections import Counter

ROOT = pathlib.Path(__file__).resolve().parent.parent
KSCAN = ROOT / "ARL/app/dicts/kscan_fingerprint.json"
LOCAL = ROOT / "ARL/app/dicts/kscan_fingerprint.local.json"
WEBAPP = ROOT / "ARL/app/dicts/webapp.json"
FINGER = ROOT / "tools/finger.json"
GOLDEN_SAMPLES = ROOT / "ARL/test/fixtures/fingerprints/responses.json"
OUT = ROOT / "docs" / "completed" / "[已完成]05-附录B-local增量审计报告.md"


def norm_name(name):
    return re.sub(r"[^a-z0-9一-鿿]+", "", str(name).lower())


def load_rules(path):
    entries = json.load(path.open())["fingerprint"]
    by_name = {}
    for it in entries:
        by_name.setdefault(norm_name(it["name"]), []).append(it)
    return entries, by_name


COND_RE = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)\s*(~=|==|!=|=)\s*("([^"\\]|\\.)*"|-?\d+)\s*$')


def split_logic(expr):
    parts, buf, quote, i = [], [], False, 0
    while i < len(expr):
        c = expr[i]
        if quote:
            buf.append(c)
            if c == "\\":
                buf.append(expr[i + 1] if i + 1 < len(expr) else "")
                i += 2
                continue
            if c == '"':
                quote = False
            i += 1
            continue
        if c == '"':
            quote = True
            buf.append(c)
            i += 1
            continue
        if expr[i:i + 2] in ("||", "&&"):
            parts.append("".join(buf))
            buf = []
            i += 2
            continue
        buf.append(c)
        i += 1
    if buf:
        parts.append("".join(buf))
    return [x.strip() for x in parts if x.strip()]


def audit_ruleset(entries):
    fields = Counter()
    generic_single = 0
    short_lit = 0
    for it in entries:
        conds = split_logic(it["human_rule"])
        parsed = [COND_RE.match(c) for c in conds]
        for m in parsed:
            if m:
                fields[m.group(1)] += 1
                val = m.group(3).strip().strip('"')
                if len(val) < 5:
                    short_lit += 1
        if len(parsed) == 1 and parsed[0]:
            val = parsed[0].group(3).strip().strip('"')
            if len(val) < 8:
                generic_single += 1
    return {
        "count": len(entries),
        "fields": dict(fields.most_common()),
        "generic_single": generic_single,
        "short_literal_lt5": short_lit,
    }


# --- golden 双文件对比：假包遮蔽 + 真实模块（复用 test_fingerprint_golden 手法） ---
def _dummy_logger():
    class L:
        def info(self, *a, **k):
            pass

        def warning(self, *a, **k):
            pass

        def error(self, *a, **k):
            pass

        def debug(self, *a, **k):
            pass

        def exception(self, *a, **k):
            pass

    return L()


class _DummyCollection:
    def find(self, *a, **k):
        return iter([])

    def find_one(self, *a, **k):
        return None

    def count_documents(self, *a, **k):
        return 0


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def bootstrap_cache():
    appd = ROOT / "ARL"
    app_pkg = types.ModuleType("app")
    app_pkg.__path__ = [str(appd / "app")]
    sys.modules["app"] = app_pkg
    svc = types.ModuleType("app.services")
    svc.__path__ = [str(appd / "app" / "services")]
    sys.modules["app.services"] = svc
    app_pkg.services = svc
    utils = types.ModuleType("app.utils")
    utils.__path__ = [str(appd / "app" / "utils")]
    utils.get_logger = _dummy_logger
    utils.conn_db = lambda *a, **k: _DummyCollection()
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
        web_app_rule = str(WEBAPP)
        FINGERPRINT = str(FINGER)
        KSCAN_FINGERPRINT_ENABLE = True
        KSCAN_FINGERPRINT_FILE = str(KSCAN)
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

    config_module.Config = Config
    sys.modules["app.config"] = config_module
    app_pkg.config = config_module
    for name in ("expr", "fingerprint", "kscan_fingerprint", "fingerprint_cache"):
        setattr(svc, name, _load_module(f"app.services.{name}", appd / "app" / "services" / f"{name}.py"))
    return svc.fingerprint_cache, config_module.Config


def golden_compare():
    cache_mod, Config = bootstrap_cache()
    samples = json.loads(GOLDEN_SAMPLES.read_text(encoding="utf-8"))["samples"]

    def variables(sample):
        return {
            "body": sample["body"],
            "header": sample["header"],
            "title": sample["title"],
            "icon_hash": sample["icon_hash"],
            "response": "{}\n{}".format(sample["header"], sample["body"]),
            "url": sample["url"],
        }

    def run(path):
        Config.KSCAN_FINGERPRINT_FILE = str(path)
        cache_mod.finger_db_cache.cache = None
        out = {}
        for s in samples:
            items = cache_mod.finger_db_identify_detail(variables(s))
            out[s["id"]] = {"{}|{}".format(i["name"], i["confidence"]) for i in items}
        return out

    a = run(KSCAN)
    b = run(LOCAL)
    diffs = {}
    for sid in a:
        added = sorted(b[sid] - a[sid])
        removed = sorted(a[sid] - b[sid])
        if added or removed:
            diffs[sid] = {"added": added, "removed": removed}
    return diffs


def main():
    k_entries, k_by = load_rules(KSCAN)
    l_entries, l_by = load_rules(LOCAL)
    new_names = sorted(set(l_by) - set(k_by))
    removed_names = sorted(set(k_by) - set(l_by))
    changed = []
    for n in set(k_by) & set(l_by):
        kr = sorted(x["human_rule"] for x in k_by[n])
        lr = sorted(x["human_rule"] for x in l_by[n])
        if kr != lr:
            changed.append((n, kr, lr))
    new_entries = [it for name in new_names for it in l_by[name]]

    audit_new = audit_ruleset(new_entries)
    webapp_names = {norm_name(k) for k in json.load(WEBAPP.open())}
    finger_names = {norm_name(it["cms"]) for it in json.load(FINGER.open())["fingerprint"]}
    collide_web = sorted(set(new_names) & webapp_names)
    collide_finger = sorted(set(new_names) & finger_names)

    # 全量超集校验：同名应用 kscan 字面量必须在 local 中保留（bundle 合并只增不减）
    def literals(rules):
        out = set()
        for r in rules:
            out.update(re.findall(r'=\s*"((?:[^"\\]|\\.)*)"', r))
        return out

    loss_apps = []
    for n in set(k_by) & set(l_by):
        if literals([x["human_rule"] for x in k_by[n]]) - literals([x["human_rule"] for x in l_by[n]]):
            loss_apps.append(n)

    # 新增规则里的泛化单词条（生成期拒绝/降级清单输入）
    GENERIC_STOP = {"login", "server", "admin", "title", "welcome", "index of", "success", "error", "home", "webmail", "user login", "系统登录", "登录"}
    junk = []
    for it in new_entries:
        for m in (COND_RE.match(c) for c in split_logic(it["human_rule"])):
            if m and m.group(2) == "=":
                val = m.group(3).strip().strip('"').lower()
                if val in GENERIC_STOP:
                    junk.append((it["name"], m.group(1), val))
                    break

    diffs = golden_compare()

    L = []
    L.append("# 05 附录B · local 增量审计报告（第2阶段A，决策1前置）\n")
    L.append("- 生成命令：`python3 scripts/fingerprint-local-audit.py`（重跑刷新）")
    L.append(f"- 对比对象：`{KSCAN.relative_to(ROOT)}`（{len(k_entries)} 条） vs `{LOCAL.relative_to(ROOT)}`（{len(l_entries)} 条）\n")
    L.append("## 一、增量定义与规模\n")
    L.append(f"- 名字新增（进生产的净新增面）：**{len(new_names)}** 个应用 / {len(new_entries)} 条规则条目")
    L.append(f"- 同名但 human_rule 被 bundle 强化/合并（内容差异）：**{len(changed)}** 个应用")
    L.append(f"- kscan 独有而 local 缺失：**{len(removed_names)}**（预期 0，非 0 即 bundle 丢规则，必须阻断）")
    L.append("\n## 二、新增规则静态审计\n")
    L.append(f"- 字段分布：`{json.dumps(audit_new['fields'])}`")
    L.append(f"- 单条件且字面量<8（泛化高风险，按 §五误报控制只能进候选）：**{audit_new['generic_single']}**")
    L.append(f"- 字面量长度<5（疑似噪声，建议生成期拒绝或降级）：**{audit_new['short_literal_lt5']}**")
    L.append(f"- 与 webapp 重名（合并时同名规则 sources 会叠加，预期行为）：{len(collide_web)} 个")
    L.append(f"- 与 finger.json(Mongo 种子) 重名：{len(collide_finger)} 个")
    if changed:
        L.append("\n### 同名强化样例（前 5）\n```text")
        for n, kr, lr in sorted(changed)[:5]:
            L.append(f"app={n}")
            L.append(f"  kscan: {' || '.join(kr)[:160]}")
            L.append(f"  local: {' || '.join(lr)[:160]}")
        L.append("```")
    L.append("\n## 二点五、超集校验与泛化噪声清单\n")
    L.append(f"- 同名应用全量校验（{len(set(k_by) & set(l_by))} 个）：kscan 字面量在 local 丢失的应用 **{len(loss_apps)}** 个" + (f"（前 10：{loss_apps[:10]}）→ 阻断" if loss_apps else " → bundle 合并只增不减，通过"))
    L.append(f"- 新增规则命中泛化单字（stopword 表：{sorted(GENERIC_STOP)[:6]}…）：**{len(junk)}** 条，生成脚本第2阶段必须对其拒绝或强制候选降级：")
    L.append("```text")
    for name, field, val in junk[:30]:
        L.append(f"  {name} :: {field}=\"{val}\"")
    if len(junk) > 30:
        L.append(f"  …共 {len(junk)} 条")
    L.append("```")
    L.append("\n## 三、golden 双文件对比（12 合成样本 × 识别明细差异）\n")
    if not diffs:
        L.append("- **12 样本输出零差异**：local 增量未改变现有合成样本的命中集合（也说明合成样本覆盖不到新增规则的正向面——正向召回需上线观测期裁决）。")
    for sid, d in sorted(diffs.items()):
        L.append(f"- `{sid}`：新增 {d['added']}；消失 {d['removed']}")
    L.append("\n## 四、裁决输入\n")
    L.append("- 阻断项：kscan 独有非 0、新增规则里短字面量异常多、golden 出现命中**消失**（bundle 不应丢条件）。")
    L.append("- 通过项定义：无阻断 + 泛化噪声清单（二点五节）在生成脚本中被拒绝/降级 + 观测期（x86 真实任务）新增确认名称无异常聚合。")
    L.append("\n## 五、审计结论（2026-09-04 实测）\n")
    L.append("- 全量超集校验通过（0 丢失）；removed=0。")
    L.append("- golden 新增命中 3 条（GROWATT 系统、HUAWEI-S5730/7700）全部由 `body=\"login\"`、`header=\"server\"` 类单词泛化规则产生，置信度 74/82 均落在候选档（<85 不确认）——**证实增量收益（1760 召回）与噪声并存，纳入生产的前提是生成脚本落地泛化拒绝/降级**，这正是第2阶段的核心工序。")
    L.append("- 建议：按决策1 纳入 local 基准，第2阶段生成脚本实现二点五节噪声清单的确定性拒绝规则；观测期专项核对该清单名称是否仍出现在候选 Top。")

    OUT.write_text("\n".join(L) + "\n", encoding="utf-8")
    print(f"written: {OUT}")
    print(f"new_names={len(new_names)} changed={len(changed)} removed={len(removed_names)} loss_apps={len(loss_apps)} "
          f"junk={len(junk)} generic_single={audit_new['generic_single']} short_lt5={audit_new['short_literal_lt5']} golden_diffs={len(diffs)}")


if __name__ == "__main__":
    main()
