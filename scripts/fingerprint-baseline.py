#!/usr/bin/env python3
"""计划5 第1阶段：指纹现状冻结取证（输出 docs/plan/05-附录A-指纹现状冻结清单.md）。

为什么脚本取证：四文件 4.6MB/近 4 万条规则，手工统计必漏；交叉对比与
weak-rule 计数是后续生成脚本（第2阶段）的 golden 基线。规则语义变化时重跑本脚本刷新清单。
"""
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "plan" / "05-附录A-指纹现状冻结清单.md"

FILES = {
    "webapp": ROOT / "ARL/app/dicts/webapp.json",
    "tools_finger": ROOT / "tools/finger.json",
    "kscan": ROOT / "ARL/app/dicts/kscan_fingerprint.json",
    "kscan_local": ROOT / "ARL/app/dicts/kscan_fingerprint.local.json",
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16]


def norm_name(name: str) -> str:
    return re.sub(r"[^a-z0-9一-鿿]+", "", str(name).lower())


def load_all():
    return {k: json.load(p.open()) for k, p in FILES.items()}


def stat_webapp(data):
    rules = data
    n = len(rules)
    zero = icon_only = 0
    sig_dist = Counter()
    for name, r in rules.items():
        heads = [h for h in (r.get("headers") or []) if str(h).strip()]
        htmls = [h for h in (r.get("html") or []) if str(h).strip()]
        titles = [h for h in (r.get("title") or []) if str(h).strip()]
        icons = str(r.get("icon") or "").strip()
        icon_valid = bool(icons) and icons != "default.png"
        sig = len(heads) + len(htmls) + len(titles) + (1 if icon_valid else 0)
        sig_dist[min(sig, 5)] += 1
        if sig == 0:
            zero += 1
        elif sig == 1 and icon_valid:
            icon_only += 1
    return {
        "count": n,
        "zero_signal": zero,
        "icon_only": icon_only,
        "sig_dist": dict(sorted(sig_dist.items())),
        "names": {norm_name(k) for k in rules},
    }


COND_RE = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)\s*(~=|==|!=|=)\s*("([^"\\]|\\.)*"|-?\d+)\s*$', re.S)


def split_logic(expr: str):
    """引号感知按 || / && 拆分（复刻 services/kscan_fingerprint._split_logic_expression 语义）。"""
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
        if expr[i:i + 2] == "||" or expr[i:i + 2] == "&&":
            parts.append("".join(buf))
            buf = []
            i += 2
            continue
        buf.append(c)
        i += 1
    if buf:
        parts.append("".join(buf))
    return [x.strip() for x in parts if x.strip()]


def stat_kscan(entries):
    fields = Counter()
    ops = Counter()
    or_conditions = Counter()
    unparsed = []
    names = set()
    single_generic = 0
    for it in entries:
        names.add(norm_name(it.get("name", "")))
        conds = split_logic(it.get("human_rule", ""))
        parsed = 0
        for cond in conds:
            m = COND_RE.match(cond.strip())
            if not m:
                ops["UNPARSED"] += 1
                unparsed.append({"name": it["name"], "cond": cond.strip()[:120]})
                continue
            parsed += 1
            field, op, val = m.group(1), m.group(2), m.group(3)
            fields[field] += 1
            ops[op] += 1
            or_conditions[min(parsed, 5)] += 0  # 计数在规则级
        if parsed:
            or_conditions[min(len(conds), 5)] += 1
            # 单条件且字面量泛化（长度<8 或纯端口/数字类）→ weak 候选
            if len(conds) == 1:
                m = COND_RE.match(conds[0].strip())
                if m:
                    val = m.group(3).strip()
                    if len(val.strip('"')) < 8 or re.fullmatch(r"[\d.:%\-/]+", val.strip('"')):
                        single_generic += 1
    return {
        "count": len(entries),
        "fields": dict(fields.most_common()),
        "ops": dict(ops),
        "cond_per_rule": dict(sorted(or_conditions.items())),
        "single_generic": single_generic,
        "unparsed": unparsed[:12],
        "unparsed_total": len(unparsed),
        "names": names,
    }


def stat_finger(data):
    entries = data["fingerprint"]
    methods = Counter(it.get("method") for it in entries)
    locations = Counter(str(it.get("location")) for it in entries)
    short_kw = 0
    total_kw = 0
    for it in entries:
        if it.get("method") != "keyword":
            continue
        for kw in it.get("keyword") or []:
            total_kw += 1
            if len(str(kw)) < 6:
                short_kw += 1
    names = {norm_name(it.get("cms", "")) for it in entries}
    # 同 cms 多规则条目（keyword 型每条目是一个 OR 分支）
    per_cms = Counter(norm_name(it.get("cms", "")) for it in entries)
    return {
        "count": len(entries),
        "meta": data.get("meta", {}),
        "methods": dict(methods),
        "locations": dict(locations),
        "keyword_total": total_kw,
        "keyword_short_lt6": short_kw,
        "unique_cms": len(names),
        "cms_multi_entry_top": per_cms.most_common(5),
        "names": names,
    }


CFG_KEYS = (
    "KSCAN_FINGERPRINT_ENABLE", "KSCAN_FINGERPRINT_FILE", "KSCAN_FINGERPRINT_NAME_PREFIX",
    "KSCAN_FINGERPRINT_REGEX_FALLBACK", "KSCAN_FINGERPRINT_MIN_LITERAL_LEN",
    "KSCAN_FINGERPRINT_MAX_RULES_PER_NAME", "KSCAN_FINGERPRINT_MAX_TOTAL_RULES",
    "FINGER_CONFIDENCE_MIN", "FINGER_CANDIDATE_CONFIDENCE_MIN", "FINGER_LEGACY_RULE_CONFIDENCE",
    "WAPPALYZER_CONFIDENCE_MIN", "FINGER_CANDIDATE_MAX_ITEMS",
)


def config_switches():
    """运行配置面：config.py 类默认值 + 各 yaml 实际设置。"""
    rows = []
    cfg_py = (ROOT / "ARL/app/config.py").read_text(encoding="utf-8", errors="ignore")
    for key in CFG_KEYS:
        m = re.search(rf"^\s*{key} = (.+)$", cfg_py, re.M)
        if m:
            rows.append(("config.py 默认", key, m.group(1).strip()))
    for y in sorted((ROOT / "ARL/docker").glob("config-*.yaml")) + [
        ROOT / "ARL/app/config.yaml",
        ROOT / "ARL/app/config.yaml.example",
    ]:
        if not y.exists():
            continue
        txt = y.read_text(encoding="utf-8", errors="ignore")
        for key in CFG_KEYS:
            m = re.search(rf"^\s*{key}:\s*(.+)$", txt, re.M)
            if m:
                rows.append((str(y.relative_to(ROOT)), key, m.group(1).strip()))
    return rows


def load_path_grep():
    refs = []
    patterns = [
        ("webapp.json 加载（legacy 站点匹配）", "web_app_rule|webapp.json"),
        ("kscan 规则加载", "KSCAN_FINGERPRINT_FILE|load_kscan_fingerprint_rules"),
        ("tools/finger.json 导入链", "finger.json"),
        ("fingerprint_cache（置信度/合并/Redis）", "fingerprint_cache|arl:fingerprint:rules"),
        ("bundle 构建工具（第2阶段扩展对象）", "build_fingerprint_bundle|import_fingerprint"),
        ("finger_candidates 字段写入", "finger_candidates"),
    ]
    for label, pat in patterns:
        try:
            out = subprocess.run(
                ["git", "grep", "-n", "-E", pat, "--", "ARL/app", "scripts", "start.sh", "tools/finger.json"],
                cwd=ROOT, capture_output=True, text=True, timeout=60,
            ).stdout
        except Exception:
            out = ""
        lines = [l for l in out.splitlines() if not l.startswith("Binary")][:14]
        refs.append((label, lines))
    return refs


def main():
    data = load_all()
    web = stat_webapp(data["webapp"])
    k1 = stat_kscan(data["kscan"]["fingerprint"])
    k2 = stat_kscan(data["kscan_local"]["fingerprint"])
    fin = stat_finger(data["tools_finger"])

    inter = {
        "kscan∩local": len(k1["names"] & k2["names"]),
        "local−kscan(local独有)": len(k2["names"] - k1["names"]),
        "kscan−local": len(k1["names"] - k2["names"]),
        "webapp∩kscan": len(web["names"] & k1["names"]),
        "webapp∩local": len(web["names"] & k2["names"]),
        "finger∩kscan": len(fin["names"] & k1["names"]),
        "finger∩local": len(fin["names"] & k2["names"]),
        "finger∩webapp": len(fin["names"] & web["names"]),
    }
    try:
        rev = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    except Exception:
        rev = "unknown"

    L = []
    L.append("# 05 附录A · 指纹现状冻结清单（第1阶段取证）\n")
    L.append(f"- 生成命令：`python3 scripts/fingerprint-baseline.py`（本文件即脚本输出，禁止手改；规则文件/代码变更后重跑刷新）")
    L.append(f"- 基线 rev：`{rev}`，生成时间：{datetime.now():%F %T}")
    L.append(f"- API 端点面冻结复用 [04-附录A](./04-附录A-API契约冻结清单.md)（`/api/fingerprint` CRUD/上传/导出、`/api/site`、`/api/service` 均在其中），本清单只覆盖指纹文件、调用条件与结果字段面。\n")

    L.append("## 一、规则文件基线（sha256 前 16 位）\n")
    L.append("| 文件 | 大小(B) | sha256 | 规则条目 | 说明 |")
    L.append("|---|---|---|---|---|")
    meta_local = data["kscan_local"].get("meta", {})
    for key, path, count, desc in [
        ("webapp", FILES["webapp"], web["count"], "wappalyzer 风格 dict；legacy `utils/fingerprint.py` import 期加载"),
        ("tools_finger", FILES["tools_finger"], fin["count"], f"外部大源，unique cms={fin['unique_cms']}；start.sh→sync-fingerprint.sh 导入 Mongo"),
        ("kscan", FILES["kscan"], k1["count"], "`{{name,human_rule}}` 列表；KSCAN_FINGERPRINT_ENABLE 控制"),
        ("kscan_local", FILES["kscan_local"], k2["count"], f"bundle 产物格式（meta.format=arl_fingerprint_bundle，{json.dumps(meta_local, ensure_ascii=False)[:120]}）"),
    ]:
        L.append(f"| `{path.relative_to(ROOT)}` | {path.stat().st_size} | `{sha(path)}` | {count} | {desc} |")

    L.append("\n## 二、规则质量画像（误报控制的现状基线，第2阶段生成脚本的对照输入）\n")
    L.append(f"- **webapp.json**：信号数分布(≤5截断) `{json.dumps(web['sig_dist'])}`；零信号规则 **{web['zero_signal']}**、仅 icon 规则 **{web['icon_only']}**。")
    L.append(f"- **tools/finger.json**：method `{json.dumps(fin['methods'])}`，location `{json.dumps(fin['locations'])}`；keyword 总数 {fin['keyword_total']}，其中长度<6 的泛化关键字 **{fin['keyword_short_lt6']}**；同 cms 多条目 Top `{json.dumps(fin['cms_multi_entry_top'], ensure_ascii=False)}`。")
    L.append(f"- **kscan**：字段分布 `{json.dumps(k1['fields'])}`；操作符 `{json.dumps(k1['ops'])}`（`!=` 即 excludes 语义）；单规则条件数分布 `{json.dumps(k1['cond_per_rule'])}`；单条件+泛化字面量(长度<8 或纯数字/端口样式) **{k1['single_generic']}** 条；解析断裂待人工复核 {k1['unparsed_total']} 条。")
    L.append(f"- **kscan_local**：字段分布 `{json.dumps(k2['fields'])}`；操作符 `{json.dumps(k2['ops'])}`；单条件泛化 **{k2['single_generic']}** 条；解析断裂 {k2['unparsed_total']} 条。")
    L.append(f"- **regex 规则存量：两 kscan 文件均无 `re:` 前缀正则形态（纯字面量 + ||/!= 布尔），第2阶段无锚点兜底桶压力≈0；** 新增 regex 通道时须按 §2.3.1 召回保障执行。")
    if k1["unparsed"] or k2["unparsed"]:
        L.append("\n人工复核样本（quote-aware 解析后仍不可判定的条件，数据质量问题）：")
        for u in (k1["unparsed"] + k2["unparsed"])[:10]:
            L.append(f"  - `{u['name']}` :: `{u['cond']}`")

    L.append("\n## 三、名称交叉（第6阶段 Kscan 迁移与第2阶段合并的输入）\n")
    for k, v in inter.items():
        L.append(f"- {k}：**{v}**")
    L.append("- 交叉按名字归一化（小写+去符号+CJK 保留）统计；同名不同规则的内容级 diff 在第2阶段生成脚本中输出（冲突清单）。")

    L.append("\n## 四、加载路径与调用条件（代码锚点，行号会漂移、以函数名为准）\n")
    L.append("```text")
    for label, lines in load_path_grep():
        L.append(f"### {label}")
        L.extend(lines if lines else ["(无引用)"])
        L.append("")
    L.append("```")
    L.append("""
调用条件结论（对照代码核实，防口径漂移）：

1. **站点识别双路径并存**：`fetchSite.py` 同时依赖 legacy `utils/fingerprint.py`（import 期模块级 `json.loads(Config.web_app_rule)`，进程级一次性）与 `fingerprint_cache`（Mongo `fingerprint` + Redis 缓存 + kscan）。统一目标 = 消灭 legacy 路径。
2. **服务识别**：Nmap 端口发现 + 可选 `-sV`（service_detection 选项）；NPoC 智能门控在 `IPTask._build_sniffer_targets`（仅低置信度端口、target_set 去重、空集时 ≤300 非 80/443 兜底、`full_port` 为用户显式选项）；`DomainTask._build_sniffer_targets` 同型。
3. **第2/3/4阶段先行件（`services/kscan_fingerprint.py` 已实现，收编复用、禁止第二套）**：引号感知 `||/&&/!=/~=` 布尔解析 `_split_logic_expression`；regex 字面量锚点提取 `_extract_literal_from_regex`（`regex_no_literal` 拒绝原因）；单名规则数上限与总量上限；`_config_signature` 配置变化即缓存失效——即 §2.3.1 锚点提取与 Stage4 "内容 hash debounce" 的同型先例。
4. **结果字段落点（冻结面）**：site/fileleak 文档 `finger`（confirmed）与 `finger_candidates`（候选，已投产，消费方 assetSite 路由/前端列）；`npoc_service` 集合（`tasks/poc.py` 与 `ip.py` 写 insert）；service 集合 product/version/exe 等字段由 Nmap 解析产出。第2阶段起新增字段必须先进本清单。
6. **导出面**：`/api/export`、`/api/batchExport/*` 的 finger 列消费 `finger` 字段（不含 candidates），冻结不变。
""")

    L.append("## 五、配置开关现状\n")
    L.append("| 文件 | 键 | 值 |")
    L.append("|---|---|---|")
    for row in config_switches():
        L.append(f"| `{row[0]}` | {row[1]} | {row[2]} |")

    L.append("""
## 六、golden 对照语料（第2-3阶段验收前置）

- 位置：`ARL/test/fixtures/fingerprints/`（测试资产入 git，不属"生成产物不进 Git"禁令）。
- 构成：`responses.json` 12 个合成样本（覆盖 header/body/title/response/icon_hash/url + `&&`/`||`/`!=` 布尔组合）× 当前实现**三段链**输出快照：legacy `utils/fingerprint.fetch_fingerprint`（webapp）→ `finger_db_identify_detail`（kscan+Mongo空集）→ `build_legacy+split` 合并 → `normalize_wappalyzer_fingerprint_items`；快照 `golden_v1.json` 由 `ARL/test/test_fingerprint_golden.py` 生成并锁定，回归模式严格对比。
- 无在线 DB：golden 只跑纯匹配函数（Redis/Mongo 以 fake 替身，先例见 test_route_build_return_items 的加载器模式）。

## 七、决策记录（2026-09-04 用户拍板，详见 05 主文档"决策记录"节）

已定：Q1 取 B（local 9673 为迁移基准，前置=第2阶段A 增量审计+golden 双文件对比）；Q2 取 A（Mongo 真相源、finger.json 仅种子）。原始待决问题与数据保留如下：


1. `kscan_fingerprint.local.json` 是否进生产：local 较主 kscan 文件独有规则 **{local_only}** 条、重叠 {overlap} 条；若进，以哪份为准（建议：bundle 已含双源合并且做过 dedupe/accept 统计，以 local 为准、主文件退役为源输入）。
2. tools/finger.json 17445 个 cms、28884 条规则经 sync 导入 Mongo 后与规范文件的关系（建议：Mongo 为用户真相源、finger.json 仅作首次导入源，见计划§Stage4 部署拓扑决策）。
""".replace("{local_only}", str(inter["local−kscan(local独有)"])).replace("{overlap}", str(inter["kscan∩local"])))

    OUT.write_text("\n".join(L), encoding="utf-8")
    print(f"written: {OUT}")


if __name__ == "__main__":
    main()
