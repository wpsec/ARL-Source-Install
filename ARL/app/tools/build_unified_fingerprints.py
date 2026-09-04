#!/usr/bin/env python3
"""计划5 第2阶段：统一指纹生成脚本（规范 JSON 生成器）。

输入四路源 → site_fingerprints.json + service_fingerprints.json（规范格式见 05 计划 §五/§六）。
关键约束：
- 置信度同源：合并后的规则序列化为 canonical human_rule，喂 `estimate_human_rule_confidence`
  （与运行时同一函数，禁第二套计算，05 §零.1）。
- 泛化控制（附录B 审计结论）：stopword 级单字条件确定性拒绝；拒绝后无分支则整条规则拒绝；
  单条件短字面量规则置信度封顶候选档（75<85）。
- 确定性：规则按 id 排序、分支/条件稳定序；meta.content_hash 由指纹文本决定，
  generated_at 仅在 --stamp 时写入（保证重复生成字节一致，golden 对比可行）。

容器内执行：
  cd /code && python3 -m app.tools.build_unified_fingerprints [--dry-run] [--mongo-export f] [--extra-rules f]
"""
import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone

from app.fp_common import (
    estimate_human_rule_confidence,
    extract_literal_from_regex as _extract_literal_from_regex,
    split_logic_expression as _split_logic_expression,
)

# 泛化噪声拒绝表：小且可述（附录B 实证词 + 通用 UI 词），宁窄勿宽——宽表本身就是误报源
GENERIC_STOPWORDS = {
    "login", "server", "admin", "welcome", "home", "index of", "download", "search",
    "登录", "系统登录", "主页", "管理登录",
}
GENERIC_SINGLE_COND_MAX_LEN = 8          # 单条件字面量短于此 → 封顶候选
DEMOTED_CONFIDENCE_CAP = 75
MIN_LITERAL_LEN = 3                      # 超短字面量条件直接丢弃

COND_RE = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)\s*(~=|==|!=|=)\s*("([^"\\]|\\.)*"|-?\d+)\s*$')


def unquote(raw: str) -> str:
    if raw.startswith('"') and raw.endswith('"'):
        inner = raw[1:-1]
        return inner.replace('\\\\', '\x00').replace('\\"', '"').replace('\\n', '\n').replace('\\t', '\t').replace('\\r', '\r').replace('\x00', '\\')
    return raw


def quote(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + '"'


# != 保持生产布尔语义（对整字段串的不等比较，常真）——不偷换为计划 §五 的 excludes 语义，
# 语义升级留给第3阶段带 golden 对照做。
OP_TO_CANON = {"=": "contains", "==": "equals", "!=": "not_equals", "~=": "regex"}
CANON_TO_OP = {v: k for k, v in OP_TO_CANON.items()}


def parse_human_rule(expression: str):
    """human_rule → {"any":[{"all":[cond]}], "excludes":[]}；非法条件进 rejected。

    复用运行时同一拆分器（_split_logic_expression 返回 flat tokens/operators，双引号外 && / ||）。
    """
    tokens, operators = _split_logic_expression(expression)
    groups = [[]]
    for index, token in enumerate(tokens):
        if index > 0 and operators[index - 1] == "||":
            groups.append([])
        groups[-1].append(token)

    any_branches, rejected = [], []
    for group in groups:
        conds = []
        for part in group:
            m = COND_RE.match(part.strip())
            if not m:
                rejected.append(part.strip()[:120])
                continue
            field, op, raw = m.group(1), m.group(2), m.group(3)
            conds.append({"field": field.lower(), "operator": OP_TO_CANON[op], "value": unquote(raw)})
        if conds:
            any_branches.append({"all": conds})
    return {"any": any_branches, "excludes": []}, rejected


def to_human_rule(match: dict) -> str:
    """canonical match → 确定性 human_rule 文本（分支/条件稳定序）。"""
    def ser_cond(c):
        return "{}{}{}".format(c["field"], CANON_TO_OP[c["operator"]], quote(c["value"]))

    branches = []
    for branch in match.get("any", []):
        conds = sorted((ser_cond(c) for c in branch.get("all", [])))
        if conds:
            branches.append(" && ".join(conds))
    branches = sorted(set(branches))
    text = " || ".join(branches)
    for ex in sorted((ser_cond(c) for c in match.get("excludes", []))):
        text = "{} || {}".format(text, ex) if text else ex
    return text


def apply_policy(match: dict, stats: dict):
    """stopword/超短字面量拒绝；返回 (policy_match, dropped[(field, value)])。"""
    kept_branches = []
    dropped = []
    for branch in match.get("any", []):
        kept = []
        for cond in branch.get("all", []):
            value = str(cond.get("value", ""))
            lowered = value.strip().lower()
            # 拒绝/长度规则只作用于正向召回条件；regex 与 not_equals（布尔负项）原样保留
            if cond["operator"] in ("contains", "equals") and (lowered in GENERIC_STOPWORDS or len(value.strip()) < MIN_LITERAL_LEN):
                stats["dropped_conditions"] += 1
                if lowered in GENERIC_STOPWORDS:
                    stats["dropped_stopword"] += 1
                else:
                    stats["dropped_too_short"] += 1
                dropped.append((cond["field"], value))
                continue
            kept.append(cond)
        if kept:
            kept_branches.append({"all": kept})
    return {"any": kept_branches, "excludes": match.get("excludes", [])}, dropped


def collect_anchors(match: dict):
    """召回锚点：contains/equals 取字面量；regex 取提取字面量；分支无正向条件 → no-anchor 桶（附录A §2.3.1）。"""
    anchors = []
    for branch in match.get("any", []):
        positive = False
        for cond in branch.get("all", []):
            if cond["operator"] == "regex":
                lit = _extract_literal_from_regex(cond["value"], min_len=4)
                if lit:
                    positive = True
                    anchors.append({"field": cond["field"], "kind": "regex_literal", "value": lit})
            elif cond["operator"] in ("contains", "equals"):
                positive = True
                anchors.append({"field": cond["field"], "kind": cond["operator"], "value": cond["value"]})
        if not positive:
            anchors.append({"field": "*", "kind": "no-anchor", "value": None})
    return anchors


def norm_name(name: str) -> str:
    return re.sub(r"[^a-z0-9一-鿿]+", "", str(name).lower())


class Merger:
    def __init__(self):
        self.by_key = {}
        self.stats = {
            "accepted": 0, "rejected_rules": 0, "dropped_conditions": 0,
            "dropped_stopword": 0, "dropped_too_short": 0, "demoted": 0,
            "conflicts": 0,
        }
        self.rejected_rule_names = set()
        self.dropped_values_by_name = {}

    def add(self, name, match, source, rejected_conds=None):
        key = norm_name(name)
        if not key:
            return
        policy_match, dropped = apply_policy(match, self.stats)
        key0 = norm_name(name)
        if dropped:
            self.dropped_values_by_name.setdefault(key0, set()).update(dropped)
        if not policy_match["any"]:
            self.stats["rejected_rules"] += 1
            self.rejected_rule_names.add(key0)
            return
        entry = self.by_key.setdefault(key, {"name": name, "sources": set(), "any": [], "excludes": [], "per_source_rules": 0})
        entry["sources"].add(source)
        entry["per_source_rules"] += 1
        entry["any"].extend(policy_match["any"])
        entry["excludes"].extend(policy_match["excludes"])
        if entry["per_source_rules"] > 1:
            self.stats["conflicts"] += 1

    def finalize(self):
        rules = []
        seen_branches = {}
        for key, entry in self.by_key.items():
            # 分支去重（同 literal 重复条件并集）
            branch_map = {}
            for branch in entry["any"]:
                sig = tuple(sorted((c["field"], c["operator"], c["value"]) for c in branch["all"]))
                branch_map[sig] = branch
            any_branches = [branch_map[s] for s in sorted(branch_map)]
            ex_map = {}
            for cond in entry["excludes"]:
                ex_map[(cond["field"], cond["operator"], cond["value"])] = cond
            excludes = [ex_map[k] for k in sorted(ex_map)]
            match = {"any": any_branches, "excludes": excludes}
            canonical = to_human_rule(match)
            confidence = estimate_human_rule_confidence(canonical)
            only_cond = any_branches[0]["all"][0] if len(any_branches) == 1 and len(any_branches[0]["all"]) == 1 else None
            single_generic = (
                only_cond is not None
                and only_cond["operator"] in ("contains", "equals")
                and len(str(only_cond["value"]).strip()) < GENERIC_SINGLE_COND_MAX_LEN
            )
            if single_generic and confidence > DEMOTED_CONFIDENCE_CAP:
                confidence = DEMOTED_CONFIDENCE_CAP
                self.stats["demoted"] += 1
            rules.append({
                "id": "site:" + key,
                "name": entry["name"],
                "match": match,
                "canonical_rule": canonical,
                "confidence": confidence,
                "sources": sorted(entry["sources"]),
                "enabled": True,
                "anchors": collect_anchors(match),
            })
        rules.sort(key=lambda r: r["id"])
        self.stats["accepted"] = len(rules)
        return rules


# --- 源加载器 ---

def load_webapp(path, merger):
    data = json.load(open(path, encoding="utf-8"))
    for name, rule in data.items():
        branches = []
        for field, key in (("header", "headers"), ("body", "html"), ("title", "title")):
            for value in rule.get(key) or []:
                text = str(value).strip()
                if text:
                    branches.append({"all": [{"field": field, "operator": "contains", "value": text}]})
        merger.add(name, {"any": branches, "excludes": []}, "webapp")
    return len(data)


def load_finger_json(path, merger):
    entries = json.load(open(path, encoding="utf-8"))["fingerprint"]
    for it in entries:
        name = it.get("cms") or ""
        method = it.get("method")
        branches = []
        for kw in it.get("keyword") or []:
            text = str(kw).strip()
            if not text:
                continue
            if method == "faviconhash":
                branches.append({"all": [{"field": "icon_hash", "operator": "equals", "value": text}]})
            else:
                field = str(it.get("location") or "body").lower()
                branches.append({"all": [{"field": field, "operator": "contains", "value": text}]})
        merger.add(name, {"any": branches, "excludes": []}, "tools_finger")
    return len(entries)


def _load_human_rule_source(path, source, merger):
    data = json.load(open(path, encoding="utf-8"))
    entries = data.get("fingerprint", data) if isinstance(data, dict) else data
    count = 0
    for it in entries:
        name, expr = it.get("name"), it.get("human_rule", "")
        if not name or not str(expr).strip():
            continue
        match, _rejected = parse_human_rule(str(expr))
        merger.add(name, match, source)
        count += 1
    return count


def load_mongo_export(path, merger):
    return _load_human_rule_source(path, "mongo_export", merger)


def load_extra_rules(path, merger):
    return _load_human_rule_source(path, "custom", merger)


# --- 服务指纹 seed（第5阶段扩展；此处只建映射骨架，端口为弱候选） ---

SERVICE_SEED = [
    ("http", ["http", "www", "http-proxy"], [80, 8080, 8888]),
    ("https", ["https", "ssl/http"], [443, 8443]),
    ("ssh", ["ssh"], [22]),
    ("ftp", ["ftp"], [21]),
    ("smtp", ["smtp", "esmtp"], [25, 465, 587]),
    ("dns", ["dns", "domain"], [53]),
    ("dhcp", ["dhcp", "dhcpc"], [67, 68]),
    ("pop3", ["pop3", "pop"], [110]),
    ("imap", ["imap"], [143, 993]),
    ("smb", ["smb", "microsoft-ds", "netbios-ssn"], [139, 445]),
    ("rdp", ["ms-wbt-server", "rdp", "terminal-server"], [3389]),
    ("vnc", ["vnc", "rfb"], [5900, 5901]),
    ("mysql", ["mysql", "mariadb"], [3306]),
    ("mssql", ["ms-sql-s", "mssql", "sqlserver"], [1433, 1434]),
    ("oracle", ["oracle", "tns"], [1521]),
    ("ldap", ["ldap", "ldaps", "636/tcp"], [389, 636]),
    ("postgres", ["postgresql", "psql"], [5432]),
    ("redis", ["redis"], [6379]),
    ("memcached", ["memcached"], [11211]),
    ("mongodb", ["mongodb"], [27017]),
    ("elasticsearch", ["elasticsearch", "elastic"], [9200, 9300]),
    ("rabbitmq", ["amqp", "rabbitmq"], [5672, 15672]),
    ("modbus", ["modbus", "modbus/tcp"], [502]),
    ("snmp", ["snmp", "snmptrap"], [161, 162]),
    ("telnet", ["telnet"], [23, 2323]),
    ("kerberos", ["kerberos", "kpasswd"], [88, 464, 749]),
    ("winrm", ["wsman", "winrm", "http-winrm"], [5985, 5986]),
    ("proxy", ["squid", "proxy"], [3128, 8080]),
    ("imap-ssl", ["imaps"], [993]),
    ("zabbix", ["zabbix-trapper"], [10051]),
]


def build_service_fingerprints():
    rules = []
    for name, aliases, ports in SERVICE_SEED:
        key = norm_name(name)
        matchers = [{"field": "nmap.service_name", "operator": "equals", "value": alias, "weight": 90} for alias in sorted(set(aliases))]
        matchers.append({"field": "npoc.scheme", "operator": "equals", "value": name, "weight": 100})
        rules.append({
            "id": "service:" + key,
            "name": name,
            "protocol": "tcp",
            "aliases": sorted(set(aliases)),
            "ports": sorted(ports),
            "matchers": matchers,
            "port_confidence": 30,
            "confidence": 90,
            "sources": ["seed"],
            "enabled": True,
        })
    rules.sort(key=lambda r: r["id"])
    return rules


def content_hash(rules):
    blob = "\n".join("{}|{}".format(r["id"], r["canonical_rule"]) for r in rules).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def build_site(args, merger):
    counts = {}
    counts["webapp"] = load_webapp(args.webapp, merger)
    counts["tools_finger"] = load_finger_json(args.finger, merger)
    counts["kscan"] = _load_human_rule_source(args.kscan_file, "kscan_local" if "local" in str(args.kscan_file) else "kscan", merger)
    if args.mongo_export:
        counts["mongo_export"] = load_mongo_export(args.mongo_export, merger)
    for extra in args.extra_rules or []:
        counts["custom"] = counts.get("custom", 0) + load_extra_rules(extra, merger)
    rules = merger.finalize()
    meta = {
        "format": "arl_site_fingerprint_v1",
        "content_hash": content_hash(rules),
        "rule_count": len(rules),
        "sources": counts,
        "policy": {
            "generic_stopwords": sorted(GENERIC_STOPWORDS),
            "min_literal_len": MIN_LITERAL_LEN,
            "generic_single_cond_max_len": GENERIC_SINGLE_COND_MAX_LEN,
            "demoted_confidence_cap": DEMOTED_CONFIDENCE_CAP,
        },
        "stats": dict(merger.stats),
    }
    if args.stamp:
        meta["generated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return {"meta": meta, "fingerprints": rules}


def render_report(site, service_rules) -> str:
    meta = site["meta"]
    no_anchor = sum(1 for r in site["fingerprints"] for a in r["anchors"] if a["kind"] == "no-anchor")
    L = ["# 统一指纹生成报告（build_unified_fingerprints）", ""]
    L.append(f"- 站点规则：**{meta['rule_count']}** 条，content_hash `{meta['content_hash'][:16]}`")
    L.append(f"- 输入计数：`{json.dumps(meta['sources'])}`")
    L.append(f"- 拒绝条件 {meta['stats']['dropped_conditions']}（stopword {meta['stats']['dropped_stopword']} / 超短 {meta['stats']['dropped_too_short']}）；整条拒绝 {meta['stats']['rejected_rules']}；候选降级封顶 {meta['stats']['demoted']}")
    L.append(f"- 同名多源合并（conflicts，保留 sources）：{meta['stats']['conflicts']}")
    L.append(f"- regex 无锚点条件（no-anchor 兜底桶规模）：{no_anchor}")
    L.append(f"- 服务规则（seed，第5阶段扩展）：{len(service_rules)} 条")
    return "\n".join(L) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--webapp", default="app/dicts/webapp.json")
    parser.add_argument("--finger", default="../tools/finger.json")
    parser.add_argument("--kscan-file", default="app/dicts/kscan_fingerprint.local.json")
    parser.add_argument("--mongo-export", default=None, help="Mongo fingerprint 导出 JSON（[{name,human_rule}]）")
    parser.add_argument("--extra-rules", action="append", default=None, help="自定义 name+human_rule 规则文件，可重复")
    parser.add_argument("--site-out", default="app/dicts/site_fingerprints.json")
    parser.add_argument("--service-out", default="app/dicts/service_fingerprints.json")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--stamp", action="store_true", help="写入 generated_at（破坏字节级可重复性，正式发布用）")
    parser.add_argument("--report", default=None)
    args = parser.parse_args(argv)

    merger = Merger()
    site = build_site(args, merger)
    service_rules = build_service_fingerprints()
    report = render_report(site, service_rules)

    if args.dry_run:
        print(report)
        return 0
    with open(args.site_out, "w", encoding="utf-8") as f:
        json.dump(site, f, ensure_ascii=False, indent=1, sort_keys=False)
        f.write("\n")
    with open(args.service_out, "w", encoding="utf-8") as f:
        json.dump({"meta": {
            "format": "arl_service_fingerprint_v1",
            "rule_count": len(service_rules),
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds") if args.stamp else None,
        }, "fingerprints": service_rules}, f, ensure_ascii=False, indent=1)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            f.write(report)
    print(report)
    print("written: {} / {}".format(args.site_out, args.service_out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
