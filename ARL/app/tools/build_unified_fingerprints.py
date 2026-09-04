#!/usr/bin/env python3
"""计划5 第2阶段：统一指纹生成脚本（规范 JSON 生成器）。

输入四路源 → site_fingerprints.json + service_fingerprints.json（规范格式见 05 计划 §五/§六）。
只依赖 app.fp_common（零 xing/celery/Mongo），本地与容器均可 `python3 -m` 直跑。

关键约束：
- 置信度同源：合并后序列化为 canonical human_rule，喂公共层 estimate_human_rule_confidence。
- 泛化控制（review 修正版）：含被拒条件的**整个分支**丢弃（禁止条件级摘除把
  `A && login` 降成 `A` 反而扩大命中面）；分支清空则整条规则拒绝。
- 表达式保守面：源语言无括号（05 附录A 实测 0 处），出现引号外括号即整条拒绝，不做语义猜测；
  `!=` 保留运行时"整串不等"现状语义（意图争议登记第3阶段决策，不顺手改）。
- 确定性：规则按 id 排序、分支/条件稳定序；默认不写时间戳（重复生成字节一致）；
  meta.input_files 记录全部输入 sha256。
- 安全写盘：内存构建 → schema 校验 → 临时文件 → last-good 备份 → 原子替换；
  第二步替换失败回滚第一步。

容器内执行：
  cd /code && python3 -m app.tools.build_unified_fingerprints [--dry-run] [--mongo-export f] [--extra-rules f]
"""
import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone

from app.fp_common import (
    estimate_human_rule_confidence,
    extract_literal_from_regex,
    safe_int,
    split_logic_expression,
)

# 泛化噪声拒绝表：小且可述（附录B 实证词 + 通用 UI 词），宁窄勿宽——宽表本身就是误报源
GENERIC_STOPWORDS = {
    "login", "server", "admin", "welcome", "home", "index of", "download", "search",
    "登录", "系统登录", "主页", "管理登录",
}
GENERIC_SINGLE_COND_MAX_LEN = 8          # 单条件字面量短于此 → 封顶候选
DEMOTED_CONFIDENCE_CAP = 75
MIN_LITERAL_LEN = 3                      # 超短字面量 → 所在分支拒绝
SUPPORTED_FIELDS = {"body", "header", "title", "response", "url", "icon_hash"}
SUPPORTED_OPS = {"contains", "equals", "not_equals", "regex"}

COND_RE = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)\s*(~=|==|!=|=)\s*("([^"\\]|\\.)*"|-?\d+)\s*$')


def unquote(raw: str) -> str:
    if raw.startswith('"') and raw.endswith('"'):
        inner = raw[1:-1]
        return inner.replace('\\\\', '\x00').replace('\\"', '"').replace('\\n', '\n').replace('\\t', '\t').replace('\\r', '\r').replace('\x00', '\\')
    return raw


def quote(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + '"'


# != 保留生产布尔语义（整串不等）——not-contains 意图升级属行为变更，第3阶段带对照决策。
OP_TO_CANON = {"=": "contains", "==": "equals", "!=": "not_equals", "~=": "regex"}
CANON_TO_OP = {v: k for k, v in OP_TO_CANON.items()}


def has_boolean_parentheses(expression: str) -> bool:
    """引号外出现 ( ) 即判不可解析（现行源 0 处；防御未来源引入歧义语法）。"""
    in_quotes = False
    escaped = False
    for ch in expression:
        if in_quotes:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_quotes = False
            continue
        if ch == '"':
            in_quotes = True
        elif ch in "()":
            return True
    return False


def parse_human_rule(expression: str):
    """human_rule → ({"any":[{"all":[cond]}], "excludes":[]}, problems)。

    problems 非空即整条拒绝（括号语法/非法条件/不支持字段一律不猜语义）。
    """
    if has_boolean_parentheses(expression):
        return None, ["parentheses_not_supported"]
    tokens, operators = split_logic_expression(expression)
    groups = [[]]
    for index, token in enumerate(tokens):
        if index > 0 and operators[index - 1] == "||":
            groups.append([])
        groups[-1].append(token)

    any_branches, problems = [], []
    for group in groups:
        conds = []
        for part in group:
            m = COND_RE.match(part.strip())
            if not m:
                problems.append("unparsable_condition")
                continue
            field, op, raw = m.group(1), m.group(2), m.group(3)
            field = field.lower()
            if field not in SUPPORTED_FIELDS:
                problems.append("unsupported_field:" + field)
                continue
            conds.append({"field": field, "operator": OP_TO_CANON[op], "value": unquote(raw)})
        if conds:
            any_branches.append({"all": conds})
    if problems:
        return None, problems
    if not any_branches:
        return None, ["no_valid_condition"]
    return {"any": any_branches, "excludes": []}, []


def to_human_rule(match: dict) -> str:
    """canonical match → 确定性 human_rule 文本（分支/条件稳定序）。"""
    def ser_cond(c):
        return "{}{}{}".format(c["field"], CANON_TO_OP[c["operator"]], quote(c["value"]))

    branches = []
    for branch in match.get("any", []):
        conds = sorted(ser_cond(c) for c in branch.get("all", []))
        if conds:
            branches.append(" && ".join(conds))
    branches = sorted(set(branches))
    text = " || ".join(branches)
    for ex in sorted(ser_cond(c) for c in match.get("excludes", [])):
        text = "{} || {}".format(text, ex) if text else ex
    return text


def branch_is_rejected(branch: dict, stats: dict) -> bool:
    """分支级拒绝：任一正向条件为 stopword/超短字面量，整个分支作废。

    条件级摘除会静默扩大命中面（`A && login` 变 `A`），review 定死的正确语义。
    """
    for cond in branch.get("all", []):
        if cond["operator"] not in ("contains", "equals"):
            continue
        value = str(cond.get("value", ""))
        lowered = value.strip().lower()
        if lowered in GENERIC_STOPWORDS or len(value.strip()) < MIN_LITERAL_LEN:
            stats["dropped_branches"] += 1
            if lowered in GENERIC_STOPWORDS:
                stats["dropped_branches_stopword"] += 1
            else:
                stats["dropped_branches_too_short"] += 1
            return True
    return False


def collect_anchors(match: dict):
    """召回锚点：contains/equals 取字面量；regex 取提取字面量；分支无正向条件 → no-anchor 桶。"""
    anchors = []
    for branch in match.get("any", []):
        positive = False
        for cond in branch.get("all", []):
            if cond["operator"] == "regex":
                lit = extract_literal_from_regex(cond["value"], min_len=4)
                if lit:
                    positive = True
                    anchors.append({"field": cond["field"], "kind": "regex_literal", "value": lit})
            elif cond["operator"] in ("contains", "equals"):
                positive = True
                anchors.append({"field": cond["field"], "kind": cond["operator"], "value": cond["value"]})
        if not positive:
            anchors.append({"field": "*", "kind": "no-anchor", "value": None})
    return anchors


def merge_key(name: str) -> str:
    """合并键：casefold + 去首尾空白 + 内部连续空白并一。标点不清理（A-B 与 AB 是不同产品）。"""
    return re.sub(r"\s+", " ", str(name).strip()).casefold()


class Merger:
    def __init__(self):
        self.by_key = {}
        self.stats = {
            "accepted": 0, "rejected_rules": 0, "malformed_rules": 0,
            "dropped_branches": 0, "dropped_branches_stopword": 0,
            "dropped_branches_too_short": 0, "demoted": 0, "conflicts": 0,
        }
        self.rejected_rule_keys = set()
        self.dropped_branch_values = {}

    def add(self, name, match, source):
        key = merge_key(name)
        if not key:
            return
        kept_branches = []
        for branch in match.get("any", []):
            values = {(c["field"], str(c.get("value", ""))) for c in branch["all"]}
            if branch_is_rejected(branch, self.stats):
                self.dropped_branch_values.setdefault(key, set()).update(values)
                continue
            kept_branches.append({"all": branch["all"], "sources": [source]})
        if not kept_branches:
            self.stats["rejected_rules"] += 1
            self.rejected_rule_keys.add(key)
            return
        entry = self.by_key.setdefault(key, {"name": str(name).strip(), "branches": [], "rule_count": 0})
        entry["branches"].extend(kept_branches)
        entry["rule_count"] += 1
        if entry["rule_count"] > 1:
            self.stats["conflicts"] += 1

    def reject_malformed(self, name):
        self.stats["malformed_rules"] += 1
        self.rejected_rule_keys.add(merge_key(name))

    def finalize(self):
        rules = []
        for key, entry in self.by_key.items():
            branch_map = {}
            for branch in entry["branches"]:
                sig = tuple(sorted((c["field"], c["operator"], c["value"]) for c in branch["all"]))
                existing = branch_map.get(sig)
                if existing is None:
                    branch_map[sig] = {"all": branch["all"], "sources": list(branch["sources"])}
                else:
                    existing["sources"] = sorted(set(existing["sources"]) | set(branch["sources"]))
            any_branches = [
                {"all": branch_map[s]["all"], "sources": sorted(set(branch_map[s]["sources"]))}
                for s in sorted(branch_map)
            ]
            match = {"any": any_branches, "excludes": []}
            canonical = to_human_rule(match)
            confidence = safe_int(estimate_human_rule_confidence(canonical), 70)
            only_branch = any_branches[0] if len(any_branches) == 1 else None
            only_cond = only_branch["all"][0] if only_branch and len(only_branch["all"]) == 1 else None
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
                "sources": sorted({s for b in any_branches for s in b["sources"]}),
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
        if branches:
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
                if field not in SUPPORTED_FIELDS:
                    field = "body"
                branches.append({"all": [{"field": field, "operator": "contains", "value": text}]})
        if branches:
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
        match, problems = parse_human_rule(str(expr))
        if problems:
            merger.reject_malformed(name)
        else:
            merger.add(name, match, source)
        count += 1
    return count


def load_mongo_export(path, merger):
    return _load_human_rule_source(path, "mongo_export", merger)


def load_extra_rules(path, merger):
    return _load_human_rule_source(path, "custom", merger)


# --- 服务指纹 seed_v0（第5阶段以真实 Nmap/NPoC fixture 重建后方可承接识别链路；结构即消费契约） ---
# (name, nmap_service_names, npoc_schemes, transports, nmap_product_hints)
SERVICE_SEED = [
    ("http", ["http", "http-proxy", "www"], ["http"], [{"proto": "tcp", "ports": [80, 8080, 8888]}], []),
    ("https", ["https", "ssl/http"], ["https"], [{"proto": "tcp", "ports": [443, 8443]}], []),
    ("ssh", ["ssh"], ["ssh"], [{"proto": "tcp", "ports": [22]}], ["openssh"]),
    ("ftp", ["ftp"], ["ftp"], [{"proto": "tcp", "ports": [21]}], []),
    ("smtp", ["smtp", "esmtp"], ["smtp"], [{"proto": "tcp", "ports": [25, 465, 587]}], []),
    ("dns", ["domain", "dns"], ["dns"], [{"proto": "udp", "ports": [53]}, {"proto": "tcp", "ports": [53]}], []),
    ("dhcp", ["dhcp", "dhcpc"], [], [{"proto": "udp", "ports": [67, 68]}], []),
    ("pop3", ["pop3", "pop"], ["pop3"], [{"proto": "tcp", "ports": [110]}], []),
    ("imap", ["imap"], ["imap"], [{"proto": "tcp", "ports": [143]}], []),
    ("imaps", ["imaps"], [], [{"proto": "tcp", "ports": [993]}], []),
    ("smb", ["smb", "microsoft-ds", "netbios-ssn"], ["smb"], [{"proto": "tcp", "ports": [139, 445]}], []),
    ("rdp", ["ms-wbt-server", "rdp", "terminal-server"], ["mstsc"], [{"proto": "tcp", "ports": [3389]}], []),
    ("vnc", ["vnc", "rfb"], ["vnc"], [{"proto": "tcp", "ports": [5900, 5901]}], []),
    ("mysql", ["mysql", "mariadb"], ["mysql"], [{"proto": "tcp", "ports": [3306]}], ["mysql"]),
    ("mssql", ["ms-sql-s", "mssql", "sqlserver"], ["mssql"], [{"proto": "tcp", "ports": [1433]}, {"proto": "udp", "ports": [1434]}], []),
    ("oracle", ["oracle", "tns"], ["oracle"], [{"proto": "tcp", "ports": [1521]}], []),
    ("ldap", ["ldap", "ldaps"], ["ldap"], [{"proto": "tcp", "ports": [389, 636]}, {"proto": "udp", "ports": [389]}], []),
    ("postgres", ["postgresql", "psql"], ["pgsql"], [{"proto": "tcp", "ports": [5432]}], ["postgresql"]),
    ("redis", ["redis"], ["redis"], [{"proto": "tcp", "ports": [6379]}], ["redis"]),
    ("memcached", ["memcached"], ["memcached"], [{"proto": "tcp", "ports": [11211]}], []),
    ("mongodb", ["mongodb"], ["mongodb"], [{"proto": "tcp", "ports": [27017]}], []),
    ("elasticsearch", ["elasticsearch", "elastic"], ["elasticsearch"], [{"proto": "tcp", "ports": [9200, 9300]}], []),
    ("rabbitmq", ["amqp", "rabbitmq"], ["amqp"], [{"proto": "tcp", "ports": [5672, 15672]}], []),
    ("modbus", ["modbus", "modbus/tcp"], ["modbus"], [{"proto": "tcp", "ports": [502]}], []),
    ("snmp", ["snmp"], ["snmp"], [{"proto": "udp", "ports": [161, 162]}], []),
    ("telnet", ["telnet"], ["telnet"], [{"proto": "tcp", "ports": [23, 2323]}], []),
    ("kerberos", ["kerberos", "kpasswd", "kerberos-adm"], [], [{"proto": "tcp", "ports": [88, 464, 749]}, {"proto": "udp", "ports": [88]}], []),
    ("winrm", ["wsman", "winrm", "http-winrm"], [], [{"proto": "tcp", "ports": [5985, 5986]}], []),
    ("proxy", ["squid", "proxy"], [], [{"proto": "tcp", "ports": [3128]}], []),
    ("zabbix", ["zabbix-trapper"], [], [{"proto": "tcp", "ports": [10051]}], []),
    ("tftp", ["tftp"], [], [{"proto": "udp", "ports": [69]}], []),
    ("syslog", ["syslog"], [], [{"proto": "udp", "ports": [514]}], []),
    ("ntp", ["ntp", "ntdp"], [], [{"proto": "udp", "ports": [123]}], []),
]


def build_service_fingerprints():
    rules = []
    for name, nmap_names, npoc_schemes, transports, products in SERVICE_SEED:
        rules.append({
            "id": "service:" + merge_key(name).replace(" ", "-"),
            "name": name,
            "transports": transports,
            "matchers": {
                "nmap_service_names": sorted(set(nmap_names)),
                "nmap_product_hints": sorted(products),
                "npoc_schemes": sorted(set(npoc_schemes)),
            },
            # 第5阶段 Matcher 消费契约：npoc > nmap service > product/version > port 弱候选；冲突保留证据
            "resolution": {
                "priority": ["npoc_scheme", "nmap_service_name", "nmap_product_version", "port_only"],
                "port_confidence": 25,
                "conflict_policy": "keep_evidence",
            },
            "confidence": 90,
            "sources": ["seed_v0"],
            "enabled": True,
        })
    rules.sort(key=lambda r: r["id"])
    return rules


# --- schema 校验与原子写盘 ---

def validate_site_document(doc):
    ids = set()
    for rule in doc["fingerprints"]:
        assert isinstance(rule["id"], str) and rule["id"].startswith("site:"), rule.get("id")
        assert rule["id"] not in ids, "duplicate id " + rule["id"]
        ids.add(rule["id"])
        assert isinstance(rule["name"], str) and rule["name"], rule["id"]
        assert isinstance(rule["confidence"], int) and 0 <= rule["confidence"] <= 100, rule["id"]
        assert rule["anchors"], rule["id"]
        assert rule["match"]["any"], rule["id"]
        for branch in rule["match"]["any"]:
            assert branch.get("sources"), rule["id"]
            for cond in branch["all"]:
                assert cond["field"] in SUPPORTED_FIELDS, (rule["id"], cond)
                assert cond["operator"] in SUPPORTED_OPS, (rule["id"], cond)
                assert isinstance(cond["value"], str), rule["id"]
    return True


def validate_service_document(doc):
    for rule in doc["fingerprints"]:
        assert rule["id"].startswith("service:"), rule["id"]
        assert rule["transports"], rule["id"]
        for transport in rule["transports"]:
            assert transport["proto"] in ("tcp", "udp"), rule["id"]
            assert transport["ports"] and all(isinstance(p, int) and 0 < p < 65536 for p in transport["ports"]), rule["id"]
        assert rule["resolution"]["priority"][0] == "npoc_scheme", rule["id"]
    return True


def sha256_file(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def serialize_document(doc, pretty=False):
    """紧凑序列化 + 剔除派生字段（anchors 由运行时 Registry 经 collect_anchors 重算）。

    gzip 产物是提交/分发形态；pretty 仅本地审计用。
    """
    slim = json.loads(json.dumps(doc, ensure_ascii=False))  # deep copy
    if slim.get("fingerprints") and str(slim["fingerprints"][0].get("id", "")).startswith("site:"):
        for rule in slim["fingerprints"]:
            rule.pop("anchors", None)
    if pretty:
        return json.dumps(slim, ensure_ascii=False, indent=1) + "\n"
    return json.dumps(slim, ensure_ascii=False, separators=(",", ":"))


def atomic_write_json(path, doc, compress=False, pretty=False):
    """临时文件 + fsync + last-good 备份 + os.replace；任何异常都不留半成品目标文件。"""
    payload = serialize_document(doc, pretty=pretty)
    mode = "wb" if compress else "w"
    target = path + ".gz" if compress else path
    import gzip
    raw = payload.encode("utf-8")
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".fpbuild_", suffix=".json")
    try:
        if compress:
            with gzip.GzipFile(fileobj=os.fdopen(fd, "wb"), mode="wb", compresslevel=9) as f:
                f.write(raw)
        else:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())
        if os.path.isfile(target):
            with open(target, "rb") as old:
                old_content = old.read()
            with open(target + ".last-good", "wb") as f:
                f.write(old_content)
        os.replace(tmp, target)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def build_site(args, merger):
    counts = {}
    counts["webapp"] = load_webapp(args.webapp, merger)
    counts["tools_finger"] = load_finger_json(args.finger, merger)
    kscan_source = "kscan_local" if "local" in os.path.basename(args.kscan_file) else "kscan"
    counts[kscan_source] = _load_human_rule_source(args.kscan_file, kscan_source, merger)
    inputs = [args.webapp, args.finger, args.kscan_file]
    if args.mongo_export:
        counts["mongo_export"] = load_mongo_export(args.mongo_export, merger)
        inputs.append(args.mongo_export)
    for extra in args.extra_rules or []:
        counts["custom"] = counts.get("custom", 0) + load_extra_rules(extra, merger)
        inputs.append(extra)
    rules = merger.finalize()
    meta = {
        "format": "arl_site_fingerprint_v1",
        "content_hash": hashlib.sha256(
            "\n".join("{}|{}".format(r["id"], r["canonical_rule"]) for r in rules).encode("utf-8")
        ).hexdigest(),
        "rule_count": len(rules),
        "sources": counts,
        "input_files": {path: sha256_file(path) for path in inputs},
        "policy": {
            "generic_stopwords": sorted(GENERIC_STOPWORDS),
            "min_literal_len": MIN_LITERAL_LEN,
            "generic_single_cond_max_len": GENERIC_SINGLE_COND_MAX_LEN,
            "demoted_confidence_cap": DEMOTED_CONFIDENCE_CAP,
            "branch_level_rejection": True,
        },
        "stats": dict(merger.stats),
    }
    if args.stamp:
        meta["generated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return {"meta": meta, "fingerprints": rules}


def render_report(site, service_rules) -> str:
    meta = site["meta"]
    stats = meta["stats"]
    no_anchor = sum(1 for r in site["fingerprints"] for a in r["anchors"] if a["kind"] == "no-anchor")
    L = ["# 统一指纹生成报告（build_unified_fingerprints）", ""]
    L.append(f"- 站点规则：**{meta['rule_count']}** 条，content_hash `{meta['content_hash'][:16]}`")
    L.append(f"- 输入计数：`{json.dumps(meta['sources'], ensure_ascii=False)}`")
    L.append(f"- 分支级拒绝：{stats['dropped_branches']}（stopword {stats['dropped_branches_stopword']} / 超短 {stats['dropped_branches_too_short']}）；整条规则拒绝 {stats['rejected_rules']}；语法非法拒绝 {stats['malformed_rules']}；候选降级封顶 {stats['demoted']}")
    L.append(f"- 同名多源合并（conflicts，分支级 sources 保留）：{stats['conflicts']}")
    L.append(f"- regex 无锚点分支（no-anchor 兜底桶规模）：{no_anchor}")
    L.append(f"- 服务规则：**seed_v0 骨架 {len(service_rules)} 条**（第5阶段以真实 Nmap/NPoC fixture 重建后方可承接识别链路）")
    L.append("- 输入文件 sha256：")
    for name, digest in sorted(meta["input_files"].items()):
        L.append(f"  - `{name}` `{digest[:16]}`")
    return "\n".join(L) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--webapp", default="app/dicts/webapp.json")
    parser.add_argument("--finger", default="tools/finger.json", help="相对容器 /code 仓库布局（review 修正默认命令路径）")
    parser.add_argument("--kscan-file", default="app/dicts/kscan_fingerprint.local.json")
    parser.add_argument("--mongo-export", default=None, help="Mongo fingerprint 导出 JSON（[{name,human_rule}]）")
    parser.add_argument("--extra-rules", action="append", default=None, help="自定义 name+human_rule 规则文件，可重复")
    parser.add_argument("--site-out", default="app/dicts/site_fingerprints.json")
    parser.add_argument("--service-out", default="app/dicts/service_fingerprints.json")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--compress", action="store_true", help="产物写 <path>.gz（提交/分发形态，运行时 Registry 透明读取）")
    parser.add_argument("--pretty", action="store_true", help="人类可读缩进（本地审计用，勿提交）")
    parser.add_argument("--stamp", action="store_true", help="写入 generated_at（破坏字节级可重复性，正式发布用）")
    parser.add_argument("--report", default=None)
    args = parser.parse_args(argv)

    merger = Merger()
    site = build_site(args, merger)
    service_doc = {
        "meta": {"format": "arl_service_fingerprint_v1", "status": "seed_v0", "rule_count": 0},
        "fingerprints": build_service_fingerprints(),
    }
    service_doc["meta"]["rule_count"] = len(service_doc["fingerprints"])
    validate_site_document(site)
    validate_service_document(service_doc)
    report = render_report(site, service_doc["fingerprints"])

    if args.dry_run:
        print(report)
        return 0

    site_target = args.site_out + (".gz" if args.compress else "")
    service_target = args.service_out + (".gz" if args.compress else "")
    site_backup = open(site_target, "rb").read() if os.path.isfile(site_target) else None
    try:
        atomic_write_json(args.site_out, site, compress=args.compress, pretty=args.pretty)
        atomic_write_json(args.service_out, service_doc, compress=args.compress, pretty=args.pretty)
    except Exception:
        if site_backup is not None:
            with open(site_target, "wb") as f:
                f.write(site_backup)
            print("[ERROR] service 写入失败，site 已回滚上一版", file=sys.stderr)
        raise
    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            f.write(report)
    print(report)
    print("written: {} / {}".format(site_target, service_target))
    return 0


if __name__ == "__main__":
    sys.exit(main())
