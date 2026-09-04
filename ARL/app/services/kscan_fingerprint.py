"""
kscan 指纹规则内建加载

目标：
- 不依赖外部导入命令
- 优先加载 ARL 内置字典 app/dicts/kscan_fingerprint.json
- 产出 ARL human_rule 并参与现有指纹识别链路
"""
import json
import os
import re
from collections import defaultdict

from app.config import Config
from app.utils import get_logger
from app.fp_common import (
    extract_literal_from_regex as _extract_literal_from_regex,
    split_logic_expression as _split_logic_expression,
    unquote_string as _unquote_string,
)
from .expr import check_expression_with_error

logger = get_logger()


SUPPORTED_FIELDS = {
    "body": "body",
    "header": "header",
    "title": "title",
    "response": "response",
    "url": "url",
    "path": "url",
    "icon": "icon_hash",
    "icon_hash": "icon_hash",
    "iconhash": "icon_hash",
    "faviconhash": "icon_hash",
}

TOKEN_PATTERN = re.compile(
    r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(~=|==|!=|=)\s*("([^"\\]|\\.)*"|-?\d+)\s*$'
)


_CACHE = {
    "file_path": "",
    "mtime": -1,
    "signature": (),
    "rules": [],
    "stats": {},
}
_MISSING_LOGGED = False


def _to_int(value, default_value):
    try:
        return int(value)
    except Exception:
        return default_value


def _escape_human_rule_value(value):
    text = str(value)
    text = text.replace("\\", "\\\\")
    text = text.replace('"', '\\"')
    return text


def _ensure_keyword_list(value):
    """
    将 keyword/keywords/path 字段统一规范为列表
    """
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def _parse_token(raw_token, regex_fallback="literal", min_literal_len=5):
    match = TOKEN_PATTERN.match(raw_token)
    if not match:
        return "", "invalid_token"

    raw_field, op, raw_value = match.group(1), match.group(2), match.group(3)
    field = SUPPORTED_FIELDS.get(str(raw_field).strip().lower(), "")
    if not field:
        return "", "unsupported_field"

    value = _unquote_string(raw_value)
    if op == "~=":
        if regex_fallback != "literal":
            return "", "unsupported_regex"
        value = _extract_literal_from_regex(raw_value, min_len=min_literal_len)
        if not value:
            return "", "regex_no_literal"
        op = "="

    value = _escape_human_rule_value(value)
    return '{}{}"{}"'.format(field, op, value), ""


def _build_standard_json_human_rule(item):
    """
    将标准化 JSON 指纹项转换为 ARL human_rule
    """
    name = str(item.get("name", item.get("cms", ""))).strip()
    if not name:
        return "", "", "missing_name"

    method = str(item.get("method", item.get("type", ""))).strip().lower()
    field = SUPPORTED_FIELDS.get(method, "")
    if not field:
        return name, "", "unsupported_field"

    raw_keywords = item.get("keyword", item.get("keywords", item.get("path", [])))
    keywords = _ensure_keyword_list(raw_keywords)

    fragments = []
    for keyword in keywords:
        keyword = str(keyword).strip()
        if not keyword:
            continue

        keyword = _escape_human_rule_value(keyword)
        if field == "icon_hash":
            fragments.append('{}=="{}"'.format(field, keyword))
        else:
            fragments.append('{}="{}"'.format(field, keyword))

    if not fragments:
        return name, "", "empty_keyword"

    return name, " || ".join(sorted(set(fragments))), ""


def _parse_kscan_expression(expression, regex_fallback="literal", min_literal_len=5):
    tokens, operators = _split_logic_expression(expression)
    if not tokens:
        return "", "empty_expression"
    if len(operators) != len(tokens) - 1:
        return "", "invalid_logic_expression"

    normalized_tokens = []
    for token in tokens:
        normalized, reason = _parse_token(
            token,
            regex_fallback=regex_fallback,
            min_literal_len=min_literal_len,
        )
        if not normalized:
            return "", reason
        normalized_tokens.append(normalized)

    result = normalized_tokens[0]
    for index, op in enumerate(operators):
        result = "{} {} {}".format(result, op, normalized_tokens[index + 1])

    return result, ""


def _config_signature():
    return (
        bool(Config.KSCAN_FINGERPRINT_ENABLE),
        str(Config.KSCAN_FINGERPRINT_FILE),
        str(Config.KSCAN_FINGERPRINT_NAME_PREFIX),
        str(Config.KSCAN_FINGERPRINT_REGEX_FALLBACK),
        _to_int(Config.KSCAN_FINGERPRINT_MIN_LITERAL_LEN, 5),
        _to_int(Config.KSCAN_FINGERPRINT_MAX_RULES_PER_NAME, 30),
        _to_int(Config.KSCAN_FINGERPRINT_MAX_TOTAL_RULES, 12000),
    )


def _load_json_rules(file_path):
    """
    加载预编译 JSON 规则。

    支持三种格式：
    1) {"fingerprint": [{"name": "...", "human_rule": "..."}], "meta": {...}}
    2) [{"name": "...", "human_rule": "..."}]
    3) {"fingerprint": [{"name": "...", "method": "...", "keyword": [...]}]}
    """
    stats = defaultdict(int)
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as fp:
            payload = json.load(fp)
    except Exception as e:
        logger.warning("load kscan fingerprint json failed: {}".format(e))
        return [], {}

    items = []
    if isinstance(payload, dict):
        data = payload.get("fingerprint", [])
        if isinstance(data, list):
            items = data
        meta = payload.get("meta", {})
        if isinstance(meta, dict):
            for key, value in meta.items():
                try:
                    stats[str(key)] = int(value)
                except Exception:
                    continue
    elif isinstance(payload, list):
        items = payload
    else:
        logger.warning("invalid kscan fingerprint json schema: {}".format(type(payload)))
        return [], {}

    rules = []
    seen = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", item.get("cms", ""))).strip()
        human_rule = str(item.get("human_rule", "")).strip()
        if not human_rule:
            name, human_rule, reason = _build_standard_json_human_rule(item)
            if not human_rule:
                if reason:
                    stats["skip_{}".format(reason)] += 1
                continue
            stats["rule_from_standard_json"] += 1
        elif name:
            stats["rule_from_precompiled_json"] += 1
        else:
            stats["skip_missing_name"] += 1
            continue

        key = "{}::{}".format(name, human_rule)
        if key in seen:
            continue
        seen.add(key)

        rules.append({
            "name": name,
            "human_rule": human_rule,
        })

    stats["app_accept"] = len(rules)
    stats["rule_accept"] = len(rules)
    return rules, dict(stats)


def load_kscan_fingerprint_rules():
    """
    加载并缓存 kscan 指纹规则，返回格式：
    [
      {"name": "...", "human_rule": "..."},
      ...
    ]
    """
    global _MISSING_LOGGED

    if not bool(Config.KSCAN_FINGERPRINT_ENABLE):
        return []

    file_path = os.path.abspath(str(Config.KSCAN_FINGERPRINT_FILE).strip())
    if not file_path or not os.path.isfile(file_path):
        if not _MISSING_LOGGED:
            logger.warning("kscan fingerprint file not found: {}".format(file_path))
            _MISSING_LOGGED = True
        return []
    _MISSING_LOGGED = False

    try:
        mtime = int(os.path.getmtime(file_path))
    except Exception:
        mtime = -1

    signature = _config_signature()
    if (
        _CACHE["rules"]
        and _CACHE["file_path"] == file_path
        and _CACHE["mtime"] == mtime
        and _CACHE["signature"] == signature
    ):
        return list(_CACHE["rules"])

    if file_path.lower().endswith(".json"):
        rules, stats = _load_json_rules(file_path)
        _CACHE["file_path"] = file_path
        _CACHE["mtime"] = mtime
        _CACHE["signature"] = signature
        _CACHE["rules"] = list(rules)
        _CACHE["stats"] = dict(stats)
        logger.info(
            "kscan fingerprint loaded(json) file:{} app:{} rule:{}".format(
                file_path,
                stats.get("app_accept", len(rules)),
                stats.get("rule_accept", len(rules)),
            )
        )
        return rules

    name_prefix = str(Config.KSCAN_FINGERPRINT_NAME_PREFIX or "").strip()
    regex_fallback = str(Config.KSCAN_FINGERPRINT_REGEX_FALLBACK or "literal").strip().lower()
    if regex_fallback not in {"none", "literal"}:
        regex_fallback = "literal"
    min_literal_len = max(1, _to_int(Config.KSCAN_FINGERPRINT_MIN_LITERAL_LEN, 5))
    max_rules_per_name = max(1, _to_int(Config.KSCAN_FINGERPRINT_MAX_RULES_PER_NAME, 30))
    max_total_rules = max(0, _to_int(Config.KSCAN_FINGERPRINT_MAX_TOTAL_RULES, 12000))

    stats = defaultdict(int)
    grouped_rules = defaultdict(list)
    grouped_seen = defaultdict(set)

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as fp:
            for raw_line in fp:
                stats["line_total"] += 1
                line = raw_line.strip()
                if not line:
                    stats["line_empty"] += 1
                    continue
                if "\t" not in line:
                    stats["line_no_tab"] += 1
                    continue

                raw_name, raw_expr = line.split("\t", 1)
                app_name = str(raw_name).strip()
                expression = str(raw_expr).strip()
                if not app_name or not expression:
                    stats["line_invalid"] += 1
                    continue

                if name_prefix:
                    app_name = "{}{}".format(name_prefix, app_name)

                normalized, reason = _parse_kscan_expression(
                    expression=expression,
                    regex_fallback=regex_fallback,
                    min_literal_len=min_literal_len,
                )
                if not normalized:
                    stats["skip_{}".format(reason)] += 1
                    continue

                ok, _ = check_expression_with_error(normalized)
                if not ok:
                    stats["skip_invalid_check_expression"] += 1
                    continue

                if normalized in grouped_seen[app_name]:
                    stats["skip_duplicate_rule"] += 1
                    continue

                if len(grouped_rules[app_name]) >= max_rules_per_name:
                    stats["skip_over_max_rules_per_name"] += 1
                    continue

                grouped_rules[app_name].append(normalized)
                grouped_seen[app_name].add(normalized)
                stats["rule_accept"] += 1

                if max_total_rules > 0 and stats["rule_accept"] >= max_total_rules:
                    stats["stop_by_max_total_rules"] += 1
                    break
    except Exception as e:
        logger.warning("load kscan fingerprint failed: {}".format(e))
        return []

    rules = []
    for name in sorted(grouped_rules.keys()):
        rule_list = grouped_rules[name]
        if not rule_list:
            continue
        rules.append({
            "name": name,
            "human_rule": " || ".join(rule_list),
        })

    stats["app_accept"] = len(rules)
    _CACHE["file_path"] = file_path
    _CACHE["mtime"] = mtime
    _CACHE["signature"] = signature
    _CACHE["rules"] = list(rules)
    _CACHE["stats"] = dict(stats)

    logger.info(
        "kscan fingerprint loaded file:{} app:{} rule:{} skip:{} regex_fallback:{} max_total_rules:{}".format(
            file_path,
            stats["app_accept"],
            stats["rule_accept"],
            stats["line_total"] - stats["rule_accept"],
            regex_fallback,
            max_total_rules,
        )
    )
    return rules
