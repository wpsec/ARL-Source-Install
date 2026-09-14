#!/usr/bin/env python3
"""将 dt 的 YAML POC 导入为 ARL-NPoC 的规范化源码。

导入器只处理 rules/*.yaml，支持 zip 文件和 rules 目录。输出内容是确定性的，
因此可以在升级规则源后重复运行并通过哈希审计变化。
"""

import argparse
import ast
import copy
import hashlib
import json
import os
import re
import sys
import zipfile
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_ROOT = ROOT / "xing" / "pocs"
sys.path.insert(0, str(ROOT))
from xing.yaml_poc import _ExpressionEvaluator, _looks_like_variable_expression
KNOWN_REPAIRS = {
    "poc-yaml-gwt-system-externalapi-xgi-sqli.yaml",
    "poc-yaml-elber-wayber-analog-digital-audio-password-reset.yaml",
}
HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "MOVE"}
SEVERITIES = {"info", "low", "medium", "high", "critical"}
ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+@-]*$")
PARTIAL_RUNTIME_FUNCTIONS = {
    "java_dns_url_gadget",
    "check_ssh_terrapin_attack",
    "check_fastcgi_unauth",
    "check_vmware_aria_static_ssh_key",
    "check_rpc_nfs_unauth",
    "check_mongodb_unauth",
}
SUPPORTED_RUNTIME_METHODS = {
    "archive.Add",
    "archive.Build",
    "conn.Close",
    "conn.ReadLine",
    "conn.ReadStr",
    "conn.WriteStr",
    "reverse.Domain",
    "reverse.Sleep",
    "reverse.Url",
    "reverse.Verify",
    "zip_arch.Add",
    "zip_arch.Build",
}


class RuleError(ValueError):
    """可报告给 manifest 的规则错误。"""


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def repair_source(source_name, content):
    """只修复已确认的两条 YAML 语法错误，避免改变其它规则语义。"""
    basename = os.path.basename(source_name)
    if basename not in KNOWN_REPAIRS:
        return content, []

    repaired = content
    reasons = []
    if basename == "poc-yaml-gwt-system-externalapi-xgi-sqli.yaml":
        if "\t" in repaired:
            repaired = repaired.replace("\t", r"\t")
            reasons.append("double-quoted expression 中的字面制表符转义")
    elif basename == "poc-yaml-elber-wayber-analog-digital-audio-password-reset.yaml":
        if r"\x3a" in repaired:
            repaired = repaired.replace(r"\x3a", r"\u003a")
            reasons.append("YAML double-quoted scalar 不支持的 \\x3a 替换为 Unicode 冒号")
        if "\t" in repaired:
            repaired = repaired.replace("\t", r"\t")
            reasons.append("double-quoted expression 中的字面制表符转义")
    return repaired, reasons


def _as_string(value, field_name, allow_empty=False):
    if value is None:
        if allow_empty:
            return ""
        raise RuleError("{} 不能为空".format(field_name))
    value = str(value).strip()
    if not value and not allow_empty:
        raise RuleError("{} 不能为空".format(field_name))
    return value


def _normalize_tags(value):
    if value is None:
        return []
    if isinstance(value, str):
        values = value.split(",")
    elif isinstance(value, (list, tuple, set)):
        values = value
    else:
        raise RuleError("info.tags 必须是字符串或列表")
    result = []
    seen = set()
    for item in values:
        text = str(item or "").strip()
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result


def _normalize_info(info):
    if not isinstance(info, dict):
        raise RuleError("info 必须是对象")
    normalized = copy.deepcopy(info)
    normalized["name"] = _as_string(info.get("name"), "info.name")
    severity = str(info.get("severity", "info") or "info").strip().lower()
    if severity not in SEVERITIES:
        raise RuleError("不支持的 severity: {}".format(severity))
    normalized["severity"] = severity
    normalized["tags"] = _normalize_tags(info.get("tags"))
    if "finger" not in normalized or normalized["finger"] is None:
        normalized["finger"] = ""
    elif isinstance(normalized["finger"], (list, tuple)):
        normalized["finger"] = ",".join(str(item).strip() for item in normalized["finger"] if str(item).strip())
    else:
        normalized["finger"] = str(normalized["finger"]).strip()
    return normalized


def _normalize_headers(headers):
    if headers is None:
        return {}
    if not isinstance(headers, dict):
        raise RuleError("request.headers 必须是对象")
    return {str(key): value for key, value in headers.items()}


def _normalize_files(files):
    if files is None:
        return None
    if not isinstance(files, dict):
        raise RuleError("request.files 必须是对象")
    normalized = copy.deepcopy(files)
    for field, value in normalized.items():
        if not isinstance(value, dict):
            raise RuleError("request.files.{} 必须是对象".format(field))
        if "filename" not in value and "name" in value:
            value["filename"] = value.pop("name")
        if "content" not in value and "data" in value:
            value["content"] = value.pop("data")
        if "filename" not in value:
            value["filename"] = "file.bin"
        if "content" not in value:
            value["content"] = ""
    return normalized


def _normalize_request(request, request_index, transport):
    if not isinstance(request, dict):
        raise RuleError("{} 请求必须是对象".format(request_index))
    item = copy.deepcopy(request)

    typo_methods = [key for key in ("mehod", "methpd") if key in item]
    if typo_methods:
        if "method" in item or len(typo_methods) != 1:
            raise RuleError("{} method 拼写字段存在歧义".format(request_index))
        item["method"] = item.pop(typo_methods[0])

    if "body" in item and "data" not in item:
        item["data"] = item.pop("body")
    if "Content-Type" in item:
        headers = _normalize_headers(item.get("headers"))
        headers.setdefault("Content-Type", item.pop("Content-Type"))
        item["headers"] = headers
    elif "headers" in item:
        item["headers"] = _normalize_headers(item.get("headers"))
    if "files" in item:
        item["files"] = _normalize_files(item.get("files"))

    is_tcp = "rawTCP" in item
    if transport == "http" and not is_tcp:
        if "method" not in item:
            if "raw" not in item:
                raise RuleError("{} 缺少 method".format(request_index))
        else:
            method = str(item["method"] or "").strip().upper()
            if method not in HTTP_METHODS:
                raise RuleError("{} 不支持 HTTP method: {}".format(request_index, method))
            item["method"] = method
        if "raw" not in item and not any(item.get(key) is not None for key in ("path", "rawPath", "paths")):
            raise RuleError("{} 缺少 path/rawPath/paths".format(request_index))
    elif is_tcp:
        if not item.get("rawTCP"):
            raise RuleError("{} rawTCP 不能为空".format(request_index))
    else:
        if "method" not in item and "raw" not in item and not isinstance(item.get("expression"), list):
            raise RuleError("{} TCP 请求缺少 rawTCP/raw/data".format(request_index))
        if "method" in item:
            method = str(item["method"] or "").strip().upper()
            if method not in HTTP_METHODS:
                raise RuleError("{} 不支持 HTTP method: {}".format(request_index, method))
            item["method"] = method

    expression = item.get("expression")
    if not expression:
        raise RuleError("{} 缺少 expression".format(request_index))
    if not isinstance(expression, (str, list)):
        raise RuleError("{} expression 类型不支持".format(request_index))
    if isinstance(expression, list) and any(
        not isinstance(value, str) or not value.strip() for value in expression
    ):
        raise RuleError("{} expression 列表包含空值或非字符串".format(request_index))
    return item


def _validate_expressions(rule):
    """在导入阶段复用运行时 AST 门禁，避免规则运行时才暴露语法错误。"""
    variables = rule.get("variables") or {}
    for name, value in variables.items():
        values = value.splitlines() if isinstance(value, str) else [value]
        for line in values:
            if isinstance(line, str) and _looks_like_variable_expression(line, variables):
                _ExpressionEvaluator.parse(line)

    def validate_request(request):
        if not isinstance(request, dict):
            return
        expressions = request.get("expression")
        expressions = expressions if isinstance(expressions, list) else [expressions]
        for expression in expressions:
            if expression is not None:
                _ExpressionEvaluator.parse(expression)
        for output in request.get("output") or []:
            _ExpressionEvaluator.parse(output)

    first_request = rule.get("firstRequest")
    if first_request:
        validate_request(first_request)
    for index, request in enumerate(rule.get("requests") or []):
        validate_request(request)
    for index, request in enumerate(rule.get("tcpRequests") or []):
        validate_request(request)


def _runtime_capability(rule):
    """记录规则是否会在运行时产生 partial，防止特殊能力被静默忽略。"""
    function_names = set()
    expressions = []
    variables = rule.get("variables") or {}
    for value in variables.values():
        values = value.splitlines() if isinstance(value, str) else [value]
        expressions.extend(
            item for item in values
            if isinstance(item, str) and _looks_like_variable_expression(item, variables)
        )
    request_items = []
    if isinstance(rule.get("firstRequest"), dict):
        request_items.append(rule["firstRequest"])
    request_items.extend(list(rule.get("requests") or []))
    request_items.extend(list(rule.get("tcpRequests") or []))
    for request in request_items:
        if not isinstance(request, dict):
            continue
        values = request.get("expression")
        expressions.extend(values if isinstance(values, list) else [values])
        expressions.extend(request.get("output") or [])
    for expression in expressions:
        if not isinstance(expression, str):
            continue
        tree = _ExpressionEvaluator.parse(expression)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name):
                function_names.add(node.func.id)
            elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                function_names.add("{}.{}".format(node.func.value.id, node.func.attr))
    unsupported = sorted(
        function_names - _ExpressionEvaluator.FUNCTIONS - SUPPORTED_RUNTIME_METHODS
    )
    partial = sorted(set(unsupported) | (function_names & PARTIAL_RUNTIME_FUNCTIONS))
    return ("partial" if partial else "full"), sorted(function_names), partial


def normalize_rule(data):
    if not isinstance(data, dict):
        raise RuleError("规则根节点必须是对象")
    source = copy.deepcopy(data)
    rule_id = _as_string(source.get("id"), "id")
    if not ID_PATTERN.fullmatch(rule_id):
        raise RuleError("id 含有不安全字符")

    if "variables" in source and "variabels" in source:
        raise RuleError("variables 与 variabels 同时存在")
    if "variables" not in source and "variabels" in source:
        source["variables"] = source.pop("variabels")
    variables = source.get("variables", {})
    if variables is None:
        variables = {}
    if not isinstance(variables, dict):
        raise RuleError("variables 必须是对象")

    if "requests" in source and isinstance(source["requests"], dict):
        source["requests"] = [source["requests"]]
    if "tcpRequests" in source and isinstance(source["tcpRequests"], dict):
        source["tcpRequests"] = [source["tcpRequests"]]
    requests = source.get("requests") or []
    tcp_requests = source.get("tcpRequests") or []
    if not isinstance(requests, list) or not isinstance(tcp_requests, list):
        raise RuleError("requests/tcpRequests 必须是列表")
    if not requests and not tcp_requests:
        raise RuleError("规则没有请求列表")

    transport = str(source.get("transport", "") or "").strip().lower()
    if not transport:
        transport = "tcp" if tcp_requests or any(isinstance(item, dict) and item.get("rawTCP") for item in requests) else "http"
    if transport not in {"http", "tcp"}:
        raise RuleError("不支持的 transport: {}".format(transport))
    normalized = copy.deepcopy(source)
    normalized["id"] = rule_id
    normalized["info"] = _normalize_info(source.get("info"))
    normalized["variables"] = variables
    normalized["transport"] = transport
    normalized_requests = [
        _normalize_request(
            item,
            "requests[{}]".format(index),
            "tcp" if isinstance(item, dict) and item.get("rawTCP") else "http",
        )
        for index, item in enumerate(requests)
    ]
    normalized_tcp_requests = [
        _normalize_request(item, "tcpRequests[{}]".format(index), "tcp")
        for index, item in enumerate(tcp_requests)
    ]
    if normalized_requests:
        normalized["requests"] = normalized_requests
    else:
        normalized.pop("requests", None)
    if normalized_tcp_requests:
        normalized["tcpRequests"] = normalized_tcp_requests
    else:
        normalized.pop("tcpRequests", None)
    if "firstRequest" in source:
        if not isinstance(source["firstRequest"], dict):
            raise RuleError("firstRequest 必须是对象")
        normalized["firstRequest"] = _normalize_request(
            source["firstRequest"], "firstRequest", "http"
        )
    _validate_expressions(normalized)
    return normalized


def canonical_bytes(rule):
    return json.dumps(rule, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def dedup_bytes(rule):
    """忽略稳定 ID 后比较规则正文，才能把同内容不同 ID 记录为 alias。"""
    content = copy.deepcopy(rule)
    content.pop("id", None)
    return canonical_bytes(content)


def _read_sources(input_path):
    input_path = Path(input_path).expanduser().resolve()
    if input_path.is_file() and zipfile.is_zipfile(str(input_path)):
        with zipfile.ZipFile(str(input_path)) as archive:
            names = sorted(
                name for name in archive.namelist()
                if name.startswith("rules/") and name.endswith((".yaml", ".yml")) and not name.endswith("/")
            )
            for name in names:
                yield name, archive.read(name)
        return

    if input_path.is_dir():
        rules_root = input_path / "rules" if (input_path / "rules").is_dir() else input_path
        for path in sorted(rules_root.rglob("*.yaml")) + sorted(rules_root.rglob("*.yml")):
            if path.is_file():
                yield str(Path("rules") / path.relative_to(rules_root)), path.read_bytes()
        return

    raise FileNotFoundError("输入不是 zip 文件或目录: {}".format(input_path))


def import_rules(input_path, output_root=DEFAULT_OUTPUT_ROOT):
    output_root = Path(output_root).expanduser().resolve()
    yaml_root = output_root / "yaml"
    yaml_root.mkdir(parents=True, exist_ok=True)
    previous_manifest = {}
    previous_manifest_path = output_root / "manifest.json"
    if previous_manifest_path.is_file():
        try:
            previous_manifest = json.loads(previous_manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            previous_manifest = {}
    entries = []
    by_content_hash = {}
    seen_rule_ids = set()
    repair_count = 0

    for source_path, raw_bytes in _read_sources(input_path):
        source_hash = sha256_bytes(raw_bytes)
        entry = {
            "source_path": source_path,
            "source_sha256": source_hash,
            "engine": "yaml",
            "source": "dt",
        }
        try:
            raw_text = raw_bytes.decode("utf-8")
            repaired_text, repairs = repair_source(source_path, raw_text)
            if repairs:
                repair_count += 1
                entry["repairs"] = repairs
            data = yaml.safe_load(repaired_text)
            rule = normalize_rule(data)
            rule_id = rule["id"]
            canonical_hash = sha256_bytes(canonical_bytes(rule))
            dedup_hash = sha256_bytes(dedup_bytes(rule))
            runtime_capability, runtime_functions, partial_functions = _runtime_capability(rule)
            canonical_path = Path("yaml") / (rule_id + ".yaml")
            entry.update({
                "rule_id": rule_id,
                "canonical_path": str(canonical_path),
                "canonical_sha256": canonical_hash,
                "dedup_sha256": dedup_hash,
                "severity": rule["info"]["severity"],
                "tags": rule["info"]["tags"],
                "finger": rule["info"].get("finger", ""),
                "runtime_capability": runtime_capability,
                "runtime_functions": runtime_functions,
            })
            if partial_functions:
                entry["partial_functions"] = partial_functions
            if rule_id in seen_rule_ids:
                entry["status"] = "quarantine"
                entry["reason"] = "规则 ID 重复，不能生成唯一执行实体"
                entries.append(entry)
                continue
            seen_rule_ids.add(rule_id)
            previous = by_content_hash.get(dedup_hash)
            if previous:
                entry["status"] = "duplicate"
                entry["alias_of"] = previous["rule_id"]
                entry["reason"] = "规范化内容与 {} 完全相同".format(previous["rule_id"])
                previous.setdefault("aliases", []).append(rule_id)
            else:
                by_content_hash[dedup_hash] = entry
                entry["status"] = "ready"
                entry["aliases"] = []
                entry["reason"] = "规范化导入"
                target = output_root / canonical_path
                canonical_text = yaml.safe_dump(
                    rule, allow_unicode=True, sort_keys=False, default_flow_style=False
                )
                target.write_text(canonical_text, encoding="utf-8")
                entry["canonical_file_sha256"] = sha256_bytes(canonical_text.encode("utf-8"))
        except Exception as exc:
            entry["status"] = "quarantine"
            entry["reason"] = str(exc)[:500]
        entries.append(entry)

    entries.sort(key=lambda item: item["source_path"])
    status_counts = {}
    capability_counts = {}
    for entry in entries:
        status = entry["status"]
        status_counts[status] = status_counts.get(status, 0) + 1
        capability = entry.get("runtime_capability", "full")
        capability_counts[capability] = capability_counts.get(capability, 0) + 1
    manifest = {
        "schema_version": 1,
        "source": "dt",
        "source_input": Path(input_path).expanduser().name,
        # 三个计数分别回答“源规则有多少、实际执行实体有多少、别名有多少”，
        # 避免把精确去重误读为静默丢弃规则。
        "source_count": len(entries),
        "execution_entity_count": status_counts.get("ready", 0),
        "alias_count": status_counts.get("duplicate", 0),
        "rule_count": len(entries),
        "ready_count": status_counts.get("ready", 0),
        "duplicate_count": status_counts.get("duplicate", 0),
        "quarantine_count": status_counts.get("quarantine", 0),
        "repair_count": repair_count,
        "runtime_capability_counts": capability_counts,
        "entries": entries,
    }
    current_paths = {
        str(entry.get("canonical_path"))
        for entry in entries
        if entry.get("status") == "ready"
    }
    for old_entry in previous_manifest.get("entries", []):
        old_relative = str(old_entry.get("canonical_path") or "")
        old_path = (output_root / old_relative).resolve()
        if (
            old_relative
            and old_relative not in current_paths
            and old_path.parent == yaml_root
            and old_path.suffix in {".yaml", ".yml"}
            and old_path.is_file()
        ):
            # 只清理上一次由本导入器生成、现在已不再被 ready 条目引用的文件。
            old_path.unlink()
    (output_root / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="dt 的 zip 文件或 rules 目录")
    parser.add_argument("--output-root", default=str(DEFAULT_OUTPUT_ROOT), help="输出 pocs 目录")
    args = parser.parse_args(argv)
    manifest = import_rules(args.input, args.output_root)
    print(json.dumps({
        "rule_count": manifest["rule_count"],
        "ready_count": manifest["ready_count"],
        "duplicate_count": manifest["duplicate_count"],
        "quarantine_count": manifest["quarantine_count"],
        "repair_count": manifest["repair_count"],
    }, ensure_ascii=False))
    return 0 if manifest["quarantine_count"] == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
