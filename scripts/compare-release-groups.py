#!/usr/bin/env python3
"""离线比较计划 6 发布验收的三组结果。

输入是已经落盘的证据 JSON，不连接 Mongo、Redis、Web API 或外部目标。
比较器验证：

* 三组是否使用同一 revision、镜像和非敏感配置指纹；
* 三组是否覆盖同一目标集合；
* unified+shadow 相对 legacy 的缺失是否有显式、可复核的允许原因；
* stage-gated-rust 与 unified+shadow 的 Endpoint、终态和 WAF 分类是否完全一致。

报告只输出目标哈希、Endpoint 哈希和计数，不把原始目标或 URL 带入报告。

输入最小结构：

{
  "schema_version": 1,
  "metadata": {
    "revision": "...",
    "image_digest": "...",
    "config_fingerprint": "...",
    "target_set_sha256": "..."
  },
  "groups": {
    "legacy": {"targets": [...]},
    "unified_shadow": {"targets": [...]},
    "stage_gated_rust": {"targets": [...]}
  },
  "allowed_legacy_missing": [
    {"target_id_sha256": "...", "endpoint_sha256": "...", "reason": "..."}
  ]
}

每个 target 至少包含 ``target_id``、``endpoints``、``terminal_status`` 和 ``waf``。
Endpoint 优先使用完整 identity 的 ``endpoint_key``；脱敏导出若没有该字段，则按
``(api_type, method, url)`` 生成证据身份，绝不退化为 ``(url, method)``。
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path


GROUPS = ("legacy", "unified_shadow", "stage_gated_rust")
ENDPOINT_FIELDS = (
    "endpoint_key",
    "url",
    "method",
    "api_type",
    "status",
    "degraded_reason",
    "graphql_query_hash",
    "operation_type",
)
METADATA_FIELDS = ("revision", "image_digest", "config_fingerprint", "target_set_sha256")


def _digest(value):
    payload = value if isinstance(value, str) else _canonical_json(value)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _canonical_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _text(value):
    return str(value or "").strip()


def _endpoint_record(raw, group_name, target_hash):
    if not isinstance(raw, dict):
        raise ValueError("{} target {} 含非对象 Endpoint".format(group_name, target_hash))
    url = _text(raw.get("url"))
    method = _text(raw.get("method")).upper()
    api_type = _text(raw.get("api_type")).lower()
    if not url or not method or not api_type:
        raise ValueError(
            "{} target {} 的 Endpoint 缺少 url/method/api_type".format(
                group_name, target_hash
            )
        )
    endpoint_key = _text(raw.get("endpoint_key")) or "{}|{}|{}".format(
        api_type, method, url
    )
    sources = raw.get("sources", [])
    if not isinstance(sources, (list, tuple, set)):
        raise ValueError("{} target {} 的 sources 必须是列表".format(group_name, target_hash))
    return {
        "endpoint_key": endpoint_key,
        "url": url,
        "method": method,
        "api_type": api_type,
        "status": _text(raw.get("status")),
        "degraded_reason": _text(raw.get("degraded_reason")),
        "graphql_query_hash": _text(raw.get("graphql_query_hash")),
        "operation_type": _text(raw.get("operation_type")),
        "sources": sorted({_text(source) for source in sources if _text(source)}),
    }


def _target_summary(raw, group_name):
    if not isinstance(raw, dict):
        raise ValueError("{} 含非对象 target".format(group_name))
    target_id = _text(raw.get("target_id"))
    if not target_id:
        raise ValueError("{} target 缺少 target_id".format(group_name))
    target_hash = _digest(target_id)
    endpoints = raw.get("endpoints")
    if not isinstance(endpoints, list):
        raise ValueError("{} target {} 的 endpoints 必须是列表".format(group_name, target_hash))

    records = []
    identity_keys = set()
    for endpoint in endpoints:
        record = _endpoint_record(endpoint, group_name, target_hash)
        identity = record["endpoint_key"]
        if identity in identity_keys:
            raise ValueError("{} target {} 存在重复 endpoint_key".format(group_name, target_hash))
        identity_keys.add(identity)
        records.append(record)
    records.sort(key=_canonical_json)
    endpoint_hashes = {_digest(record) for record in records}

    terminal_status = _text(raw.get("terminal_status"))
    if not terminal_status:
        raise ValueError("{} target {} 缺少 terminal_status".format(group_name, target_hash))
    waf = raw.get("waf")
    if not isinstance(waf, dict):
        raise ValueError("{} target {} 的 waf 必须是对象".format(group_name, target_hash))

    provided_hash = _text(raw.get("endpoint_hash"))
    computed_hash = _digest(records)
    if provided_hash and provided_hash != computed_hash:
        raise ValueError("{} target {} 的 endpoint_hash 不匹配".format(group_name, target_hash))

    return {
        "target_id_hash": target_hash,
        "endpoint_hash": computed_hash,
        "endpoint_hashes": endpoint_hashes,
        "endpoint_count": len(records),
        "terminal_status": terminal_status,
        "waf_hash": _digest(waf),
    }


def _group_summary(name, group, target_count):
    if not isinstance(group, dict):
        raise ValueError("group {} 必须是对象".format(name))
    targets = group.get("targets")
    if not isinstance(targets, list):
        raise ValueError("group {} 的 targets 必须是列表".format(name))
    if len(targets) != target_count:
        raise ValueError("group {} 目标数为 {}，期望 {}".format(name, len(targets), target_count))

    summary = {}
    for target in targets:
        row = _target_summary(target, name)
        target_hash = row["target_id_hash"]
        if target_hash in summary:
            raise ValueError("group {} 存在重复 target_id".format(name))
        summary[target_hash] = row
    return summary


def _metadata_errors(payload):
    metadata = payload.get("metadata")
    if not isinstance(metadata, dict):
        return ["metadata 必须是对象"]
    return [
        "metadata 缺少 {}".format(field)
        for field in METADATA_FIELDS
        if not _text(metadata.get(field))
    ]


def _metadata_consistent(payload):
    return not _metadata_errors(payload)


def _allowed_missing(payload):
    entries = payload.get("allowed_legacy_missing", [])
    if not isinstance(entries, list):
        raise ValueError("allowed_legacy_missing 必须是列表")
    result = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("allowed_legacy_missing 含非对象条目")
        target_hash = _text(entry.get("target_id_sha256"))
        endpoint_hash = _text(entry.get("endpoint_sha256"))
        reason = _text(entry.get("reason"))
        if not target_hash or not endpoint_hash or not reason:
            raise ValueError("allowed_legacy_missing 条目必须包含 hash 和 reason")
        result.add((target_hash, endpoint_hash))
    return result


def _compare_shadow_legacy(legacy, shadow, allowed):
    missing = []
    added = []
    allowed_missing = []
    for target_hash in sorted(legacy):
        legacy_endpoints = legacy[target_hash]["endpoint_hashes"]
        shadow_endpoints = shadow[target_hash]["endpoint_hashes"]
        for endpoint_hash in sorted(legacy_endpoints - shadow_endpoints):
            item = (target_hash, endpoint_hash)
            if item in allowed:
                allowed_missing.append(item)
            else:
                missing.append(item)
        added.extend(
            (target_hash, endpoint_hash)
            for endpoint_hash in sorted(shadow_endpoints - legacy_endpoints)
        )
    return {
        "ok": not missing,
        "missing_count": len(missing),
        "allowed_missing_count": len(allowed_missing),
        "added_count": len(added),
        "missing_hashes": [list(item) for item in missing],
        "allowed_missing_hashes": [list(item) for item in allowed_missing],
        "added_hashes": [list(item) for item in added],
    }


def _compare_rust_shadow(shadow, rust):
    mismatches = []
    for target_hash in sorted(shadow):
        shadow_row = shadow[target_hash]
        rust_row = rust[target_hash]
        fields = ("endpoint_hash", "terminal_status", "waf_hash")
        changed = [field for field in fields if shadow_row[field] != rust_row[field]]
        if changed:
            mismatches.append({"target_id_hash": target_hash, "fields": changed})
    return {
        "ok": not mismatches,
        "mismatch_count": len(mismatches),
        "mismatches": mismatches,
    }


def compare_release_groups(payload, target_count=40):
    errors = []
    if not isinstance(payload, dict):
        raise ValueError("输入必须是 JSON 对象")
    if payload.get("schema_version") != 1:
        errors.append("schema_version 必须为 1")
    errors.extend(_metadata_errors(payload))
    try:
        allowed = _allowed_missing(payload)
        groups = payload.get("groups")
        if not isinstance(groups, dict):
            raise ValueError("groups 必须是对象")
        missing_groups = [name for name in GROUPS if name not in groups]
        if missing_groups:
            raise ValueError("缺少 group: {}".format(",".join(missing_groups)))
        summaries = {
            name: _group_summary(name, groups[name], target_count)
            for name in GROUPS
        }
    except ValueError as exc:
        errors.append(str(exc))
        summaries = {}

    if not summaries:
        return {
            "schema_version": 1,
            "ok": False,
            "target_count": target_count,
            "errors": errors,
            "groups": {},
        }

    target_sets = {name: set(value) for name, value in summaries.items()}
    common_targets = target_sets[GROUPS[0]]
    for name in GROUPS[1:]:
        if target_sets[name] != common_targets:
            errors.append("{} 与 legacy 的目标集合不一致".format(name))

    metadata_ok = _metadata_consistent(payload)
    if not metadata_ok:
        errors.append("metadata 在四个字段上不一致")

    if all(name in summaries for name in GROUPS) and all(
        target_sets[name] == common_targets for name in GROUPS
    ):
        shadow_legacy = _compare_shadow_legacy(
            summaries["legacy"], summaries["unified_shadow"], allowed
        )
        rust_shadow = _compare_rust_shadow(
            summaries["unified_shadow"], summaries["stage_gated_rust"]
        )
    else:
        shadow_legacy = {"ok": False, "error": "目标集合无法对齐"}
        rust_shadow = {"ok": False, "error": "目标集合无法对齐"}

    group_report = {}
    for name, summary in summaries.items():
        group_report[name] = {
            "target_count": len(summary),
            "endpoint_total": sum(row["endpoint_count"] for row in summary.values()),
            "endpoint_hash": _digest(
                sorted(
                    (target_hash, row["endpoint_hash"])
                    for target_hash, row in summary.items()
                )
            ),
        }

    ok = not errors and shadow_legacy["ok"] and rust_shadow["ok"]
    return {
        "schema_version": 1,
        "ok": ok,
        "target_count": target_count,
        "metadata_consistent": metadata_ok,
        "errors": errors,
        "groups": group_report,
        "shadow_vs_legacy": shadow_legacy,
        "rust_vs_shadow": rust_shadow,
    }


def _load(path):
    with Path(path).open("r", encoding="utf-8") as stream:
        return json.load(stream)


def main(argv=None):
    parser = argparse.ArgumentParser(description="离线比较 API 发布三组结果")
    parser.add_argument("--input", required=True, help="三组结果证据 JSON")
    parser.add_argument("--target-count", type=int, default=40)
    parser.add_argument("--output", help="输出报告 JSON；省略时写入标准输出")
    args = parser.parse_args(argv)

    try:
        report = compare_release_groups(_load(args.input), target_count=max(1, args.target_count))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("比较发布三组结果失败: {}".format(exc), file=sys.stderr)
        return 2

    output = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output)
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
