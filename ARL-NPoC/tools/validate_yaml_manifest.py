#!/usr/bin/env python3
"""校验 YAML POC 清单、哈希、隔离状态和源码覆盖范围。"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

import yaml


def _canonical_hash(rule):
    data = json.dumps(rule, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _dedup_hash(rule):
    content = dict(rule)
    content.pop("id", None)
    return _canonical_hash(content)


def validate(output_root):
    root = Path(output_root).expanduser().resolve()
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entries = manifest.get("entries") or []
    errors = []
    all_ids = [entry.get("rule_id") for entry in entries]
    if len(all_ids) != len(set(all_ids)):
        errors.append("manifest 中存在重复 rule_id")
    if manifest.get("rule_count") != len(entries):
        errors.append("rule_count 与 entries 数量不一致")

    referenced = set()
    hashes = {}
    status_counts = {}
    for entry in entries:
        status = entry.get("status")
        status_counts[status] = status_counts.get(status, 0) + 1
        relative = Path(str(entry.get("canonical_path") or ""))
        if status != "ready":
            continue
        path = (root / relative).resolve()
        yaml_root = (root / "yaml").resolve()
        if yaml_root not in path.parents or path.suffix not in {".yaml", ".yml"}:
            errors.append("ready 规则路径越界: {}".format(relative))
            continue
        if not path.is_file():
            errors.append("ready 规则文件不存在: {}".format(relative))
            continue
        referenced.add(path)
        try:
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
            canonical_hash = _canonical_hash(rule)
            dedup_hash = _dedup_hash(rule)
        except (OSError, UnicodeError, ValueError, yaml.YAMLError) as exc:
            errors.append("规则无法读取 {}: {}".format(relative, str(exc)[:160]))
            continue
        if entry.get("canonical_sha256") != canonical_hash:
            errors.append("规范化哈希不匹配: {}".format(relative))
        previous = hashes.get(dedup_hash)
        if previous:
            errors.append("ready 规则存在重复规范化哈希: {} 与 {}".format(previous, relative))
        hashes[dedup_hash] = str(relative)
        file_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        if entry.get("canonical_file_sha256") and entry["canonical_file_sha256"] != file_hash:
            errors.append("规范文件哈希不匹配: {}".format(relative))

    source_files = {
        path.resolve()
        for path in (root / "yaml").rglob("*.yaml")
        if path.is_file() and "legacy" not in path.parts
    }
    unreferenced = source_files - referenced
    if unreferenced:
        errors.append("存在未被主 manifest 引用的 dt YAML: {}".format(len(unreferenced)))

    report = {
        "rule_count": len(entries),
        "ready_count": status_counts.get("ready", 0),
        "duplicate_count": status_counts.get("duplicate", 0),
        "quarantine_count": status_counts.get("quarantine", 0),
        "referenced_ready_files": len(referenced),
        "unreferenced_dt_files": len(unreferenced),
        "errors": errors,
    }
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", required=True)
    args = parser.parse_args(argv)
    report = validate(args.output_root)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 1 if report["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
