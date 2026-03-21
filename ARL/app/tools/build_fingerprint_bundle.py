#!/usr/bin/env python3
"""
本地生成单文件指纹库

功能说明：
1. 读取多个 JSON 指纹源
2. 统一转换为 ARL human_rule
3. 按名称聚合、去重并生成单一 JSON 文件

说明：
- 该脚本只负责生成本地单文件产物，不要求把外部规则直接提交进仓库
- 生成后的文件可通过 KSCAN_FINGERPRINT_FILE 指向使用
"""
import argparse
import json
import os
import sys
from collections import defaultdict
from datetime import datetime

from app.tools.import_fingerprint import parse_finger_json, load_check_expression


def build_fingerprint_bundle(file_paths, max_rules_per_name=30, max_total_rules=12000):
    """
    将多个指纹源合并为单一规则列表
    """
    try:
        check_expression = load_check_expression()
    except Exception:
        # 本地缺少完整运行依赖时允许降级构建，避免脚本无法用于离线规则整理
        check_expression = None
    merged = defaultdict(list)
    seen = defaultdict(set)
    stats = defaultdict(int)

    for file_path in file_paths:
        file_path = os.path.abspath(str(file_path or "").strip())
        if not file_path or not os.path.isfile(file_path):
            raise FileNotFoundError("fingerprint file not found: {}".format(file_path))

        stats["source_file"] += 1
        finger_map = parse_finger_json(file_path)
        for name, human_rule in finger_map.items():
            name = str(name or "").strip()
            human_rule = str(human_rule or "").strip()
            if not name or not human_rule:
                stats["skip_invalid_item"] += 1
                continue

            if human_rule in seen[name]:
                stats["skip_duplicate_rule"] += 1
                continue

            if len(merged[name]) >= max_rules_per_name:
                stats["skip_over_max_rules_per_name"] += 1
                continue

            if max_total_rules > 0 and stats["rule_accept"] >= max_total_rules:
                stats["stop_by_max_total_rules"] += 1
                break

            candidate = human_rule if not merged[name] else " || ".join(merged[name] + [human_rule])
            if check_expression is not None and not check_expression(candidate):
                stats["skip_invalid_expression"] += 1
                continue

            merged[name].append(human_rule)
            seen[name].add(human_rule)
            stats["rule_accept"] += 1

    items = []
    for name in sorted(merged.keys()):
        rules = merged[name]
        if not rules:
            continue
        items.append({
            "name": name,
            "human_rule": " || ".join(rules),
        })

    stats["app_accept"] = len(items)
    return items, dict(stats)


def write_bundle(output_path, items, stats):
    """
    将合并结果写入单文件 JSON
    """
    payload = {
        "meta": {
            "format": "arl_fingerprint_bundle",
            "generated_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source_count": int(stats.get("source_file", 0)),
            "app_accept": int(stats.get("app_accept", len(items))),
            "rule_accept": int(stats.get("rule_accept", 0)),
        },
        "fingerprint": items,
    }

    output_path = os.path.abspath(output_path)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fp:
        json.dump(payload, fp, ensure_ascii=False, indent=2)


def parse_args():
    """
    解析命令行参数
    """
    parser = argparse.ArgumentParser(description="Build merged fingerprint bundle")
    parser.add_argument(
        "--source",
        action="append",
        required=True,
        help="fingerprint source file, can be passed multiple times",
    )
    parser.add_argument("--output", required=True, help="output json file path")
    parser.add_argument("--max-rules-per-name", type=int, default=30, help="max rules kept per app name")
    parser.add_argument("--max-total-rules", type=int, default=12000, help="max accepted rules, 0 means unlimited")
    parser.add_argument("--dry-run", action="store_true", help="only print summary without writing file")
    return parser.parse_args()


def main():
    """
    脚本入口
    """
    args = parse_args()
    items, stats = build_fingerprint_bundle(
        file_paths=args.source,
        max_rules_per_name=max(1, int(args.max_rules_per_name)),
        max_total_rules=max(0, int(args.max_total_rules)),
    )

    print(
        "fingerprint bundle summary: source_file={} app_accept={} rule_accept={} duplicate_skip={}".format(
            stats.get("source_file", 0),
            stats.get("app_accept", len(items)),
            stats.get("rule_accept", 0),
            stats.get("skip_duplicate_rule", 0),
        )
    )

    if args.dry_run:
        return 0

    write_bundle(args.output, items, stats)
    print("fingerprint bundle written: {}".format(os.path.abspath(args.output)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
