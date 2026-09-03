#!/usr/bin/env python3
"""校验 WIH 基线是否满足进入结构重构的前置门禁。"""
import argparse
import json
import sys
from pathlib import Path


REQUIRED_STAGES = ("wih_primary_scan", "wih_urlfinder_sensitive")
REQUIRED_METRICS = (
    "p95_elapsed_sec",
    "p95_cpu_elapsed_sec",
    "p95_non_cpu_elapsed_sec",
    "max_rss_peak_mb",
)


def load_baseline(path):
    with Path(path).open("r", encoding="utf-8") as stream:
        payload = json.load(stream)
    if not isinstance(payload, dict):
        raise ValueError("基线文件必须是 JSON 对象")
    return payload


def validate_baseline(payload, target_count=64, min_runs=2):
    errors = []
    warnings = []
    if payload.get("schema_version") != 1:
        errors.append("schema_version 必须为 1")

    tasks = payload.get("tasks")
    if not isinstance(tasks, list):
        errors.append("tasks 必须是列表")
        tasks = []

    target_runs = [
        task for task in tasks
        if isinstance(task, dict) and task.get("target_count") == target_count
    ]
    if len(target_runs) < min_runs:
        errors.append(
            "目标数为 {} 的任务需要至少 {} 轮，当前 {} 轮".format(
                target_count,
                min_runs,
                len(target_runs),
            )
        )

    stage_summary = payload.get("stage_summary")
    if not isinstance(stage_summary, dict):
        errors.append("stage_summary 必须是对象")
        stage_summary = {}

    for stage_name in REQUIRED_STAGES:
        stage = stage_summary.get(stage_name)
        if not isinstance(stage, dict):
            errors.append("缺少阶段 {} 的汇总".format(stage_name))
            continue
        for metric_name in REQUIRED_METRICS:
            if stage.get(metric_name) is None:
                errors.append("阶段 {} 缺少 {}".format(stage_name, metric_name))
        if not stage.get("status_counts"):
            errors.append("阶段 {} 缺少状态统计".format(stage_name))
        if not stage.get("end_reason_counts"):
            errors.append("阶段 {} 缺少结束原因统计".format(stage_name))

    for task in target_runs:
        stages = task.get("stages")
        if not isinstance(stages, list):
            errors.append("任务 {} 缺少 stages".format(task.get("task_id", "unknown")))
            continue
        stage_map = {
            str(stage.get("name", "")): stage
            for stage in stages
            if isinstance(stage, dict)
        }
        for stage_name in REQUIRED_STAGES:
            stage = stage_map.get(stage_name)
            if not stage:
                errors.append(
                    "任务 {} 缺少阶段 {}".format(task.get("task_id", "unknown"), stage_name)
                )
                continue
            if stage.get("budget_sec") is None:
                errors.append(
                    "任务 {} 阶段 {} 缺少预算".format(task.get("task_id", "unknown"), stage_name)
                )
            if not stage.get("status") or not stage.get("end_reason"):
                errors.append(
                    "任务 {} 阶段 {} 缺少状态或结束原因".format(
                        task.get("task_id", "unknown"),
                        stage_name,
                    )
                )

    run_modes = {
        str(task.get("run_mode", "") or "").strip().lower()
        for task in target_runs
        if isinstance(task, dict)
    }
    if run_modes and not {"cold", "hot"}.issubset(run_modes):
        warnings.append("任务数据未同时标注 cold 和 hot 两种运行模式")

    return {
        "ok": not errors,
        "target_count": target_count,
        "required_runs": min_runs,
        "actual_runs": len(target_runs),
        "errors": errors,
        "warnings": warnings,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="校验 WIH 性能基线门禁")
    parser.add_argument("--input", required=True, help="collect_wih_baseline.py 生成的 JSON")
    parser.add_argument("--output", help="输出校验结果 JSON；省略时写入标准输出")
    parser.add_argument("--target-count", type=int, default=64, help="代表性目标数量，默认 64")
    parser.add_argument("--min-runs", type=int, default=2, help="至少需要的运行轮数，默认 2")
    args = parser.parse_args(argv)

    try:
        result = validate_baseline(
            load_baseline(args.input),
            target_count=max(1, args.target_count),
            min_runs=max(1, args.min_runs),
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("校验 WIH 基线失败: {}".format(exc), file=sys.stderr)
        return 2

    output = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        with Path(args.output).open("w", encoding="utf-8") as stream:
            stream.write(output)
    else:
        sys.stdout.write(output)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
