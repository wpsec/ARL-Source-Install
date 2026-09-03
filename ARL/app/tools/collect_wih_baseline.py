#!/usr/bin/env python3
"""从任务导出数据生成可复算的 WIH 阶段基线。

输入可以是任务文档列表，也可以是接口常见的 ``{"items": [...]}`` 包装格式。
工具只读取已落盘的任务数据，不连接 Mongo、Redis 或外部扫描器。
"""
import argparse
import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path


def _as_number(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _as_count(value):
    number = _as_number(value)
    return max(0, int(number)) if number is not None else None


def _percentile(values, percentile=0.95):
    numbers = sorted(value for value in values if value is not None)
    if not numbers:
        return None
    index = max(0, min(len(numbers) - 1, math.ceil(len(numbers) * percentile) - 1))
    return round(numbers[index], 6)


def _parse_timestamp(value):
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _load_task_items(path):
    with Path(path).open("r", encoding="utf-8") as stream:
        payload = json.load(stream)

    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        raise ValueError("输入必须是任务对象列表或对象包装")

    for key in ("items", "tasks", "data"):
        nested = payload.get(key)
        if isinstance(nested, list):
            return [item for item in nested if isinstance(item, dict)]
        if isinstance(nested, dict):
            for nested_key in ("items", "tasks"):
                nested_items = nested.get(nested_key)
                if isinstance(nested_items, list):
                    return [item for item in nested_items if isinstance(item, dict)]
    return [payload]


def _service_items(task):
    services = task.get("service")
    return [item for item in services if isinstance(item, dict)] if isinstance(services, list) else []


def _stage_is_aggregate(item, skipped_parent_names):
    stage_kind = str(item.get("stage_kind", "") or "").strip().lower()
    stage_name = str(item.get("name", "") or "").strip().lower()
    return stage_kind == "aggregate" or stage_name in skipped_parent_names


def _stage_row(item, aggregate):
    metrics = item.get("metrics")
    metrics = dict(metrics) if isinstance(metrics, dict) else {}
    elapsed = _as_number(item.get("elapsed"))
    cpu_elapsed = _as_number(metrics.get("cpu_elapsed_sec"))
    non_cpu_elapsed = _as_number(metrics.get("non_cpu_elapsed_sec"))
    network_wait = _as_number(metrics.get("network_wait_sec"))
    rss_peak = _as_number(metrics.get("rss_peak_mb"))
    return {
        "name": str(item.get("name", "") or "").strip(),
        "elapsed_sec": elapsed,
        "status": str(item.get("status", "") or "").strip().lower() or "unknown",
        "end_reason": str(item.get("end_reason", "") or "").strip().lower() or "unknown",
        "input_count": _as_count(item.get("input_count")),
        "output_count": _as_count(item.get("output_count")),
        "budget_sec": _as_number(item.get("budget_sec")),
        "cpu_elapsed_sec": cpu_elapsed,
        "non_cpu_elapsed_sec": non_cpu_elapsed,
        "network_wait_sec": network_wait,
        "network_wait_estimated_sec": non_cpu_elapsed if network_wait is None else None,
        "rss_peak_mb": rss_peak,
        "aggregate": bool(aggregate),
        "metrics": metrics,
    }


def _task_baseline(task):
    service_summary = task.get("service_summary")
    skipped_parent_names = set()
    if isinstance(service_summary, dict):
        skipped_parent_names = {
            str(item or "").strip().lower()
            for item in service_summary.get("skipped_parent_phase", [])
            if str(item or "").strip()
        }
    service_names = {
        str(item.get("name", "") or "").strip().lower()
        for item in _service_items(task)
        if str(item.get("name", "") or "").strip()
    }
    if "web_info_hunter" in service_names and any(
        name.startswith("wih_") for name in service_names
    ):
        skipped_parent_names.add("web_info_hunter")

    stages = [
        _stage_row(item, _stage_is_aggregate(item, skipped_parent_names))
        for item in _service_items(task)
    ]
    execution_stages = [item for item in stages if not item["aggregate"]]
    wih_stage = next((item for item in stages if item["name"] == "wih_primary_scan"), None)
    task_start = _parse_timestamp(task.get("start_time"))
    task_end = _parse_timestamp(task.get("end_time"))
    task_elapsed = None
    if task_start is not None and task_end is not None:
        task_elapsed = max(0.0, task_end - task_start)

    return {
        "task_id": str(task.get("_id", task.get("task_id", "")) or ""),
        "run_mode": str(task.get("run_mode", task.get("baseline_run", "")) or "").strip().lower(),
        "target_count": wih_stage.get("input_count") if wih_stage else None,
        "task_elapsed_sec": round(task_elapsed, 6) if task_elapsed is not None else None,
        "execution_stage_elapsed_sum_sec": round(
            sum(item["elapsed_sec"] or 0.0 for item in execution_stages), 6
        ),
        "stages": stages,
    }


def build_baseline(tasks):
    task_rows = [_task_baseline(task) for task in tasks]
    stage_values = {}
    for task in task_rows:
        for stage in task["stages"]:
            if stage["aggregate"]:
                continue
            stage_values.setdefault(stage["name"], []).append(stage)

    stage_summary = {}
    for name, rows in sorted(stage_values.items()):
        statuses = {}
        end_reasons = {}
        for row in rows:
            statuses[row["status"]] = statuses.get(row["status"], 0) + 1
            end_reasons[row["end_reason"]] = end_reasons.get(row["end_reason"], 0) + 1
        stage_summary[name] = {
            "sample_count": len(rows),
            "p95_elapsed_sec": _percentile([row["elapsed_sec"] for row in rows]),
            "p95_cpu_elapsed_sec": _percentile([row["cpu_elapsed_sec"] for row in rows]),
            "p95_non_cpu_elapsed_sec": _percentile(
                [row["non_cpu_elapsed_sec"] for row in rows]
            ),
            "max_rss_peak_mb": max(
                [row["rss_peak_mb"] for row in rows if row["rss_peak_mb"] is not None],
                default=None,
            ),
            "input_count_total": sum(row["input_count"] or 0 for row in rows),
            "output_count_total": sum(row["output_count"] or 0 for row in rows),
            "status_counts": statuses,
            "end_reason_counts": end_reasons,
        }

    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "task_count": len(task_rows),
        "target_count_distribution": sorted(
            row["target_count"] for row in task_rows if row["target_count"] is not None
        ),
        "stage_summary": stage_summary,
        "tasks": task_rows,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="生成 WIH 阶段性能基线 JSON")
    parser.add_argument("--input", required=True, help="任务文档 JSON 文件")
    parser.add_argument("--output", help="输出 JSON 文件；省略时写入标准输出")
    args = parser.parse_args(argv)

    try:
        baseline = build_baseline(_load_task_items(args.input))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("生成 WIH 基线失败: {}".format(exc), file=sys.stderr)
        return 2

    output = json.dumps(baseline, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        with Path(args.output).open("w", encoding="utf-8") as stream:
            stream.write(output)
    else:
        sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
