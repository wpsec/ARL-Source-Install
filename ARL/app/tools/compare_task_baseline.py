#!/usr/bin/env python3
"""比较 Python 与 Rust 两组任务导出数据的性能和结果完整性。

工具只读取 ``collect_wih_baseline.py`` 生成的 JSON，不连接运行中的服务。
吞吐使用每个样本的平均输入量除以阶段 p95 CPU 时间估算，结果中会明确标注。
"""

import argparse
import json
import math
import sys
from pathlib import Path


DEFAULT_STAGES = (
    "wih_urlfinder_extract",
    "wih_urlfinder_sensitive",
    "wih_url_probe",
)


def _number(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _p95(values):
    numbers = sorted(value for value in values if value is not None)
    if not numbers:
        return None
    index = max(0, min(len(numbers) - 1, math.ceil(len(numbers) * 0.95) - 1))
    return numbers[index]


def _target_tasks(payload, target_count):
    tasks = payload.get("tasks") if isinstance(payload, dict) else None
    if not isinstance(tasks, list):
        return []
    return [
        task
        for task in tasks
        if isinstance(task, dict) and task.get("target_count") == target_count
    ]


def _stage_summary(payload, stage_name):
    summaries = payload.get("stage_summary") if isinstance(payload, dict) else None
    value = summaries.get(stage_name) if isinstance(summaries, dict) else None
    return value if isinstance(value, dict) else None


def _average_count(summary, field_name):
    total = _number(summary.get(field_name))
    sample_count = _number(summary.get("sample_count"))
    if total is None or not sample_count or sample_count <= 0:
        return None
    return total / sample_count


def _task_elapsed_p95(tasks):
    return _p95([_number(task.get("task_elapsed_sec")) for task in tasks])


def _fallback_total(tasks, stage_name):
    total = 0
    for task in tasks:
        for stage in task.get("stages", []):
            if not isinstance(stage, dict) or stage.get("name") != stage_name:
                continue
            metrics = stage.get("metrics")
            if not isinstance(metrics, dict):
                continue
            value = _number(
                metrics.get("rust_fallback_count", metrics.get("fallback_count"))
            )
            if value is not None:
                total += max(0, int(value))
    return total


def compare_baselines(
    python_payload,
    rust_payload,
    target_count=64,
    stages=DEFAULT_STAGES,
    min_runs=2,
    cpu_reduction_target=0.30,
    throughput_target=1.50,
    elapsed_regression_limit=0.05,
):
    errors = []
    python_tasks = _target_tasks(python_payload, target_count)
    rust_tasks = _target_tasks(rust_payload, target_count)
    for label, payload, tasks in (
        ("Python", python_payload, python_tasks),
        ("Rust", rust_payload, rust_tasks),
    ):
        if not isinstance(payload, dict) or payload.get("schema_version") != 1:
            errors.append("{} 基线 schema_version 必须为 1".format(label))
        if len(tasks) < min_runs:
            errors.append(
                "{} 基线目标数为 {} 的任务需要至少 {} 轮，当前 {} 轮".format(
                    label, target_count, min_runs, len(tasks)
                )
            )

    stage_reports = []
    for stage_name in stages:
        stage_name = str(stage_name or "").strip()
        if not stage_name:
            continue
        python_stage = _stage_summary(python_payload, stage_name)
        rust_stage = _stage_summary(rust_payload, stage_name)
        if python_stage is None or rust_stage is None:
            errors.append("缺少阶段 {} 的 Python 或 Rust 汇总".format(stage_name))
            continue

        python_cpu = _number(python_stage.get("p95_cpu_elapsed_sec"))
        rust_cpu = _number(rust_stage.get("p95_cpu_elapsed_sec"))
        python_elapsed = _number(python_stage.get("p95_elapsed_sec"))
        rust_elapsed = _number(rust_stage.get("p95_elapsed_sec"))
        python_input = _average_count(python_stage, "input_count_total")
        rust_input = _average_count(rust_stage, "input_count_total")
        python_output = _average_count(python_stage, "output_count_total")
        rust_output = _average_count(rust_stage, "output_count_total")

        cpu_reduction = None
        if python_cpu and python_cpu > 0 and rust_cpu is not None:
            cpu_reduction = 1 - rust_cpu / python_cpu

        throughput_ratio = None
        if (
            python_cpu
            and python_cpu > 0
            and rust_cpu
            and rust_cpu > 0
            and python_input is not None
            and rust_input is not None
        ):
            python_throughput = python_input / python_cpu
            rust_throughput = rust_input / rust_cpu
            if python_throughput > 0:
                throughput_ratio = rust_throughput / python_throughput

        elapsed_change = None
        if python_elapsed and python_elapsed > 0 and rust_elapsed is not None:
            elapsed_change = rust_elapsed / python_elapsed - 1

        result_not_reduced = (
            python_output is not None
            and rust_output is not None
            and rust_output >= python_output
        )
        cpu_gate = (
            cpu_reduction is not None
            and cpu_reduction >= cpu_reduction_target
        )
        throughput_gate = (
            throughput_ratio is not None
            and throughput_ratio >= throughput_target
        )
        stage_reports.append(
            {
                "stage": stage_name,
                "python_p95_cpu_sec": python_cpu,
                "rust_p95_cpu_sec": rust_cpu,
                "cpu_reduction": cpu_reduction,
                "estimated_throughput_ratio": throughput_ratio,
                "python_p95_elapsed_sec": python_elapsed,
                "rust_p95_elapsed_sec": rust_elapsed,
                "elapsed_change": elapsed_change,
                "python_average_output": python_output,
                "rust_average_output": rust_output,
                "result_not_reduced": result_not_reduced,
                "hotspot_gate": bool(cpu_gate or throughput_gate),
                "elapsed_gate": elapsed_change is not None and elapsed_change <= elapsed_regression_limit,
                "fallback_count": _fallback_total(rust_tasks, stage_name),
            }
        )

    python_task_p95 = _task_elapsed_p95(python_tasks)
    rust_task_p95 = _task_elapsed_p95(rust_tasks)
    task_elapsed_change = None
    if python_task_p95 and python_task_p95 > 0 and rust_task_p95 is not None:
        task_elapsed_change = rust_task_p95 / python_task_p95 - 1

    if not stage_reports:
        errors.append("没有可比较的热点阶段")

    stage_gate_ok = all(
        item["hotspot_gate"]
        and item["elapsed_gate"]
        and item["result_not_reduced"]
        for item in stage_reports
    )
    task_elapsed_gate = (
        task_elapsed_change is not None
        and task_elapsed_change <= elapsed_regression_limit
    )
    return {
        "schema_version": 1,
        "ok": not errors and stage_gate_ok and task_elapsed_gate,
        "target_count": target_count,
        "python_run_count": len(python_tasks),
        "rust_run_count": len(rust_tasks),
        "python_task_p95_elapsed_sec": python_task_p95,
        "rust_task_p95_elapsed_sec": rust_task_p95,
        "task_elapsed_change": task_elapsed_change,
        "task_elapsed_gate": task_elapsed_gate,
        "stage_gate": stage_gate_ok,
        "errors": errors,
        "stages": stage_reports,
    }


def _load(path):
    with Path(path).open("r", encoding="utf-8") as stream:
        return json.load(stream)


def main(argv=None):
    parser = argparse.ArgumentParser(description="比较 Python/Rust 任务性能基线")
    parser.add_argument("--python", required=True, help="Python 基线 JSON")
    parser.add_argument("--rust", required=True, help="Rust 基线 JSON")
    parser.add_argument("--output", help="输出比较报告 JSON；省略时写入标准输出")
    parser.add_argument("--target-count", type=int, default=64)
    parser.add_argument("--min-runs", type=int, default=2)
    parser.add_argument(
        "--stage",
        action="append",
        dest="stages",
        help="指定热点阶段，可重复传入；默认比较三个 WIH 热点阶段",
    )
    args = parser.parse_args(argv)

    try:
        result = compare_baselines(
            _load(args.python),
            _load(args.rust),
            target_count=max(1, args.target_count),
            stages=tuple(args.stages or DEFAULT_STAGES),
            min_runs=max(1, args.min_runs),
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("比较任务基线失败: {}".format(exc), file=sys.stderr)
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
