#!/usr/bin/env python3
"""合并计划 6 任务查询响应，生成基线工具可读取的任务列表。"""

import argparse
import json
import sys
from pathlib import Path


def _items(payload):
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and isinstance(payload.get("items"), list):
        return payload["items"]
    raise ValueError("任务查询响应必须是列表或包含 items 列表的对象")


def merge_exports(input_dir, group):
    paths = sorted(Path(input_dir).glob("{}-task-*.json".format(group)))
    if not paths:
        raise ValueError("未找到 {} 的任务导出".format(group))

    tasks = []
    seen_ids = set()
    for path in paths:
        try:
            with path.open(encoding="utf-8") as stream:
                payload = json.load(stream)
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("读取 {} 失败: {}".format(path.name, exc)) from exc
        for item in _items(payload):
            if not isinstance(item, dict):
                raise ValueError("{} 含非对象任务记录".format(path.name))
            task_id = str(item.get("_id", item.get("task_id", "")) or "")
            if not task_id:
                raise ValueError("{} 缺少任务 ID".format(path.name))
            if task_id in seen_ids:
                continue
            seen_ids.add(task_id)
            tasks.append(item)

    return tasks


def main(argv=None):
    parser = argparse.ArgumentParser(description="合并计划 6 任务导出")
    parser.add_argument("--input-dir", required=True, type=Path)
    parser.add_argument("--group", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)

    try:
        tasks = merge_exports(args.input_dir, args.group)
        with args.output.open("w", encoding="utf-8") as stream:
            json.dump(tasks, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    except (OSError, ValueError) as exc:
        print("合并任务导出失败: {}".format(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
