#!/usr/bin/env python3
"""
配置模板增量同步脚本（只补缺失，不覆盖现有值）

用途：
1. 升级后将 config-docker.yaml 中新增配置键补齐到运行配置。
2. 保留用户已修改的 runtime 配置值，不做覆盖。
3. 对列表场景（list[dict{id:...}]）按 id 增量补齐并补内部缺失字段。
"""
import argparse
import copy
import errno
import hashlib
import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path

import yaml

try:
    import fcntl
except Exception:  # pragma: no cover
    fcntl = None


def _load_yaml(path_obj):
    if not path_obj.exists():
        return {}
    with path_obj.open("r", encoding="utf-8") as f:
        loaded = yaml.safe_load(f) or {}
    if not isinstance(loaded, dict):
        raise ValueError("配置文件根节点必须为对象: {}".format(path_obj))
    return loaded


def _atomic_write_yaml(path_obj, data):
    path_obj.parent.mkdir(parents=True, exist_ok=True)
    text = yaml.safe_dump(
        data,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    )
    fd, tmp_name = tempfile.mkstemp(
        prefix=path_obj.name + ".",
        suffix=".tmp",
        dir=str(path_obj.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.replace(tmp_name, str(path_obj))
        except OSError as exc:
            if exc.errno not in (errno.EBUSY, errno.EXDEV, errno.EPERM):
                raise
            print(
                "runtime config atomic replace unavailable (errno={}), fallback to direct write: {}".format(
                    exc.errno, path_obj
                ),
                file=sys.stderr,
            )
            with path_obj.open("w", encoding="utf-8") as f:
                f.write(text)
                f.flush()
                os.fsync(f.fileno())
    finally:
        try:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
        except Exception:
            pass


def _resolve_default_paths():
    app_dir = Path(__file__).resolve().parents[1]  # /code/app
    custom_runtime = str(os.environ.get("ARL_CONFIG_EDIT_PATH", "") or "").strip()
    runtime_path = Path(custom_runtime) if custom_runtime else app_dir / "config.yaml"
    template_path = app_dir.parent / "docker" / "config-docker.yaml"
    return template_path, runtime_path


def _is_dict_list_with_id(value):
    if not isinstance(value, list) or not value:
        return False
    for item in value:
        if not isinstance(item, dict):
            return False
        if not str(item.get("id") or "").strip():
            return False
    return True


def _merge_missing(template_obj, runtime_obj, path="", stats=None):
    """
    递归补齐缺失项：
    - dict: 补缺失 key
    - list[dict{id}]: 按 id 增量补齐
    - 其他类型: runtime 存在则不改
    """
    if stats is None:
        stats = {
            "added_keys": [],
            "added_list_items": [],
            "updated": False,
        }

    if isinstance(template_obj, dict) and isinstance(runtime_obj, dict):
        for key, tpl_value in template_obj.items():
            child_path = "{}.{}".format(path, key) if path else str(key)
            if key not in runtime_obj:
                runtime_obj[key] = copy.deepcopy(tpl_value)
                stats["added_keys"].append(child_path)
                stats["updated"] = True
                continue
            _merge_missing(tpl_value, runtime_obj[key], child_path, stats)
        return stats

    if _is_dict_list_with_id(template_obj) and _is_dict_list_with_id(runtime_obj):
        runtime_map = {}
        for item in runtime_obj:
            item_id = str(item.get("id") or "").strip()
            if item_id and item_id not in runtime_map:
                runtime_map[item_id] = item

        for tpl_item in template_obj:
            tpl_id = str(tpl_item.get("id") or "").strip()
            if not tpl_id:
                continue
            if tpl_id not in runtime_map:
                runtime_obj.append(copy.deepcopy(tpl_item))
                stats["added_list_items"].append("{}[id={}]".format(path, tpl_id))
                stats["updated"] = True
                continue
            _merge_missing(tpl_item, runtime_map[tpl_id], "{}[id={}]".format(path, tpl_id), stats)

    return stats


def _build_backup_path(runtime_path):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return runtime_path.with_name("{}.bak.{}".format(runtime_path.name, timestamp))


def _acquire_lock(lock_file_path):
    lock_file_path.parent.mkdir(parents=True, exist_ok=True)
    fp = lock_file_path.open("a+", encoding="utf-8")
    if fcntl is not None:
        fcntl.flock(fp.fileno(), fcntl.LOCK_EX)
    return fp


def parse_args():
    parser = argparse.ArgumentParser(description="Sync runtime config by filling missing keys from template")
    parser.add_argument("--template", default="", help="template config path (default: docker/config-docker.yaml)")
    parser.add_argument("--runtime", default="", help="runtime config path (default: /code/app/config.yaml)")
    parser.add_argument("--no-backup", action="store_true", help="disable runtime backup before write")
    parser.add_argument("--dry-run", action="store_true", help="show missing keys only, do not write")
    parser.add_argument("--quiet", action="store_true", help="print only essential summary")
    return parser.parse_args()


def main():
    args = parse_args()
    default_template, default_runtime = _resolve_default_paths()
    template_path = Path(args.template).expanduser().resolve() if args.template else default_template
    runtime_path = Path(args.runtime).expanduser().resolve() if args.runtime else default_runtime
    lock_name = "arl_config_merge_{}.lock".format(
        hashlib.md5(str(runtime_path).encode("utf-8")).hexdigest()[:12]
    )
    lock_path = Path(tempfile.gettempdir()) / lock_name

    if not template_path.exists():
        print("template config not found: {}".format(template_path), file=sys.stderr)
        return 2
    if not runtime_path.exists():
        print("runtime config not found: {}".format(runtime_path), file=sys.stderr)
        return 2

    lock_fp = _acquire_lock(lock_path)
    try:
        template_obj = _load_yaml(template_path)
        runtime_obj = _load_yaml(runtime_path)
        stats = _merge_missing(template_obj, runtime_obj)

        if not stats.get("updated"):
            if not args.quiet:
                print("runtime config already up-to-date")
            return 0

        if not args.quiet:
            print("added_keys={}".format(len(stats.get("added_keys", []))))
            for item in stats.get("added_keys", []):
                print("  + {}".format(item))
            print("added_list_items={}".format(len(stats.get("added_list_items", []))))
            for item in stats.get("added_list_items", []):
                print("  + {}".format(item))

        if args.dry_run:
            if not args.quiet:
                print("dry-run mode, no file updated")
            return 0

        if not args.no_backup:
            backup_path = _build_backup_path(runtime_path)
            backup_path.write_text(runtime_path.read_text(encoding="utf-8"), encoding="utf-8")
            if not args.quiet:
                print("backup created: {}".format(backup_path))

        _atomic_write_yaml(runtime_path, runtime_obj)
        if not args.quiet:
            print("runtime config synced: {}".format(runtime_path))
        return 0
    finally:
        try:
            if fcntl is not None:
                fcntl.flock(lock_fp.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass
        lock_fp.close()


if __name__ == "__main__":
    sys.exit(main())
