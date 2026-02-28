#!/usr/bin/env python3
"""
容器启动阶段导入自定义指纹规则

功能说明：
1. 读取 /code/tools/finger.json（cms/method/location/keyword 格式）
2. 转换为 ARL 指纹管理使用的 human_rule 语法
3. 写入 fingerprint 集合并刷新指纹缓存
"""
import argparse
import importlib.util
import json
import os
import sys
from collections import defaultdict

FINGERPRINT_REDIS_KEY = "arl:fingerprint:rules:v1"


def ensure_project_root_in_path():
    """
    兼容脚本直跑场景（python app/tools/*.py），确保可以导入 app 包
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(current_dir, "..", ".."))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)


def escape_human_rule_value(value):
    """
    转义表达式字符串中的特殊字符，防止规则语法被破坏
    """
    text = str(value)
    text = text.replace("\\", "\\\\")
    text = text.replace('"', '\\"')
    return text


def load_check_expression():
    """
    通过文件路径加载表达式校验函数，避免触发 app.services 包级导入
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    expr_path = os.path.abspath(os.path.join(current_dir, "..", "services", "expr.py"))

    spec = importlib.util.spec_from_file_location("arl_expr_module", expr_path)
    if spec is None or spec.loader is None:
        raise ImportError("load spec failed for {}".format(expr_path))

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    check_func = getattr(module, "check_expression", None)
    if not callable(check_func):
        raise ImportError("check_expression not found in {}".format(expr_path))

    return check_func


def refresh_fingerprint_cache():
    """
    刷新指纹缓存：删除 Redis key，促使业务进程下次读取时回源 MongoDB
    """
    from app.config import Config

    if not bool(Config.REDIS_ENABLE):
        return

    try:
        import redis
    except Exception:
        return

    try:
        client = redis.Redis(
            host=Config.REDIS_HOST,
            port=Config.REDIS_PORT,
            db=Config.REDIS_DB,
            password=Config.REDIS_PASSWORD or None,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
        client.delete(FINGERPRINT_REDIS_KEY)
    except Exception as e:
        print("fingerprint cache refresh skipped: {}".format(e))


def build_rule_fragments(item):
    """
    将一条指纹项转换为 human_rule 片段列表
    """
    method = str(item.get("method", "")).strip().lower()
    location = str(item.get("location", "")).strip().lower()
    keywords = item.get("keyword", [])
    if not isinstance(keywords, list):
        return []

    location_map = {
        "body": "body",
        "header": "header",
        "title": "title",
    }

    fragments = []
    for keyword in keywords:
        keyword = str(keyword).strip()
        if not keyword:
            continue

        keyword = escape_human_rule_value(keyword)

        if method == "keyword":
            variable = location_map.get(location)
            if variable:
                fragments.append('{}="{}"'.format(variable, keyword))
            continue

        if method == "faviconhash":
            # icon_hash 使用精确匹配，避免子串匹配引入误报
            fragments.append('icon_hash=="{}"'.format(keyword))

    return fragments


def parse_finger_json(file_path):
    """
    解析 finger.json 并按 cms 聚合规则
    """
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    items = data.get("fingerprint", [])
    if not isinstance(items, list):
        raise ValueError("fingerprint is not list in {}".format(file_path))

    rule_map = defaultdict(set)
    for item in items:
        if not isinstance(item, dict):
            continue

        cms_name = str(item.get("cms", "")).strip()
        if not cms_name:
            continue

        fragments = build_rule_fragments(item)
        for fragment in fragments:
            rule_map[cms_name].add(fragment)

    finger_map = {}
    for name in sorted(rule_map.keys()):
        fragments = sorted(rule_map[name])
        if not fragments:
            continue
        finger_map[name] = " || ".join(fragments)

    return finger_map


def import_finger_map(finger_map):
    """
    导入规则到 MongoDB 的 fingerprint 集合
    """
    ensure_project_root_in_path()
    from app import utils
    check_expression = load_check_expression()

    collection = utils.conn_db("fingerprint")
    now = utils.curr_date_obj()

    inserted = 0
    updated = 0
    skipped = 0
    invalid = 0

    for name in sorted(finger_map.keys()):
        human_rule = finger_map[name]
        if not check_expression(human_rule):
            invalid += 1
            continue

        exist = collection.find_one({"name": name}, {"human_rule": 1})
        if exist is None:
            collection.insert_one(
                {
                    "name": name,
                    "human_rule": human_rule,
                    "update_date": now,
                }
            )
            inserted += 1
            continue

        old_rule = str(exist.get("human_rule", ""))
        if old_rule == human_rule:
            skipped += 1
            continue

        collection.update_one(
            {"_id": exist["_id"]},
            {"$set": {"human_rule": human_rule, "update_date": now}},
        )
        updated += 1

    refresh_fingerprint_cache()
    return inserted, updated, skipped, invalid


def parse_args():
    """
    解析命令行参数
    """
    parser = argparse.ArgumentParser(description="Import fingerprint rules from json")
    parser.add_argument("--file", required=True, help="path to finger.json")
    parser.add_argument("--dry-run", action="store_true", help="only parse and print summary")
    return parser.parse_args()


def main():
    """
    脚本入口
    """
    args = parse_args()
    file_path = os.path.abspath(args.file)
    if not os.path.isfile(file_path):
        print("fingerprint file not found: {}".format(file_path))
        return 1

    finger_map = parse_finger_json(file_path)
    print("fingerprint parsed: {}".format(len(finger_map)))
    if args.dry_run:
        return 0

    inserted, updated, skipped, invalid = import_finger_map(finger_map)
    print(
        "fingerprint import done, inserted={}, updated={}, skipped={}, invalid={}".format(
            inserted, updated, skipped, invalid
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
