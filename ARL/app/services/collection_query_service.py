"""
通用集合查询服务
================================================

负责把路由层里的 Mongo 查询拼装、分页、排序与缓存逻辑抽离出来，
让路由层只保留参数解析与响应返回职责。
"""
import json
import re
from datetime import datetime

from bson.objectid import ObjectId

from app.config import Config
from app.utils import conn_db as conn
from app.utils.cache import build_cache_key, cached_call

DEFAULT_QUERY_FIELD_NAMES = {"page", "size", "order", "_refresh"}
EQUAL_FIELDS = {"task_id", "task_tag", "ip_type", "scope_id", "type"}
TASK_STATUS_RUNNING_EXCLUDE = ["waiting", "done", "done_pending", "done_degraded", "stop", "error"]
TASK_STATUS_COLLECTIONS = {"task", "github_task"}


def normalize_task_status_query(collection, args, query):
    """
    任务状态查询兼容：
    - status=running -> 真实阶段状态聚合（排除 waiting/done/stop/error）
    - status=waiting/done/stop/error -> 精确匹配
    """
    if collection not in TASK_STATUS_COLLECTIONS:
        return query
    if not isinstance(args, dict) or not isinstance(query, dict):
        return query

    raw_status = args.get("status")
    if raw_status is None:
        return query

    status_text = str(raw_status).strip().lower()
    if not status_text:
        return query

    if status_text == "running":
        query["status"] = {
            "$exists": True,
            "$nin": TASK_STATUS_RUNNING_EXCLUDE,
        }
        return query

    if status_text == "done":
        # done 过滤覆盖 done 家族终态：done_pending/done_degraded 都是"已结束
        # 但非干净完成"，在任务列表中仍属于已完成桶。
        query["status"] = {"$in": ["done", "done_pending", "done_degraded"]}
    elif status_text in TASK_STATUS_RUNNING_EXCLUDE:
        query["status"] = status_text

    return query


def normalize_domain_source_query(collection, query):
    """域名来源筛选同时匹配兼容字段 source 和完整来源集合 sources。"""
    if collection not in {"domain", "asset_domain"} or not isinstance(query, dict) or "source" not in query:
        return query

    source_query = query.pop("source")
    query["$or"] = [
        {"source": source_query},
        {"sources": source_query},
    ]
    return query


def parse_refresh_flag(value):
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return value > 0

    text = str(value).strip().lower()
    return text in {"1", "true", "yes", "on", "refresh", "force"}


def build_db_query(args, ignored_fields=None):
    """
    构建 MongoDB 查询条件。
    """
    ignored_field_names = set(ignored_fields or DEFAULT_QUERY_FIELD_NAMES)
    query_args = {}

    for key in args:
        if key in ignored_field_names:
            continue

        if key == "_id":
            if args[key]:
                query_args[key] = ObjectId(args[key])
            continue

        if args[key] is None:
            continue

        if key.endswith("__dgt"):
            real_key = key.split("__dgt")[0]
            raw_value = query_args.get(real_key, {})
            raw_value.update({
                "$gt": datetime.strptime(args[key], "%Y-%m-%d %H:%M:%S")
            })
            query_args[real_key] = raw_value

        elif key.endswith("__dlt"):
            real_key = key.split("__dlt")[0]
            raw_value = query_args.get(real_key, {})
            raw_value.update({
                "$lt": datetime.strptime(args[key], "%Y-%m-%d %H:%M:%S")
            })
            query_args[real_key] = raw_value

        elif key.endswith("__neq"):
            real_key = key.split("__neq")[0]
            query_args[real_key] = {"$ne": args[key]}

        elif key.endswith("__not"):
            real_key = key.split("__not")[0]
            query_args[real_key] = {"$not": re.compile(re.escape(args[key]))}

        elif isinstance(args[key], str):
            if key in EQUAL_FIELDS:
                raw_text = args[key].strip()
                if key in {"task_id", "scope_id"}:
                    values = [item for item in re.split(r"[,\s]+", raw_text) if item]
                    if len(values) > 1:
                        query_args[key] = {"$in": values}
                    elif len(values) == 1:
                        query_args[key] = values[0]
                    else:
                        query_args[key] = raw_text
                else:
                    query_args[key] = raw_text
            else:
                query_args[key] = {
                    "$regex": re.escape(args[key]),
                    "$options": "i",
                }
        else:
            query_args[key] = args[key]

    return query_args


def get_default_field(args):
    """
    提取并规范分页、排序字段。
    """
    default_field_map = {
        "page": 1,
        "size": 10,
        "order": "-_id",
    }

    ret = default_field_map.copy()
    is_export = bool(args.pop("_export", False))
    max_size = 100000 if is_export else Config.API_PAGE_SIZE_MAX
    if is_export:
        ret["size"] = max_size

    for key in default_field_map:
        if key in args and args[key]:
            ret[key] = args.pop(key)
            if key == "size":
                if ret[key] <= 0:
                    ret[key] = 10
                if ret[key] >= max_size:
                    ret[key] = max_size
            if key == "page" and ret[key] <= 0:
                ret[key] = 1

    orderby_list = []
    orderby_field = ret.get("order", "-_id")
    for field in orderby_field.split(","):
        field = field.strip()
        if field.startswith("-"):
            orderby_list.append((field.split("-")[1], -1))
        elif field.startswith("+"):
            orderby_list.append((field.split("+")[1], 1))
        else:
            orderby_list.append((field, 1))

    ret["order"] = orderby_list
    return ret


def build_collection_data(args, collection, item_builder, query_serializer):
    """
    执行集合分页查询并返回标准列表响应。
    """
    if not isinstance(args, dict):
        args = {}

    working_args = args.copy()
    refresh_cache = parse_refresh_flag(working_args.pop("_refresh", None))
    raw_args = working_args.copy()

    default_field = get_default_field(working_args)
    page = default_field.get("page", 1)
    size = default_field.get("size", 10)
    orderby_list = default_field.get("order", [("_id", -1)])

    def _loader():
        query = build_db_query(working_args)
        query = normalize_domain_source_query(collection, query)
        query = normalize_task_status_query(collection, working_args, query)

        result = conn(collection).find(query).sort(orderby_list).skip(size * (page - 1)).limit(size)
        if query:
            count = conn(collection).count_documents(query)
        elif Config.API_USE_ESTIMATED_COUNT:
            count = conn(collection).estimated_document_count()
        else:
            count = conn(collection).count_documents({})

        items = item_builder(result)
        serialized_query = query_serializer(query)

        return {
            "page": page,
            "size": size,
            "total": count,
            "items": items,
            "query": serialized_query,
            "code": 200,
        }

    if size > 5000:
        return _loader()

    cache_raw = {
        "collection": collection,
        "page": page,
        "size": size,
        "order": orderby_list,
        "args": raw_args,
    }
    cache_key = build_cache_key(
        "route:build_data:{}".format(collection),
        json.dumps(cache_raw, ensure_ascii=False, sort_keys=True, default=str)
    )
    cache_expire = int(getattr(Config, "API_LIST_CACHE_EXPIRE", 60) or 0)
    if cache_expire <= 0:
        return _loader()

    return cached_call(cache_key, _loader, expire=cache_expire, force_refresh=refresh_cache)
