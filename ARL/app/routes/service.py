"""
服务信息管理模块

功能：
- 服务信息查询、导出
- 端口和服务识别结果管理

说明：
- 服务数据来自端口扫描和服务识别
- 包含端口、协议、产品、版本等信息
- 支持按IP、端口、服务名称等维度查询
"""
import re

from flask_restx import Resource, Api, reqparse, fields, Namespace
from app.utils import conn_db, get_logger, auth
from . import base_query_fields, ARLResource, get_arl_parser

ns = Namespace('service', description="系统服务信息")

logger = get_logger()

# 服务查询字段
base_search_fields = {
    'service_name': fields.String(description="系统服务名称"),
    'service_info.ip': fields.String(required=False, description="IP"),
    'service_info.port_id': fields.Integer(description="端口号"),
    'service_info.version': fields.String(description="系统服务版本"),
    'service_info.product': fields.String(description="产品"),
    "task_id": fields.String(description="任务ID")
}

# 合并通用查询字段
base_search_fields.update(base_query_fields)


SERVICE_FALLBACK_PROJECTION = {
    "ip": 1,
    "port_info": 1,
    "task_id": 1,
    "task_tag": 1,
    "classification": 1,
    "type": 1,
}


def _as_list(value):
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _has_value(value):
    return value is not None and str(value).strip() != ""


def _matches_text(value, expected):
    if not _has_value(expected):
        return True
    return re.search(re.escape(str(expected).strip()), str(value or ""), re.IGNORECASE) is not None


def _matches_exact(value, expected):
    if not _has_value(expected):
        return True
    return str(value or "").strip() == str(expected).strip()


def _normalize_task_ids(value):
    result = []
    for item in _as_list(value):
        for task_id in re.split(r"[,\s]+", str(item or "").strip()):
            if task_id and task_id not in result:
                result.append(task_id)
    return result


def _fallback_ip_query(args):
    task_ids = _normalize_task_ids(args.get("task_id"))
    if not task_ids:
        return {}, task_ids
    return {"task_id": task_ids[0] if len(task_ids) == 1 else {"$in": task_ids}}, task_ids


def _fallback_service_rows(args=None):
    """
    从 IP 的 port_info 生成兼容服务列表。

    服务识别阶段异常时，端口扫描结果仍然可能已经写入 ip 集合；保留这条
    只读回退路径，避免网页列表和导出报告使用两套数据口径。
    """
    args = dict(args or {})
    ip_query, task_ids = _fallback_ip_query(args)
    rows = []
    seen = set()

    for ip_item in conn_db("ip").find(ip_query, SERVICE_FALLBACK_PROJECTION).sort([("_id", -1)]):
        if not isinstance(ip_item, dict):
            continue
        item_task_id = str(ip_item.get("task_id", "") or "").strip()
        if task_ids and item_task_id not in task_ids:
            continue
        if not _matches_exact(ip_item.get("task_tag"), args.get("task_tag")):
            continue
        if not _matches_exact(ip_item.get("classification"), args.get("classification")):
            continue
        if not _matches_exact(ip_item.get("type"), args.get("type")):
            continue

        ip = ip_item.get("ip", "")
        for index, raw_info in enumerate(_as_list(ip_item.get("port_info", []))):
            if not isinstance(raw_info, dict):
                continue

            info = dict(raw_info)
            info_ip = info.get("ip") or ip
            service_name = info.get("service_name") or info.get("name") or ""
            product = info.get("product") or info.get("service_product") or ""
            version = info.get("version") or ""
            port_id = info.get("port_id")

            # 没有端口、服务、产品或版本的空结构不是可展示的服务记录。
            if not any(_has_value(value) for value in (info_ip, port_id, service_name, product, version)):
                continue
            if not _matches_text(service_name, args.get("service_name")):
                continue
            if not _matches_text(info_ip, args.get("service_info.ip")):
                continue
            if _has_value(args.get("service_info.port_id")) and not _matches_exact(
                port_id, args.get("service_info.port_id")
            ):
                continue
            if not _matches_text(version, args.get("service_info.version")):
                continue
            if not _matches_text(product, args.get("service_info.product")):
                continue

            dedup_key = (str(info_ip), str(port_id), str(service_name), str(product), str(version), item_task_id)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            info["ip"] = info_ip
            rows.append({
                "_id": "service-fallback:{}:{}".format(ip_item.get("_id", ""), index),
                "task_id": ip_item.get("task_id", ""),
                "task_tag": ip_item.get("task_tag", ""),
                "classification": ip_item.get("classification", ""),
                "type": ip_item.get("type", ""),
                "service_name": service_name,
                "service_info": [info],
            })

    return rows


def _fallback_sort_value(row, field):
    if field.startswith("service_info."):
        info_list = row.get("service_info") or []
        info = info_list[0] if info_list and isinstance(info_list[0], dict) else {}
        return info.get(field.split(".", 1)[1], "")
    return row.get(field, "")


def _sort_fallback_service_rows(rows, order):
    raw_order = str(order or "-_id")
    order_fields = []
    for field in raw_order.split(","):
        field = field.strip()
        if not field:
            continue
        direction = -1 if field.startswith("-") else 1
        order_fields.append((field.lstrip("+-"), direction))

    for field, direction in reversed(order_fields or [("_id", -1)]):
        rows.sort(
            key=lambda row: str(_fallback_sort_value(row, field) or "").lower(),
            reverse=direction < 0,
        )


def _fallback_service_response(args, item_builder):
    rows = _fallback_service_rows(args)
    _sort_fallback_service_rows(rows, args.get("order", "-_id"))

    try:
        page = max(1, int(args.get("page") or 1))
    except (TypeError, ValueError):
        page = 1
    try:
        size = max(1, min(100000, int(args.get("size") or 10)))
    except (TypeError, ValueError):
        size = 10

    start = (page - 1) * size
    query = {
        key: value
        for key, value in args.items()
        if key not in {"page", "size", "order", "_refresh"} and _has_value(value)
    }
    return {
        "page": page,
        "size": size,
        "total": len(rows),
        "items": item_builder(rows[start:start + size]),
        "query": query,
        "code": 200,
    }


def _service_collection_has_records(args):
    task_ids = _normalize_task_ids(args.get("task_id"))
    query = {}
    if task_ids:
        query["task_id"] = task_ids[0] if len(task_ids) == 1 else {"$in": task_ids}
    return conn_db("service").count_documents(query) > 0


def count_service_records():
    """返回与服务列表一致的记录数，供控制台统计使用。"""
    try:
        service_count = conn_db("service").count_documents({})
        return service_count if service_count > 0 else len(_fallback_service_rows())
    except Exception as exc:
        logger.warning("统计服务记录失败: %s", exc)
        return 0


@ns.route('/')
class ARLService(ARLResource):
    """服务信息查询接口"""
    
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        查询服务信息
        
        参数：
            - service_name: 服务名称（如 http、mysql、ssh）
            - service_info.ip: IP地址
            - service_info.port_id: 端口号
            - service_info.version: 服务版本
            - service_info.product: 产品名称（如 nginx、Apache）
            - task_id: 任务ID
            - page: 页码（默认1）
            - size: 每页数量（默认10）
        
        返回：
            {
                "code": 200,
                "data": {
                    "items": [服务信息列表],
                    "total": 总数
                }
            }
        
        服务字段说明：
            - service_name: 服务名称（如 http、ssh、mysql）
            - service_info: {
                - ip: IP地址
                - port_id: 端口号
                - protocol: 协议类型（tcp/udp）
                - product: 产品名称
                - version: 版本号
                - banner: 服务Banner信息
              }
            - task_id: 关联的任务ID
        """
        args = self.parser.parse_args()
        if not _service_collection_has_records(args):
            return _fallback_service_response(args, self.build_return_items)
        data = self.build_data(args=args, collection='service')

        return data
