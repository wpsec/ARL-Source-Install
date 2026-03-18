"""
PoC 扫描结果管理模块

功能说明：
- 统一聚合 Nuclei 与 afrog 两类 Web PoC 扫描结果
- 支持查询、分页、删除
- 对外复用原有 `nuclei_result` 接口路径，兼容前端模块入口

统一字段：
- scanner_type: 扫描器类型（nuclei / afrog）
- rule_id: 模板 ID / PoC ID
- vuln_name: 风险名称
- vuln_severity: 风险等级
- vuln_url: 命中 URL（afrog 回退为 target）
- target: 扫描目标
- verify_data: 验证信息（nuclei 为 curl_command，afrog 为 verify_data）
"""
import re

from bson import ObjectId
from flask_restx import fields, Namespace

from app import utils
from app.modules import ErrorMsg
from app.utils import get_logger, auth

from . import ARLResource, base_query_fields, get_arl_parser

ns = Namespace('nuclei_result', description="PoC 扫描结果")

logger = get_logger()

base_search_fields = {
    'scanner_type': fields.String(description="扫描器类型（nuclei/afrog）"),
    'rule_id': fields.String(description="模板ID / PoC ID"),
    'template_id': fields.String(description="兼容旧参数：模板ID / PoC ID"),
    'vuln_name': fields.String(description="风险名称"),
    'vuln_severity': fields.String(description="风险等级（critical/high/medium/low/info）"),
    'vuln_url': fields.String(description="风险URL"),
    'target': fields.String(description="扫描目标"),
    "task_id": fields.String(description="任务ID")
}

base_search_fields.update(base_query_fields)

POC_SORT_FIELD_MAP = {
    "save_date": "save_date",
    "target": "target",
    "vuln_name": "vuln_name",
    "vuln_severity": "vuln_severity",
    "rule_id": "rule_id",
    "scanner_type": "scanner_type",
}


def _build_regex_query(value):
    text = str(value or "").strip()
    if not text:
        return None
    return {
        "$regex": re.escape(text),
        "$options": "i",
    }


def _build_multi_value_query(value):
    raw_text = str(value or "").strip()
    if not raw_text:
        return None

    values = [item for item in re.split(r"[,\s]+", raw_text) if item]
    if not values:
        return None
    if len(values) == 1:
        return values[0]
    return {"$in": values}


def _match_scanner_type(value):
    text = str(value or "").strip().lower()
    if not text:
        return True, True

    include_nuclei = ("nuclei" in text) or (text in "nuclei")
    include_afrog = ("afrog" in text) or (text in "afrog")
    return include_nuclei, include_afrog


def _build_collection_queries(args):
    nuclei_query = {}
    afrog_query = {"plg_type": "afrog"}

    include_nuclei, include_afrog = _match_scanner_type(args.get("scanner_type"))

    task_id_query = _build_multi_value_query(args.get("task_id"))
    if task_id_query is not None:
        nuclei_query["task_id"] = task_id_query
        afrog_query["task_id"] = task_id_query

    rule_id = args.get("rule_id") or args.get("template_id")
    rule_query = _build_regex_query(rule_id)
    if rule_query:
        nuclei_query["template_id"] = rule_query
        afrog_query["plg_name"] = rule_query

    target_query = _build_regex_query(args.get("target"))
    if target_query:
        nuclei_query["target"] = target_query
        afrog_query["target"] = target_query

    vuln_url_query = _build_regex_query(args.get("vuln_url"))
    if vuln_url_query:
        nuclei_query["vuln_url"] = vuln_url_query
        afrog_query["target"] = vuln_url_query

    vuln_name_query = _build_regex_query(args.get("vuln_name"))
    if vuln_name_query:
        nuclei_query["vuln_name"] = vuln_name_query
        afrog_query["vul_name"] = vuln_name_query

    vuln_severity = str(args.get("vuln_severity") or "").strip().lower()
    if vuln_severity:
        nuclei_query["vuln_severity"] = vuln_severity
        afrog_query["severity"] = vuln_severity

    return {
        "include_nuclei": include_nuclei,
        "include_afrog": include_afrog,
        "nuclei_query": nuclei_query,
        "afrog_query": afrog_query,
    }


def _build_nuclei_project_stage():
    return {
        "$project": {
            "_id": "$_id",
            "scanner_type": {"$literal": "nuclei"},
            "rule_id": {"$ifNull": ["$template_id", ""]},
            "target": {"$ifNull": ["$target", ""]},
            "vuln_url": {"$ifNull": ["$vuln_url", ""]},
            "vuln_name": {"$ifNull": ["$vuln_name", ""]},
            "vuln_severity": {"$ifNull": ["$vuln_severity", "info"]},
            "verify_data": {"$ifNull": ["$curl_command", ""]},
            "task_id": {"$ifNull": ["$task_id", ""]},
            "save_date": {"$ifNull": ["$save_date", ""]},
        }
    }


def _build_afrog_project_stage():
    return {
        "$project": {
            "_id": "$_id",
            "scanner_type": {"$literal": "afrog"},
            "rule_id": {"$ifNull": ["$plg_name", ""]},
            "target": {"$ifNull": ["$target", ""]},
            "vuln_url": {"$ifNull": ["$target", ""]},
            "vuln_name": {"$ifNull": ["$vul_name", ""]},
            "vuln_severity": {"$ifNull": ["$severity", "info"]},
            "verify_data": {"$ifNull": ["$verify_data", ""]},
            "task_id": {"$ifNull": ["$task_id", ""]},
            "save_date": {"$ifNull": ["$save_date", ""]},
        }
    }


def _build_poc_scan_pipeline(query_info, sort_field="save_date", sort_direction=-1, skip=0, limit=50, count_only=False):
    collection_pipelines = []

    if query_info.get("include_nuclei"):
        nuclei_pipeline = []
        if query_info.get("nuclei_query"):
            nuclei_pipeline.append({"$match": query_info["nuclei_query"]})
        nuclei_pipeline.append(_build_nuclei_project_stage())
        collection_pipelines.append(("nuclei_result", nuclei_pipeline))

    if query_info.get("include_afrog"):
        afrog_pipeline = []
        if query_info.get("afrog_query"):
            afrog_pipeline.append({"$match": query_info["afrog_query"]})
        afrog_pipeline.append(_build_afrog_project_stage())
        collection_pipelines.append(("vuln", afrog_pipeline))

    if not collection_pipelines:
        return None, []

    base_collection, base_pipeline = collection_pipelines[0]
    final_pipeline = list(base_pipeline)
    for collection_name, pipeline in collection_pipelines[1:]:
        final_pipeline.append({
            "$unionWith": {
                "coll": collection_name,
                "pipeline": pipeline,
            }
        })

    if count_only:
        final_pipeline.append({"$count": "total"})
        return base_collection, final_pipeline

    final_pipeline.append({
        "$sort": {
            sort_field: sort_direction,
            "_id": sort_direction,
        }
    })
    final_pipeline.append({"$skip": skip})
    final_pipeline.append({"$limit": limit})
    return base_collection, final_pipeline


def _normalize_order(order_list):
    if not isinstance(order_list, list) or not order_list:
        return "save_date", -1

    for raw_field, raw_direction in order_list:
        field_name = POC_SORT_FIELD_MAP.get(str(raw_field or "").strip())
        if not field_name:
            continue
        return field_name, -1 if int(raw_direction or -1) < 0 else 1

    return "save_date", -1


def _format_poc_result_items(data):
    items = []
    for item in data or []:
        row = dict(item)
        raw_id = row.pop("_id", "")
        record_id = str(raw_id or "")
        scanner_type = str(row.get("scanner_type") or "").strip().lower() or "nuclei"
        row["_id"] = "{}:{}".format(scanner_type, record_id)
        row["record_id"] = record_id
        row["scanner_type"] = scanner_type
        row["rule_id"] = str(row.get("rule_id") or "").strip()
        row["target"] = str(row.get("target") or "").strip()
        row["vuln_url"] = str(row.get("vuln_url") or "").strip()
        row["vuln_name"] = str(row.get("vuln_name") or "").strip()
        row["vuln_severity"] = str(row.get("vuln_severity") or "info").strip().lower()
        row["verify_data"] = str(row.get("verify_data") or "").strip()
        row["task_id"] = str(row.get("task_id") or "").strip()
        row["save_date"] = str(row.get("save_date") or "").strip()
        items.append(row)
    return items


def _parse_poc_result_id(raw_id):
    text = str(raw_id or "").strip()
    if not text:
        return "", ""

    if ":" in text:
        prefix, object_id = text.split(":", 1)
        return prefix.strip().lower(), object_id.strip()
    return "", text


@ns.route('/')
class ARLUrl(ARLResource):
    """PoC 扫描结果查询接口"""

    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        查询 PoC 扫描结果（统一聚合 Nuclei + afrog）。
        """
        args = self.parser.parse_args()
        default_field = self.get_default_field(args)
        page = default_field.get("page", 1)
        size = default_field.get("size", 10)
        order_list = default_field.get("order", [("save_date", -1)])
        sort_field, sort_direction = _normalize_order(order_list)

        query_info = _build_collection_queries(args)
        base_collection, count_pipeline = _build_poc_scan_pipeline(query_info, count_only=True)
        if not base_collection:
            return {
                "page": page,
                "size": size,
                "total": 0,
                "items": [],
                "query": query_info,
                "code": 200,
            }

        count_result = list(utils.conn_db(base_collection).aggregate(count_pipeline, allowDiskUse=True))
        total = int(count_result[0].get("total", 0) or 0) if count_result else 0

        _, data_pipeline = _build_poc_scan_pipeline(
            query_info,
            sort_field=sort_field,
            sort_direction=sort_direction,
            skip=size * (page - 1),
            limit=size,
            count_only=False,
        )
        items = _format_poc_result_items(
            utils.conn_db(base_collection).aggregate(data_pipeline, allowDiskUse=True)
        )

        return {
            "page": page,
            "size": size,
            "total": total,
            "items": items,
            "query": query_info,
            "code": 200,
        }


delete_nuclei_result_fields = ns.model('deleteNucleiResultFields',  {
    '_id': fields.List(fields.String(required=True, description="PoC 扫描结果_id 列表"))
})


@ns.route('/delete/')
class DeleteNucleiResult(ARLResource):
    """删除 PoC 扫描结果接口"""

    @auth
    @ns.expect(delete_nuclei_result_fields)
    def post(self):
        """
        批量删除 PoC 扫描结果。
        """
        args = self.parse_args(delete_nuclei_result_fields)
        id_list = args.pop('_id', [])

        for raw_id in id_list:
            prefix, object_text = _parse_poc_result_id(raw_id)
            if not ObjectId.is_valid(object_text):
                continue

            query = {'_id': ObjectId(object_text)}
            if prefix in {"nuclei", "nuclei_result"}:
                utils.conn_db('nuclei_result').delete_one(query)
                continue
            if prefix == "afrog":
                query["plg_type"] = "afrog"
                utils.conn_db('vuln').delete_one(query)
                continue

            deleted = utils.conn_db('nuclei_result').delete_one(query)
            if deleted.deleted_count == 0:
                query["plg_type"] = "afrog"
                utils.conn_db('vuln').delete_one(query)

        return utils.build_ret(ErrorMsg.Success, {'_id': id_list})
