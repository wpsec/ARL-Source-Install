"""
PoC（Proof of Concept）管理模块

功能说明：
- 管理漏洞验证插件（PoC插件）
- 支持PoC的查询、同步和清空
- PoC用于验证漏洞是否真实存在

PoC类型：
1. poc：漏洞验证插件（如CVE漏洞检测）
2. brute：暴力破解插件（如弱口令检测）

主要功能：
- 查询可用的PoC插件
- 从NPoC项目同步最新PoC
- 清空PoC数据库
"""
from bson import ObjectId
from flask import request
from flask_restx import Resource, Api, reqparse, fields, Namespace
from app.utils import get_logger, auth
from . import base_query_fields, ARLResource, get_arl_parser
from app.services.npoc import NPoC
from app import utils, celerytask
from app.config import Config
from app.modules import ErrorMsg, TaskStatus, CeleryAction
import copy

ns = Namespace('poc', description="PoC信息")

logger = get_logger()

# PoC查询字段定义
base_search_fields = {
    'q': fields.String(description="关键字（ID、漏洞名称、指纹、标签）"),
    'keyword': fields.String(description="关键字（兼容别名）"),
    'plugin_name': fields.String(description="PoC插件名称/ID"),
    'app_name': fields.String(description="应用名称（目标应用）"),
    'finger': fields.String(description="产品指纹"),
    'scheme': fields.String(description="支持的协议（http、https等）"),
    'vul_name': fields.String(description="漏洞名称"),
    'plugin_type': fields.String(description="插件类别", enum=['poc', 'brute']),
    'engine': fields.String(description="执行引擎（python/yaml）"),
    'source': fields.String(description="规则来源（npoc/dt）"),
    'status': fields.String(description="规则状态（ready/quarantine）"),
    'severity': fields.String(description="严重等级"),
    'tags': fields.String(description="规则标签"),
    'update_date': fields.String(description="更新时间"),
    'category': fields.String(description="PoC分类（如CMS、框架、中间件等）")
}

base_search_fields.update(base_query_fields)


@ns.route('/')
class ARLPoC(ARLResource):
    """PoC查询接口"""
    
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        查询PoC插件信息
        
        参数：
            - q/keyword：跨 ID、漏洞名称、指纹和标签的关键字
            - plugin_name: PoC插件名称过滤
            - app_name: 应用名称过滤
            - scheme: 协议过滤
            - vul_name: 漏洞名称过滤
            - plugin_type: 插件类别过滤（poc/brute）
            - category: PoC分类过滤
            - engine/source/status/severity/tags：执行引擎、来源、状态、严重等级和标签过滤
            - page: 页码
            - size: 每页数量
        
        返回：
            {
                "code": 200,
                "items": [
                    {
                        "_id": "插件ID",
                        "plugin_name": "插件名称",
                        "app_name": "应用名称",
                        "vul_name": "漏洞名称",
                        "scheme": "协议",
                        "plugin_type": "插件类型",
                        "category": "分类",
                        "description": "描述",
                        "engine": "yaml",
                        "source": "dt",
                        "status": "ready",
                        "severity": "严重级别",
                        "tags": ["标签"],
                        "update_date": "更新时间"
                    }
                ],
                "total": 总数
            }
        
        说明：
        - PoC插件用于漏洞验证和暴力破解
        - 可在任务配置中选择要使用的PoC
        - 支持HTTP、HTTPS等多种协议
        - 插件来自ARL-NPoC项目
        """
        args = self.parser.parse_args()
        data = self.build_data(args=args,  collection='poc')

        return data


@ns.route('/names/')
class ARLPoCNames(ARLResource):
    """返回用于批量选择的PoC名称，避免传输完整规则内容。"""

    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        args = self.parser.parse_args()
        default_field = self.get_default_field(args)
        query = self.build_db_query(args)
        collection = utils.conn_db('poc')
        page = default_field['page']
        size = default_field['size']
        offset = size * (page - 1)
        max_offset = max(0, int(getattr(Config, 'API_MAX_PAGE_OFFSET', 50000) or 0))
        if offset > max_offset:
            return {
                'page': page,
                'size': size,
                'total': 0,
                'items': [],
                'query': {},
                'code': 400,
                'message': '分页过深，请缩小筛选范围或使用导出任务',
            }
        result = (
            collection.find(query, {'_id': 0, 'plugin_name': 1})
            .sort(default_field['order'])
            .skip(offset)
            .limit(size)
        )
        items = []
        for item in result:
            plugin_name = str(item.get('plugin_name', '') or '').strip()
            if plugin_name:
                items.append({'plugin_name': plugin_name})
        return {
            'page': page,
            'size': size,
            'total': collection.count_documents(query),
            'items': items,
            'code': 200,
        }


@ns.route('/sync/')
class ARLPoCSync(ARLResource):
    """PoC同步接口"""

    @auth
    def post(self):
        """
        异步更新 PoC 插件信息
        
        返回：
            {
                "code": 200,
                "message": "同步任务已提交",
                "job_id": "同步任务ID",
                "celery_id": "Celery任务ID"
            }
        
        说明：
        - 从ARL-NPoC项目同步最新的PoC插件
        - 会更新现有插件并删除已废弃的插件
        - 建议定期执行以获取最新漏洞检测能力
        - 同步过程在后台 worker 执行，避免阻塞 Web worker
        
        操作流程：
        1. 读取NPoC插件列表
        2. 同步到数据库（更新或新增）
        3. 删除已废弃的插件
        """
        principal = utils.current_principal() or {}
        owner_username = str(principal.get("username") or "").strip()
        job_collection = utils.conn_db("poc_sync_job")
        active_job = job_collection.find_one(
            {"status": {"$in": ["queued", "running"]}},
            {"_id": 1, "status": 1, "celery_id": 1},
        )
        if active_job:
            return utils.build_ret(
                ErrorMsg.Success,
                {
                    "job_id": str(active_job.get("_id")),
                    "celery_id": str(active_job.get("celery_id") or ""),
                    "status": active_job.get("status", "queued"),
                    "reused": True,
                },
            ), 202
        job_doc = {
            "status": "queued",
            "requested_by": owner_username,
            "created_at": utils.curr_date(),
            "updated_at": utils.curr_date(),
        }
        insert_result = job_collection.insert_one(job_doc)
        job_id = str(insert_result.inserted_id)
        try:
            celery_result = celerytask.arl_task_web.delay({
                "celery_action": CeleryAction.POC_SYNC_TASK,
                "data": {"sync_job_id": job_id},
            })
        except Exception as exc:
            job_collection.update_one(
                {"_id": insert_result.inserted_id},
                {"$set": {
                    "status": "error",
                    "updated_at": utils.curr_date(),
                    "error_type": type(exc).__name__,
                }},
            )
            logger.exception("submit POC sync job failed")
            return utils.build_ret(
                ErrorMsg.Error,
                {"job_id": job_id, "status": "error"},
            ), 503

        celery_id = str(celery_result)
        job_collection.update_one(
            {"_id": insert_result.inserted_id},
            {"$set": {"celery_id": celery_id, "updated_at": utils.curr_date()}},
        )
        return utils.build_ret(
            ErrorMsg.Success,
            {"job_id": job_id, "celery_id": celery_id, "status": "queued"},
        ), 202


@ns.route('/sync/<string:job_id>/')
class ARLPoCSyncStatus(ARLResource):
    """查询 PoC 同步任务状态。"""

    @auth
    def get(self, job_id):
        principal = utils.current_principal() or {}
        query = {"_id": ObjectId(job_id)} if ObjectId.is_valid(job_id) else None
        if query is None:
            return utils.build_ret(ErrorMsg.NotFound, {}), 404
        if principal.get("type") != "api":
            query["requested_by"] = str(principal.get("username") or "").strip()
        item = utils.conn_db("poc_sync_job").find_one(query, {"_id": 1, "status": 1,
                                                               "celery_id": 1,
                                                               "plugin_cnt": 1,
                                                               "updated_at": 1,
                                                               "error_type": 1})
        if not item:
            return utils.build_ret(ErrorMsg.NotFound, {}), 404
        item["job_id"] = str(item.pop("_id"))
        return utils.build_ret(ErrorMsg.Success, item)


@ns.route('/delete/')
class ARLPoCDelete(ARLResource):
    """PoC清空接口"""

    @auth
    def post(self):
        """
        清空所有PoC插件信息
        
        返回：
            {
                "code": 200,
                "message": "成功",
                "delete_cnt": 删除数量
            }
        
        说明：
        - 清空PoC数据库中的所有插件
        - 删除操作不可逆
        - 清空后需要重新同步才能使用PoC功能
        - 通常在重新初始化或排查问题时使用
        """
        principal = utils.current_principal()
        if not isinstance(principal, dict) or principal.get("type") != "api":
            return {
                "code": 403,
                "message": "仅 API 管理主体可以清空 POC",
                "data": {},
            }, 403

        payload = request.get_json(silent=True) or {}
        if payload.get("confirm") is not True:
            return {
                "code": 400,
                "message": "清空 POC 需要显式确认",
                "data": {"confirm_required": True},
            }, 400

        audit_collection = utils.conn_db("audit_event")
        audit_result = audit_collection.insert_one({
            "event": "poc_delete_requested",
            "actor": str(principal.get("username") or "ARL-API"),
            "created_at": utils.curr_date(),
        })
        result = utils.conn_db('poc').delete_many({})

        try:
            audit_collection.update_one(
                {"_id": audit_result.inserted_id},
                {"$set": {
                    "event": "poc_delete_completed",
                    "deleted_count": int(result.deleted_count or 0),
                    "completed_at": utils.curr_date(),
                }},
            )
        except Exception as exc:
            logger.warning(
                "poc delete audit completion update failed error_type=%s",
                type(exc).__name__,
            )

        delete_cnt = result.deleted_count

        return utils.build_ret(ErrorMsg.Success, {"delete_cnt": delete_cnt})
