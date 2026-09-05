"""
API 路由基础模块
================================================

该模块提供所有 API 路由的基础类和工具函数
主要功能：
- ARLResource 基类：所有 API 资源的父类
- 参数解析和验证
- MongoDB 查询构建
- 数据分页和排序
- 文件导出功能
- 批量导出功能

ARLResource 类提供的核心功能：
1. 请求参数解析（支持 JSON 和 URL 参数）
2. MongoDB 查询条件构建（支持正则、比较、不等于等）
3. 分页查询支持
4. 排序支持
5. 数据导出（TXT文件）
6. 批量导出
"""
import re
import json
from flask_restx import Resource, reqparse, fields
from bson.objectid import ObjectId
from datetime import datetime
from urllib.parse import quote
from flask import make_response
import time

from app.utils import conn_db as conn
from app.utils.cache import build_cache_key, cached_call
from app.config import Config
from app.modules import CollectSource
from app.services.collection_query_service import (
    build_collection_data as build_collection_data_service,
    build_db_query as build_db_query_service,
    get_default_field as get_default_field_service,
    normalize_task_status_query as normalize_task_status_query_service,
    parse_refresh_flag as parse_refresh_flag_service,
)

# 基础查询字段定义
# 这些字段用于分页、排序等通用查询功能
base_query_fields = {
    'page': fields.Integer(description="当前页数", example=1),
    'size': fields.Integer(description="页面大小", example=10),
    'order': fields.String(description="排序字段", example='_id'),
    '_refresh': fields.String(description="强制刷新缓存（1/true）", example='1'),
}

# 只能用等号进行 MongoDB 查询的字段
# 这些字段不支持模糊匹配，只支持精确匹配
EQUAL_FIELDS = ["task_id", "task_tag", "ip_type", "scope_id", "type"]
TASK_STATUS_RUNNING_EXCLUDE = ["waiting", "done", "done_pending", "done_degraded", "stop", "error"]
TASK_STATUS_COLLECTIONS = {"task", "github_task"}
TASK_SERVICE_PARENT_PREFIXES = {
    "web_info_hunter": ("wih_",),
}


def build_task_service_summary(service_list):
    """
    生成任务阶段耗时汇总，避免父子阶段重复累计。
    """
    if not isinstance(service_list, list):
        return {}

    service_names = set()
    for item in service_list:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        if name:
            service_names.add(name)

    skip_parent_names = set()
    for item in service_list:
        if not isinstance(item, dict):
            continue
        stage_name = str(item.get("name", "")).strip()
        stage_kind = str(item.get("stage_kind", "")).strip().lower()
        if stage_name and stage_kind == "aggregate":
            skip_parent_names.add(stage_name)

    for parent_name, child_prefixes in TASK_SERVICE_PARENT_PREFIXES.items():
        if parent_name not in service_names:
            continue
        for service_name in service_names:
            if any(service_name.startswith(prefix) for prefix in child_prefixes):
                skip_parent_names.add(parent_name)
                break

    total_elapsed = 0.0
    dedup_elapsed = 0.0
    phase_count = 0
    dedup_phase_count = 0
    skipped = []

    for item in service_list:
        if not isinstance(item, dict):
            continue

        name = str(item.get("name", "")).strip()
        elapsed = item.get("elapsed", 0)
        try:
            elapsed = float(elapsed)
        except Exception:
            elapsed = 0.0

        phase_count += 1
        total_elapsed += elapsed

        if name in skip_parent_names:
            skipped.append(name)
            continue

        dedup_phase_count += 1
        dedup_elapsed += elapsed

    return {
        "phase_count": phase_count,
        "dedup_phase_count": dedup_phase_count,
        "total_elapsed": round(total_elapsed, 2),
        "dedup_elapsed": round(dedup_elapsed, 2),
        "skipped_parent_phase": sorted(list(set(skipped))),
    }


class ARLResource(Resource):
    """
    ARL API 资源基类
    所有的 API 资源类都应该继承此类
    
    提供的功能：
    - 参数解析和验证
    - MongoDB 查询构建
    - 分页数据构建
    - 数据导出
    """
    
    @staticmethod
    def normalize_task_status_query(collection, args, query):
        """
        任务状态查询兼容：
        - status=running -> 真实阶段状态聚合（排除 waiting/done/stop/error）
        - status=waiting/done/stop/error -> 精确匹配
        """
        return normalize_task_status_query_service(collection, args, query)

    @staticmethod
    def parse_refresh_flag(value):
        return parse_refresh_flag_service(value)

    @staticmethod
    def serialize_response_value(value):
        """
        将 MongoDB / Python 特有对象递归转换为 JSON 安全值。

        说明：
        - 任务文档后续可能新增 datetime/ObjectId 字段（如 kb_push_time）
        - 统一在路由层兜底，避免列表接口因为单个字段未显式处理而整体 500
        """
        if isinstance(value, ObjectId):
            return str(value)

        if isinstance(value, datetime):
            return value.strftime("%Y-%m-%d %H:%M:%S")

        if isinstance(value, type(re.compile(""))):
            return value.pattern

        if isinstance(value, dict):
            return {
                key: ARLResource.serialize_response_value(item)
                for key, item in value.items()
            }

        if isinstance(value, list):
            return [ARLResource.serialize_response_value(item) for item in value]

        if isinstance(value, tuple):
            return [ARLResource.serialize_response_value(item) for item in value]

        return value

    def get_parser(self, model, location='json'):
        """
        根据模型定义创建请求参数解析器
        
        参数：
            model: 字段模型定义（Flask-RESTX fields）
            location: 参数位置（json/args/headers）
        
        返回：
            RequestParser 对象
        """
        parser = reqparse.RequestParser(bundle_errors=True)
        for name in model:
            curr_field = model[name]

            parser.add_argument(name,
                                required=curr_field.required,
                                type=curr_field.format,
                                help=curr_field.description,
                                location=location)
        return parser

    def parse_args(self, model, location='json'):
        """
        解析请求参数
        
        参数：
            model: 字段模型定义
            location: 参数位置
        
        返回：
            解析后的参数字典
        """
        parser = self.get_parser(model, location)
        args = parser.parse_args()
        return args

    def build_db_query(self, args):
        """
        构建 MongoDB 查询条件
        
        支持的查询操作符：
        - __dgt: 日期大于（date greater than）
        - __dlt: 日期小于（date less than）
        - __neq: 不等于（not equal）
        - __not: 正则不匹配（not match）
        - 默认: 字符串模糊匹配或精确匹配
        
        参数：
            args: 请求参数字典
        
        返回：
            MongoDB 查询条件字典
        """
        return build_db_query_service(args, ignored_fields=base_query_fields.keys())

    def build_return_items(self, data):
        """
        构建返回数据列表
        将 MongoDB 数据转换为 API 返回格式
        
        主要操作：
        - 将 ObjectId 转换为字符串
        - 将日期对象转换为字符串
        
        参数：
            data: MongoDB 查询结果（游标对象）
        
        返回：
            处理后的数据列表
        """
        items = []

        for item in data:
            item = self.serialize_response_value(item)

            if isinstance(item.get("service"), list):
                item["service_summary"] = build_task_service_summary(item["service"])

            items.append(item)

        return items

    def build_data(self, args=None, collection=None):
        """
        构建分页数据
        执行 MongoDB 查询并返回分页结果
        
        参数：
            args: 请求参数
            collection: 数据集合名称
        
        返回：
            包含分页信息和数据的字典：
            {
                "page": 当前页码,
                "size": 页面大小,
                "total": 总记录数,
                "items": 数据列表,
                "query": 查询条件,
                "code": 状态码
            }
        """
        return build_collection_data_service(
            args=args,
            collection=collection,
            item_builder=self.build_return_items,
            query_serializer=self.serialize_response_value,
        )

    def get_default_field(self, args):
        """
        提取并处理默认字段（分页、排序）
        从 args 中提取这些字段并删除，避免影响数据查询
        
        参数：
            args: 请求参数字典（会被修改）
        
        返回：
            包含分页排序信息的字典：
            {
                "page": 页码,
                "size": 页面大小,
                "order": 排序列表 [("field", 1/-1), ...]
            }
        """
        return get_default_field_service(args)

    def send_export_file(self, args, _type):
        """
        导出数据为文本文件
        根据查询条件导出指定集合的数据
        
        参数：
            args: 查询参数
            _type: 数据类型（site/domain/ip/url等）
        
        返回：
            文件下载响应
        """
        # 定义不同类型对应的字段名
        _type_map_field_name = {
            "site": "site",
            "domain": "domain",
            "ip": "ip",
            "asset_site": "site",
            "asset_domain": "domain",
            "asset_ip": "ip",
            "asset_wih": "content",
            "url": "url",
            "fileleak": "url",
            "cip": "cidr_ip",
            "wih": "content",
            "wih_endpoint": "url",
        }
        
        # 导出场景：注入 _export 标记，绕过 API_PAGE_SIZE_MAX 限制
        args["_export"] = True
        # 查询数据
        data = self.build_data(args=args, collection=_type)["items"]
        items_set = set()
        
        # 提取要导出的字段
        for item in data:
            filed_name = _type_map_field_name.get(_type, "")
            if filed_name and filed_name in item:
                # IP 类型特殊处理：导出 IP:端口 格式
                if filed_name == "ip":
                    curr_ip = item[filed_name]
                    for port_info in item.get("port_info", []):
                        items_set.add("{}:{}".format(curr_ip, port_info["port_id"]))
                else:
                    items_set.add(item[filed_name])

        return self.send_file(items_set, _type)

    def send_export_file_attr(self, args, collection, field):
        """
        从指定集合中导出指定字段的数据
        
        参数：
            args: 查询参数
            collection: 集合名称
            field: 字段名
        
        返回：
            文件下载响应
        """
        # 导出场景：注入 _export 标记，绕过 API_PAGE_SIZE_MAX 限制
        args["_export"] = True
        data = self.build_data(args=args, collection=collection)["items"]
        items_set = set()
        
        for item in data:
            if field in item:
                value = item[field]
                # 如果是列表，展开后添加
                if isinstance(value, list):
                    items_set |= set(value)
                else:
                    items_set.add(value)

        return self.send_file(items_set, f"{collection}_{field}")

    def send_batch_export_file(self, task_id_list, _type):
        """
        批量导出多个任务的数据
        
        参数：
            task_id_list: 任务ID列表
            _type: 数据类型
        
        返回：
            文件下载响应
        """
        _type_map_field_name = {
            "site": "site",
            "domain": "domain",
            "ip": "ip",
            "url": "url",
            "fileleak": "url",
            "cip": "cidr_ip"
        }
        items_set = set()
        filed_name = _type_map_field_name.get(_type, "")

        # 遍历每个任务ID，查询并合并数据
        for task_id in task_id_list:
            if not filed_name:
                continue
            if not task_id:
                continue
            query = {"task_id": task_id}
            if _type == "fileleak":
                query["source"] = {"$ne": CollectSource.WIH_URL_PROBE}
            items = conn(_type).distinct(filed_name, query)
            items_set |= set(items)

        return self.send_file(items_set, _type)

    def send_scope_batch_export_file(self, scope_id_list, _type):
        """
        批量导出多个资产范围的数据
        
        参数：
            scope_id_list: 资产范围ID列表
            _type: 数据类型
        
        返回：
            文件下载响应
        """
        _type_map_field_name = {
            "asset_site": "site",
            "asset_domain": "domain",
            "asset_ip": "ip",
            "asset_wih": "content"
        }

        items_set = set()
        filed_name = _type_map_field_name.get(_type, "")

        # 遍历每个资产范围ID，查询并合并数据
        for scope_id in scope_id_list:
            if not filed_name:
                continue
            if not scope_id:
                continue
            query = {"scope_id": scope_id}
            items = conn(_type).distinct(filed_name, query)
            items_set |= set(items)

        return self.send_file(items_set, _type)

    def send_file(self, items_set, _type):
        """
        生成文件下载响应
        
        参数：
            items_set: 要导出的数据集合
            _type: 文件类型标识
        
        返回：
            Flask 响应对象（文件下载）
        """
        # 每行一个数据项
        response = make_response("\r\n".join(items_set))
        
        # 文件名格式：类型_数量_时间戳.txt
        filename = "{}_{}_{}.txt".format(_type, len(items_set), int(time.time()))
        
        # 设置响应头
        response.headers['Content-Type'] = 'application/octet-stream'
        response.headers["Access-Control-Expose-Headers"] = "Content-Disposition"
        response.headers["Content-Disposition"] = "attachment; filename={}".format(quote(filename))
        return response


def get_arl_parser(model, location='args'):
    """
    工具函数：创建参数解析器
    
    参数：
        model: 字段模型定义
        location: 参数位置（默认为 URL 参数）
    
    返回：
        RequestParser 对象
    """
    r = ARLResource()
    return r.get_parser(model, location)


# ==================== 导入所有路由命名空间 ====================
# 这些命名空间会在 main.py 中注册到 Flask-RESTX API

from .task import ns as task_ns                              # 任务管理
from .domain import ns as domain_ns                          # 域名资产
from .site import ns as site_ns                              # 站点资产
from .ip import ns as ip_ns                                  # IP 资产
from .url import ns as url_ns                                # URL 资产
from .user import ns as user_ns                              # 用户管理
from .image import ns as image_ns                            # 图片管理
from .cert import ns as cert_ns                              # 证书资产
from .service import ns as service_ns                        # 服务资产
from .fileleak import ns as fileleak_ns                      # 文件泄露
from .export import ns as export_ns                          # 单项导出
from .assetScope import ns as asset_scope_ns                 # 资产范围
from .assetDomain import ns as asset_domain_ns               # 资产域名
from .assetIP import ns as asset_ip_ns                       # 资产 IP
from .assetSite import ns as asset_site_ns                   # 资产站点
from .scheduler import ns as scheduler_ns                    # 任务调度器
from .poc import ns as poc_ns                                # PoC 管理
from .vuln import ns as vuln_ns                              # 漏洞管理
from .batchExport import ns as batch_export_ns               # 批量导出
from .policy import ns as policy_ns                          # 策略配置
from .npoc_service import ns as npoc_service_ns              # NPoC 服务
from .taskFofa import ns as task_fofa_ns                     # FOFA 任务
from .console import ns as console_ns                        # 控制台
from .cip import ns as cip_ns                                # CIP 管理
from .fingerprint import ns as fingerprint_ns                # 指纹管理
from .stat_finger import ns as stat_finger_ns                # 指纹统计
from .github_task import ns as github_task_ns                # GitHub 任务
from .github_result import ns as github_result_ns            # GitHub 结果
from .github_monitor_result import ns as github_monitor_result_ns  # GitHub 监控结果
from .github_scheduler import ns as github_scheduler_ns      # GitHub 调度器
from .task_schedule import ns as task_schedule_ns            # 任务调度
from .dingtalk_api import ns as dingtalk_api_ns              # 钉钉开放平台调试
from .nuclei_result import ns as nuclei_result_ns            # Nuclei 扫描结果
from .wih import ns as wih_ns                                # WIH
from .wih_endpoint import ns as wih_endpoint_ns              # WIH 接口提取
from .waf_host import ns as waf_host_ns                      # WAF 识别结果
from .assetWih import ns as asset_wih_ns                     # 资产 WIH
from .api_console import ns as api_console_ns                # 配置中心
