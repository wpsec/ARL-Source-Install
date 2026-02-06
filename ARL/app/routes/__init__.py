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

# 基础查询字段定义
# 这些字段用于分页、排序等通用查询功能
base_query_fields = {
    'page': fields.Integer(description="当前页数", example=1),
    'size': fields.Integer(description="页面大小", example=10),
    'order': fields.String(description="排序字段", example='_id'),
}

# 只能用等号进行 MongoDB 查询的字段
# 这些字段不支持模糊匹配，只支持精确匹配
EQUAL_FIELDS = ["task_id", "task_tag", "ip_type", "scope_id", "type"]


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
        query_args = {}
        for key in args:
            # 跳过分页、排序等基础字段
            if key in base_query_fields:
                continue

            # 处理 _id 字段（转换为 ObjectId）
            if key == '_id':
                if args[key]:
                    query_args[key] = ObjectId(args[key])

                continue

            # 跳过空值
            if args[key] is None:
                continue

            # 日期大于查询
            if key.endswith("__dgt"):
                real_key = key.split('__dgt')[0]
                raw_value = query_args.get(real_key, {})
                raw_value.update({
                    "$gt": datetime.strptime(args[key],
                                             "%Y-%m-%d %H:%M:%S")
                })
                query_args[real_key] = raw_value

            # 日期小于查询
            elif key.endswith("__dlt"):
                real_key = key.split('__dlt')[0]
                raw_value = query_args.get(real_key, {})
                raw_value.update({
                    "$lt": datetime.strptime(args[key],
                                             "%Y-%m-%d %H:%M:%S")
                })
                query_args[real_key] = raw_value

            # 不等于查询
            elif key.endswith("__neq"):
                real_key = key.split('__neq')[0]
                raw_value = {
                    "$ne": args[key]
                }
                query_args[real_key] = raw_value

            # 正则不匹配查询
            elif key.endswith("__not"):
                real_key = key.split('__not')[0]
                raw_value = {
                    "$not": re.compile(re.escape(args[key]))
                }
                query_args[real_key] = raw_value

            # 字符串查询（模糊或精确）
            elif isinstance(args[key], str):
                if key in EQUAL_FIELDS:
                    # 精确匹配
                    query_args[key] = args[key]
                else:
                    # 模糊匹配（不区分大小写）
                    query_args[key] = {
                        "$regex": re.escape(args[key]),
                        '$options': "i"
                    }
            else:
                # 其他类型直接赋值
                query_args[key] = args[key]

        return query_args

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

        # 需要特殊处理的字段（转换为字符串）
        special_keys = ["_id", "save_date", "update_date"]

        for item in data:
            for key in item:
                if key in special_keys:
                    item[key] = str(item[key])

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
        # 复制原始参数用于构建缓存键，避免 get_default_field 修改原字典导致键不稳定
        raw_args = {}
        if isinstance(args, dict):
            raw_args = args.copy()

        # 获取分页、排序参数
        default_field = self.get_default_field(args)
        page = default_field.get("page", 1)
        size = default_field.get("size", 10)
        orderby_list = default_field.get('order', [("_id", -1)])

        def _loader():
            # 构建查询条件
            query = self.build_db_query(args)

            # 执行分页查询
            result = conn(collection).find(query).sort(orderby_list).skip(size * (page - 1)).limit(size)
            count = conn(collection).count(query)
            items = self.build_return_items(result)

            # 处理查询条件中的特殊字段（用于返回）
            special_keys = ["_id", "save_date", "update_date"]
            for key in query:
                if key in special_keys:
                    query[key] = str(query[key])

                raw_value = query[key]
                if isinstance(raw_value, dict):
                    if "$not" in raw_value:
                        if isinstance(raw_value["$not"], type(re.compile(""))):
                            raw_value["$not"] = raw_value["$not"].pattern
                    if "$gt" in raw_value and isinstance(raw_value["$gt"], datetime):
                        raw_value["$gt"] = raw_value["$gt"].strftime("%Y-%m-%d %H:%M:%S")
                    if "$lt" in raw_value and isinstance(raw_value["$lt"], datetime):
                        raw_value["$lt"] = raw_value["$lt"].strftime("%Y-%m-%d %H:%M:%S")

            return {
                "page": page,
                "size": size,
                "total": count,
                "items": items,
                "query": query,
                "code": 200
            }

        # 大分页请求通常一次性查询，不进入缓存，避免缓存超大对象
        if size > 5000:
            return _loader()

        # 列表查询缓存键：按 collection + 分页排序 + 原始参数稳定化
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
        return cached_call(cache_key, _loader, expire=60)

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
        default_field_map = {
            "page": 1,
            "size": 10,
            "order": "-_id"
        }

        ret = default_field_map.copy()

        for x in default_field_map:
            if x in args and args[x]:
                ret[x] = args.pop(x)
                if x == "size":
                    # 限制页面大小范围 [1, 100000]
                    if ret[x] <= 0:
                        ret[x] = 10
                    if ret[x] >= 100000:
                        ret[x] = 100000

                if x == "page":
                    # 页码最小为 1
                    if ret[x] <= 0:
                        ret[x] = 1

        # 解析排序字段
        # 支持格式："-field1,+field2,field3"
        # -: 降序，+: 升序，无符号: 升序
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

        ret['order'] = orderby_list
        return ret

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
            "cip": "cidr_ip",
            "wih": "content",
        }
        
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
from .nuclei_result import ns as nuclei_result_ns            # Nuclei 扫描结果
from .wih import ns as wih_ns                                # WIH
from .assetWih import ns as asset_wih_ns                     # 资产 WIH
