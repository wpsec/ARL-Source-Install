"""
资产域名管理模块

功能：
- 资产组中的域名查询、导出
- 添加域名到资产组
- 域名删除和更新

说明：
- 资产域名是资产组管理的核心数据
- 支持从任务同步域名到资产组
- 可以手动添加域名到资产组
- 支持监控域名的变化
"""
import re
from bson import ObjectId
from flask_restx import Resource, Api, reqparse, fields, Namespace
from app import utils
from app.utils import get_logger, auth
from . import base_query_fields, ARLResource, get_arl_parser
from app.modules import ErrorMsg
from app.helpers import submit_task_task, get_ip_domain_list, get_options_by_policy_id
from app.modules import TaskTag

ns = Namespace('asset_domain', description="资产组域名信息")

logger = get_logger()

# 域名查询字段
base_search_fields = {
    'domain': fields.String(required=False, description="域名"),
    'record': fields.String(description="解析值"),
    'type': fields.String(description="解析类型"),
    'ips': fields.String(description="IP"),
    'source': fields.String(description="来源"),
    "task_id": fields.String(description="来源任务 ID"),
    "update_date__dgt": fields.String(description="更新时间大于"),
    "update_date__dlt": fields.String(description="更新时间小于"),
    'scope_id': fields.String(description="范围 ID")
}

base_search_fields.update(base_query_fields)


# 添加域名请求模型
add_domain_fields = ns.model('addAssetDomain',  {
    'domain': fields.String(required=True, description="域名"),
    'scope_id': fields.String(required=True, description="资产组范围ID"),
    'policy_id': fields.String(description="策略 ID"),
})


@ns.route('/')
class ARLAssetDomain(ARLResource):
    """资产域名管理接口"""
    
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        查询资产组中的域名信息
        
        参数：
            - domain: 域名（模糊匹配）
            - record: DNS解析值
            - type: DNS记录类型（A/AAAA/CNAME等）
            - ips: IP地址
            - source: 来源（任务/手动添加）
            - task_id: 来源任务ID
            - update_date__dgt: 更新时间大于
            - update_date__dlt: 更新时间小于
            - scope_id: 资产组ID
            - page: 页码
            - size: 每页数量
        
        返回：
            {
                "code": 200,
                "data": {
                    "items": [域名列表],
                    "total": 总数
                }
            }
        
        域名字段说明：
            - domain: 域名
            - ips: 解析的IP列表
            - record: DNS解析记录
            - type: 记录类型
            - source: 来源（任务ID或manual）
            - scope_id: 所属资产组
        """
        args = self.parser.parse_args()
        data = self.build_data(args=args, collection='asset_domain')

        return data

    @auth
    @ns.expect(add_domain_fields)
    def post(self):
        """
        手动添加域名到资产组
        
        请求体：
            {
                "domain": "要添加的域名（多个用空格或逗号分隔）",
                "scope_id": "资产组ID",
                "policy_id": "策略ID（可选，用于自动扫描）"
            }
        
        返回：
            {
                "code": 200,
                "data": {
                    "domain": "成功添加的域名列表",
                    "scope_id": "资产组ID",
                    "domain_in_scope": "已存在的域名",
                    "add_domain_len": 新增数量,
                    "task_id": "扫描任务ID（如果指定了策略）"
                }
            }
        
        说明：
        - 域名必须属于资产组的范围（根域名匹配）
        - 已存在的域名不会重复添加
        - 如果指定了policy_id，会自动创建扫描任务
        - 只有域名类型的资产组才能添加域名
        
        示例：
            domain: "www.example.com sub.example.com"
            scope_id: "603c65316591e73dd717d176"
        """
        args = self.parse_args(add_domain_fields)
        raw_domain = args.pop("domain")
        scope_id = args.pop("scope_id")
        policy_id = args.pop("policy_id")

        # 解析域名列表
        try:
            _, domain_list = get_ip_domain_list(raw_domain)
        except Exception as e:
            return utils.build_ret(ErrorMsg.Error, {"error": str(e)})

        # 查询资产组信息
        scope_data = utils.conn_db('asset_scope').find_one({"_id": ObjectId(scope_id)})
        if not scope_data:
            return utils.build_ret(ErrorMsg.NotFoundScopeID, {"scope_id": scope_id})

        # 验证资产组类型
        scope_type = scope_data.get("scope_type", "domain")
        if scope_type != 'domain':
            return utils.build_ret(ErrorMsg.Error, {"error": "目前仅域名资产组可添加子域名"})

        # 验证域名是否在资产组范围内，并检查是否已存在
        domain_in_scope_list = []
        add_domain_list = []
        for domain in domain_list:
            # 检查域名的根域名是否在资产组范围内
            if utils.get_fld(domain) not in scope_data["scope"]:
                return utils.build_ret(ErrorMsg.DomainNotFoundViaScope, {"domain": domain})

            # 检查域名是否已存在
            domain_data = utils.conn_db("asset_domain").find_one({"domain": domain, "scope_id": scope_id})
            if domain_data:
                domain_in_scope_list.append(domain)
                continue
            add_domain_list.append(domain)

        ret_data = {
            "domain": ",".join(add_domain_list),
            "scope_id": scope_id,
            "domain_in_scope": ",".join(domain_in_scope_list),
            "add_domain_len": len(add_domain_list)
        }

        if len(add_domain_list) == 0:
            return utils.build_ret(ErrorMsg.DomainNotFoundNotInScope, ret_data)

        # 准备提交扫描任务
        target = " ".join(add_domain_list)
        name = "添加域名-{}".format(scope_data["name"])

        # 默认扫描选项（轻量级扫描）
        options = {
            'domain_brute': True,  # 域名爆破
            'domain_brute_type': 'test',  # 测试级别爆破
            'port_scan_type': 'test',  # 测试级别端口扫描
            'port_scan': True,  # 启用端口扫描
            'service_detection': False,  # 服务识别
            'service_brute': False,  # 服务暴力破解
            'os_detection': False,  # 操作系统识别
            'site_identify': False,  # 站点识别
            'site_capture': False,  # 站点截图
            'file_leak': False,  # 文件泄露检测
            'alt_dns': False,  # DNS字典智能生成
            'site_spider': False,  # 站点爬虫
            'search_engines': False,  # 搜索引擎
            'ssl_cert': False,  # SSL证书获取
            'fofa_search': False,  # FOFA搜索
            'dns_query_plugin': False,  # DNS查询插件
            'related_scope_id': scope_id  # 关联资产组
        }

        try:
            # 如果指定了策略ID，使用策略配置
            if policy_id and len(policy_id) == 24:
                policy_options = get_options_by_policy_id(policy_id=policy_id, task_tag=TaskTag.TASK)
                if policy_options:
                    policy_options["related_scope_id"] = scope_id
                    options.update(policy_options)

            # 提交扫描任务
            submit_task_task(target=target, name=name, options=options)
        except Exception as e:
            logger.exception(e)
            return utils.build_ret(ErrorMsg.Error, {"error": str(e)})

        return utils.build_ret(ErrorMsg.Success, ret_data)


# 删除域名请求模型
delete_domain_fields = ns.model('deleteAssetDomain',  {
    '_id': fields.List(fields.String(required=True, description="数据_id"))
})


@ns.route('/delete/')
class DeleteARLAssetDomain(ARLResource):
    """删除资产域名接口"""
    
    @auth
    @ns.expect(delete_domain_fields)
    def post(self):
        """
        批量删除资产组中的域名
        
        请求体：
            {
                "_id": ["域名数据ID1", "域名数据ID2", ...]
            }
        
        返回：
            操作结果
        
        说明：
        - 支持批量删除多个域名
        - 删除操作不可逆
        - 只删除资产组中的域名记录，不影响任务数据
        """
        args = self.parse_args(delete_domain_fields)
        id_list = args.pop('_id', "")
        
        # 遍历删除每个域名
        for _id in id_list:
            query = {'_id': ObjectId(_id)}
            utils.conn_db('asset_domain').delete_one(query)

        return utils.build_ret(ErrorMsg.Success, {'_id': id_list})


@ns.route('/export/')
class ARLAssetDomainExport(ARLResource):
    """资产域名导出接口"""
    
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        导出资产组中的域名信息到Excel
        
        参数：
            与查询接口相同
        
        返回：
            Excel文件下载
        
        说明：
        - 导出字段：域名、IP、DNS记录类型、解析值、来源等
        - 文件名：asset_domain_export_时间戳.xlsx
        """
        args = self.parser.parse_args()
        response = self.send_export_file(args=args, _type="asset_domain")

        return response

