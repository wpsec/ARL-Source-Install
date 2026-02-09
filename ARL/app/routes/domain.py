"""
域名资产管理 API
================================================

该模块提供域名资产的查询、导出和删除功能

主要功能：
1. 查询域名信息（支持多种查询条件）
2. 导出域名数据为文本文件
3. 批量删除域名记录

域名信息包括：
- 域名本身
- DNS 解析记录（A、AAAA、CNAME、MX等）
- 解析的IP地址
- 域名来源（爆破、搜索引擎、证书等）
- 关联的任务ID

域名来源类型：
- domain_brute: 域名爆破发现
- alt_dns: 域名变异生成
- cert_common_name: 证书中的域名
- cert_alternative_name: 证书备用名称
- search_engines: 搜索引擎发现
- dns_query_plugin: DNS查询插件发现
"""
from bson import ObjectId
from flask_restx import Resource, Api, reqparse, fields, Namespace
from app.utils import get_logger, auth
from app import utils
from app.modules import ErrorMsg
from . import base_query_fields, ARLResource, get_arl_parser

# 创建域名信息命名空间
ns = Namespace('domain', description="域名信息")

logger = get_logger()

# 域名查询字段定义
base_search_fields = {
    'domain': fields.String(required=False, description="域名（支持模糊匹配）"),
    'record': fields.String(description="DNS解析值（IP地址或域名）"),
    'type': fields.String(description="DNS记录类型（A、AAAA、CNAME、MX等）"),
    'ips': fields.String(description="解析到的IP地址"),
    'source': fields.String(description="域名来源（domain_brute、alt_dns、cert等）"),
    "task_id": fields.String(description="关联的任务ID")
}

# 合并基础查询字段（分页、排序等）
base_search_fields.update(base_query_fields)


@ns.route('/')
class ARLDomain(ARLResource):
    """域名信息查询接口"""
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        查询域名信息
        
        支持的查询条件：
        - domain: 域名（模糊匹配）
        - record: DNS解析值
        - type: DNS记录类型
        - ips: IP地址
        - source: 域名来源
        - task_id: 任务ID
        
        返回：
            分页的域名信息列表
        
        应用场景：
        - 查询子域名
        - 查询解析到特定IP的域名
        - 按来源筛选域名
        - 查询特定任务发现的域名
        """
        args = self.parser.parse_args()
        # 从 domain 集合查询数据
        data = self.build_data(args=args, collection='domain')

        return data


@ns.route('/export/')
class ARLDomainExport(ARLResource):
    """域名数据导出接口"""
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        导出域名数据为文本文件
        
        根据查询条件导出符合条件的所有域名
        每行一个域名
        
        返回：
            文本文件下载
            文件名格式：domain_数量_时间戳.txt
        
        应用场景：
        - 导出子域名列表用于其他工具
        - 批量导出资产清单
        - 数据备份
        """
        args = self.parser.parse_args()
        response = self.send_export_file(args=args, _type="domain")

        return response


# 删除域名请求模型定义
delete_domain_fields = ns.model('deleteDomainFields', {
    '_id': fields.List(fields.String(required=True, description="要删除的域名ID列表"))
})


@ns.route('/delete/')
class DeleteARLDomain(ARLResource):
    """域名信息删除接口"""
    
    @auth
    @ns.expect(delete_domain_fields)
    def post(self):
        """
        批量删除域名记录
        
        请求体：
            {
                "_id": ["域名ID1", "域名ID2", ...]
            }
        
        返回：
            删除成功的域名ID列表
        
        注意：
        - 支持批量删除
        - 删除操作不可恢复
        - 只删除域名记录，不影响关联的其他资产
        - 需要管理员权限
        """
        args = self.parse_args(delete_domain_fields)
        id_list = args.pop('_id', [])
        
        # 遍历删除每个域名记录
        for _id in id_list:
            query = {'_id': ObjectId(_id)}
            utils.conn_db('domain').delete_one(query)

        return utils.build_ret(ErrorMsg.Success, {'_id': id_list})
