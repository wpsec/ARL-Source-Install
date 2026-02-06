"""
资产范围管理模块

功能：
- 资产范围查询、添加
- 资产范围删除、更新
- 支持域名和IP两种范围类型
- 支持黑名单配置

说明：
- 资产范围用于组织和管理资产
- 可以关联到任务和策略
- 支持监控任务定期扫描
"""
import re
from bson import ObjectId
from flask_restx import Resource, Api, reqparse, fields, Namespace
from app.utils import get_logger, auth
from app import utils
from . import base_query_fields, ARLResource, get_arl_parser
from app.utils import conn_db as conn
from app.modules import ErrorMsg, AssetScopeType

ns = Namespace('asset_scope', description="资产组范围")

logger = get_logger()

# 基础字段定义
base_fields = {
    'name': fields.String(description="资产组名称"),
    'scope': fields.String(description="资产范围"),
    "black_scope": fields.String(description="资产黑名单"),
    "scope_type": fields.String(description="资产范围类别")
}

# 添加资产范围字段
add_asset_scope_fields = ns.model('addAssetScope', base_fields)

# 查询字段（添加_id）
base_fields.update({
    "_id": fields.String(description="资产范围 ID")
})

# 合并通用查询字段
base_fields.update(base_query_fields)


@ns.route('/')
class ARLAssetScope(ARLResource):
    """资产范围管理接口"""
    
    parser = get_arl_parser(base_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        查询资产组列表
        
        参数：
            - name: 资产组名称（模糊匹配）
            - scope: 资产范围
            - black_scope: 黑名单
            - scope_type: 资产类型（domain|ip）
            - _id: 资产组ID
            - page: 页码
            - size: 每页数量
        
        返回：
            {
                "code": 200,
                "data": {
                    "items": [资产组列表],
                    "total": 总数
                }
            }
        
        资产组字段说明：
            - name: 资产组名称
            - scope_type: 类型（domain/ip）
            - scope_array: 资产范围数组
            - black_scope_array: 黑名单数组
        """
        args = self.parser.parse_args()
        data = self.build_data(args=args, collection='asset_scope')

        return data

    @auth
    @ns.expect(add_asset_scope_fields)
    def post(self):
        """
        添加新的资产组
        
        请求体：
            {
                "name": "资产组名称",
                "scope": "资产范围（逗号或空格分隔）",
                "black_scope": "黑名单（可选）",
                "scope_type": "domain|ip"
            }
        
        返回：
            {
                "code": 200,
                "data": {
                    "scope_id": "资产组ID",
                    "scope_array": [资产范围数组]
                }
            }
        
        说明：
        - scope_type为domain时，验证域名格式
        - scope_type为ip时，支持IP、CIDR、IP段格式
        - 示例：
          * 域名：example.com, test.com
          * IP: 192.168.1.1, 192.168.1.0/24, 192.168.1.1-192.168.1.100
        """
        args = self.parse_args(add_asset_scope_fields)
        name = args.pop('name')
        scope = args.pop('scope')
        black_scope = args.pop('black_scope')
        scope_type = args.pop('scope_type')

        # 验证资产类型
        if scope_type not in [AssetScopeType.IP, AssetScopeType.DOMAIN]:
            scope_type = AssetScopeType.DOMAIN

        # 处理黑名单
        black_scope_array = []
        if black_scope:
            black_scope_array = re.split(r",|\s", black_scope)

        # 分割资产范围（支持逗号和空格）
        scope_array = re.split(r",|\s", scope)
        # 清除空白符
        scope_array = list(filter(None, scope_array))
        new_scope_array = []
        
        # 验证每个资产范围
        for x in scope_array:
            if scope_type == AssetScopeType.DOMAIN:
                # 验证域名格式
                if not utils.is_valid_domain(x):
                    return utils.build_ret(ErrorMsg.DomainInvalid, {"scope": x})

                new_scope_array.append(x)

            if scope_type == AssetScopeType.IP:
                # 转换IP范围格式（支持CIDR、IP段等）
                transfer = utils.ip.transfer_ip_scope(x)
                if transfer is None:
                    return utils.build_ret(ErrorMsg.ScopeTypeIsNotIP, {"scope": x})

                new_scope_array.append(transfer)

        if not new_scope_array:
            return utils.build_ret(ErrorMsg.DomainInvalid, {"scope": ""})

        # 构建资产范围数据
        scope_data = {
            "name": name,
            "scope_type": scope_type,
            "scope": ",".join(new_scope_array),
            "scope_array": new_scope_array,
            "black_scope": black_scope,
            "black_scope_array": black_scope_array,
        }
        conn('asset_scope').insert(scope_data)

        scope_id = str(scope_data.pop("_id"))
        scope_data["scope_id"] = scope_id

        return utils.build_ret(ErrorMsg.Success, scope_data)


# 删除资产范围字段（GET方式）
delete_task_get_fields = ns.model('DeleteScopeByID',  {
    'scope': fields.String(description="删除资产范围", required=True),
    'scope_id': fields.String(description="资产范围id", required=True)
})

# 删除资产范围字段（POST方式）
delete_task_post_fields = ns.model('DeleteScope',  {
    'scope_id': fields.List(fields.String(description="删除资产范围", required=True), required=True)
})


@ns.route('/delete/')
class DeleteARLAssetScope(ARLResource):
    """资产范围删除接口"""
    
    parser = get_arl_parser(delete_task_get_fields, location='args')

    _table = 'asset_scope'

    @auth
    @ns.expect(parser)
    def get(self):
        """
        从资产组中删除单个资产范围（GET方式）
        
        参数：
            - scope_id: 资产组ID
            - scope: 要删除的资产范围
        
        返回：
            操作结果
        
        说明：
        - 从指定资产组中移除某个资产范围
        - 不会删除整个资产组
        - 用于精细化管理资产范围
        """
        args = self.parser.parse_args()
        scope = str(args.pop('scope', "")).lower()
        scope_id = str(args.pop('scope_id', "")).lower()

        # 查询资产组数据
        scope_data = self.get_scope_data(scope_id)
        if not scope_data:
            return utils.build_ret(ErrorMsg.NotFoundScopeID, {"scope_id": scope_id})

        query = {'_id': ObjectId(scope_id)}
        
        # 检查资产范围是否存在
        if scope not in scope_data.get("scope_array", []):
            return utils.build_ret(ErrorMsg.NotFoundScope, {"scope_id": scope_id, "scope":scope})

        # 从数组中移除该范围
        scope_data["scope_array"].remove(scope)
        scope_data["scope"] = ",".join(scope_data["scope_array"])
        utils.conn_db(self._table).find_one_and_replace(query, scope_data)

        return utils.build_ret(ErrorMsg.Success, {"scope_id": scope_id, "scope":scope})

    def get_scope_data(self, scope_id):
        """
        获取资产组数据
        
        参数：
            scope_id: 资产组ID
        
        返回：
            资产组数据或None
        """
        query = {'_id': ObjectId(scope_id)}
        scope_data = utils.conn_db(self._table).find_one(query)
        return scope_data

    @auth
    @ns.expect(delete_task_post_fields)
    def post(self):
        """
        批量删除资产组（POST方式）
        
        请求体：
            {
                "scope_id": ["资产组ID1", "资产组ID2", ...]
            }
        
        返回：
            操作结果
        
        说明：
        - 删除整个资产组及其关联的所有资产
        - 会同时删除以下数据：
          * asset_domain: 域名资产
          * asset_site: 站点资产
          * asset_ip: IP资产
          * scheduler: 相关定时任务
          * asset_wih: WIH资产
        - 删除操作不可逆，请谨慎使用
        """
        args = self.parse_args(delete_task_post_fields)
        scope_id_list = args.pop('scope_id')
        
        # 验证所有资产组是否存在
        for scope_id in scope_id_list:
            if not self.get_scope_data(scope_id):
                return utils.build_ret(ErrorMsg.NotFoundScopeID, {"scope_id": scope_id})

        # 需要删除的关联表
        table_list = ["asset_domain", "asset_site", "asset_ip", "scheduler", "asset_wih"]

        # 执行删除操作
        for scope_id in scope_id_list:
            # 删除资产组
            utils.conn_db(self._table).delete_many({'_id': ObjectId(scope_id)})

            # 删除关联的资产数据
            for name in table_list:
                utils.conn_db(name).delete_many({'scope_id': scope_id})

        return utils.build_ret(ErrorMsg.Success, {"scope_id": scope_id_list})


# 添加资产范围字段
add_scope_fields = ns.model('AddScope',  {
    'scope': fields.String(description="添加资产范围"),
    "scope_id": fields.String(description="添加资产范围")
})


@ns.route('/add/')
class AddARLAssetScope(ARLResource):
    """添加资产范围接口"""
    
    @auth
    @ns.expect(add_scope_fields)
    def post(self):
        """
        向已有资产组添加新的资产范围
        
        请求体：
            {
                "scope_id": "资产组ID",
                "scope": "新增资产范围（逗号或空格分隔）"
            }
        
        返回：
            {
                "code": 200,
                "data": {
                    "scope_id": "资产组ID",
                    "scope_array": [更新后的资产范围数组]
                }
            }
        
        说明：
        - 向现有资产组追加新的资产范围
        - 会根据资产组类型自动验证格式
        - 域名类型：验证域名格式
        - IP类型：支持IP、CIDR、IP段
        - 自动去重，不会添加重复的资产范围
        """
        args = self.parse_args(add_scope_fields)
        scope = str(args.pop('scope', "")).lower()

        scope_id = args.pop('scope_id', "")

        table = 'asset_scope'
        query = {'_id': ObjectId(scope_id)}
        scope_data = utils.conn_db(table).find_one(query)
        if not scope_data:
            return utils.build_ret(ErrorMsg.NotFoundScopeID, {"scope_id": scope_id, "scope": scope})

        # 获取资产组类型
        scope_type = scope_data.get("scope_type")
        if scope_type not in [AssetScopeType.IP, AssetScopeType.DOMAIN]:
            scope_type = AssetScopeType.DOMAIN

        # 分割资产范围
        scope_array = re.split(r",|\s", scope)
        # 清除空白符
        scope_array = list(filter(None, scope_array))
        if not scope_array:
            return utils.build_ret(ErrorMsg.DomainInvalid, {"scope": ""})

        # 验证并添加每个资产范围
        for x in scope_array:
            new_scope = x
            
            # 域名类型验证
            if scope_type == AssetScopeType.DOMAIN:
                if not utils.is_valid_domain(x):
                    return utils.build_ret(ErrorMsg.DomainInvalid, {"scope": x})

            # IP类型验证和转换
            if scope_type == AssetScopeType.IP:
                transfer = utils.ip.transfer_ip_scope(x)
                if transfer is None:
                    return utils.build_ret(ErrorMsg.ScopeTypeIsNotIP, {"scope": x})
                new_scope = transfer

            # 检查是否已存在（去重）
            if new_scope in scope_data.get("scope_array", []):
                return utils.build_ret(ErrorMsg.ExistScope, {"scope_id": scope_id, "scope": x})

            # 添加到数组
            scope_data["scope_array"].append(new_scope)

        # 更新数据库
        scope_data["scope"] = ",".join(scope_data["scope_array"])
        utils.conn_db(table).find_one_and_replace(query, scope_data)

        return utils.build_ret(ErrorMsg.Success, {"scope_id": scope_id, "scope": scope})
