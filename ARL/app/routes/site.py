"""
站点信息管理模块

功能：
- 站点信息查询、导出
- 站点结果集保存
- 站点指纹信息统计
- 站点批量删除

说明：
- 站点数据来自HTTP/HTTPS探测
- 包含站点标题、服务器信息、指纹、favicon等
- 支持多维度查询和筛选
"""
import copy
from bson import ObjectId
from flask_restx import Resource, Api, reqparse, fields, Namespace
from app.utils import get_logger, auth
from app.modules import ErrorMsg
from app import utils
from . import base_query_fields, ARLResource, get_arl_parser


ns = Namespace('site', description="站点信息")

logger = get_logger()

# 站点查询基础字段
base_search_fields = {
    'site': fields.String(required=False, description="站点URL"),
    'hostname': fields.String(description="主机名"),
    'ip': fields.String(description="ip"),
    'title': fields.String(description="标题"),
    'http_server': fields.String(description="Web servers"),
    'headers': fields.String(description="headers"),
    'finger.name': fields.String(description="指纹"),
    'status': fields.Integer(description="状态码"),
    'favicon.hash': fields.Integer(description="favicon hash"),
    'task_id': fields.String(description="任务 ID"),
    'tag': fields.String(description="标签列表")
}

# 复制一份用于结果集保存
site_search_fields = copy.copy(base_search_fields)

# 合并通用查询字段（分页、排序等）
base_search_fields.update(base_query_fields)


@ns.route('/')
class ARLSite(ARLResource):
    """站点信息查询接口"""
    
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        查询站点信息
        
        参数：
            - site: 站点URL（模糊匹配）
            - hostname: 主机名
            - ip: IP地址
            - title: 页面标题（支持模糊搜索）
            - http_server: Web服务器类型（如nginx、Apache）
            - headers: HTTP响应头（模糊搜索）
            - finger.name: 指纹名称（如WordPress、ThinkPHP）
            - status: HTTP状态码
            - favicon.hash: favicon图标哈希值
            - task_id: 任务ID
            - tag: 标签
            - page: 页码（默认1）
            - size: 每页数量（默认10）
        
        返回：
            {
                "code": 200,
                "data": {
                    "items": [站点信息列表],
                    "total": 总数
                }
            }
        
        站点字段说明：
            - site: 完整URL
            - title: 页面标题
            - http_server: Web服务器
            - status: 状态码
            - headers: 响应头
            - finger: 指纹列表 [{name, version}]
            - favicon: {hash, location}
            - screenshot: 截图路径
        """
        args = self.parser.parse_args()
        data = self.build_data(args = args,  collection = 'site')

        return data


@ns.route('/export/')
class ARLSiteExport(ARLResource):
    """站点信息导出接口"""
    
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        导出站点信息到Excel文件
        
        参数：
            与查询接口相同
        
        返回：
            Excel文件下载
        
        说明：
        - 导出字段：站点URL、标题、IP、状态码、服务器、指纹等
        - 文件名：site_export_时间戳.xlsx
        """
        args = self.parser.parse_args()
        response = self.send_export_file(args=args, _type="site")

        return response


@ns.route('/save_result_set/')
class ARLSaveResultSet(ARLResource):
    """保存站点结果集接口"""
    
    parser = get_arl_parser(site_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        保存站点查询结果为结果集
        
        参数：
            与查询接口相同（不包含分页参数）
        
        返回：
            {
                "code": 200,
                "data": {
                    "total": 保存的站点数量,
                    "result_set_id": "结果集ID"
                }
            }
        
        说明：
        - 结果集可用于后续的风险巡航任务
        - 会自动去重和去除URL文件名
        - 示例：http://example.com/index.html -> http://example.com/
        """
        args = self.parser.parse_args()
        query = self.build_db_query(args)
        # 获取所有匹配的站点URL
        items = utils.conn_db('site').distinct("site", query)

        # 去重并去除文件名（只保留到路径）
        items = list(set([utils.url.cut_filename(x) for x in items]))

        # 检查是否有结果
        if len(items) == 0:
            return utils.build_ret(ErrorMsg.QueryResultIsEmpty, {})

        # 保存结果集到数据库
        data = {
            "items": items,
            "type": "site",
            "total": len(items)
        }
        result = utils.conn_db('result_set').insert_one(data)

        ret_data = {
            "result_set_id": str(result.inserted_id),
            "result_total": len(items),
            "type": "site",
        }

        return utils.build_ret(ErrorMsg.Success, ret_data)


# 添加站点标签请求模型
add_site_tag_fields = ns.model('AddSiteTagFields',  {
    "tag": fields.String(required=True, description="添加站点标签"),
    "_id": fields.String(description="站点ID", required=True)
})


@ns.route('/add_tag/')
class AddSiteTagARL(ARLResource):
    """站点添加标签接口"""

    @auth
    @ns.expect(add_site_tag_fields)
    def post(self):
        """
        为站点添加标签
        
        请求体：
            {
                "_id": "站点ID",
                "tag": "标签名称"
            }
        
        返回：
            操作结果
        
        说明：
        - 支持为站点添加自定义标签
        - 标签可用于分类管理和筛选
        - 一个站点可以有多个标签
        """
        args = self.parse_args(add_site_tag_fields)
        site_id = args.pop("_id")
        tag = args.pop("tag")

        query = {"_id": ObjectId(site_id)}
        data = utils.conn_db('site').find_one(query)
        if not data:
            return utils.build_ret(ErrorMsg.SiteIdNotFound, {"site_id": site_id})

        # 获取现有标签列表
        tag_list = []
        old_tag = data.get("tag")
        if old_tag:
            if isinstance(old_tag, str):
                tag_list.append(old_tag)

            if isinstance(old_tag, list):
                tag_list.extend(old_tag)

        # 检查标签是否已存在
        if tag in tag_list:
            return utils.build_ret(ErrorMsg.SiteTagIsExist, {"tag": tag})

        # 添加新标签
        tag_list.append(tag)

        utils.conn_db('site').update_one(query, {"$set": {"tag": tag_list}})

        return utils.build_ret(ErrorMsg.Success, {"tag": tag})


# 删除站点标签请求模型
delete_site_tag_fields = ns.model('DeleteSiteTagFields',  {
    "tag": fields.String(required=True, description="删除站点标签"),
    "_id": fields.String(description="站点ID", required=True)
})


@ns.route('/delete_tag/')
class DeleteSiteTagARL(ARLResource):
    """删除站点标签接口"""

    @auth
    @ns.expect(delete_site_tag_fields)
    def post(self):
        """
        删除站点标签
        
        请求体：
            {
                "_id": "站点ID",
                "tag": "要删除的标签名称"
            }
        
        返回：
            操作结果
        
        说明：
        - 从站点的标签列表中移除指定标签
        - 标签不存在时返回错误
        """
        args = self.parse_args(delete_site_tag_fields)
        site_id = args.pop("_id")
        tag = args.pop("tag")

        query = {"_id": ObjectId(site_id)}
        data = utils.conn_db('site').find_one(query)
        if not data:
            return utils.build_ret(ErrorMsg.SiteIdNotFound, {"site_id": site_id})

        # 获取现有标签列表
        tag_list = []
        old_tag = data.get("tag")
        if old_tag:
            if isinstance(old_tag, str):
                tag_list.append(old_tag)

            if isinstance(old_tag, list):
                tag_list.extend(old_tag)

        # 检查标签是否存在
        if tag not in tag_list:
            return utils.build_ret(ErrorMsg.SiteTagNotExist, {"tag": tag})

        # 删除标签
        tag_list.remove(tag)

        utils.conn_db('site').update_one(query, {"$set": {"tag": tag_list}})

        return utils.build_ret(ErrorMsg.Success, {"tag": tag})



# 删除站点请求模型
delete_site_fields = ns.model('deleteSiteFields',  {
    '_id': fields.List(fields.String(required=True, description="站点 _id"))
})


@ns.route('/delete/')
class DeleteARLSite(ARLResource):
    """站点批量删除接口"""
    
    @auth
    @ns.expect(delete_site_fields)
    def post(self):
        """
        批量删除站点记录
        
        请求体：
            {
                "_id": ["站点ID1", "站点ID2", ...]
            }
        
        返回：
            {
                "code": 200,
                "data": {
                    "_id": [已删除的站点ID列表]
                }
            }
        
        说明：
        - 支持批量删除多个站点记录
        - 删除操作不可逆，请谨慎使用
        - 删除站点不会影响关联的域名、IP等其他资产
        """
        args = self.parse_args(delete_site_fields)
        id_list = args.pop('_id', [])
        
        # 遍历删除每个站点
        for _id in id_list:
            query = {'_id': ObjectId(_id)}
            utils.conn_db('site').delete_one(query)

        return utils.build_ret(ErrorMsg.Success, {'_id': id_list})
