"""
资产站点管理模块

功能说明：
- 管理资产组中的站点信息（Web页面）
- 支持站点的查询、添加、导出、删除
- 提供标签管理功能（添加/删除标签）
- 支持保存查询结果集

主要数据字段：
- site: 站点URL
- hostname: 主机名
- ip: IP地址
- title: 页面标题
- http_server: Web服务器类型
- status: HTTP状态码
- finger: 指纹信息（框架、中间件等）
- favicon.hash: 网站图标哈希值
- tag: 自定义标签列表
"""
from bson import ObjectId
from flask_restx import Resource, Api, reqparse, fields, Namespace
from app.utils import get_logger, auth
from . import base_query_fields, ARLResource, get_arl_parser
from app.modules import ErrorMsg, TaskTag
from app import utils, services
from app.helpers.asset_site import find_asset_site_not_in_scope
from app.helpers.task import target2list, submit_add_asset_site_task
from app.helpers.policy import get_options_by_policy_id

ns = Namespace('asset_site', description="资产组站点信息")

logger = get_logger()

# 站点查询字段定义
base_search_fields = {
    'site': fields.String(required=False, description="站点URL（如https://example.com/path）"),
    'hostname': fields.String(description="主机名（如www.example.com）"),
    'ip': fields.String(description="站点IP地址"),
    'title': fields.String(description="页面标题"),
    'http_server': fields.String(description="Web服务器（如nginx, apache）"),
    'headers': fields.String(description="HTTP响应头"),
    'finger.name': fields.String(description="指纹名称（如Spring, Laravel等框架）"),
    'status': fields.Integer(description="HTTP状态码（200, 404等）"),
    'favicon.hash': fields.Integer(description="favicon图标哈希值"),
    'task_id': fields.String(description="任务ID"),
    'scope_id': fields.String(description="所属资产组ID"),
    "update_date__dgt": fields.String(description="更新时间大于（格式：YYYY-MM-DD HH:mm:ss）"),
    "update_date__dlt": fields.String(description="更新时间小于（格式：YYYY-MM-DD HH:mm:ss）"),
    'tag': fields.String(description="自定义标签")
}

site_search_fields = base_search_fields.copy()

base_search_fields.update(base_query_fields)

# 添加站点请求模型
add_site_fields = ns.model('addAssetSite',  {
    'site': fields.String(required=True, description="站点URL，支持多个用换行分隔"),
    'scope_id': fields.String(required=True, description="资产组范围ID"),
    'policy_id': fields.String(description="策略ID（可选，使用策略配置）"),
})


@ns.route('/')
class ARLAssetSite(ARLResource):
    """资产站点管理接口"""
    
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        查询资产组中的站点信息
        
        参数：
            - site: 站点URL过滤
            - hostname: 主机名过滤
            - ip: IP地址过滤
            - title: 页面标题过滤
            - http_server: Web服务器过滤
            - finger.name: 指纹名称过滤
            - status: HTTP状态码过滤
            - favicon.hash: favicon哈希值过滤
            - scope_id: 资产组ID过滤
            - tag: 标签过滤
            - update_date__dgt/dlt: 更新时间范围
            - page: 页码
            - size: 每页数量
        
        返回：
            {
                "code": 200,
                "items": [
                    {
                        "_id": "数据ID",
                        "site": "站点URL",
                        "hostname": "主机名",
                        "ip": "IP地址",
                        "title": "页面标题",
                        "http_server": "Web服务器",
                        "status": HTTP状态码,
                        "finger": [{"name": "指纹名"}],
                        "favicon": {"hash": 哈希值},
                        "headers": "响应头",
                        "tag": ["标签1", "标签2"],
                        "screenshot": "截图路径",
                        "scope_id": "资产组ID",
                        "update_date": "更新时间"
                    }
                ],
                "total": 总数
            }
        
        说明：
        - 返回站点的完整信息，包括指纹、截图等
        - 支持按多种维度组合查询
        """
        args = self.parser.parse_args()
        data = self.build_data(args=args, collection='asset_site')

        return data

    @auth
    @ns.expect(add_site_fields)
    def post(self):
        """
        添加站点到资产组中
        
        请求体：
            {
                "site": "https://example.com\nhttps://test.com",
                "scope_id": "资产组ID",
                "policy_id": "策略ID（可选）"
            }
        
        返回：
            {
                "code": 200,
                "message": "成功",
                "task_id": "任务ID",
                "task_name": "任务名称"
            }
        
        说明：
        - 支持批量添加多个站点，用换行分隔
        - 验证站点是否在资产组范围内（域名类型资产组）
        - IP类型资产组不支持添加站点
        - 自动提交站点扫描任务
        - 可使用策略ID应用预定义的扫描配置
        """
        args = self.parse_args(add_site_fields)
        site = args.pop("site")  # 支持批量提交多个站点
        scope_id = args.pop("scope_id")
        policy_id = args.pop("policy_id")

        # 验证资产组是否存在
        scope_data = utils.conn_db('asset_scope').find_one({"_id": ObjectId(scope_id)})
        if not scope_data:
            return utils.build_ret(ErrorMsg.NotFoundScopeID, {"scope_id": scope_id})

        # 检查资产组类型（只支持域名类型）
        scope_type = scope_data.get("scope_type", "domain")
        if scope_type == "ip":
            return utils.build_ret(ErrorMsg.AddAssetSiteNotSupportIP, {})

        # 解析站点列表
        sites = target2list(site)
        if not sites:
            return utils.build_ret(ErrorMsg.URLInvalid, {"site": site})

        # 验证站点是否在资产组范围内
        not_in_scope_sites = find_asset_site_not_in_scope(sites, scope_id)
        if not_in_scope_sites:
            return utils.build_ret(ErrorMsg.TaskTargetNotInScope, {"not_in_scope_sites": site})

        name = "添加站点-{}".format(scope_data["name"])

        # 默认扫描选项（轻量级）
        options = {
            'site_identify': False,  # 站点识别
            'site_capture': False,  # 站点截图
            'file_leak': False,  # 文件泄露检测
            'site_spider': False,  # 站点爬虫
            'search_engines': False,  # 搜索引擎
            'related_scope_id': scope_id  # 关联资产组
        }

        try:
            # 如果指定了策略ID，使用策略配置
            if policy_id and len(policy_id) == 24:
                policy_options = get_options_by_policy_id(policy_id=policy_id, task_tag=TaskTag.RISK_CRUISING)
                if policy_options:
                    policy_options["related_scope_id"] = scope_id
                    options.update(policy_options)

            # 提交站点扫描任务
            task_data = submit_add_asset_site_task(task_name=name, target=sites, options=options)
        except Exception as e:
            logger.exception(e)
            return utils.build_ret(ErrorMsg.Error, {"error": str(e)})

        return utils.build_ret(ErrorMsg.Success, task_data)


@ns.route('/export/')
class ARLSiteExport(ARLResource):
    """资产站点导出接口"""
    
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        导出资产组中的站点信息到Excel
        
        参数：
            与查询接口相同
        
        返回：
            Excel文件下载
        
        说明：
        - 导出站点URL、标题、服务器、状态码、指纹等完整信息
        - 文件名：asset_site_export_时间戳.xlsx
        """
        args = self.parser.parse_args()
        response = self.send_export_file(args=args, _type="asset_site")

        return response


def add_site_to_scope(site, scope_id):
    """
    将站点添加到资产组（内部辅助函数）
    
    参数：
        site: 站点URL
        scope_id: 资产组ID
    
    功能：
    - 获取站点信息（标题、服务器、状态码等）
    - 进行Web指纹识别
    - 保存到资产组中
    """
    # 获取站点基础信息
    fetch_site_data = services.fetch_site([site])
    # Web指纹分析
    web_analyze_data = services.web_analyze([site])
    finger = web_analyze_data.get(site, [])
    curr_date = utils.curr_date_obj()
    
    if fetch_site_data:
        item = fetch_site_data[0]
        item["finger"] = finger
        item["screenshot"] = ""
        item["scope_id"] = scope_id
        item["save_date"] = curr_date
        item["update_date"] = curr_date

        utils.conn_db('asset_site').insert_one(item)


# 删除站点请求模型
delete_asset_site_fields = ns.model('deleteAssetSite',  {
    '_id': fields.List(fields.String(required=True, description="站点数据_id列表"))
})


@ns.route('/delete/')
class DeleteARLAssetSite(ARLResource):
    """删除资产站点接口"""
    
    @auth
    @ns.expect(delete_asset_site_fields)
    def post(self):
        """
        批量删除资产组中的站点
        
        请求体：
            {
                "_id": ["站点ID1", "站点ID2", ...]
            }
        
        返回：
            {
                "code": 200,
                "message": "成功",
                "_id": ["已删除的ID列表"]
            }
        
        说明：
        - 支持批量删除多个站点
        - 删除操作不可逆
        - 只删除资产组中的站点记录，不影响任务数据
        """
        args = self.parse_args(delete_asset_site_fields)
        id_list = args.pop('_id', "")
        
        # 遍历删除每个站点
        for _id in id_list:
            query = {'_id': ObjectId(_id)}
            utils.conn_db('asset_site').delete_one(query)

        return utils.build_ret(ErrorMsg.Success, {'_id': id_list})


@ns.route('/save_result_set/')
class ARLSaveResultSet(ARLResource):
    """保存站点查询结果集接口"""
    
    parser = get_arl_parser(site_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        保存资产站点查询结果到结果集
        
        参数：
            与查询接口相同
        
        返回：
            {
                "code": 200,
                "result_set_id": "结果集ID",
                "result_total": 结果数量,
                "type": "asset_site"
            }
        
        说明：
        - 根据查询条件保存站点URL列表
        - 自动去重和去除文件名
        - 结果集可用于后续批量操作
        - 空结果返回错误
        """
        args = self.parser.parse_args()
        query = self.build_db_query(args)
        
        # 查询所有站点URL
        items = utils.conn_db('asset_site').distinct("site", query)

        # 去除URL中的文件名，只保留到路径
        items = list(set([utils.url.cut_filename(x) for x in items]))

        if len(items) == 0:
            return utils.build_ret(ErrorMsg.QueryResultIsEmpty, {})

        # 保存到结果集
        data = {
            "items": items,
            "type": "asset_site",
            "total": len(items)
        }
        result = utils.conn_db('result_set').insert_one(data)

        ret_data = {
            "result_set_id": str(result.inserted_id),
            "result_total": len(items),
            "type": "asset_site"
        }

        return utils.build_ret(ErrorMsg.Success, ret_data)


# 添加标签请求模型
add_asset_site_tag_fields = ns.model('AddAssetSiteTagFields',  {
    "tag": fields.String(required=True, description="标签名称"),
    "_id": fields.String(description="资产站点ID", required=True)
})


@ns.route('/add_tag/')
class AddAssetSiteTagARL(ARLResource):
    """添加站点标签接口"""

    @auth
    @ns.expect(add_asset_site_tag_fields)
    def post(self):
        """
        为资产站点添加标签
        
        请求体：
            {
                "_id": "站点ID",
                "tag": "标签名称"
            }
        
        返回：
            {
                "code": 200,
                "message": "成功",
                "tag": "标签名称"
            }
        
        说明：
        - 为站点添加自定义标签（如"重要"、"已处理"等）
        - 支持多个标签，以列表形式存储
        - 标签不能重复
        - 方便后续按标签筛选和管理
        """
        args = self.parse_args(add_asset_site_tag_fields)
        site_id = args.pop("_id")
        tag = args.pop("tag")

        # 验证站点是否存在
        query = {"_id": ObjectId(site_id)}
        data = utils.conn_db('asset_site').find_one(query)
        if not data:
            return utils.build_ret(ErrorMsg.SiteIdNotFound, {"site_id": site_id})

        # 处理现有标签
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

        utils.conn_db('asset_site').update_one(query, {"$set": {"tag": tag_list}})

        return utils.build_ret(ErrorMsg.Success, {"tag": tag})


# 删除标签请求模型
delete_asset_site_tag_fields = ns.model('delete_asset_site_tag_fields',  {
    "tag": fields.String(required=True, description="要删除的标签名称"),
    "_id": fields.String(description="资产站点ID", required=True)
})


@ns.route('/delete_tag/')
class DeleteAssetSiteTagARL(ARLResource):
    """删除站点标签接口"""

    @auth
    @ns.expect(delete_asset_site_tag_fields)
    def post(self):
        """
        删除资产站点的标签
        
        请求体：
            {
                "_id": "站点ID",
                "tag": "标签名称"
            }
        
        返回：
            {
                "code": 200,
                "message": "成功",
                "tag": "标签名称"
            }
        
        说明：
        - 从站点的标签列表中移除指定标签
        - 标签不存在时返回错误
        """
        args = self.parse_args(delete_asset_site_tag_fields)
        site_id = args.pop("_id")
        tag = args.pop("tag")

        # 验证站点是否存在
        query = {"_id": ObjectId(site_id)}
        data = utils.conn_db('asset_site').find_one(query)
        if not data:
            return utils.build_ret(ErrorMsg.SiteIdNotFound, {"site_id": site_id})

        # 处理现有标签
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

        # 移除标签
        tag_list.remove(tag)

        utils.conn_db('asset_site').update_one(query, {"$set": {"tag": tag_list}})

        return utils.build_ret(ErrorMsg.Success, {"tag": tag})


