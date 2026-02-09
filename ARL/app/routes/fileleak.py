"""
文件泄露检测管理模块

功能说明：
- 管理扫描发现的敏感文件泄露
- 支持文件泄露信息的查询和删除

检测内容：
- 备份文件：.bak, .old, .backup等
- 配置文件：config.php, web.config, application.yml等
- 日志文件：error.log, access.log等
- 源代码：.git, .svn, .env等
- 数据库备份：.sql, .db等
- 压缩包：.zip, .tar.gz, .rar等

主要数据字段：
- url: 泄露文件的完整URL
- site: 所属站点
- title: 页面标题
- status_code: HTTP状态码
- content_length: 响应体大小
- task_id: 任务ID
"""
from bson import ObjectId
from flask_restx import Resource, Api, reqparse, fields, Namespace
from app.utils import get_logger, auth
from . import base_query_fields, ARLResource, get_arl_parser
from app import utils
from app.modules import ErrorMsg

ns = Namespace('fileleak', description="文件泄漏信息")

logger = get_logger()

# 文件泄露查询字段定义
base_search_fields = {
    'url': fields.String(required=False, description="泄露文件URL"),
    'site': fields.String(description="所属站点"),
    'content_length': fields.Integer(description="响应体大小（字节）"),
    'status_code': fields.Integer(description="HTTP状态码"),
    'title': fields.String(description="页面标题"),
    "task_id": fields.String(description="任务ID")
}

base_search_fields.update(base_query_fields)


@ns.route('/')
class ARLFileLeak(ARLResource):
    """文件泄露查询接口"""
    
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        查询文件泄露信息
        
        参数：
            - url: URL过滤
            - site: 站点过滤
            - content_length: 文件大小过滤
            - status_code: 状态码过滤
            - title: 标题过滤
            - task_id: 任务ID过滤
            - page: 页码
            - size: 每页数量
        
        返回：
            {
                "code": 200,
                "items": [
                    {
                        "_id": "数据ID",
                        "url": "泄露文件URL",
                        "site": "所属站点",
                        "title": "页面标题",
                        "status_code": HTTP状态码,
                        "content_length": 响应体大小,
                        "task_id": "任务ID",
                        "save_date": "保存时间"
                    }
                ],
                "total": 总数
            }
        
        说明：
        - 检测常见的敏感文件泄露
        - 包括备份文件、配置文件、源代码、数据库等
        - status_code=200表示文件可直接访问
        - content_length可判断文件大小
        - 用于发现安全风险和敏感信息
        """
        args = self.parser.parse_args()
        data = self.build_data(args=args, collection='fileleak')

        return data


# 删除文件泄露请求模型
delete_fileleak_fields = ns.model('deleteFileleakFields',  {
    '_id': fields.List(fields.String(required=True, description="文件泄露数据_id列表"))
})


@ns.route('/delete/')
class DeleteARLFileleak(ARLResource):
    """删除文件泄露信息接口"""
    
    @auth
    @ns.expect(delete_fileleak_fields)
    def post(self):
        """
        批量删除文件泄露信息
        
        请求体：
            {
                "_id": ["文件泄露ID1", "文件泄露ID2", ...]
            }
        
        返回：
            {
                "code": 200,
                "message": "成功",
                "_id": ["已删除的ID列表"]
            }
        
        说明：
        - 支持批量删除多个文件泄露记录
        - 删除操作不可逆
        - 通常用于清理误报或已修复的泄露
        """
        args = self.parse_args(delete_fileleak_fields)
        id_list = args.pop('_id', [])
        
        # 遍历删除每个文件泄露记录
        for _id in id_list:
            query = {'_id': ObjectId(_id)}
            utils.conn_db('fileleak').delete_one(query)

        return utils.build_ret(ErrorMsg.Success, {'_id': id_list})


