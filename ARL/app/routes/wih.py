"""
WIH（Web Info Hunter）任务结果管理模块

功能说明：
- 管理任务扫描中的WIH数据（与asset_wih类似但来自任务）
- WIH通过分析JavaScript文件自动提取敏感信息
- 支持WIH数据的查询和导出

区别说明：
- wih表：存储任务扫描产生的WIH数据（临时数据）
- asset_wih表：存储资产组中的WIH数据（持久化数据）

主要数据类型：
- API端点：从JS中提取的API接口地址
- URL链接：页面中的各类URL
- 敏感路径：可能泄露的敏感路径
- 参数信息：API参数、字段名等
- 其他敏感信息：邮箱、密钥、凭证等

使用场景：
- 任务完成后查看提取的信息
- 发现隐藏的API接口
- 识别敏感信息泄露
- 导出数据进行离线分析
"""
from flask_restx import fields, Namespace
from app.utils import get_logger, auth
from . import base_query_fields, ARLResource, get_arl_parser


ns = Namespace('wih', description="WEB Info Hunter 信息")

logger = get_logger()

# WIH查询字段定义
base_search_fields = {
    'record_type': fields.String(required=False, description="记录类型（如api, url, path, email等）"),
    'record_type__neq': fields.String(required=False, description="记录类型不等于（精确匹配）"),
    'record_type__not': fields.String(required=False, description="记录类型不包含（模糊匹配）"),
    'content': fields.String(description="内容（提取到的具体信息）"),
    'source': fields.String(description="来源JS URL（从哪个JS文件中提取）"),
    'site': fields.String(description="站点URL（JS所属的网站）"),
    'task_id': fields.String(description="任务ID"),
}


base_search_fields.update(base_query_fields)


@ns.route('/')
class ARLWebInfoHunter(ARLResource):
    """WIH查询接口"""
    
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        查询任务中的WIH信息
        
        参数：
            - record_type: 记录类型过滤（api/url/path/email等）
            - record_type__neq: 排除指定记录类型
            - record_type__not: 记录类型不包含
            - content: 内容关键字过滤
            - source: 来源JS文件过滤
            - site: 站点URL过滤
            - task_id: 任务ID过滤
            - page: 页码
            - size: 每页数量
        
        返回：
            {
                "code": 200,
                "items": [
                    {
                        "_id": "数据ID",
                        "record_type": "记录类型",
                        "content": "提取的内容",
                        "source": "来源JS URL",
                        "site": "所属站点URL",
                        "task_id": "任务ID",
                        "save_date": "保存时间"
                    }
                ],
                "total": 总数
            }
        
        说明：
        - 数据来自任务扫描过程
        - 常见记录类型：
          * api: API接口地址
          * url: 各类URL链接
          * path: 路径信息
          * email: 邮箱地址
          * key: 密钥、token等
        - 可用于发现隐藏接口和敏感信息
        - 与asset_wih不同，这是任务临时数据
        """
        args = self.parser.parse_args()
        data = self.build_data(args=args, collection='wih')

        return data


@ns.route('/export/')
class ARLWihExport(ARLResource):
    """WIH导出接口"""
    
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        导出任务中的WIH信息到Excel
        
        参数：
            与查询接口相同
        
        返回：
            Excel文件下载
        
        说明：
        - 导出记录类型、内容、来源、站点等完整信息
        - 文件名：wih_export_时间戳.xlsx
        - 适合进行线下分析和审计
        - 可按任务ID导出特定任务的WIH数据
        """
        args = self.parser.parse_args()
        response = self.send_export_file(args=args, _type="wih")

        return response

