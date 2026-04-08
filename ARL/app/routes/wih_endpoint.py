"""
WIH 结构化接口提取结果管理。
"""
from bson import ObjectId
from flask_restx import fields, Namespace

from app import utils
from app.modules import ErrorMsg
from app.utils import auth, get_logger
from . import ARLResource, base_query_fields, get_arl_parser

ns = Namespace('wih_endpoint', description="WIH 接口提取信息")

logger = get_logger()

base_search_fields = {
    'target': fields.String(description="目标"),
    'page_url': fields.String(description="页面URL"),
    'url': fields.String(description="接口URL"),
    'method': fields.String(description="HTTP方法"),
    'status_code': fields.Integer(description="HTTP状态码"),
    'response_size': fields.Integer(description="响应大小"),
    'task_id': fields.String(description="任务ID"),
}

base_search_fields.update(base_query_fields)


@ns.route('/')
class ARLWihEndpoint(ARLResource):
    """WIH 接口提取结果查询接口"""

    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        args = self.parser.parse_args()
        return self.build_data(args=args, collection='wih_endpoint')


@ns.route('/export/')
class ARLWihEndpointExport(ARLResource):
    """WIH 接口提取结果导出接口"""

    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        args = self.parser.parse_args()
        response = self.send_export_file_attr(args=args, collection="wih_endpoint", field="url")
        return response


delete_wih_endpoint_fields = ns.model('deleteWihEndpointFields', {
    '_id': fields.List(fields.String(required=True, description="WIH接口提取数据_id列表"))
})


@ns.route('/delete/')
class DeleteARLWihEndpoint(ARLResource):
    """删除 WIH 接口提取结果接口"""

    @auth
    @ns.expect(delete_wih_endpoint_fields)
    def post(self):
        args = self.parse_args(delete_wih_endpoint_fields)
        id_list = args.pop('_id', [])

        for _id in id_list:
            utils.conn_db('wih_endpoint').delete_one({'_id': ObjectId(_id)})

        return utils.build_ret(ErrorMsg.Success, {'_id': id_list})
