"""
SSL 证书信息管理 API
================================================

该模块提供 SSL/TLS 证书信息的查询和管理功能

主要功能：
1. 查询 SSL 证书信息
2. 删除 SSL 证书记录

证书信息包括：
- IP 和端口
- 证书主题和签发者
- 序列号
- 有效期
- 指纹（SHA-256、SHA-1、MD5）
- 备用名称（subjectAltName）

这些证书信息在端口扫描时自动收集
"""
from bson import ObjectId
from flask_restx import Resource, Api, reqparse, fields, Namespace
from app.utils import get_logger, auth
from . import base_query_fields, ARLResource, get_arl_parser
from app import utils
from app.modules import ErrorMsg

# 创建证书信息命名空间
ns = Namespace('cert', description="证书信息")

logger = get_logger()

# 证书查询字段定义
# 支持按照证书的各个属性进行查询
base_search_fields = {
    'ip': fields.String(description="IP地址"),
    'port': fields.Integer(description="端口号"),
    'cert.subject_dn': fields.String(description="证书主题名称（Subject DN）"),
    'cert.issuer_dn': fields.String(description="证书签发者名称（Issuer DN）"),
    'cert.serial_number ': fields.String(description="证书序列号"),
    'cert.validity.start': fields.String(description="证书有效期开始时间"),
    'cert.validity.end': fields.String(description="证书有效期结束时间"),
    'cert.fingerprint.sha256': fields.String(description="证书SHA-256指纹"),
    'cert.fingerprint.sha1': fields.String(description="证书SHA-1指纹"),
    'cert.fingerprint.md5': fields.String(description="证书MD5指纹"),
    'cert.extensions.subjectAltName': fields.String(description="证书备用名称（SAN），包含额外的域名"),
    'task_id': fields.String(description="关联的任务ID"),
}

# 合并基础查询字段（分页、排序等）
base_search_fields.update(base_query_fields)


@ns.route('/')
class ARLCert(ARLResource):
    """SSL 证书信息查询接口"""
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        查询 SSL 证书信息
        
        支持的查询条件：
        - IP地址和端口
        - 证书主题、签发者
        - 证书序列号、指纹
        - 证书有效期
        - 备用名称（SAN）
        - 任务ID
        
        返回：
            分页的证书信息列表
        
        应用场景：
        - 查找使用特定 CA 签发的证书
        - 查找特定域名的证书
        - 查找即将过期的证书
        - 审计证书配置
        """
        args = self.parser.parse_args()
        # 从 cert 集合查询数据
        data = self.build_data(args=args, collection='cert')

        return data


# 删除证书请求模型定义
delete_cert_fields = ns.model('deleteCertFields', {
    '_id': fields.List(fields.String(required=True, description="要删除的证书ID列表"))
})


@ns.route('/delete/')
class DeleteARLCert(ARLResource):
    """SSL 证书信息删除接口"""
    
    @auth
    @ns.expect(delete_cert_fields)
    def post(self):
        """
        批量删除 SSL 证书信息
        
        请求体：
            {
                "_id": ["证书ID1", "证书ID2", ...]
            }
        
        返回：
            删除成功的证书ID列表
        
        注意：
        - 支持批量删除
        - 删除操作不可恢复
        - 需要管理员权限
        """
        args = self.parse_args(delete_cert_fields)
        id_list = args.pop('_id', [])
        
        # 遍历删除每个证书
        for _id in id_list:
            query = {'_id': ObjectId(_id)}
            utils.conn_db('cert').delete_one(query)

        return utils.build_ret(ErrorMsg.Success, {'_id': id_list})