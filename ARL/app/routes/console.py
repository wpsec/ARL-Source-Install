"""
控制台信息管理模块

功能说明：
- 获取系统设备信息
- 包括 CPU、内存、磁盘使用情况
- 用于系统监控和健康检查

说明：
- 信息来自系统调用
- 实时更新
- 用于展示系统资源状态
"""
from flask_restx import fields, Namespace
from app.utils import get_logger, auth
from app import utils
from app.modules import ErrorMsg
from . import base_query_fields, ARLResource, get_arl_parser

ns = Namespace('console', description="控制台信息")

logger = get_logger()


@ns.route('/info')
class ARLConsole(ARLResource):
    """系统信息查询接口"""

    @auth
    def get(self):
        """
        获取系统控制台信息
        
        返回：
            {
                "code": 200,
                "data": {
                    "device_info": {
                        "cpu": CPU信息,
                        "memory": 内存信息,
                        "disk": 磁盘信息
                    }
                }
            }
        
        说明：
        - 返回实时的系统资源使用情况
        - CPU: 处理器类型和使用率
        - Memory: 内存大小和使用率
        - Disk: 磁盘容量和使用率
        
        应用场景：
        - 监控系统健康状态
        - 排查资源瓶颈
        - 系统管理页面展示
        """

        data = {
            "device_info": utils.device_info()   # 包含 CPU 内存和磁盘信息
        }

        return utils.build_ret(ErrorMsg.Success, data)



