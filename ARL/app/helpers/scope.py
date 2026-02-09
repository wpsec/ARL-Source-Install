"""
资产范围辅助函数模块

功能说明：
- 检查目标是否在指定范围内
- 根据范围ID获取范围配置
- 用于任务目标验证
"""
import bson
from app import utils
from app.utils.ip import ip_in_scope
from app.utils.domain import is_in_scopes
from app.utils.cache import build_cache_key, cached_call


def check_target_in_scope(target, scope_list):
    """
    检查目标是否在指定范围内
    
    参数：
        target: 目标字符串（IP或域名）
        scope_list: 范围列表
    
    返回：
        tuple: (ip_list, domain_list) IP列表和域名列表
    
    异常：
        Exception: 目标不在范围内
    
    说明：
    - 分离IP和域名
    - 检查每个IP是否在IP范围内
    - 检查每个域名是否在域名范围内
    - 任何一个不符合则抛出异常
    """
    from .task import get_ip_domain_list
    ip_list, domain_list = get_ip_domain_list(target)
    for ip in ip_list:
        if not ip_in_scope(ip, scope_list):
            raise Exception("{}不在范围{}中".format(ip, ",".join(scope_list)))

    for domain in domain_list:
        if not is_in_scopes(domain, scope_list):
            raise Exception("{}不在范围{}中".format(domain, ",".join(scope_list)))

    return ip_list, domain_list


def get_scope_by_scope_id(scope_id):
    """
    根据范围ID获取范围配置
    
    参数：
        scope_id: 资产范围ID
    
    返回：
        dict: 范围配置数据
        None: 范围不存在
    
    说明：
    - 从asset_scope表查询范围配置
    - 包含范围名称、范围列表等信息
    """
    key = build_cache_key("helper:get_scope_by_scope_id", scope_id)

    def _loader():
        query = {
            "_id": bson.ObjectId(scope_id)
        }
        return utils.conn_db("asset_scope").find_one(query)

    return cached_call(key, _loader, expire=120)


