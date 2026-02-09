"""
资产站点辅助函数模块

功能说明：
- 根据范围ID查询站点资产
- 检查站点是否在范围内
- 用于资产监控和站点验证
"""
from app import utils
from app.utils.cache import build_cache_key, cached_call
from .scope import get_scope_by_scope_id


def build_show_filed_map(fields):
    """
    构建MongoDB查询的字段映射
    
    参数：
        fields: 字段名列表
    
    返回：
        dict: 字段映射字典 {field: 1}
    
    说明：
    - 用于MongoDB的find查询指定返回字段
    """
    q = {}
    for field in fields:
        q[field] = 1

    return q


def find_site_info_by_scope_id(scope_id):
    """
    根据范围ID查找站点信息
    
    参数：
        scope_id: 资产范围ID
    
    返回：
        list: 站点信息列表，包含site、title、status字段
    
    说明：
    - 查询asset_site表中指定范围的站点
    - 只返回site、title、status字段
    - 用于站点列表展示
    """
    key = build_cache_key("helper:find_site_info_by_scope_id", scope_id)

    def _loader():
        query = {
            "scope_id": scope_id
        }
        fields = ["site", "title", "status"]
        show_map = build_show_filed_map(fields)
        items = utils.conn_db('asset_site').find(query, show_map)
        return list(items)

    return cached_call(key, _loader, expire=120)


def find_site_by_scope_id(scope_id):
    """
    根据范围ID查找站点URL
    
    参数：
        scope_id: 资产范围ID
    
    返回：
        list: 去重后的站点URL列表
    
    说明：
    - 查询asset_site表中指定范围的站点
    - 使用distinct去重
    - 用于站点监控
    """
    key = build_cache_key("helper:find_site_by_scope_id", scope_id)

    def _loader():
        query = {
            "scope_id": scope_id
        }
        items = utils.conn_db('asset_site').distinct("site", query)
        return list(items)

    return cached_call(key, _loader, expire=120)


def check_asset_site_in_scope(site: str, scope_array: list) -> bool:
    """
    检查站点是否在范围内
    
    参数：
        site: 站点URL
        scope_array: 范围数组
    
    返回：
        bool: True-在范围内，False-不在范围内
    
    说明：
    - 简单判断站点URL是否包含范围中的任一元素
    - 例如：范围包含"example.com"，则"https://www.example.com"在范围内
    """
    for scope in scope_array:
        # 简单判断下
        if scope in site:
            return True
    return False


def find_asset_site_not_in_scope(sites: list, scope_id: str) -> list:
    """
    找出不在范围内的站点
    
    参数：
        sites: 站点URL列表
        scope_id: 资产范围ID
    
    返回：
        list: 不在范围内的站点列表
    
    说明：
    - 用于用户提交站点时的范围验证
    - 返回需要过滤掉的站点
    """
    ret = []
    scopes = get_scope_by_scope_id(scope_id)
    scope_array = scopes.get("scope_array", [])
    for site in sites:
        if not check_asset_site_in_scope(site, scope_array):
            ret.append(site)

    return ret

