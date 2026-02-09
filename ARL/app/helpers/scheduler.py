"""
调度器辅助函数模块

功能说明：
- 检查是否已存在相同的监控任务
- 防止重复创建监控任务
- 用于站点更新监控和WIH监控
"""
from app import utils


def have_same_site_update_monitor(scope_id):
    """
    检查是否已存在相同的站点更新监控任务
    
    参数：
        scope_id: 资产范围ID
    
    返回：
        bool: True-已存在，False-不存在
    
    说明：
    - 查询scheduler表中是否有相同scope_id和scope_type的记录
    - 防止重复创建站点更新监控任务
    """
    query = {
        "scope_id": scope_id,
        "scope_type": "site_update_monitor"
    }

    result = utils.conn_db('scheduler').find_one(query)
    if result:
        return True

    return False


def have_same_wih_update_monitor(scope_id):
    """
    检查是否已存在相同的WIH更新监控任务
    
    参数：
        scope_id: 资产范围ID
    
    返回：
        bool: True-已存在，False-不存在
    
    说明：
    - 查询scheduler表中是否有相同scope_id和scope_type的记录
    - 防止重复创建WIH更新监控任务
    - WIH监控用于检测JavaScript文件中的资产变化
    """
    query = {
        "scope_id": scope_id,
        "scope_type": "wih_update_monitor"
    }

    result = utils.conn_db('scheduler').find_one(query)
    if result:
        return True

    return False
