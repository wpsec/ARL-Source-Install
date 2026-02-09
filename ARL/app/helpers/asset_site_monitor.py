"""
资产站点监控辅助函数模块

功能说明：
- 提交资产站点监控任务
- 检查站点是否在黑名单中
- 用于资产站点更新监控
"""
from app.modules import CeleryAction, SchedulerStatus, AssetScopeType, TaskStatus, TaskType
from app import celerytask, utils
from app.config import Config
logger = utils.get_logger()


def submit_asset_site_monitor_job(scope_id, name, scheduler_id):
    """
    提交资产站点监控任务
    
    参数：
        scope_id: 资产范围ID
        name: 任务名称
        scheduler_id: 调度器ID
    
    说明：
    - 创建资产站点更新任务
    - 关联到指定的调度器
    - 通过submit_task提交到Celery
    - 用于定期检查站点变化
    """
    from app.helpers.task import submit_task

    task_data = {
        'name': name,
        'target': "资产站点更新",
        'start_time': '-',
        'status': TaskStatus.WAITING,
        'type':  TaskType.ASSET_SITE_UPDATE,
        "task_tag": TaskType.ASSET_SITE_UPDATE,
        'options': {
            "scope_id": scope_id,
            "scheduler_id": scheduler_id
        },
        "end_time": "-",
        "service": [],
        "celery_id": ""
    }

    submit_task(task_data)


black_asset_site_list = None


def is_black_asset_site(site):
    """
    检查站点是否在黑名单中
    
    参数：
        site: 站点URL
    
    返回：
        bool: True-在黑名单中，False-不在黑名单中
    
    说明：
    - 从配置文件读取黑名单（首次调用时）
    - 使用startswith匹配站点前缀
    - 用于过滤不需要监控的站点
    - 黑名单文件路径在Config.black_asset_site
    """
    global black_asset_site_list
    if black_asset_site_list is None:
        with open(Config.black_asset_site) as f:
            black_asset_site_list = f.readlines()

    for item in black_asset_site_list:
        item = item.strip()
        if not item:
            continue
        if site.startswith(item):
            return True

    return False





