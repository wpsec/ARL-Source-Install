"""
WIH资产监控辅助函数模块

功能说明：
- 提交WIH资产监控任务
- 用于定期检查JavaScript文件中的资产变化
"""
from app.modules import TaskStatus, TaskType


def submit_asset_wih_monitor_job(scope_id, name, scheduler_id):
    """
    提交WIH资产监控任务
    
    参数：
        scope_id: 资产范围ID
        name: 任务名称
        scheduler_id: 调度器ID
    
    说明：
    - 创建WIH资产更新任务
    - 关联到指定的调度器
    - 通过submit_task提交到Celery
    - 用于定期从JavaScript文件提取域名、URL、API等信息
    - WIH (Web Info Hunter) 专门用于前端资产发现
    """
    from app.helpers.task import submit_task

    task_data = {
        'name': name,
        'target': "资产分组 WIH 更新",
        'start_time': '-',
        'status': TaskStatus.WAITING,
        'type':  TaskType.ASSET_WIH_UPDATE,
        "task_tag": TaskType.ASSET_WIH_UPDATE,
        'options': {
            "scope_id": scope_id,
            "scheduler_id": scheduler_id
        },
        "end_time": "-",
        "service": [],
        "celery_id": ""
    }

    submit_task(task_data)
