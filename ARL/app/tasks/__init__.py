"""
Tasks模块初始化文件

功能说明：
- 导出所有任务执行函数
- 供Celery调度器和API接口调用

任务类型：
1. 域名任务：domain_task, domain_executors
2. IP任务：ip_task, ip_executor
3. PoC任务：run_risk_cruising_task
4. GitHub任务：github_task_task, github_task_monitor
5. 资产站点任务：asset_site_update_task, run_add_asset_site_task
6. 资产WIH任务：asset_wih_update_task

说明：
- domain_task/ip_task: 一次性扫描任务
- domain_executors/ip_executor: 定期监控任务
- 监控任务通过调度器(scheduler)定时触发
"""
from .domain import domain_task
from .ip import ip_task
from .scheduler import domain_executors, ip_executor
from .poc import run_risk_cruising_task
from .github import github_task_task, github_task_monitor
from .asset_site import asset_site_update_task
from app.tasks.asset_site import run_add_asset_site_task
from .asset_wih import asset_wih_update_task
