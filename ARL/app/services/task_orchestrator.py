"""域名/IP任务的高层编排。

编排器只负责阶段顺序和任务终态；具体发现、探测和持久化逻辑由阶段服务与
任务兼容入口提供，避免把 Mongo、网络策略和外部工具实现复制到新的服务层。
"""

from app import utils
from app.config import Config
from app.modules import TaskStatus
from app.services.commonTask import WebSiteFetch
from app.services.ip_stage_services import IPNetworkStageService, IPPostProcessStageService
from app.services.task_lifecycle_service import TaskLifecycleService
from app.helpers.message_notify import push_task_finish_notify
import time


class DomainTaskOrchestrator(object):
    """编排域名任务的发现、深度扫描和收尾阶段。"""

    def __init__(self, task):
        self.task = task

    def run_discovery(self, include_preview=False):
        task = self.task
        task.update_task_field("start_time", utils.curr_date())
        task._seed_base_domain()
        if include_preview:
            task._run_discovery_preview()

    def run_deep(self):
        task = self.task

        task._load_saved_domain_info()
        task.domain_fetch()
        task.search_engines()

        if Config.IP_PIVOT_QUERY_ENABLE:
            task.update_task_field("status", "ip_query_plugin")
            started_at = time.time()
            task.ip_query_plugin_enhance()
            task.update_services(
                "ip_query_plugin",
                time.time() - started_at,
                metrics=task._last_ip_query_metrics,
            )

        task.start_ip_fetch()
        task.start_site_fetch()
        task.start_find_vhost()
        task.start_poc_run()
        task.start_wih_domain_update()
        task.common_run()

        task.update_task_field("status", TaskStatus.DONE)
        task.update_task_field("end_time", utils.curr_date())
        push_task_finish_notify(task.task_id)

    def run(self):
        self.run_discovery()
        self.run_deep()


class IPTaskOrchestrator(object):
    """编排 IP 任务的阶段顺序和终态收尾。"""

    def __init__(self, task):
        self.task = task

    def run(self):
        task = self.task
        base_update = task.base_update_task
        base_update.update_task_field("start_time", utils.curr_date())
        IPNetworkStageService(task).run()

        web_site_fetch = WebSiteFetch(
            task_id=task.task_id,
            sites=task.site_list,
            options=task.options,
        )
        web_site_fetch.run()

        IPPostProcessStageService(task, web_site_fetch).run()

        TaskLifecycleService(task).run_finalize(sync_asset=task.task_tag == "task")

        base_update.update_task_field("status", TaskStatus.DONE)
        base_update.update_task_field("end_time", utils.curr_date())
        push_task_finish_notify(task.task_id)
