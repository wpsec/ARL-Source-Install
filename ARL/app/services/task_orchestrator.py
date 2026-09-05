"""域名/IP任务的高层编排。

编排器只负责阶段顺序和任务终态；具体发现、探测和持久化逻辑由阶段服务与
任务兼容入口提供，避免把 Mongo、网络策略和外部工具实现复制到新的服务层。
"""

from app import utils
from app.config import Config
from app.services.commonTask import WebSiteFetch
from app.services.ip_stage_services import IPNetworkStageService, IPPostProcessStageService
from app.services.task_finalizer import TaskFinalizer
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
        # 统一收尾：有界 drain 动态候选 + 残余显式记 pending，先于统计与终态。
        # 终态由收尾器决策决定（Review 20260905 §4 重要项1）：队列证明清空才写
        # done；有残余写 done_pending；收尾证据不可证明写 done_degraded。
        finalizer = TaskFinalizer(task)
        finalizer.run()
        task.common_run()

        task.update_task_field("status", finalizer.terminal_status())
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
        # 终态唯一 owner 是本 IP 宿主（下方 TaskFinalizer）：嵌套站点层跳过收尾。
        web_site_fetch.terminal_finalize_host_owned = True
        web_site_fetch.run()
        # 收尾器按 holder 解析发现上下文，IP 任务同样挂到站点实例上。
        task.web_site_fetch = web_site_fetch

        IPPostProcessStageService(task, web_site_fetch).run()

        # 同域名任务：终态以收尾器决策为准，残余未清不写裸 done。
        finalizer = TaskFinalizer(task)
        finalizer.run()
        TaskLifecycleService(task).run_finalize(sync_asset=task.task_tag == "task")

        base_update.update_task_field("status", finalizer.terminal_status())
        base_update.update_task_field("end_time", utils.curr_date())
        push_task_finish_notify(task.task_id)
