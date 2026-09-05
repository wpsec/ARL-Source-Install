"""WebSiteFetch 的阶段编排。

站点阶段的具体实现仍由 WebSiteFetch 提供；本模块只维护阶段顺序、可选开关
和延迟重试，避免 CommonTask 同时承担任务生命周期和站点流程编排。
"""

from app.services.task_finalizer import TaskFinalizer
from app.services.web_site_stage_services import (
    WebSiteDiscoveryStageService,
    WebSiteExternalScanStageService,
    WebSiteIntelStageService,
    WebSitePostProcessStageService,
)


class WebSiteFetchOrchestrator(object):
    """执行站点信息、文件泄漏、外部扫描和 WIH 阶段。"""

    def __init__(self, task):
        self.task = task

    def run(self):
        task = self.task
        task._nuclei_deferred_retry_needed = False
        task._nuclei_final_skip = False

        WebSiteDiscoveryStageService(task).run()
        WebSiteExternalScanStageService(task).run()
        WebSiteIntelStageService(task).run()
        WebSitePostProcessStageService(task).run()

        # 统一收尾：站点作为唯一宿主（独立 WebSiteFetch/预览/PoC/资产监控）时
        # 有界 drain + 残余记 pending；WebSiteFetch 本身从不写任务终态。
        # Review 20260905 P0.4：终态所有权收敛为单一宿主——域名/IP 深度流程会在
        # 本实例之后统一执行一次 TaskFinalizer，嵌套调用必须整体跳过，否则
        # drain/显影执行两遍且宿主后续阶段消费的候选被过早记成 pending。
        if getattr(task, "terminal_finalize_host_owned", False):
            task.last_finalization = {}
        else:
            finalizer = TaskFinalizer(task)
            finalizer.run()
            task.last_finalization = dict(finalizer.decision or {})

        # 共享发现上下文观测收口：只输出诊断日志，供请求去重/候选传播/WAF 类别回归核对。
        observation_hook = getattr(task, "_log_discovery_observation", None)
        if callable(observation_hook):
            observation_hook()
