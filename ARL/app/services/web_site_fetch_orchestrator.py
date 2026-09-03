"""WebSiteFetch 的阶段编排。

站点阶段的具体实现仍由 WebSiteFetch 提供；本模块只维护阶段顺序、可选开关
和延迟重试，避免 CommonTask 同时承担任务生命周期和站点流程编排。
"""

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

        # 共享发现上下文观测收口：只输出诊断日志，供请求去重/候选传播/WAF 类别回归核对。
        observation_hook = getattr(task, "_log_discovery_observation", None)
        if callable(observation_hook):
            observation_hook()
