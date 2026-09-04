"""WebSiteFetch 的阶段业务服务。

阶段服务只组合已有任务入口，不复制网络、数据库或外部工具实现；这样可以在
不改变站点任务入口和结果语义的情况下，逐步把 CommonTask 的业务边界移出。
"""

from app import utils
from app.modules import WebSiteFetchOption, WebSiteFetchStatus
from app.services.single_scan_stage_services import WebSiteSingleStageService


logger = utils.get_logger()


class WebSiteDiscoveryStageService(object):
    """执行站点获取、爬虫、识别和截图。"""

    def __init__(self, task):
        self.task = task

    def run(self):
        task = self.task
        stage = WebSiteSingleStageService(task, logger=logger)
        stage.run(WebSiteFetchStatus.FETCH_SITE, task.fetch_site)

        if task.options.get(WebSiteFetchOption.SITE_SPIDER):
            task.update_page_url_set()
            stage.run(
                WebSiteFetchStatus.SITE_SPIDER,
                task.site_spider,
                fallback=None,
                fallback_note="继续执行站点识别",
            )

        stage.run(WebSiteFetchStatus.SITE_IDENTIFY, task.site_identify)
        task.save_site_info()
        task.site_info_list = []

        if task.options.get(WebSiteFetchOption.SITE_CAPTURE):
            stage.run(
                WebSiteFetchStatus.SITE_CAPTURE,
                task.site_screenshot,
                fallback=None,
                fallback_note="保留站点结果并继续后置阶段",
            )


class WebSiteExternalScanStageService(object):
    """执行文件泄漏、AI-PoC 计划、Nuclei 和 afrog。"""

    def __init__(self, task):
        self.task = task

    def run(self):
        task = self.task
        stage = WebSiteSingleStageService(task, logger=logger)
        if task.options.get(WebSiteFetchOption.FILE_LEAK):
            stage.run(
                WebSiteFetchStatus.FILE_LEAK,
                task.file_leak,
                fallback=[],
                fallback_note="仅回退当前文件泄漏阶段",
            )

        if task.options.get(WebSiteFetchOption.NUCLEI_SCAN):
            stage.run(
                WebSiteFetchStatus.NUCLEI_SCAN,
                task.nuclei_scan,
                fallback=None,
                fallback_note="继续执行其他站点扫描阶段",
            )

        if task.options.get(WebSiteFetchOption.AFROG_SCAN):
            stage.run(
                WebSiteFetchStatus.AFROG_SCAN,
                task.afrog_scan,
                fallback=None,
                fallback_note="继续执行其他站点扫描阶段",
            )

class WebSiteIntelStageService(object):
    """执行 WIH 信息收集阶段。"""

    def __init__(self, task):
        self.task = task

    def run(self):
        task = self.task
        stage = WebSiteSingleStageService(task, logger=logger)
        if task.options.get(WebSiteFetchOption.Info_Hunter):
            stage.run(
                WebSiteFetchStatus.Info_Hunter,
                task.run_web_info_hunter,
                fallback=None,
                fallback_note="保留已发现站点并继续收尾",
            )
        else:
            logger.info(
                "task_id:{} skip web_info_hunter because option disabled".format(
                    task.task_id
                )
            )


class WebSitePostProcessStageService(object):
    """执行兼容的 Web 专项阶段和 WAF 观测收尾。"""

    def __init__(self, task):
        self.task = task

    def run(self):
        task = self.task
        stage = WebSiteSingleStageService(task, logger=logger)
        if task._nuclei_deferred_retry_needed:
            task.run_deferred_nuclei_scan()

        task._save_waf_skip_summary()
