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


class WebSiteResultPersistStageService(object):
    """承载站点结果和 PoC 风险的统一落库边界。"""

    def __init__(self, task):
        self.task = task

    def save_site_info(self):
        from pymongo import UpdateOne

        task = self.task
        for site_info in task.site_info_list:
            task._result_item_service.build_site_document(
                site_info,
                web_analyze_map=task.web_analyze_map,
            )

        logger.info(
            "save_site_info site:{}, {}".format(
                len(task.site_info_list),
                task,
            )
        )
        if not task.site_info_list:
            return

        site_operations = []
        for site_info in task.site_info_list:
            site = str(site_info.get("site", "") or "").strip()
            if not site:
                continue
            replacement = {
                key: value
                for key, value in site_info.items()
                if key != "_id"
            }
            site_operations.append(
                UpdateOne(
                    {"task_id": task.task_id, "site": site},
                    {"$set": replacement},
                    upsert=True,
                )
            )
        if site_operations:
            task._result_writer.bulk_write("site", site_operations, ordered=False)
        # 站点信息落库完成后，触发“站点”模块 AI 去噪增量分析。
        task.base_update_task.trigger_ai_denoise_stage(
            stage_name="site_saved",
            task_options=task.options,
        )

    def risk_cruising(self, npoc_service_target_set: set):
        from app.services import run_risk_cruising

        task = self.task
        poc_config = task.options.get("poc_config", [])
        plugins = []
        for info in poc_config:
            if not info.get("enable"):
                continue
            plugins.append(info["plugin_name"])

        poc_targets = task.poc_sites
        if npoc_service_target_set is not None:
            poc_targets = task.poc_sites | npoc_service_target_set

        result = run_risk_cruising(plugins=plugins, targets=poc_targets)
        for item in result:
            if not task._scan_result_in_task_scope(item, target_keys=("target", "url")):
                continue
            result_item = task._result_item_service.build_risk_document(item)
            if result_item:
                task._result_writer.insert_one("vuln", result_item)


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
