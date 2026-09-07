"""域名任务的可测试阶段服务。

这些服务只接收一个已初始化的任务上下文，负责单一阶段的业务边界；任务类
继续保留同名兼容方法，避免改变 Celery、历史重试和外部调用的入口。
"""

import time
from urllib.parse import urlparse

from app import services, utils
from app.config import Config
from app.modules import CollectSource
from app.services.searchEngines import search_engines
from app.services.task_pipeline import TaskPipeline


logger = utils.get_logger()

def _run_measured_stage(task, name, func):
    """阶段统一经执行器产出独立 metrics（报告§4：禁止手工稀疏指标）。

    轻量测试任务可能没有 StageExecutor，回退为原手工语义。
    """

    runner = getattr(task, "_run_internal_stage", None)
    if callable(runner):
        return runner(name, func)
    task.update_task_field("status", name)
    started_at = time.time()
    func()
    task.update_services(name, time.time() - started_at)
    return None


def _domain_count_stage(task, func):
    """闭包工厂：以 domain_info_list 增量作为 output_count。"""

    def _run():
        before = len(getattr(task, "domain_info_list", []) or [])
        func()
        after = len(getattr(task, "domain_info_list", []) or [])
        return {"output_count": max(0, after - before), "metrics": {"status": "ok", "domain_total": after}}

    return _run


class DomainDiscoveryStageService(object):
    """执行域名爆破、插件发现和智能 DNS 生成。"""

    def __init__(self, task):
        self.task = task

    def run(self):
        task = self.task
        if task.options.get("domain_brute"):
            _run_measured_stage(task, "domain_brute", _domain_count_stage(task, task.domain_brute))

            # 用户输入的根域名始终作为后续阶段的保底种子。
            base_domain_info = task.build_single_domain_info(task.base_domain)
            if base_domain_info and base_domain_info not in task.domain_info_list:
                task.domain_info_list.append(base_domain_info)
                task.add_domain_source_map([base_domain_info], CollectSource.DOMAIN_BRUTE)
                if task.task_tag == "task":
                    task.save_domain_info_list(
                        [base_domain_info], source=CollectSource.DOMAIN_BRUTE
                    )
        else:
            domain_info = task.build_single_domain_info(task.base_domain)
            if domain_info:
                if domain_info not in task.domain_info_list:
                    task.domain_info_list.append(domain_info)
                task.add_domain_source_map([domain_info], CollectSource.DOMAIN_BRUTE)
                task.save_domain_info_list([domain_info])

        if "{fuzz}" in task.base_domain:
            return

        if task.options.get("dns_query_plugin"):
            task.update_task_field("status", "dns_query_plugin")
            started_at = time.time()
            task.dns_query_plugin()
            task.update_services(
                "dns_query_plugin",
                time.time() - started_at,
                metrics=task._last_dns_query_metrics,
            )

        if task.options.get("arl_search"):
            _run_measured_stage(task, "arl_search", _domain_count_stage(task, task.arl_search))

        if task.options.get("alt_dns"):
            _run_measured_stage(task, "alt_dns", _domain_count_stage(task, task.alt_dns))

    def run_search_engines(self):
        """执行搜索引擎发现并把页面证据接入统一上下文。"""

        task = self.task
        if not task.options.get("search_engines") or "{fuzz}" in task.base_domain:
            return

        task.update_task_field("status", "search_engines")
        started_at = time.time()
        search_engines_urls = search_engines(task.base_domain)
        search_engine_metrics = dict(getattr(search_engines_urls, "metrics", {}) or {})

        urls = set()
        domains = set()
        for url in search_engines_urls:
            parsed = urlparse(url)
            netloc_domain = utils.normalize_domain(parsed.netloc.split(":")[0])
            if not netloc_domain:
                continue
            if not (
                netloc_domain.endswith("." + task.base_domain)
                or task.base_domain == netloc_domain
            ):
                continue
            domains.add(netloc_domain)
            # 首页只作为站点种子，不进入 URL 结果面，保持历史结果语义。
            if parsed.path in ("", "/"):
                continue
            urls.add(url)

        domain_info_list = []
        if domains:
            task.add_domain_source_names(domains, CollectSource.SEARCHENGINE)
            domain_info_list = task.build_domain_info(domains)
            if task.task_tag == "task":
                domain_info_list = task.clear_domain_info_by_record(domain_info_list)
                task.save_domain_info_list(
                    domain_info_list,
                    source=CollectSource.SEARCHENGINE,
                )
            task.add_domain_source_map(domain_info_list, CollectSource.SEARCHENGINE)
            task.domain_info_list.extend(domain_info_list)

        task.update_services(
            "search_engines",
            time.time() - started_at,
            metrics=search_engine_metrics,
        )
        logger.info(
            "search_engines {} result domain:{} url:{}".format(
                task.base_domain,
                len(domain_info_list),
                len(urls),
            )
        )

        if not urls:
            return

        # 页面获取必须带任务上下文，避免搜索结果绕过响应复用、流量类别调度
        # 和 WAF 隔离；失败候选留给后续 url_probe 显式收口。
        page_map = services.page_fetch(
            urls,
            discovery_context=getattr(task, "discovery_context", None),
            traffic_class="crawler",
        )
        self.register_search_page_candidates(urls, page_map)
        from app.services.commonTask import build_url_item

        for url in page_map:
            item = build_url_item(url, task.task_id, source=CollectSource.SEARCHENGINE)
            item.update(page_map[url])
            utils.conn_db("url").insert_one(item)

    def register_search_page_candidates(self, urls, page_map):
        """将搜索结果页面登记为统一候选，保留失败候选的后续处理入口。"""

        task = self.task
        context = getattr(task, "discovery_context", None)
        if context is None:
            return
        fetched = set(page_map or {})
        for url in urls:
            try:
                context.register_candidate(
                    event_type="UrlCandidateDiscovered",
                    candidate=url,
                    candidate_type="page",
                    source="search_engine",
                    status="fetched" if url in fetched else "discovered",
                    metadata={"collect_source": str(CollectSource.SEARCHENGINE)},
                )
            except Exception as exc:
                logger.debug(
                    "search page candidate register failed error_type:%s",
                    type(exc).__name__,
                )


class DomainNetworkStageService(object):
    """执行 IP 映射、端口、证书关联和 IP 结果保存。"""

    def __init__(self, task):
        self.task = task

    def run(self):
        task = self.task
        task.gen_ipv4_map()
        pipeline = TaskPipeline(task)
        pipeline.run_many([
            {
                "name": "port_scan",
                "func": task.port_scan,
                "enabled": bool(task.options.get("port_scan")),
            },
            {
                "name": "ssl_cert",
                "func": task.ssl_cert,
                "enabled": bool(task.options.get("ssl_cert")),
            },
        ])

        if Config.CERT_PIVOT_QUERY_ENABLE and task.options.get("ssl_cert"):
            def run_cert_query_plugin():
                cert_new_domain_count = task.cert_query_plugin_enhance()
                if cert_new_domain_count > 0:
                    task.gen_ipv4_map()
                    if task.options.get("port_scan"):
                        task.incremental_port_scan_for_new_ips()
                    task.sync_ip_domain_from_ipv4_map()
                return cert_new_domain_count

            pipeline.run_stage("cert_query_plugin", run_cert_query_plugin)

        task.save_ip_info()


class DomainSiteStageService(object):
    """执行站点发现并移交站点级扫描编排。"""

    def __init__(self, task):
        self.task = task

    def run(self):
        task = self.task
        pipeline = TaskPipeline(task)
        pipeline.run_stage("find_site", task.find_site)
        task.domain_info_list = []

        # 延迟导入避免把站点任务实现重新耦合到域名阶段服务的导入过程。
        from app.services.commonTask import WebSiteFetch

        web_site_fetch = WebSiteFetch(
            task_id=task.task_id,
            sites=task.site_list,
            options=task.options,
            scope_domain=[task.base_domain],
        )
        # 终态唯一 owner 是 DomainTaskOrchestrator.run_deep 的 TaskFinalizer：
        # 嵌套站点层跳过收尾，避免 drain/显影双执行。
        web_site_fetch.terminal_finalize_host_owned = True
        web_site_fetch.run()
        task.wih_domain_set = web_site_fetch.wih_domain_set
        task.web_site_fetch = web_site_fetch


class DomainPostProcessStageService(object):
    """执行协议识别、风险巡航、弱口令和 Host 碰撞等后置阶段。"""

    def __init__(self, task):
        self.task = task

    def run_poc(self):
        task = self.task
        if task._enable_protocol_detection():
            TaskPipeline(task).run_stage(
                "npoc_service_detection",
                lambda: task.npoc_service_detection(
                    full_port=bool(task.options.get("npoc_service_detection"))
                ),
            )

        if (
            task.options.get("port_scan")
            or task.options.get("service_detection")
            or task.options.get("npoc_service_detection")
        ):
            task.save_service_info()

        if task.options.get("poc_config"):
            TaskPipeline(task).run_stage(
                "poc_run",
                lambda: task.web_site_fetch.risk_cruising(task.npoc_service_target_set),
            )

        if task.options.get("brute_config"):
            TaskPipeline(task).run_stage("weak_brute", task.brute_config)

    def run_find_vhost(self):
        task = self.task
        if task.options.get("findvhost"):
            TaskPipeline(task).run_stage("findvhost", task.find_vhost_vuln)
