"""域名任务的可测试阶段服务。

这些服务只接收一个已初始化的任务上下文，负责单一阶段的业务边界；任务类
继续保留同名兼容方法，避免改变 Celery、历史重试和外部调用的入口。
"""

import time

from app.config import Config
from app.modules import CollectSource
from app.services.task_pipeline import TaskPipeline

class DomainDiscoveryStageService(object):
    """执行域名爆破、插件发现和智能 DNS 生成。"""

    def __init__(self, task):
        self.task = task

    def run(self):
        task = self.task
        if task.options.get("domain_brute"):
            task.update_task_field("status", "domain_brute")
            started_at = time.time()
            task.domain_brute()
            task.update_services("domain_brute", time.time() - started_at)

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
            task.update_task_field("status", "arl_search")
            started_at = time.time()
            task.arl_search()
            task.update_services("arl_search", time.time() - started_at)

        if task.options.get("alt_dns"):
            task.update_task_field("status", "alt_dns")
            started_at = time.time()
            task.alt_dns()
            task.update_services("alt_dns", time.time() - started_at)


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
