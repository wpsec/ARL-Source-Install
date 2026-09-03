"""IP 任务的可测试阶段服务。

组合服务只负责阶段顺序；端口、站点、NPoC 和弱口令的具体实现位于对应的
具体 stage service。
"""

from app.services.single_scan_stage_services import IPSingleStageService


class IPNetworkStageService(object):
    """执行 IP 端口、证书和站点发现阶段。"""

    def __init__(self, task):
        self.task = task

    def run(self):
        task = self.task
        stage = IPSingleStageService(task)
        results = {}
        results["port_scan"] = stage.run(
            "port_scan",
            task.port_scan,
            enabled=bool(task.options.get("port_scan")),
        )
        results["ssl_cert"] = stage.run(
            "ssl_cert",
            task.ssl_cert,
            enabled=bool(task.options.get("ssl_cert")),
        )
        results["find_site"] = stage.run("find_site", task.find_site)
        return results


class IPPostProcessStageService(object):
    """执行协议识别、风险巡航、弱口令和结果保存阶段。"""

    def __init__(self, task, web_site_fetch):
        self.task = task
        self.web_site_fetch = web_site_fetch

    def run(self):
        task = self.task
        stage = IPSingleStageService(task)

        if task._enable_protocol_detection():
            stage.run(
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
            stage.run(
                "poc_run",
                lambda: self.web_site_fetch.risk_cruising(task.npoc_service_target_set),
            )

        if task.options.get("brute_config"):
            stage.run("weak_brute", task.brute_config)
