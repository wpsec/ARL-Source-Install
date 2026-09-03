"""IP 后置扫描阶段的具体业务服务。

组合编排保留在 IP stage service；本模块只承接 NPoC 和弱口令的具体执行边界。
"""

from app import utils
from app.services import run_risk_cruising, run_sniffer


logger = utils.get_logger()


class IPNPOCServiceDetectionStageService(object):
    """执行 NPoC 协议识别并回写服务目标。"""

    def __init__(self, task, utils_module=None, sniffer=None):
        self.task = task
        self.utils = utils_module or utils
        self.sniffer = sniffer or run_sniffer

    def run(self, full_port=False):
        task = self.task
        targets, total_targets, low_conf_targets, mode = task._build_sniffer_targets(
            full_port=full_port,
        )
        logger.info(
            "npoc_service_detection mode:{} selected:{} total:{} low_conf:{} "
            "skip_common_http_ports:{}".format(
                mode,
                len(targets),
                total_targets,
                low_conf_targets,
                not full_port,
            )
        )
        if not targets:
            return []

        result = self.sniffer(targets, skip_common_http_ports=not full_port)
        enriched_count = task._apply_npoc_service_result(result)
        logger.info(
            "npoc_service_detection result:{} enriched_port:{}".format(
                len(result),
                enriched_count,
            )
        )
        for item in result:
            task.npoc_service_target_set.add(item["target"])
            item["task_id"] = task.task_id
            item["save_date"] = self.utils.curr_date()
            item["source"] = "npoc_sniffer"
            self.utils.conn_db("npoc_service").insert_one(item)
        return result


class IPBruteConfigStageService(object):
    """执行弱口令配置对应的风险巡航。"""

    def __init__(self, task, risk_runner=None, utils_module=None):
        self.task = task
        self.risk_runner = risk_runner or run_risk_cruising
        self.utils = utils_module or utils

    def run(self):
        task = self.task
        plugins = []
        for item in task.options.get("brute_config") or []:
            if item.get("enable"):
                plugins.append(item["plugin_name"])
        if not plugins:
            return []

        targets = list(task.site_list)
        targets.extend(list(task.npoc_service_target_set))
        result = self.risk_runner(targets=targets, plugins=plugins)
        for item in result:
            item["task_id"] = task.task_id
            item["save_date"] = self.utils.curr_date()
            self.utils.conn_db("vuln").insert_one(item)
        return result
