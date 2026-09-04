"""WebSiteFetch PoC 扫描阶段服务(Nuclei/Afrog)。

功能说明：
- 组装 Nuclei 目标、执行 Nuclei/Afrog 扫描并写回 nuclei_result/vuln
- 任务类保留同名兼容方法;外部行为、结果字段与延迟重试语义不变
- Mongo 写操作仍经 task._result_writer,文档组装仍经 task._result_item_service
"""

import hashlib
import re
import time

from app import utils
from app.config import Config
from app.services.afrog_scan import run_afrog_scan
from app.services.nuclei_scan import nuclei_scan, NucleiScan, NucleiScanResult
from app.utils.log_safety import safe_error_text


logger = utils.get_logger()


class WebSiteNucleiScanStageService(object):
    """Nuclei 目标组装、扫描执行与结果写回。"""

    def __init__(self, task, utils_module=None, scanner_factory=None):
        self.task = task
        self.utils = utils_module or utils
        self._nuclei_scan = scanner_factory or nuclei_scan

    def build_targets(self):
        """组装 nuclei 扫描目标，附带站点指纹信息。"""
        task = self.task
        poc_sites = sorted(task.poc_sites)
        if not poc_sites:
            return []

        # 标题关键词提示，用于补足指纹命名差异。
        title_hint_keywords = (
            "jenkins", "grafana", "kibana", "gitlab", "jira", "confluence",
            "harbor", "nacos", "rabbitmq", "minio", "tomcat", "weblogic",
            "kong", "apisix", "zabbix", "prometheus",
        )

        query = {
            "task_id": task.task_id,
            "site": {"$in": poc_sites},
        }
        fields = {"site": 1, "finger": 1, "http_server": 1, "title": 1}
        site_finger_map = {}
        for attempt in range(1, task.NUCLEI_TARGET_BUILD_RETRY_COUNT + 1):
            site_finger_map = {}
            try:
                for item in self.utils.conn_db("site").find(
                    query,
                    fields,
                    max_time_ms=Config.MONGO_SOCKET_TIMEOUT_MS,
                ):
                    site = str(item.get("site", "")).strip()
                    if not site:
                        continue

                    finger_names = []
                    finger_list = item.get("finger", [])
                    if isinstance(finger_list, list):
                        for finger in finger_list:
                            if not isinstance(finger, dict):
                                continue
                            finger_name = str(finger.get("name", "")).strip().lower()
                            if finger_name:
                                finger_names.append(finger_name)

                    # 将 HTTP Server 头拆分成关键词并作为 hint。
                    http_server = str(item.get("http_server", "")).strip().lower()
                    if http_server:
                        finger_names.append(http_server)
                        for token in re.split(r"[^a-z0-9]+", http_server):
                            token = token.strip()
                            if len(token) >= 3:
                                finger_names.append(token)

                    # 将 title 中的高价值技术关键词加入 hint。
                    title_text = str(item.get("title", "")).strip().lower()
                    if title_text:
                        for keyword in title_hint_keywords:
                            if keyword in title_text:
                                finger_names.append(keyword)

                    site_finger_map[site] = sorted(set(finger_names))
                break
            except task.RETRYABLE_MONGO_ERRORS as e:
                if attempt >= task.NUCLEI_TARGET_BUILD_RETRY_COUNT:
                    logger.warning(
                        "build_nuclei_targets failed after retries task_id:{} attempts:{} error:{}".format(
                            task.task_id, task.NUCLEI_TARGET_BUILD_RETRY_COUNT, e
                        )
                    )
                    raise

                sleep_sec = task.NUCLEI_TARGET_BUILD_RETRY_SLEEP_SEC * attempt
                logger.warning(
                    "build_nuclei_targets mongo timeout task_id:{} attempt:{}/{} sleep:{}s error:{}".format(
                        task.task_id,
                        attempt,
                        task.NUCLEI_TARGET_BUILD_RETRY_COUNT,
                        sleep_sec,
                        e,
                    )
                )
                time.sleep(sleep_sec)

        nuclei_targets = []
        for site in poc_sites:
            nuclei_targets.append(
                {
                    "target": site,
                    "finger": site_finger_map.get(site, []),
                }
            )

        return nuclei_targets

    def _ledger_context(self):
        context = getattr(self.task, "discovery_context", None)
        ledger = getattr(context, "ledger", None) if context is not None else None
        return context, ledger

    @staticmethod
    def _ledger_key(context, nuclei_targets, scan_profile):
        """账本键=目标集合指纹+profile 指纹；同任务重跑且参数未变才可跳过。"""
        targets_fp = hashlib.md5(
            "\n".join(sorted(str((item or {}).get("target", "")) for item in nuclei_targets)).encode("utf-8", "ignore")
        ).hexdigest()[:16]
        profile_text = "default"
        if isinstance(scan_profile, dict):
            tags = sorted({str(x).strip().lower() for x in (scan_profile.get("force_tags") or []) if str(x).strip()})
            profile_text = "{}:{}".format(str(scan_profile.get("name", "") or "profile"), ",".join(tags))
        return context.idempotency_key("nuclei_scan", targets_fp, scan_profile=profile_text, input_signature="")

    def run(self, deferred_retry=False):
        """执行 Nuclei 扫描并写回结果；mongo 超时的延迟重试语义保持原样。"""
        task = self.task
        try:
            nuclei_targets = self.build_targets()
        except task.RETRYABLE_MONGO_ERRORS as e:
            if deferred_retry:
                task._nuclei_final_skip = True
                logger.warning(
                    "nuclei_scan skipped task_id:{} after deferred retry due to mongo timeout:{}".format(
                        task.task_id, e
                    )
                )
                return NucleiScanResult(
                    [],
                    metrics={
                        "status": "error",
                        "end_reason": "mongo_timeout",
                        "failed_count": 1,
                    },
                )
            else:
                task._nuclei_deferred_retry_needed = True
                logger.warning(
                    "nuclei_scan deferred task_id:{} due to mongo timeout, will retry after later stages:{}".format(
                        task.task_id, e
                    )
                )
                return NucleiScanResult(
                    [],
                    metrics={
                        "status": "pending",
                        "end_reason": "deferred_mongo_timeout",
                        "pending_count": 1,
                    },
                )

        finger_hit_count = 0
        for item in nuclei_targets:
            if item.get("finger"):
                finger_hit_count += 1

        logger.info(
            "start nuclei_scan, poc_sites:{} finger_hit:{}".format(
                len(nuclei_targets), finger_hit_count
            )
        )
        scan_profile = None

        context, ledger = self._ledger_context()
        ledger_key = ""
        if ledger is not None and nuclei_targets:
            ledger_key = self._ledger_key(context, nuclei_targets, scan_profile)
            entry = ledger.get(ledger_key)
            if entry is not None and getattr(entry, "status", "") == "covered":
                # 同任务重跑：上次 nuclei 已全量成功，不再消耗模板执行预算。
                logger.info(
                    "nuclei_scan skipped by ledger covered task_id:{} targets:{}".format(
                        task.task_id, len(nuclei_targets)
                    )
                )
                return NucleiScanResult(
                    [],
                    metrics={
                        "status": "success",
                        "end_reason": "ledger_covered",
                        "input_count": len(nuclei_targets),
                    },
                )

        scan_results = self._nuclei_scan(nuclei_targets, scan_profile=scan_profile)
        for item in scan_results:
            if not task._scan_result_in_task_scope(item, target_keys=("vuln_url", "target")):
                continue
            result_item = task._result_item_service.build_nuclei_document(item)
            if result_item:
                task._result_writer.insert_one("nuclei_result", result_item)

        if ledger is not None and ledger_key:
            result_metrics = getattr(scan_results, "metrics", None) or {}
            if (
                str(result_metrics.get("status") or "success") == "success"
                and str(result_metrics.get("end_reason") or "completed") == "completed"
            ):
                ledger.finish(
                    ledger_key,
                    "covered",
                    input_count=len(nuclei_targets),
                    output_count=len(scan_results),
                )

        logger.info("end nuclei_scan， result:{}".format(len(scan_results)))
        return scan_results

class WebSiteAfrogScanStageService(object):
    """Afrog 扫描与 vuln 写回。"""

    def __init__(self, task, afrog_runner=None):
        self.task = task
        self._run_afrog = afrog_runner or run_afrog_scan

    def run(self):
        """
        运行 afrog Web 漏洞扫描，并写入 vuln 模块。

        字段映射：
        - plg_name: afrog:<poc_id>
        - plg_type: afrog
        - vul_name / severity / target: 来自 afrog 结果
        """
        task = self.task
        afrog_targets = sorted(task.poc_sites)
        if not afrog_targets:
            logger.info("skip afrog_scan, no poc_sites")
            return

        origin_target_count = len(afrog_targets)
        afrog_targets = task._filter_waf_blocked_targets(afrog_targets, stage_name="afrog")
        if not afrog_targets:
            logger.info("skip afrog_scan, no targets after waf filter")
            return

        logger.info(
            "start afrog_scan targets:{} after_waf_filter:{} smart_skip_waf:{}".format(
                origin_target_count,
                len(afrog_targets),
                task.smart_skip_waf,
            )
        )
        scan_results = self._run_afrog(afrog_targets)
        saved_count = 0
        for result in scan_results:
            target = str(result.get("target", "") or "").strip()
            if not target:
                continue
            if not task._scan_result_in_task_scope(result, target_keys=("target",)):
                continue

            poc_id = str(result.get("poc_id", "") or "").strip()
            item = task._result_item_service.build_afrog_document(result, target, poc_id)
            if not item:
                continue
            task._result_writer.insert_one("vuln", item)
            saved_count += 1

        logger.info("end afrog_scan, result:{} saved:{}".format(len(scan_results), saved_count))
