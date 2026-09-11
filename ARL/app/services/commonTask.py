"""
通用任务执行框架
"""
import time
import re
import os
import yaml
import subprocess
import base64
import hashlib
import hmac
import requests
from types import SimpleNamespace
from urllib.parse import urlparse, parse_qsl, urlencode, urlsplit, urlunsplit, urljoin, quote
from pymongo.errors import NetworkTimeout, AutoReconnect, ServerSelectionTimeoutError
from app import utils
from app import services
from app.config import Config, normalize_dict_path_compat
from app.modules import CollectSource, WebSiteFetchStatus, WebSiteFetchOption
from app.services.waf_guard import WAFSmartSkipGuard
from app.services.task_scope_guard import load_task_scope_context, host_in_scope, url_in_scope
from app.services.infoHunter import InfoHunter
from app.services.stage_executor import StageExecutor
from app.services.task_lifecycle_service import TaskLifecycleService
from app.services.task_result_write_service import TaskResultWriteService
from app.services.task_result_item_service import TaskResultItemService
from app.services.web_site_fetch_orchestrator import WebSiteFetchOrchestrator
from app.services.discovery_context import DiscoveryContext, DiscoveryLedger
from app.services.discovery_ledger_store import MongoLedgerBackend
from app.services.discovery_context import url_host
from app.services.discovery_queue import DiscoveryEventConsumer, NewHostQueue
from app.services.wih_result_persist_services import WihResultPersistService
from app.services.web_site_poc_stage_services import (
    WebSiteNucleiScanStageService,
    WebSiteAfrogScanStageService,
)
from app.services.web_site_scan_stage_services import (
    WebSiteFetchStageService,
    WebSiteFileLeakStageService,
    WebSiteIdentifyStageService,
    WebSiteScreenshotStageService,
    WebSiteSpiderStageService,
)
from app.services import BaseUpdateTask
from app.services.web_site_stage_services import (
    WebSiteDiscoveryContextStageService,
    WebSiteResultPersistStageService,
    WebSiteTargetStageService,
    WebSiteWafStageService,
)
from app.utils.log_safety import safe_error_text
logger = utils.get_logger()


# 任务类中一些相关公共类
class CommonTask(object):
    def __init__(self, task_id):
        self.task_id = task_id
        self._task_scope_context_cache = None
        self._result_writer = TaskResultWriteService(task_id)
        self._result_item_service = TaskResultItemService(task_id, logger=logger)

    def _get_task_scope_context(self, seed_sites=None, scope_domains=None):
        if isinstance(self._task_scope_context_cache, dict) and self._task_scope_context_cache:
            return self._task_scope_context_cache
        self._task_scope_context_cache = load_task_scope_context(
            task_id=self.task_id,
            seed_sites=seed_sites,
            scope_domains=scope_domains,
        )
        return self._task_scope_context_cache

    def _url_in_task_scope(self, value: str, seed_sites=None, scope_domains=None) -> bool:
        context = self._get_task_scope_context(seed_sites=seed_sites, scope_domains=scope_domains)
        return url_in_scope(value, context.get("allowed_hosts", []), context.get("allowed_flds", []))

    def _host_in_task_scope(self, value: str, seed_sites=None, scope_domains=None) -> bool:
        context = self._get_task_scope_context(seed_sites=seed_sites, scope_domains=scope_domains)
        return host_in_scope(value, context.get("allowed_hosts", []), context.get("allowed_flds", []))

    def insert_task_stat(self):
        return TaskLifecycleService(self).insert_task_stat()

    def insert_finger_stat(self):
        return TaskLifecycleService(self).insert_finger_stat()

    def insert_cip_stat(self):
        return TaskLifecycleService(self).insert_cip_stat()

    # 资产同步
    def sync_asset(self):
        return TaskLifecycleService(self).sync_asset()

    @staticmethod
    def _stage_result_metadata(result):
        metrics = {}

        def visit(value):
            if value is None:
                return None

            value_metrics = getattr(value, "metrics", None)
            if isinstance(value_metrics, dict):
                metrics.update(value_metrics)

            if isinstance(value, dict):
                nested_metrics = value.get("metrics") or value.get("stage_metrics")
                if isinstance(nested_metrics, dict):
                    metrics.update(nested_metrics)
                for key in ("output_count", "result_count", "count"):
                    if value.get(key) is not None:
                        try:
                            return max(0, int(value[key]))
                        except (TypeError, ValueError):
                            continue
                for key in ("records", "results", "items", "targets"):
                    nested = value.get(key)
                    if isinstance(nested, (list, tuple, set, dict)):
                        return len(nested)
                return None

            if isinstance(value, (list, set)):
                return len(value)

            if isinstance(value, tuple):
                nested_counts = [visit(nested) for nested in value]
                valid_counts = [count for count in nested_counts if count is not None]
                return sum(valid_counts) if valid_counts else None

            if isinstance(value, (int, float)) and not isinstance(value, bool):
                return max(0, int(value))

            return None

        output_count = visit(result)
        return output_count, metrics

    def _stage_input_count(self, name: str = ""):
        for attribute in ("sites", "available_sites", "scan_sites"):
            value = self.__dict__.get(attribute)
            if isinstance(value, (list, tuple, set, dict)):
                return len(value)
        return None

    @staticmethod
    def _stage_budget_sec(name: str = ""):
        stage_key = str(name or "").strip().lower()
        budget_key_map = {
            "wih_primary_scan": "WIH_TOTAL_BUDGET_SEC",
            "wih_urlfinder_sensitive": "URLFINDER_SENSITIVE_STAGE_TIMEOUT_SEC",
            "search_engines": "SEARCH_PROVIDER_STAGE_TIMEOUT_SEC",
            "port_scan": "PORT_SCAN_STAGE_TIMEOUT_SEC",
            "dns_query_plugin": "DNS_QUERY_PLUGIN_STAGE_TIMEOUT_SEC",
            "asset_pivot": "ASSET_DISCOVERY_STAGE_TIMEOUT_SEC",
            "asset_pivot_round": "ASSET_DISCOVERY_STAGE_TIMEOUT_SEC",
            "nuclei_scan": "NUCLEI_STAGE_TIMEOUT_SEC",
            "nuclei_scan_retry": "NUCLEI_STAGE_TIMEOUT_SEC",
            "afrog_scan": "AFROG_STAGE_TIMEOUT_SEC",
        }
        config_key = budget_key_map.get(stage_key)
        if not config_key:
            return None
        value = getattr(Config, config_key, None)
        try:
            return max(0, float(value)) if value is not None else None
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _stage_failure_reason(exc) -> str:
        exception_name = type(exc).__name__.lower()
        if "timeout" in exception_name or "deadline" in exception_name:
            return "timeout"
        return "exception"

    def _run_internal_stage(self, name: str, func: callable, detail: str = ""):
        return self._get_stage_executor().execute(
            name,
            func,
            detail=detail,
            detail_provider=lambda _name, stage_detail: stage_detail,
            trigger_ai=False,
            stage_kind="execution",
            log_kind="internal",
        )

    def _get_stage_executor(self):
        base_update_task = getattr(self, "base_update_task", None)
        executor = getattr(self, "_stage_executor", None)
        if executor is None or executor.base_update_task is not base_update_task:
            self._stage_executor = StageExecutor(
                task_id=self.task_id,
                base_update_task=base_update_task,
                logger=logger,
                input_count_provider=self._stage_input_count,
                budget_provider=self._stage_budget_sec,
                result_metadata_provider=self._stage_result_metadata,
                failure_reason_provider=self._stage_failure_reason,
                description_provider=lambda: self.__str__(),
            )
        return self._stage_executor

    def common_run(self):
        return TaskLifecycleService(self).run_finalize()


# *** 对用户提交的站点或者是发现的站点进行后续处理
class WebSiteFetch(CommonTask):
    # 低性能环境下，Mongo 读取可能因网络抖动/带宽占满触发超时；nuclei 目标构建最多重试 3 次。
    NUCLEI_TARGET_BUILD_RETRY_COUNT = 3
    NUCLEI_TARGET_BUILD_RETRY_SLEEP_SEC = 3
    RETRYABLE_MONGO_ERRORS = (NetworkTimeout, AutoReconnect, ServerSelectionTimeoutError)
    # 站点识别分层策略：先快扫，再对高价值站点精扫。
    SITE_IDENTIFY_AUTO_MIN_SELECT = 20
    SITE_IDENTIFY_AUTO_MAX_SELECT = 160
    SITE_IDENTIFY_AUTO_RATIO = 0.25
    SITE_IDENTIFY_FORCE_STATUS_SET = {401, 403}
    SITE_IDENTIFY_TITLE_KEYWORDS = (
        "login", "signin", "admin", "manage", "dashboard", "console",
        "swagger", "grafana", "jenkins", "gitlab", "jira", "confluence",
        "harbor", "nacos", "phpmyadmin", "tomcat", "weblogic", "kibana",
        "zabbix", "prometheus", "rabbitmq", "minio",
    )
    SITE_IDENTIFY_HOST_KEYWORDS = (
        "admin", "manage", "ops", "dev", "test", "staging", "pre",
        "console", "panel", "oa", "vpn", "api",
    )

    def __init__(self, task_id: str, sites: list, options: dict, scope_domain: list = None):
        super(WebSiteFetch, self).__init__(task_id)
        self.task_id = task_id
        self.sites = sites  # ** 这个是用户提交的目标
        self.options = options or {}
        self.smart_skip_waf = bool(self.options.get("smart_skip_waf", False))
        self.waf_guard = WAFSmartSkipGuard(
            enabled=self.smart_skip_waf,
            smart_skip_enabled=self.smart_skip_waf,
            task_id=self.task_id,
            scope_sites=self.sites,
            signal_sink=self._on_waf_guard_block,
        )
        self.base_update_task = BaseUpdateTask(self.task_id)
        self.site_info_list = []  # *** 这个是来自 services.fetch_site 的结果
        self.available_sites = []  # *** 这个是存活的站点
        self.web_analyze_map = dict()
        self.wih_domain_set = set()  # 用于保存来自wih的域名，已添加的域名不再添加
        self.wih_record_set = set()  # 用于保存来自wih的记录，已添加的记录不再添加

        # 用于判断应该收集的子域名
        if not scope_domain:
            scope_domain = []

        self.scope_domain = scope_domain
        self.page_url_set = set()
        self.search_engines_result = dict()
        self._poc_sites = None  # 用于PoC 执行， 文件目录爆破 的目标
        self._task_domain_set = None  # 用于保存任务中的域名
        self._nuclei_deferred_retry_needed = False
        self._nuclei_final_skip = False
        self._task_scope_context_cache = None
        self._service_detail_overrides = {}
        self._waf_stage_stats = {}
        # 站点策略共享任务级上下文；候选图容量软读配置，非法值回默认而不是打断任务初始化。
        try:
            discovery_candidate_max = int(getattr(Config, "DISCOVERY_CANDIDATE_MAX", 20000) or 20000)
        except (TypeError, ValueError):
            discovery_candidate_max = 20000
        self.discovery_context = DiscoveryContext(
            task_id=self.task_id,
            allowed_hosts=self.sites,
            response_max_body_bytes=getattr(Config, "PAGE_INTEL_MAX_PAGE_BYTES", 384 * 1024),
            candidate_max_entries=discovery_candidate_max,
            # 账本走 Mongo 后端：跨 worker 重启保存可恢复阶段状态；后端内部全量 fail-open。
            ledger=DiscoveryLedger(MongoLedgerBackend(self.task_id)),
        )
        try:
            new_host_queue_max = int(getattr(Config, "DISCOVERY_NEW_HOST_QUEUE_MAX", 50) or 50)
        except (TypeError, ValueError):
            new_host_queue_max = 50
        self.new_host_queue = NewHostQueue(
            self.discovery_context,
            waf_guard=self.waf_guard,
            max_hosts=new_host_queue_max,
            allowed_hosts={url_host(site) for site in self.sites if url_host(site)},
        )
        try:
            discovery_event_queue_max = int(
                getattr(Config, "DISCOVERY_EVENT_QUEUE_MAX", 2000) or 2000
            )
        except (TypeError, ValueError):
            discovery_event_queue_max = 2000
        self.discovery_event_consumer = DiscoveryEventConsumer(
            self.discovery_context,
            max_events=discovery_event_queue_max,
            allowed_hosts={url_host(site) for site in self.sites if url_host(site)},
        )
        try:
            # worker 恢复：把上轮被容量驱逐的待处理候选读回共享图（幂等）。
            self.discovery_context.restore_overflow_candidates()
        except Exception as exc:
            logger.debug(
                "task_id:{} overflow restore skipped error_type:{}".format(
                    self.task_id, type(exc).__name__))
        try:
            # worker 恢复：回灌账本中已确认的 WAF 阻断，重投不留熔断空窗。
            self.discovery_context.restore_waf_state()
        except Exception as exc:
            logger.debug(
                "task_id:{} waf state restore skipped error_type:{}".format(
                    self.task_id, type(exc).__name__))

    def _on_waf_guard_block(self, url, module, reason, block_scope=""):
        return WebSiteDiscoveryContextStageService(self).on_waf_guard_block(
            url,
            module,
            reason,
            block_scope,
        )

    def _log_discovery_observation(self):
        return WebSiteDiscoveryContextStageService(self).log_observation()

    def _filter_waf_blocked_targets(self, targets, stage_name="") -> list:
        return WebSiteWafStageService(self).filter_targets(targets, stage_name)

    def _save_waf_skip_summary(self):
        return WebSiteWafStageService(self).save_waf_skip_summary()

    @property
    def task_domain_set(self):
        return WebSiteTargetStageService(self).task_domain_set()

    def _site_identify_score(self, site_info: dict) -> tuple:
        return WebSiteIdentifyStageService(self)._site_identify_score(site_info)

    def _build_site_identify_targets(self) -> list:
        return WebSiteIdentifyStageService(self)._build_site_identify_targets()

    def site_identify(self):
        return WebSiteIdentifyStageService(self).run()

    def __str__(self):
        return "<WebSiteFetch> task_id:{}, sites: {}, available_sites:{}".format(
            self.task_id, len(self.sites), len(self.available_sites))

    def _get_task_scope_context(self):
        if isinstance(self._task_scope_context_cache, dict) and self._task_scope_context_cache:
            return self._task_scope_context_cache
        self._task_scope_context_cache = load_task_scope_context(
            task_id=self.task_id,
            seed_sites=self.sites,
            scope_domains=self.scope_domain,
        )
        return self._task_scope_context_cache

    def _url_in_task_scope(self, value: str) -> bool:
        context = self._get_task_scope_context()
        return url_in_scope(value, context.get("allowed_hosts", []), context.get("allowed_flds", []))

    def _host_in_task_scope(self, value: str) -> bool:
        context = self._get_task_scope_context()
        return host_in_scope(value, context.get("allowed_hosts", []), context.get("allowed_flds", []))

    def save_site_info(self):
        return WebSiteResultPersistStageService(self).save_site_info()

    def site_screenshot(self):
        return WebSiteScreenshotStageService(self).run()

    def site_spider(self):
        return WebSiteSpiderStageService(self, build_url_item).run()

    def _enhance_site_spider_urls_with_intel(self):
        return WebSiteSpiderStageService(self, build_url_item)._enhance_site_spider_urls_with_intel()

    def fetch_site(self):
        return WebSiteFetchStageService(self).run()

    def file_leak(self):
        return WebSiteFileLeakStageService(self).run()

    @property
    def poc_sites(self):
        return WebSiteTargetStageService(self).poc_sites()

    def risk_cruising(self, npoc_service_target_set: set):
        return WebSiteResultPersistStageService(self).risk_cruising(
            npoc_service_target_set
        )

    def build_nuclei_targets(self):
        """组装 nuclei 扫描目标（兼容入口，实现见 WebSiteNucleiScanStageService）。"""
        return WebSiteNucleiScanStageService(self).build_targets()

    @staticmethod
    def nuclei_scan(self, deferred_retry=False):
        """Nuclei 扫描阶段（兼容入口，实现见 WebSiteNucleiScanStageService）。"""
        return WebSiteNucleiScanStageService(self).run(deferred_retry=deferred_retry)

    def run_deferred_nuclei_scan(self):
        return WebSiteNucleiScanStageService(self).run_deferred_retry()

    @staticmethod
    def _build_afrog_detail_text(result, target, poc_id):
        return TaskResultItemService.build_afrog_detail_text(result, target, poc_id)

    def afrog_scan(self):
        """Afrog 扫描阶段（兼容入口，实现见 WebSiteAfrogScanStageService）。"""
        return WebSiteAfrogScanStageService(self).run()

    def _clip_text(value, max_len=220):
        text = str(value or "").replace("\r", " ").replace("\n", " ").strip()
        if len(text) <= max_len:
            return text
        return "{}...".format(text[:max_len])

    @staticmethod
    def _clip_multiline_text(value, max_len=220):
        text = str(value or "").replace("\r\n", "\n").replace("\r", "\n").strip()
        if len(text) <= max_len:
            return text
        return "{}...".format(text[:max_len])

    @staticmethod
    def _is_http_target(value: str) -> bool:
        text = str(value or "").strip().lower()
        return text.startswith("http://") or text.startswith("https://")

    @staticmethod
    def _normalize_object_id(value) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        return text

    @staticmethod
    def _normalize_risk_type(value, default_value="unknown"):
        text = str(value or "").strip().lower()
        if not text:
            return default_value
        return text[:64]

    def run_func(self, name: str, func: callable):
        stage_kind = (
            "aggregate"
            if str(name or "").strip().lower() in {"web_info_hunter", "task_finalize"}
            else "execution"
        )
        self._get_stage_executor().execute(
            name,
            func,
            detail_provider=self._consume_service_detail_override,
            trigger_ai=True,
            stage_kind=stage_kind,
            log_kind="stage",
        )

    def _run_substage(
        self,
        name: str,
        func: callable,
        detail: str = "",
        input_count: int = None,
        budget_sec: float = None,
    ):
        return self._get_stage_executor().execute(
            name,
            func,
            detail=detail,
            input_count=input_count,
            budget_sec=budget_sec,
            detail_provider=self._consume_service_detail_override,
            trigger_ai=False,
            stage_kind="execution",
            log_kind="substage",
        )

    def _mark_service_detail_override(self, service_name: str, detail: str):
        service_key = str(service_name or "").strip()
        detail_text = str(detail or "").strip()
        if not service_key or not detail_text:
            return
        if not isinstance(self._service_detail_overrides, dict):
            self._service_detail_overrides = {}
        self._service_detail_overrides[service_key] = detail_text[:1200]

    def _consume_service_detail_override(self, service_name: str, base_detail: str = "") -> str:
        detail_text = str(base_detail or "").strip()
        service_key = str(service_name or "").strip()
        override_detail = ""
        if isinstance(self._service_detail_overrides, dict) and service_key:
            override_detail = str(self._service_detail_overrides.pop(service_key, "") or "").strip()
        if detail_text and override_detail:
            return "{} | {}".format(detail_text, override_detail)[:1200]
        return override_detail or detail_text

    def _build_optional_ai_stage_error_detail(self, stage_name: str, exc, fallback_note: str = "") -> str:
        stage_text = str(stage_name or "ai_stage").strip() or "ai_stage"
        error_text = self._clip_text(exc, 220) or "unknown_error"
        detail_parts = [
            "degraded=true",
            "stage={}".format(stage_text),
            "error={}".format(error_text),
        ]
        note_text = self._clip_text(fallback_note, 220)
        if note_text:
            detail_parts.append("fallback={}".format(note_text))
        return " | ".join(detail_parts)[:1200]

    def _run_optional_ai_stage_best_effort(
        self,
        service_name: str,
        func: callable,
        fallback_result=None,
        feature_name: str = "",
        fallback_note: str = "",
        push_service_on_error: bool = False,
        trigger_ai: bool = False,
        on_error=None,
    ):
        started_at = time.time()
        try:
            return func()
        except Exception as exc:
            service_text = str(service_name or "").strip()
            feature_text = str(feature_name or service_text or "ai_stage").strip() or "ai_stage"
            detail_text = self._build_optional_ai_stage_error_detail(feature_text, exc, fallback_note=fallback_note)
            logger.warning(
                "task_id:{} optional ai stage degraded service:{} feature:{} err:{}".format(
                    self.task_id,
                    service_text or "-",
                    feature_text,
                    self._clip_text(exc, 220),
                )
            )
            if callable(on_error):
                try:
                    on_error(exc, detail_text)
                except Exception as callback_exc:
                    logger.warning(
                        "task_id:{} optional ai stage degrade callback failed service:{} err:{}".format(
                            self.task_id,
                            service_text or "-",
                            self._clip_text(callback_exc, 220),
                        )
                    )
            if push_service_on_error and service_text:
                self.base_update_task.append_service(
                    service_name=service_text,
                    elapsed=max(time.time() - started_at, 0.0),
                    detail=detail_text,
                    trigger_ai=trigger_ai,
                )
            elif service_text:
                self._mark_service_detail_override(service_text, detail_text)
            return fallback_result

    def update_page_url_set(self):
        from app.services.web_site_stage_services import WebSiteDiscoveryStageService

        return WebSiteDiscoveryStageService(self).update_page_url_set()

    def _wih_persist_service(self):
        return WihResultPersistService(self)

    def add_wih_domain_set(self, record):
        self._wih_persist_service().add_domain_set(record)

    @staticmethod
    def _is_http_url(value: str) -> bool:
        """判断文本是否是 http/https URL。"""
        return WihResultPersistService.is_http_url(value)

    def _extract_scope_urls_from_wih_record(self, record) -> list:
        return self._wih_persist_service().extract_scope_urls(record)

    def _wih_record_in_task_scope(self, record) -> bool:
        return self._wih_persist_service().record_in_task_scope(record)

    @staticmethod
    def _is_obvious_wih_secret_noise(record_type: str, content: str, source: str = "", site: str = "") -> bool:
        """复用 WIH 统一规则，过滤已明确判定为占位值或调试代码的敏感命中。"""
        return WihResultPersistService(None).is_obvious_secret_noise(
            record_type, content, source=source, site=site
        )

    def _is_sensitive_wih_record(self, record_type: str, content: str, source: str = "", site: str = "") -> bool:
        """判断 WIH 记录是否属于可进入风险提升链的敏感类型。"""
        return self._wih_persist_service().is_sensitive_record(
            record_type, content, source=source, site=site
        )

    def _scan_result_in_task_scope(self, result: dict, target_keys=None) -> bool:
        item = result if isinstance(result, dict) else {}
        keys = list(target_keys or ("target", "url", "vuln_url"))
        for key in keys:
            value = str(item.get(key, "") or "").strip()
            if not value:
                continue
            if self._is_http_url(value):
                return self._url_in_task_scope(value)
            return self._host_in_task_scope(value)
        return False

    def _should_promote_wih_to_risk(self, record) -> bool:
        """判断 WIH 记录是否需要同步到风险(vuln)模块。"""
        return self._wih_persist_service().should_promote_to_risk(record)

    @staticmethod
    def _infer_wih_risk_severity(record_type: str, content: str) -> str:
        """基于记录类型和内容推断风险等级。"""
        return WihResultPersistService.infer_risk_severity(record_type, content)

    def _build_wih_vuln_item(self, record):
        return self._wih_persist_service().build_vuln_item(record)

    def _save_wih_risk(self, record):
        """将敏感 WIH 记录写入风险库，按任务+WIH哈希去重。"""
        self._wih_persist_service().save_risk(record)

    def _save_wih_endpoints(self, endpoints):
        """WIH 结构化接口独立落库，保留前台按任务维度分页查询语义。"""
        self._wih_persist_service().save_endpoints(endpoints)

    def _save_wih_record(self, record):
        """保存已经完成范围校验和去重的 WIH 记录。"""
        self._wih_persist_service().save_record(record)

    def _apply_reused_wih_records(self, records):
        return self._wih_persist_service().apply_reused_records(records)

    def run_web_info_hunter(self):
        from app.services.wih_orchestrator import WihOrchestrator

        return WihOrchestrator(self).run()

    def run(self):
        return WebSiteFetchOrchestrator(self).run()


def domain_in_scope_domain(domain: str, scope_domain: list):
    for scope in scope_domain:
        if domain.endswith("." + scope):
            return True
    return False


def build_url_item(site, task_id, source):
    item = {
        "site": site,
        "task_id": task_id,
        "source": source
    }
    domain_parsed = utils.domain_parsed(site)
    if domain_parsed:
        item["fld"] = domain_parsed["fld"]

    return item
