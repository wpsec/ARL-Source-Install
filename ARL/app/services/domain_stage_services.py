"""域名任务的可测试阶段服务。

这些服务只接收一个已初始化的任务上下文，负责单一阶段的业务边界；任务类
继续保留同名兼容方法，避免改变 Celery、历史重试和外部调用的入口。
"""

import time
from urllib.parse import urlparse

from app import services, utils
from app.config import Config
from app.modules import CollectSource
from app.services.dns_query import run_query_plugin
from app.services.searchEngines import search_engines
from app.services.task_pipeline import TaskPipeline
from app.utils.provider_http import stage_execution_context


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
            self.run_dns_query_plugin()
            task.update_services(
                "dns_query_plugin",
                time.time() - started_at,
                metrics=task._last_dns_query_metrics,
            )

        if task.options.get("arl_search"):
            _run_measured_stage(task, "arl_search", _domain_count_stage(task, task.arl_search))

        if task.options.get("alt_dns"):
            _run_measured_stage(task, "alt_dns", _domain_count_stage(task, task.alt_dns))

    @staticmethod
    def _chunk_list(items, chunk_size):
        try:
            size = int(chunk_size)
        except Exception:
            size = 0

        if size <= 0:
            size = len(items) if items else 1

        for index in range(0, len(items), size):
            yield items[index:index + size]

    @staticmethod
    def _format_timeout(timeout_sec):
        if int(timeout_sec or 0) <= 0:
            return "unlimited"
        return "{}s".format(int(timeout_sec))

    @staticmethod
    def _calc_dns_query_plugin_stage_timeout(source_count):
        """按来源数量计算 DNS 插件阶段预算。"""

        base = int(getattr(Config, "DNS_QUERY_PLUGIN_STAGE_TIMEOUT_SEC", 0) or 0)
        per_source = int(
            getattr(Config, "DNS_QUERY_PLUGIN_STAGE_TIMEOUT_PER_SOURCE_SEC", 0) or 0
        )
        max_budget = int(
            getattr(Config, "DNS_QUERY_PLUGIN_STAGE_TIMEOUT_MAX_SEC", 0) or 0
        )

        if base < 0:
            base = 0
        if per_source < 0:
            per_source = 0
        if max_budget < 0:
            max_budget = 0

        if base <= 0 and per_source <= 0:
            return 0

        budget = base
        if source_count > 0 and per_source > 0:
            budget += int(source_count) * per_source

        if max_budget > 0:
            budget = min(budget, max_budget)

        if budget <= 0:
            return 0
        return budget

    def _resolve_dns_query_sources(self):
        """解析可执行的 DNS 查询来源并过滤无效配置。"""

        plugins = utils.load_query_plugins(Config.dns_query_plugin_path)
        query_key = Config.QUERY_PLUGIN_CONFIG if isinstance(Config.QUERY_PLUGIN_CONFIG, dict) else {}

        source_list = []
        seen = set()
        for plugin in plugins:
            source_name = str(getattr(plugin, "source_name", "") or "").strip()
            if not source_name or source_name in seen:
                continue
            seen.add(source_name)

            source_conf = query_key.get(source_name)
            if isinstance(source_conf, dict):
                if source_conf.get("enable", None) is False:
                    continue

                required_fields = {
                    key: value
                    for key, value in source_conf.items()
                    if key != "enable"
                }
                if required_fields and not all(required_fields.values()):
                    miss_keys = [k for k, v in required_fields.items() if not v]
                    logger.warning(
                        "skip dns query source {} because required config missing:{}".format(
                            source_name, ",".join(miss_keys)
                        )
                    )
                    continue

            source_list.append(source_name)

        return source_list

    def _compat_resolve_dns_query_sources(self):
        resolver = getattr(self.task, "_resolve_dns_query_sources", None)
        if callable(resolver):
            return resolver()
        return self._resolve_dns_query_sources()

    def _compat_calc_dns_query_plugin_stage_timeout(self, source_count):
        calculator = getattr(self.task, "_calc_dns_query_plugin_stage_timeout", None)
        if callable(calculator):
            return calculator(source_count)
        return self._calc_dns_query_plugin_stage_timeout(source_count)

    def _compat_chunk_list(self, items, chunk_size):
        chunker = getattr(self.task, "_chunk_list", None)
        if callable(chunker):
            return chunker(items, chunk_size)
        return self._chunk_list(items, chunk_size)

    def _compat_format_timeout(self, timeout_sec):
        formatter = getattr(self.task, "_format_timeout", None)
        if callable(formatter):
            return formatter(timeout_sec)
        return self._format_timeout(timeout_sec)

    def _run_query_plugin(self, target, source_batch):
        runner = getattr(self.task, "_run_query_plugin", None)
        if callable(runner):
            return runner(target, source_batch)
        return run_query_plugin(target, source_batch)

    def run_dns_query_plugin(self):
        """执行 DNS 查询插件阶段，保留旧入口的预算与异常边界。"""

        task = self.task
        source_list = self._compat_resolve_dns_query_sources()
        stage_timeout_sec = self._compat_calc_dns_query_plugin_stage_timeout(len(source_list))
        with stage_execution_context("dns_query_plugin", stage_timeout_sec):
            return self._run_dns_query_plugin_impl()

    def _run_dns_query_plugin_impl(self):
        task = self.task
        logger.info("start run dns_query_plugin {}".format(task.base_domain))
        task._last_dns_query_metrics = {}
        source_batch_size = int(
            getattr(Config, "DOMAIN_DNS_QUERY_PLUGIN_SOURCE_BATCH_SIZE", 4) or 4
        )
        if source_batch_size <= 0:
            source_batch_size = 1

        source_list = self._compat_resolve_dns_query_sources()
        if not source_list:
            logger.warning("dns_query_plugin {} no available source".format(task.base_domain))
            return
        stage_timeout_sec = self._compat_calc_dns_query_plugin_stage_timeout(len(source_list))
        validation_batch_size = int(
            getattr(Config, "DNS_QUERY_PLUGIN_DOMAIN_BATCH_SIZE", 100) or 100
        )
        if validation_batch_size <= 0:
            validation_batch_size = 100

        source_batches = list(self._compat_chunk_list(source_list, source_batch_size))
        aggregate_metrics = {
            "input_count": 0,
            "output_count": 0,
            "provider_count": 0,
            "provider_success_count": 0,
            "failed_count": 0,
            "degraded_count": 0,
            "dedup_count": 0,
            "request_count": 0,
            "timeout_count": 0,
            "retry_count": 0,
            "network_wait_sec": 0.0,
            "provider_status": [],
        }
        logger.info(
            "dns_query_plugin timeout_budget:{} sources:{} batches:{} batch_size:{}".format(
                self._compat_format_timeout(stage_timeout_sec),
                len(source_list),
                len(source_batches),
                source_batch_size,
            )
        )
        stage_start = time.time()
        seen_result = set()
        results = []
        for idx, source_batch in enumerate(source_batches, start=1):
            elapsed = time.time() - stage_start
            if stage_timeout_sec > 0 and elapsed >= stage_timeout_sec:
                logger.warning(
                    "dns_query_plugin stage timeout {} elapsed:{:.2f}s timeout:{}s finished_batch:{}/{}".format(
                        task.base_domain, elapsed, stage_timeout_sec, idx - 1, len(source_batches)
                    )
                )
                break

            logger.info(
                "dns_query_plugin source batch start {} {}/{} sources:{} elapsed:{:.2f}s".format(
                    task.base_domain, idx, len(source_batches), ",".join(source_batch), elapsed
                )
            )
            batch_results = self._run_query_plugin(task.base_domain, source_batch)
            batch_metrics = dict(getattr(batch_results, "metrics", {}) or {})
            for key in (
                "input_count",
                "output_count",
                "provider_count",
                "provider_success_count",
                "failed_count",
                "degraded_count",
                "dedup_count",
                "request_count",
                "timeout_count",
                "retry_count",
            ):
                aggregate_metrics[key] += int(batch_metrics.get(key, 0) or 0)
            aggregate_metrics["network_wait_sec"] += float(
                batch_metrics.get("network_wait_sec", 0.0) or 0.0
            )
            aggregate_metrics["provider_status"].extend(
                list(batch_metrics.get("provider_status") or [])
            )
            for result in batch_results:
                domain = str(result.get("domain", "")).strip()
                source = str(result.get("source", "")).strip()
                if not domain or not source:
                    continue
                uniq_key = "{}|{}".format(domain, source)
                if uniq_key in seen_result:
                    continue
                seen_result.add(uniq_key)
                results.append({"domain": domain, "source": source})
            logger.info(
                "dns_query_plugin source batch end {} {}/{} source_result:{} merged_result:{}".format(
                    task.base_domain, idx, len(source_batches), len(batch_results), len(results)
                )
            )

        domain_sources = {}
        primary_source_map = {}
        for result in results:
            domain = utils.normalize_domain(result.get("domain", ""))
            source = str(result.get("source", "")).strip()
            if not domain or not source:
                continue
            domain_sources.setdefault(domain, set()).add(source)
            primary_source_map.setdefault(domain, source)

        # 先按来源写入关系，再按域名只执行一次 DNS 校验。
        source_domains_map = {}
        for domain, source_set in domain_sources.items():
            for source in source_set:
                source_domains_map.setdefault(source, []).append(domain)
        for source, source_domains in source_domains_map.items():
            task.add_domain_source_names(source_domains, source)

        unique_domains = list(domain_sources)
        domain_dedup_count = max(len(results) - len(unique_domains), 0)
        logger.info(
            "dns_query_plugin domain validation start {} source_relations:{} unique_domains:{} dedup:{}".format(
                task.base_domain,
                len(results),
                len(unique_domains),
                domain_dedup_count,
            )
        )

        cnt = 0
        validation_batch_count = 0
        validation_batch_total = (
            (len(unique_domains) + validation_batch_size - 1) // validation_batch_size
            if unique_domains
            else 0
        )
        for batch_index, domain_batch in enumerate(
            self._compat_chunk_list(unique_domains, validation_batch_size), start=1
        ):
            batch_started = time.time()
            domain_info_list = task.build_domain_info(domain_batch)
            if task.task_tag == "task":
                domain_info_list = task.clear_domain_info_by_record(domain_info_list)

                # 按首次来源分组保存，保证每个域名只 upsert 一次，同时保留完整 sources。
                info_by_primary_source = {}
                for info in domain_info_list:
                    domain = utils.normalize_domain(getattr(info, "domain", ""))
                    source = primary_source_map.get(domain, "")
                    if source:
                        info_by_primary_source.setdefault(source, []).append(info)
                for source, source_infos in info_by_primary_source.items():
                    task.save_domain_info_list(source_infos, source=source)

                self.register_dns_domain_candidates(domain_info_list)

            cnt += len(domain_info_list)
            task.domain_info_list.extend(domain_info_list)
            validation_batch_count += 1
            logger.info(
                "dns_query_plugin domain validation batch {} {}/{} input:{} output:{} elapsed:{:.2f}s".format(
                    task.base_domain,
                    batch_index,
                    validation_batch_total,
                    len(domain_batch),
                    len(domain_info_list),
                    time.time() - batch_started,
                )
            )

        logger.info(
            "dns_query_plugin domain validation end {} input:{} output:{} pending:0".format(
                task.base_domain,
                len(unique_domains),
                cnt,
            )
        )

        logger.info(
            "end run dns_query_plugin {}, result {}, real result:{}".format(
                task.base_domain, len(results), cnt
            )
        )
        aggregate_metrics["output_count"] = len(results)
        aggregate_metrics["unique_domain_count"] = len(domain_sources)
        aggregate_metrics["domain_dedup_count"] = domain_dedup_count
        aggregate_metrics["dns_validation_input_count"] = len(domain_sources)
        aggregate_metrics["dns_validation_output_count"] = cnt
        aggregate_metrics["dns_validation_batch_count"] = validation_batch_count
        aggregate_metrics["dns_validation_pending_count"] = 0
        aggregate_metrics["network_wait_sec"] = round(
            aggregate_metrics["network_wait_sec"], 6
        )
        task._last_dns_query_metrics = aggregate_metrics

    def register_dns_domain_candidates(self, domain_info_list):
        """将完成 DNS 校验的域名登记为统一主机候选。"""

        task = self.task
        context = getattr(task, "discovery_context", None)
        if context is None:
            return

        source_map = getattr(task, "domain_source_map", {}) or {}
        for info in domain_info_list or []:
            domain = utils.normalize_domain(getattr(info, "domain", ""))
            if not domain:
                continue
            sources = sorted(
                str(source or "").strip()
                for source in source_map.get(domain, set())
                if str(source or "").strip()
            )
            if not sources:
                sources = ["dns_query_plugin"]
            for source in sources:
                try:
                    context.register_candidate(
                        event_type="NewHostDiscovered",
                        candidate=domain,
                        candidate_type="host",
                        source=source,
                        status="discovered",
                        metadata={"stage": "dns_query_plugin"},
                    )
                except Exception as exc:
                    logger.debug(
                        "dns domain candidate register failed domain:{} error_type:{}".format(
                            domain, type(exc).__name__
                        )
                    )

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
