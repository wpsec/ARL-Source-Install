"""
WebInfoHunter 阶段编排。

这里仅编排 WIH 的批次顺序和阶段之间的数据流。任务状态、结果落库、范围判断和
阶段计时由 CommonTask 提供，避免编排器直接依赖 Mongo、Celery 或外部工具。
"""

from app import services, utils
from app.config import Config
from app.services.infoHunter import InfoHunter
from app.services.discovery_context import register_intel_candidate, url_host


logger = utils.get_logger()

def _wih_primary_fully_succeeded(stage_metrics) -> bool:
    """仅整批正常完成（无超时/抢救/失败）才允许写 covered，降级批次必须重扫。"""
    if not isinstance(stage_metrics, dict):
        return False
    if str(stage_metrics.get("end_reason") or "completed") != "completed":
        return False
    for key in ("timeout_count", "salvage_count", "failed_count"):
        if int(stage_metrics.get(key, 0) or 0):
            return False
    return True




class WihOrchestrator(object):
    def __init__(self, task):
        self.task = task

    def run(self):
        task = self.task
        wih_targets = task._filter_waf_blocked_targets(task.sites, stage_name="wih")
        reuse_summary = {}
        reused_sites = set()
        if wih_targets:
            reuse_summary = services.run_wih_periodic_reuse(
                task_id=task.task_id,
                sites=wih_targets,
                options=task.options,
            ) or {}
            reused_sites = {
                str(item or "").strip()
                for item in list(reuse_summary.get("reused_sites", []) or [])
                if str(item or "").strip()
            }
            effective_reused_records = task._apply_reused_wih_records(
                reuse_summary.get("records", []) or []
            )
            for reused_url in list(reuse_summary.get("reused_urls", []) or []):
                reused_url_text = str(reused_url or "").strip()
                if reused_url_text:
                    task.page_url_set.add(reused_url_text)
            if reused_sites:
                logger.info(
                    "task_id:{} wih periodic reuse applied schedule_id:{} baseline_task:{} reused_sites:{} reused_records:{} reused_endpoints:{} reused_urls:{} effective_records:{}".format(
                        task.task_id,
                        str(reuse_summary.get("schedule_id", "") or ""),
                        str(reuse_summary.get("previous_task_id", "") or ""),
                        len(reused_sites),
                        int(reuse_summary.get("reused_record_count", 0) or 0),
                        int(reuse_summary.get("reused_endpoint_count", 0) or 0),
                        int(reuse_summary.get("reused_url_count", 0) or 0),
                        effective_reused_records,
                    )
                )

        scan_sites = [
            site
            for site in list(wih_targets or [])
            if str(site or "").strip() not in reused_sites
        ]
        discovery_context = getattr(task, "discovery_context", None)
        # 事件队列消费点：NewHostDiscovered 汇聚的新子域进入 WIH 主扫描队列。
        new_host_queue = getattr(task, "new_host_queue", None)
        if new_host_queue is not None and getattr(new_host_queue, "enabled", False):
            known_hosts = set()
            for site in list(scan_sites):
                host = url_host(site)
                if host:
                    known_hosts.add(host)
            queue_targets = []
            for candidate_site in new_host_queue.take_for_wih():
                candidate_host = url_host(candidate_site)
                if not candidate_host or candidate_host in known_hosts:
                    continue
                known_hosts.add(candidate_host)
                queue_targets.append(candidate_site)
            if queue_targets:
                logger.info(
                    "task_id:{} wih directory queue injected new hosts:{}".format(
                        task.task_id, len(queue_targets)
                    )
                )
                scan_sites = scan_sites + queue_targets
        ledger = getattr(discovery_context, "ledger", None) if discovery_context is not None else None
        wih_site_keys = {}
        if ledger is not None and scan_sites:
            kept_sites = []
            for site in scan_sites:
                site_key = discovery_context.idempotency_key(
                    "wih_primary_scan", site, scan_profile="wih_v1", input_signature=""
                )
                entry = ledger.get(site_key)
                if entry is not None and getattr(entry, "status", "") == "covered":
                    continue
                wih_site_keys[site] = site_key
                kept_sites.append(site)
            if len(kept_sites) != len(scan_sites):
                logger.info(
                    "task_id:{} wih primary ledger skip covered sites:{} kept:{}".format(
                        task.task_id, len(scan_sites) - len(kept_sites), len(kept_sites)
                    )
                )
            scan_sites = kept_sites
        wih_endpoints = []
        if scan_sites:
            def _run_primary_wih():
                result = services.run_wih(
                    scan_sites,
                    include_endpoints=True,
                    prefer_fast_mode=bool(task.options.get("from_task_schedule", False)),
                )
                raw_result = result[0] if isinstance(result, tuple) else result
                stage_metrics = getattr(raw_result, "metrics", None)
                if isinstance(stage_metrics, dict):
                    stage_metrics.update(
                        {
                            "reused_site_count": len(reused_sites),
                            "scan_site_count": len(scan_sites),
                            # Go 子进程自带网络栈，任务内响应缓存不可见；显式标记边界。
                            "external_network": "wih_go",
                        }
                    )
                return result

            wih_result = task._run_substage(
                "wih_primary_scan",
                _run_primary_wih,
                detail="targets={} reused={} scan={} fast_mode={}".format(
                    len(wih_targets),
                    len(reused_sites),
                    len(scan_sites),
                    bool(task.options.get("from_task_schedule", False)),
                ),
                input_count=len(scan_sites),
                budget_sec=getattr(Config, "WIH_TOTAL_BUDGET_SEC", None),
            )
            if isinstance(wih_result, tuple):
                raw_records, wih_endpoints = wih_result
            else:
                raw_records = wih_result
            records = set(raw_records or [])
            primary_raw = wih_result[0] if isinstance(wih_result, tuple) else wih_result
            primary_metrics = getattr(primary_raw, "metrics", None)
            if ledger is not None and wih_site_keys and _wih_primary_fully_succeeded(primary_metrics):
                for site, site_key in wih_site_keys.items():
                    ledger.finish(site_key, "covered", input_count=1, output_count=0)
        else:
            records = set()

        urlfinder_records = set()
        if scan_sites:
            urlfinder_records = set(
                task._run_substage(
                    "wih_urlfinder_extract",
                    lambda: services.run_urlfinder_extract(
                        scan_sites,
                        list(records),
                        waf_guard=task.waf_guard,
                        discovery_context=getattr(task, "discovery_context", None),
                    ),
                    detail="sites={}".format(len(scan_sites)),
                    input_count=len(scan_sites),
                )
                or []
            )
        if urlfinder_records:
            records |= urlfinder_records

        # endpoint 探测排在 URLFinder 之后：探测 GET 与抓取链路共用
        # html_get 缓存 profile，先跑 URLFinder 可让同页结果直接复用、
        # 避免对同一页面二次发起请求。
        if wih_endpoints:
            wih_endpoints = list(
                task._run_substage(
                    "wih_endpoint_probe",
                    lambda: services.run_wih_endpoint_probe(
                        wih_endpoints,
                        waf_guard=task.waf_guard,
                        discovery_context=getattr(task, "discovery_context", None),
                    ),
                    detail="endpoints={}".format(len(wih_endpoints)),
                    input_count=len(wih_endpoints),
                )
                or wih_endpoints
            )
            wih_endpoints = list(
                task._run_substage(
                    "wih_endpoint_ai_fill",
                    lambda: task._run_optional_ai_stage_best_effort(
                        "wih_endpoint_ai_fill",
                        lambda: services.run_wih_endpoint_ai_fill(
                            task.task_id,
                            wih_endpoints,
                            waf_guard=task.waf_guard,
                        ),
                        fallback_result=wih_endpoints,
                        feature_name="wih_endpoint_ai_fill",
                        fallback_note="保留原始 WIH 接口探测结果，不影响后续结果入库",
                    ),
                    detail="endpoints={}".format(len(wih_endpoints)),
                    input_count=len(wih_endpoints),
                )
                or wih_endpoints
            )
            task._save_wih_endpoints(wih_endpoints)

            discovery_context = getattr(task, "discovery_context", None)
            if discovery_context is not None:
                for endpoint_item in wih_endpoints:
                    if not isinstance(endpoint_item, dict):
                        continue
                    endpoint_url = str(endpoint_item.get("url") or "").strip()
                    if not endpoint_url:
                        continue
                    try:
                        discovery_context.register_candidate(
                            event_type="EndpointCandidateDiscovered",
                            candidate=endpoint_url,
                            candidate_type="endpoint",
                            source="wih",
                            parent_target=str(endpoint_item.get("page_url") or ""),
                            metadata={"method": str(endpoint_item.get("method") or "")},
                        )
                    except Exception as exc:
                        # 接口候选登记失败不能影响 WIH 结果入库链路。
                        logger.debug(
                            "wih endpoint candidate register failed error_type:{}".format(type(exc).__name__)
                        )

        if scan_sites:
            page_intel_records = set(
                task._run_substage(
                    "wih_page_intel",
                    lambda: services.run_page_intel_scan(
                        scan_sites,
                        list(records),
                        waf_guard=task.waf_guard,
                        discovery_context=getattr(task, "discovery_context", None),
                    ),
                    detail="records={}".format(len(records)),
                    input_count=len(records),
                )
                or []
            )
            if page_intel_records:
                records |= page_intel_records

        if scan_sites:
            api_doc_records = set(
                task._run_substage(
                    "wih_api_doc",
                    lambda: services.run_api_doc_scan(
                        scan_sites,
                        list(records),
                        waf_guard=task.waf_guard,
                        discovery_context=getattr(task, "discovery_context", None),
                    ),
                    detail="records={}".format(len(records)),
                    input_count=len(records),
                )
                or []
            )
            if api_doc_records:
                records |= api_doc_records

        if records:
            js_intel_records = set(
                task._run_substage(
                    "wih_js_intel",
                    lambda: services.run_js_intel_scan(
                        scan_sites,
                        list(records),
                        waf_guard=task.waf_guard,
                        discovery_context=getattr(task, "discovery_context", None),
                    ),
                    detail="records={}".format(len(records)),
                    input_count=len(records),
                )
                or []
            )
            if js_intel_records:
                records |= js_intel_records

        # endpoint 队列二次消费：API 文档/JS 情报等非主扫描链路登记的
        # endpoint 候选补一轮 GET-only 探测；缓存优先、探测上限沿用
        # WIH_ENDPOINT_PROBE_MAX_TARGETS，不重复首轮已探测过的 URL。
        discovery_context = getattr(task, "discovery_context", None)
        if discovery_context is not None:
            followup_items = []
            try:
                probed_urls = {
                    str(item.get("url") or "").strip()
                    for item in list(wih_endpoints or [])
                    if isinstance(item, dict)
                }
                for record in discovery_context.candidate_registry.values():
                    if str(getattr(record, "candidate_type", "") or "") != "endpoint":
                        continue
                    if str(getattr(record, "status", "") or "") != "discovered":
                        continue
                    candidate_url = str(getattr(record, "candidate", "") or "").strip()
                    if (not candidate_url
                            or candidate_url in probed_urls
                            or not candidate_url.lower().startswith(("http://", "https://"))):
                        continue
                    probed_urls.add(candidate_url)
                    followup_items.append({"url": candidate_url, "method": "GET"})
            except Exception as exc:
                # 候选图读取失败只放弃补探，不影响主链路。
                logger.debug(
                    "wih endpoint followup collect failed error_type:{}".format(
                        type(exc).__name__))
            if followup_items:
                logger.info(
                    "task_id:{} wih endpoint followup probe candidates:{}".format(
                        task.task_id, len(followup_items)))
                followup_results = task._run_substage(
                    "wih_endpoint_followup_probe",
                    lambda: services.run_wih_endpoint_probe(
                        followup_items,
                        waf_guard=task.waf_guard,
                        discovery_context=discovery_context,
                    ),
                    detail="endpoints={}".format(len(followup_items)),
                    input_count=len(followup_items),
                ) or []
                task._save_wih_endpoints(followup_results)
                for endpoint_item in followup_results:
                    if not isinstance(endpoint_item, dict):
                        continue
                    try:
                        discovery_context.mark_candidate_status(
                            str(endpoint_item.get("url") or ""),
                            "endpoint",
                            "fetched",
                        )
                    except Exception as exc:
                        logger.debug(
                            "wih endpoint followup mark status failed error_type:{}".format(
                                type(exc).__name__))

        if records:
            urlfinder_sensitive_records = set(
                task._run_substage(
                    "wih_urlfinder_sensitive",
                    lambda: services.run_urlfinder_sensitive_scan(
                        scan_sites,
                        list(records),
                        waf_guard=task.waf_guard,
                    ),
                    detail="records={}".format(len(records)),
                    input_count=len(records),
                    budget_sec=getattr(
                        Config,
                        "URLFINDER_SENSITIVE_STAGE_TIMEOUT_SEC",
                        None,
                    ),
                )
                or []
            )
            if urlfinder_sensitive_records:
                records |= urlfinder_sensitive_records

        if records:
            trufflehog_records = set(
                task._run_substage(
                    "wih_trufflehog_js",
                    lambda: services.run_trufflehog_js(
                        scan_sites,
                        list(records),
                        waf_guard=task.waf_guard,
                    ),
                    detail="records={}".format(len(records)),
                    input_count=len(records),
                )
                or []
            )
            if trufflehog_records:
                records |= trufflehog_records

        if records:
            task._run_substage(
                "wih_url_probe",
                lambda: services.run_urlfinder_url_probe(
                    task_id=task.task_id,
                    sites=scan_sites,
                    wih_records=list(records),
                    page_url_set=task.page_url_set,
                    waf_guard=task.waf_guard,
                    discovery_context=getattr(task, "discovery_context", None),
                ),
                detail="records={}".format(len(records)),
                input_count=len(records),
            )

        for raw_record in records:
            record = InfoHunter.normalize_wih_record(raw_record)
            if not record:
                continue
            if record.fnv_hash in task.wih_record_set:
                continue
            if not task._wih_record_in_task_scope(record):
                continue

            task.add_wih_domain_set(record)
            task._save_wih_record(record)

            # WIH 记录同步进共享候选图，供目录/探测等后续 stage 复用来源关系。
            register_intel_candidate(
                getattr(task, "discovery_context", None),
                getattr(record, "record_type", "") or "",
                getattr(record, "content", "") or "",
                getattr(record, "source", "") or "",
                getattr(record, "site", "") or "",
            )
