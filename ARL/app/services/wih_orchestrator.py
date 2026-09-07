"""
WebInfoHunter 阶段编排。

这里仅编排 WIH 的批次顺序和阶段之间的数据流。任务状态、结果落库、范围判断和
阶段计时由 CommonTask 提供，避免编排器直接依赖 Mongo、Celery 或外部工具。
"""

from app import services, utils
from app.config import Config
from app.services.infoHunter import InfoHunter
from app.services.discovery_context import register_intel_candidate, url_host
from app.services.api_unified_models import (
    UnifiedApiEndpoint,
    compute_input_signature,
)


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


def _legacy_endpoint_followup(task, wih_endpoints, discovery_context):
    """第 3 批前既有补探通道：候选图 endpoint/discovered → GET-only 探测。

    flag 关闭与统一通道异常时的显式 fallback（计划 6 §十三.5），行为逐字保持。
    """

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
    if not followup_items:
        return
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


def _endpoint_identity(endpoint, item, method):
    """T11-1：Endpoint 探测/回填/收口的稳定内部身份键。

    事实源 = UnifiedApiEndpoint.idempotency_key（P1-12 冻结：
    api_endpoint|url|method|api_type|input_signature）；非模型对象（桩/
    旧记录）退化为按构造参数拼同形键，保证两侧可比。
    """

    key = getattr(endpoint, "idempotency_key", None)
    if key:
        return str(key)
    if isinstance(endpoint, dict):
        url = str(endpoint.get("url") or "").strip()
        method_text = str(endpoint.get("method") or method or "GET").strip().upper() or "GET"
        api_type = str(endpoint.get("api_type") or "rest")
        signature = str(endpoint.get("input_signature") or "")
    else:
        url = str(getattr(endpoint, "url", "") or "").strip()
        method_text = str(getattr(endpoint, "method", "") or method or "GET").strip().upper() or "GET"
        api_type = str(getattr(endpoint, "api_type", "") or "rest")
        signature = str(getattr(endpoint, "input_signature", "") or "")
    if not url:
        return ""
    return "|".join(("api_endpoint", url, method_text, api_type, signature))


def _registry_endpoint_followup(task, registry, wih_endpoints, discovery_context):
    """计划 6 第 8 批：统一 Registry 作为 Endpoint 探测的唯一候选入口（§7.3）。

    首轮 Go 引擎探测结果双写为 covered 的 `api_type=rest` 资产（§7.3 映射，
    只并证据不重复探测）；claimed 资产中 GET/HEAD 走轻量探测，POST/SOAP/
    GraphQL 等无法从文档摘要重建请求体的资产显式标 skipped——不发无 body 的
    POST（§2.2 不构造业务请求体），首轮已观察到**同一 Endpoint identity**
    （idempotency_key：url+method+api_type+input_signature，P1-12 冻结键）的
    资产才回报 observed。探测回报经 probe_report 词表映射收口状态机。

    T11-1（第 11 批 Review P1）：合并/回填/收口一律用完整 identity，不再按
    (url, method)——同 url+method 的 rest/graphql 或不同请求形态（不同
    input_signature）是不同资产，按 pair 合并会把未探测资产错误收口 observed、
    把 WAF/失败/降级归因回填到错误资产。probe item 携带 `endpoint_key`，
    结果按该键回映射（wih_endpoint_probe 全链路 dict 拷贝透传）。
    """

    probed_identities = set()
    for item in list(wih_endpoints or []):
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "").strip()
        if not url:
            continue
        method = str(item.get("method") or "GET").strip().upper() or "GET"
        try:
            stored, _created = registry.register_endpoint(UnifiedApiEndpoint(
                url=url, method=method, api_type="rest",
                source="wih",
                parent_target=str(item.get("page_url") or item.get("target") or ""),
                status="covered",
                input_signature=compute_input_signature("wih", url, method),
            ))
            # identity 取注册后的权威对象键（合并命中既有资产时同为该 identity）。
            probed_identities.add(
                getattr(stored, "idempotency_key", "")
                or _endpoint_identity(stored, item, method))
        except Exception as exc:
            # 首轮观察证据登记失败只丢观测面，不影响补探。
            logger.debug(
                "wih endpoint asset register failed error_type:{}".format(
                    type(exc).__name__))

    # lease 过期回收先行（执行版 P1-2）：上一轮 worker 异常/缺报留下的 queued
    # 超时项回到 pending 视野，本轮才能重新领取。
    expire = getattr(registry, "expire_stale_claims", None)
    if callable(expire):
        try:
            expired = expire()
            if expired:
                discovery_context.record_metric("api_endpoint_lease_expired_total", expired)
                logger.info(
                    "task_id:{} endpoint lease expired requeued:{}".format(
                        task.task_id, expired))
        except Exception as exc:
            logger.debug(
                "endpoint lease expire failed error_type:{}".format(
                    type(exc).__name__))

    max_probe = max(0, int(getattr(Config, "API_ENDPOINT_PROBE_MAX_TARGETS", 500) or 500))
    claimed = registry.claim_endpoints_for_probe(limit=max_probe, with_tokens=True)
    items = []
    pairs = []  # (endpoint, claim_token)——token 用于回报/回收的代际校验
    seen_probe_identities = set()
    identity_of = {}
    skipped_count = 0
    for endpoint, claim_token in claimed:
        identity = _endpoint_identity(endpoint, None, "")
        if identity in probed_identities or identity in seen_probe_identities:
            # 仅"同一 Endpoint identity 已被观察"才走无代际 observed 收口
            # （T11-1：(url,method) 相同但 api_type/input_signature 不同不是
            # 同一资产，不得据此免探）。
            registry.probe_report(endpoint, "observed")
            continue
        if endpoint.method not in ("GET", "HEAD"):
            registry.probe_report(endpoint, "skipped", claim_token=claim_token)
            skipped_count += 1
            continue
        seen_probe_identities.add(identity)
        identity_of[identity] = endpoint
        items.append({"url": endpoint.url, "method": endpoint.method,
                      "endpoint_key": identity})
        pairs.append((endpoint, claim_token))

    try:
        discovery_context.record_metric("api_probe_total", len(items))
        if skipped_count:
            discovery_context.record_metric("api_probe_skipped_total", skipped_count)
        # §十二 api_probe_pending_total：低置信度显影 pending 的待处理队列
        # （不因排序丢弃，等预算/阈值变化再领——第 9 批观测面收口）。
        pending_assets = getattr(registry, "pending_endpoints", None)
        if callable(pending_assets):
            pending_count = len(pending_assets())
            if pending_count:
                discovery_context.record_metric("api_probe_pending_total", pending_count)
    except Exception as exc:
        logger.debug("api probe metric failed error_type:{}".format(type(exc).__name__))

    if not items:
        return
    logger.info(
        "task_id:{} wih registry endpoint followup probe candidates:{}".format(
            task.task_id, len(items)))

    def _probe():
        return services.run_wih_endpoint_probe(
            items, waf_guard=task.waf_guard, discovery_context=discovery_context)

    try:
        results = task._run_substage(
            "wih_endpoint_followup_probe", _probe,
            detail="endpoints={}".format(len(items)),
            input_count=len(items),
        ) or []
        task._save_wih_endpoints(results)
        by_key = {}
        error_count = 0
        for record_item in results:
            if not isinstance(record_item, dict):
                continue
            probe_key = str(record_item.get("endpoint_key") or "").strip()
            if not probe_key:
                # 探测结果必须回携带的内部键；缺失说明透传面被破坏——
                # 不回退 (url,method) 猜测归因（那正是 T11-1 关闭的错误面），
                # 让该资产留在 queued 由 lease/finally 回收，下轮重探。
                logger.warning(
                    "task_id:{} endpoint probe result missing endpoint_key; "
                    "result not applied (identity attribution unsafe)".format(
                        task.task_id))
                continue
            by_key.setdefault(probe_key, record_item)
        for endpoint, claim_token in pairs:
            record_item = by_key.get(_endpoint_identity(endpoint, None, ""))
            if record_item is None:
                continue
            status = str(record_item.get("verification_status") or "")
            degraded_reason = ""
            if str(record_item.get("degraded_reason") or "") == "host_waf_blocked":
                # 第 9 批 §8.2：主机级封禁资产收口 degraded（区别于普通 skip）。
                # P2-01：原因随回报进资产面（受控枚举），快照可稳定归因。
                status = "degraded"
                degraded_reason = "host_waf_blocked"
            if status == "error":
                error_count += 1
            try:
                registry.probe_report(
                    endpoint, status, claim_token=claim_token,
                    degraded_reason=degraded_reason)
            except Exception as exc:
                logger.debug(
                    "wih registry endpoint report failed error_type:{}".format(
                        type(exc).__name__))
        try:
            if error_count:
                discovery_context.record_metric("api_probe_failed_total", error_count)
        except Exception as exc:
            logger.debug("api probe metric failed error_type:{}".format(type(exc).__name__))
    finally:
        # 领取未回报回收（Review P1-04 + R6-P1-01 fencing）：阶段异常或结果缺项时，
        # 本 owner 仍在 queued 的资产带各自 claim_token 回 pending。已回报项 token
        # 已清除、被新 claim 取代的项 token 已换代，二者经 token 校验变 no-op——
        # 过期 worker 的 finally 不再能把新 owner 的 queued 资产改回 pending。
        try:
            requeued = registry.requeue_unreported(pairs)
            if requeued:
                discovery_context.record_metric("api_endpoint_requeued_total", requeued)
                logger.info(
                    "task_id:{} wih registry endpoint followup requeued unreported:{}".format(
                        task.task_id, requeued))
        except Exception as exc:
            logger.debug(
                "wih registry endpoint requeue failed error_type:{}".format(
                    type(exc).__name__))




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
                if discovery_context is not None:
                    # 上下文级外部边界计数：收尾指标/全链路一次请求门禁的排除口径。
                    try:
                        discovery_context.record_metric(
                            "external_network_wih_go", len(scan_sites)
                        )
                    except Exception:
                        pass
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
                if not records and not wih_endpoints:
                    # Go 引擎"成功返回"但零产出（真实环境见过撞 403 墙）：
                    # covered 会把空手而归变成重投永久跳过，宁可不记账。
                    logger.info(
                        "task_id:{} wih primary zero result, skip ledger covered sites:{}".format(
                            task.task_id, len(wih_site_keys)))
                else:
                    for site, site_key in wih_site_keys.items():
                        if (discovery_context is not None
                                and not discovery_context.waf_policy.allow(site, "wih")):
                            # 该站 wih 类处于熔断态时引擎结果不可信，留给重投重试。
                            logger.info(
                                "task_id:{} wih site blocked class, skip covered site:{}".format(
                                    task.task_id, str(site)[:120]))
                            continue
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

        # 计划 6 第 3 批开关：启用时文档获取让位给统一队列（js_intel 之后运行，
        # 使 JS 发现的文档在当前任务内回流）；关闭时保持 legacy 阶段位不变。
        api_unified_enabled = bool(services.api_unified_enabled())
        if scan_sites and not api_unified_enabled:
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

        if scan_sites and api_unified_enabled:
            api_doc_records = set(
                task._run_substage(
                    "wih_api_doc_unified",
                    lambda: services.run_api_document_pipeline(
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

        # 计划 6 第 8 批（P0-05）：浏览器运行时采集接入统一 Registry 消费面。
        # flag 关闭不新增子阶段（legacy 行为面不变）；管线回退导致 Registry 未
        # 挂载时整段跳过；采集/摄取任何异常只隔离本阶段，不影响 WIH 主链路。
        if scan_sites and api_unified_enabled and bool(
                getattr(Config, "BROWSER_INTEL_ENABLE", False)):
            browser_registry = getattr(
                getattr(task, "discovery_context", None),
                "api_candidate_registry", None)
            if browser_registry is not None:
                try:
                    browser_results = task._run_substage(
                        "wih_browser_intel",
                        lambda: services.run_browser_intel_scan(scan_sites),
                        detail="sites={}".format(len(scan_sites)),
                        input_count=len(scan_sites),
                    ) or {}
                    ingested = services.ingest_browser_runtime_events(
                        browser_registry, browser_results)
                    # 外部边界记账（T5/A8 同口径）：Playwright 自带网络栈，
                    # 浏览器真实请求不经过 RequestScheduler，单列不计入
                    # 统一请求总量；类别 browser 仅约束共用调度面的请求。
                    try:
                        discovery_ctx = getattr(task, "discovery_context", None)
                        if discovery_ctx is not None:
                            discovery_ctx.record_metric(
                                "external_network_browser_intel", len(scan_sites))
                    except Exception as exc:
                        logger.debug(
                            "browser external metric failed error_type:{}".format(
                                type(exc).__name__))
                    if ingested:
                        logger.info(
                            "task_id:{} browser runtime endpoints ingested:{}".format(
                                task.task_id, ingested))
                except Exception as exc:
                    logger.warning(
                        "wih browser intel stage failed task_id:{} error_type:{}".format(
                            task.task_id, type(exc).__name__))

        # endpoint 队列二次消费：API 文档/JS 情报等非主扫描链路登记的
        # endpoint 候选补一轮 GET-only 探测；缓存优先、探测上限沿用
        # WIH_ENDPOINT_PROBE_MAX_TARGETS，不重复首轮已探测过的 URL。
        # 计划 6 第 8 批：统一管线已挂载 Registry 时，补探改由 Registry 通道
        # 接管（§7.3 "WIH endpoint probe 只消费 Registry 待探测 Endpoint"）；
        # 未挂载（flag 关/管线回退）保留下方候选图扫描作为显式 fallback。
        discovery_context = getattr(task, "discovery_context", None)
        if discovery_context is not None:
            api_registry = getattr(discovery_context, "api_candidate_registry", None)
            if api_registry is not None:
                try:
                    _registry_endpoint_followup(
                        task, api_registry, wih_endpoints, discovery_context)
                except Exception as exc:
                    # 统一通道消费失败只回退候选图扫描，不影响主链路。
                    logger.debug(
                        "wih registry endpoint followup failed error_type:{}".format(
                            type(exc).__name__))
            else:
                _legacy_endpoint_followup(task, wih_endpoints, discovery_context)

        if records:
            urlfinder_sensitive_records = set(
                task._run_substage(
                    "wih_urlfinder_sensitive",
                    lambda: services.run_urlfinder_sensitive_scan(
                        scan_sites,
                        list(records),
                        waf_guard=task.waf_guard,
                        discovery_context=getattr(task, "discovery_context", None),
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
            if discovery_context is not None:
                # 外部边界显式记账：TruffleHog 外部进程按 JS URL 二次抓取，
                # 不在统一响应缓存共享面内。
                try:
                    discovery_context.record_metric(
                        "external_network_trufflehog", len(scan_sites)
                    )
                except Exception:
                    pass
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
            # WihRecord 的属性名是 recordType（构造参数才叫 record_type），
            # 读错属性不抛异常只会静默丢候选，两种形态都要兼容。
            register_intel_candidate(
                getattr(task, "discovery_context", None),
                getattr(record, "recordType", "") or getattr(record, "record_type", "") or "",
                getattr(record, "content", "") or "",
                getattr(record, "source", "") or "",
                getattr(record, "site", "") or "",
            )
