"""API 候选注册表与文档队列（计划 6 第 3 批）。

统一任务内 API 文档候选的注册、状态机、来源聚合与有界消费：
- 文档候选以规范化 URL 为消费单元，`sources` 聚合多来源证据（G8 替代面）；
  幂等键形态冻结于 `api_unified_models.ApiDocumentCandidate`；
- `ApiDocumentQueue` 在当前任务内持续消费：种子采集、page_intel/js_intel
  已产出的 `api_doc_url` 记录回流、解析新发现的文档引用再入队，
  受深度/数量/大小/阶段时限四道预算闸约束（计划 6 §7.2/§8.3）；
- 获取走统一 `api_doc` 请求 profile，并镜像登记 `html_get` 桶保持
  既有消费者（Endpoint 探测等）的复用面不变（§十三.2 双写兼容）；
- 输出仍为旧 `WihRecord` 面（内容由 `ApiDocScanner` 同一解析实现产生，
  与 golden 基线逐字节一致）；统一 Parser 第 4 批接入、Endpoint 消费方
  第 8 批接入，本批 `ApiEndpointAssetRegistry` 只做资产登记与观测。

回滚面：`API_UNIFIED_ENABLE` 默认 False，False 时 `run_api_document_pipeline`
直接委托 legacy `run_api_doc_scan`，行为与第 2 批完全一致。
`API_UNIFIED_FALLBACK_ENABLE`（默认 True）下统一层整体异常时回退 legacy
并计数，单文档失败只影响当前文档（§7.2），不触发回退。
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections import OrderedDict
from typing import Any, Callable, Dict, List, Optional, Tuple

from app import utils
from app.config import Config

from .api_doc_scan import ApiDocScanner
from .api_unified_models import (
    API_DOCUMENT_TYPE_HINTS,
    UNIFIED_API_CONFIG_DEFAULTS,
    ApiDocumentCandidate,
    UnifiedApiEndpoint,
    compute_input_signature,
)
from .discovery_context import LedgerEntry, normalize_url
from .api_unified_shadow import (
    shadow_document_fetch_result,
    shadow_document_fetch_start,
)

logger = utils.get_logger()

# 文档状态机合法迁移边（§4.1 枚举冻结；越边调用返回 None 不静默改态）。
_DOC_TRANSITIONS: Dict[str, set] = {
    "discovered": {"queued", "skipped"},
    "queued": {"fetching", "skipped"},
    "fetching": {"fetched", "failed", "skipped"},
    "fetched": {"parsed", "failed"},
    "parsed": set(),
    "failed": set(),
    "skipped": set(),
}

# type_hint 判定关键词（顺序即优先级；与 ApiDocScanner._DOC_KEYWORDS 的语义交集冻结）。
_TYPE_HINT_KEYWORDS: Tuple[Tuple[str, str], ...] = (
    ("postman", "postman"),
    ("openapi", "openapi"),
    ("swagger", "swagger"),
    ("api-docs", "swagger"),
)

_DOC_PRIORITY_SEED = 10
_DOC_PRIORITY_EVIDENCE = 20  # 来自记录/候选图的真实发现证据优先于路径猜测


def unified_api_config(name: str) -> Any:
    """§8.3 键的唯一读取口径：Config 未定义时回退代码常量默认（附录A §三）。"""

    default = UNIFIED_API_CONFIG_DEFAULTS[name]
    value = getattr(Config, name, default)
    if isinstance(default, bool):
        return bool(value)
    if isinstance(default, int):
        try:
            value = int(value)
        except (TypeError, ValueError):
            return default
        # 预算键全部为正数语义；0/负值视为误配置回退默认。
        return value if value > 0 else default
    return value


def api_unified_enabled() -> bool:
    return bool(unified_api_config("API_UNIFIED_ENABLE"))


def resolve_unified_api_config() -> Dict[str, Any]:
    return {name: unified_api_config(name) for name in UNIFIED_API_CONFIG_DEFAULTS}


def document_type_hint(url: Any) -> str:
    lowered = str(url or "").strip().lower()
    for keyword, hint in _TYPE_HINT_KEYWORDS:
        if keyword in lowered:
            return hint
    return "unknown"


class ApiCandidateRegistry:
    """任务内 API 文档候选 + Endpoint 资产注册表。

    文档以规范化 URL 唯一（同一 URL 不同来源合并 sources，不重复获取）；
    Endpoint 以 `scoped_idempotency_key` 唯一（同 URL 不同 method 为不同资产）。
    注册表是消费调度与证据聚合结构，不是结果事实源：落库仍是旧记录面。
    """

    def __init__(self, task_id: str, context: Any = None):
        self.task_id = str(task_id or "").strip()
        self._context = context
        self._lock = threading.RLock()
        self._documents: "OrderedDict[str, ApiDocumentCandidate]" = OrderedDict()
        self._endpoints: "OrderedDict[str, UnifiedApiEndpoint]" = OrderedDict()
        self.created_document_count = 0
        self.merged_source_count = 0
        self.endpoint_created_count = 0
        self.endpoint_deduplicated_count = 0

    # -- 文档候选 ---------------------------------------------------------

    def register_document(
        self,
        url: str,
        source: str = "",
        type_hint: str = "unknown",
        parent_url: str = "",
        parent_target: str = "",
        depth: int = 0,
        priority: int = _DOC_PRIORITY_SEED,
        status: str = "discovered",
    ) -> Tuple[ApiDocumentCandidate, bool]:
        candidate = ApiDocumentCandidate(
            task_id=self.task_id,
            url=url,
            type_hint=type_hint if type_hint in API_DOCUMENT_TYPE_HINTS else document_type_hint(url),
            source=source,
            parent_target=parent_target,
            parent_url=parent_url,
            depth=depth,
            priority=priority,
            status=status,
            created_at=time.time(),
        )
        with self._lock:
            existing = self._documents.get(candidate.url)
            if existing is None:
                self._documents[candidate.url] = candidate
                self.created_document_count += 1
                created = True
            else:
                created = False
                if existing.add_source(source or "unknown"):
                    self.merged_source_count += 1
                existing.depth = min(existing.depth, depth)
                existing.priority = max(existing.priority, priority)
                if parent_url and not existing.parent_url:
                    existing.parent_url = parent_url
                candidate = existing
        if created and self._context is not None:
            try:
                self._context.register_candidate(
                    event_type="ApiDocumentCandidateDiscovered",
                    candidate=candidate.url,
                    candidate_type="api_doc",
                    source=str(source or "registry"),
                    request_profile=candidate.request_profile,
                    parent_target=str(parent_target or ""),
                    depth=depth,
                    priority=priority,
                    metadata={"type_hint": candidate.type_hint},
                )
            except Exception as exc:
                # 镜像登记失败只影响观测完整性，不打断候选注册主链路。
                logger.debug(
                    "api doc candidate graph mirror failed error_type:%s",
                    type(exc).__name__,
                )
        return candidate, created

    def document(self, url: str) -> Optional[ApiDocumentCandidate]:
        with self._lock:
            return self._documents.get(normalize_url(url))

    def has_document(self, url: str) -> bool:
        return self.document(url) is not None

    def document_count(self) -> int:
        with self._lock:
            return len(self._documents)

    def mark_document(
        self,
        url: str,
        status: str,
        error_type: str = "",
        input_signature: str = "",
    ) -> Optional[ApiDocumentCandidate]:
        """按迁移表改态；非法边返回 None（调用方计数，不改态不抛错）。"""

        with self._lock:
            candidate = self.document(url)
            if candidate is None:
                return None
            if status not in _DOC_TRANSITIONS.get(candidate.status, set()):
                return None
            candidate.status = status
            if error_type:
                candidate.error_type = str(error_type)[:64]
            if input_signature and not candidate.input_signature:
                # 幂等键随正文摘要补全而稳定（§4.2：input_signature 参与拼接）。
                candidate.input_signature = input_signature
            return candidate

    def pending_documents(self, limit: int = 0) -> List[ApiDocumentCandidate]:
        with self._lock:
            items = [
                item for item in self._documents.values() if item.status == "discovered"
            ]
        items.sort(key=lambda item: (-int(item.priority or 0), float(item.created_at or 0.0)))
        if limit and limit > 0:
            return items[:limit]
        return items

    def open_documents(self) -> List[ApiDocumentCandidate]:
        with self._lock:
            return [
                item
                for item in self._documents.values()
                if item.status in ("discovered", "queued", "fetching")
            ]

    def snapshot_documents(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [item.to_dict() for item in self._documents.values()]

    # -- Endpoint 资产（第 8 批消费方的登记面） ----------------------------

    def register_endpoint(self, endpoint: UnifiedApiEndpoint) -> Tuple[UnifiedApiEndpoint, bool]:
        key = endpoint.scoped_idempotency_key(self.task_id)
        with self._lock:
            existing = self._endpoints.get(key)
            if existing is None:
                self._endpoints[key] = endpoint
                self.endpoint_created_count += 1
                return endpoint, True
            existing.add_source(endpoint.parent_document or endpoint.source)
            existing.add_source(endpoint.source)
            self.endpoint_deduplicated_count += 1
            return existing, False

    def snapshot_endpoints(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [item.to_dict() for item in self._endpoints.values()]

    def __len__(self) -> int:
        with self._lock:
            return len(self._documents) + len(self._endpoints)


class ApiDocumentQueue:
    """当前任务内的文档候选有界消费循环。

    注入点便于回归：`fetch_fn(doc) -> text`（默认走 fetch_text + shadow 钩子）、
    `clock()`（阶段时限判定）。单文档任何异常收敛为 failed，不外溢。
    """

    def __init__(
        self,
        scanner: ApiDocScanner,
        registry: ApiCandidateRegistry,
        context: Any = None,
        config: Optional[Dict[str, Any]] = None,
        fetch_fn: Optional[Callable[[ApiDocumentCandidate], str]] = None,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.scanner = scanner
        self.registry = registry
        self.context = context
        self.config = dict(config or resolve_unified_api_config())
        self._fetch_fn = fetch_fn
        self._clock = clock
        self.fetch_count = 0
        self.parse_success_count = 0
        self.parse_failed_count = 0
        self.skipped_budget_count = 0
        self.resumed_skip_count = 0
        self.stage_timeout_stopped = False
        self._harvested_index = 0

    # -- 预算与获取 --------------------------------------------------------

    def _stage_deadline(self) -> float:
        budget = max(1, int(self.config.get("API_DOCUMENT_STAGE_TIMEOUT_SEC", 120) or 120))
        try:
            from app.utils.provider_http import current_stage_remaining_sec

            remaining = current_stage_remaining_sec()
        except Exception:
            remaining = None
        if remaining is not None:
            try:
                budget = max(1, min(budget, int(remaining)))
            except (TypeError, ValueError):
                pass
        return self._clock() + budget

    def _default_fetch(self, doc: ApiDocumentCandidate) -> str:
        from .web_info_intel_utils import fetch_text

        shadow_document_fetch_start(self.context, doc.url)
        max_bytes = max(1024, int(self.config.get("API_DOCUMENT_MAX_SIZE_BYTES", 5242880) or 5242880))
        text, _resp = fetch_text(
            doc.url,
            waf_guard=self.scanner.waf_guard,
            timeout=self.scanner.timeout,
            max_bytes=max_bytes,
            waf_module="api_doc_scan",
            discovery_context=self.context,
            request_profile="api_doc",
            mirror_html_get=True,
        )
        shadow_document_fetch_result(self.context, doc.url, bool(text))
        return text or ""

    # -- 账本幂等契约（Review 20260905 §4 一般项，2026-09-05 显式化）-----------
    # 文档获取在本任务族内固定单一 profile=`api_doc`、GET、无认证上下文差异，
    # 因此"任务窗口内 URL 唯一"是设计决策而非缺陷：同一 task_id 的重投轮次
    # 不因正文变化强制重验（窗口为分钟级，正文漂移由新 task_id 的下一周期
    # 覆盖）。键的 input_signature 段恒为空即该契约的形态表达；若未来引入
    # 多认证 profile 的文档获取，必须改为"先定 profile 再领取"并以
    # (profile, body-hash) 组合键重定义本方法对，同步修订 06-附录A §4.7。
    def _ledger_entry(self, doc: ApiDocumentCandidate) -> Optional[Any]:
        ledger = getattr(self.context, "ledger", None) if self.context is not None else None
        if ledger is None:
            return None
        try:
            key = self.context.idempotency_key("api_doc", doc.url, doc.request_profile, "")
            return ledger.get(key)
        except Exception as exc:
            logger.debug("api doc ledger read failed error_type:%s", type(exc).__name__)
            return None

    def _ledger_finish(self, doc: ApiDocumentCandidate, status: str) -> None:
        ledger = getattr(self.context, "ledger", None) if self.context is not None else None
        if ledger is None:
            return
        try:
            key = self.context.idempotency_key("api_doc", doc.url, doc.request_profile, "")
            ledger.upsert(LedgerEntry(idempotency_key=key, status=status, input_count=1, output_count=1))
        except Exception as exc:
            # 账本失败不阻断扫描（fail-open，与 fileLeak/WIH 先例同口径）。
            logger.debug("api doc ledger finish failed error_type:%s", type(exc).__name__)

    # -- 回流与消费 --------------------------------------------------------

    def _collect_backflow(self, wih_records: List[Any]) -> int:
        """把记录面与候选图里已发现的 api_doc_url 回流进注册表（JS 回流核心通道）。"""

        registered = 0
        max_targets = max(1, int(self.config.get("API_DOCUMENT_MAX_TARGETS", 200) or 200))
        for record in wih_records or []:
            try:
                if str(getattr(record, "recordType", "") or getattr(record, "record_type", "") or "").strip() != "api_doc_url":
                    continue
                content = str(getattr(record, "content", "") or "").strip()
                if not content:
                    continue
                _doc, created = self._register_within_budget(
                    content,
                    source=str(getattr(record, "source", "") or "intel"),
                    parent_target=str(getattr(record, "site", "") or ""),
                    priority=_DOC_PRIORITY_EVIDENCE,
                    max_targets=max_targets,
                )
                if created:
                    registered += 1
            except Exception as exc:
                logger.debug(
                    "api doc backflow record skipped error_type:%s", type(exc).__name__)
        if self.context is not None:
            try:
                for graph_item in self.context.candidate_registry.values():
                    if str(getattr(graph_item, "candidate_type", "") or "") != "endpoint":
                        continue
                    if str((getattr(graph_item, "metadata", None) or {}).get("intel_record_type") or "") != "api_doc_url":
                        continue
                    if str(getattr(graph_item, "status", "") or "") not in ("discovered", "queued"):
                        continue
                    candidate = str(getattr(graph_item, "candidate", "") or "").strip()
                    if not candidate:
                        continue
                    _doc, created = self._register_within_budget(
                        candidate,
                        source=sorted(getattr(graph_item, "sources", set()) or {"graph"})[0],
                        parent_target=str(getattr(graph_item, "parent_target", "") or ""),
                        priority=_DOC_PRIORITY_EVIDENCE,
                        max_targets=max_targets,
                    )
                    if created:
                        registered += 1
            except Exception as exc:
                logger.debug(
                    "api doc backflow graph scan failed error_type:%s", type(exc).__name__)
        return registered

    def _register_within_budget(
        self,
        url: str,
        source: str,
        parent_url: str = "",
        parent_target: str = "",
        depth: int = 0,
        priority: int = _DOC_PRIORITY_SEED,
        max_targets: int = 200,
    ) -> Tuple[ApiDocumentCandidate, bool]:
        over_budget = (
            self.registry.document_count() >= max_targets
            and not self.registry.has_document(url)
        )
        if over_budget:
            self.skipped_budget_count += 1
            placeholder = ApiDocumentCandidate(
                task_id=self.registry.task_id, url=url, type_hint=document_type_hint(url),
                source=source, depth=depth, priority=priority, status="skipped",
            )
            return placeholder, False
        return self.registry.register_document(
            url,
            source=source,
            type_hint=document_type_hint(url),
            parent_url=parent_url,
            parent_target=parent_target,
            depth=depth,
            priority=priority,
        )

    def _register_parsed_endpoints(self, new_records: List[Any]) -> None:
        """把旧记录面的 api_doc_endpoint 同步登记为统一 Endpoint 资产（§7.3 映射）。"""

        for record in new_records:
            try:
                record_type = str(getattr(record, "recordType", "") or getattr(record, "record_type", "") or "").strip()
                if record_type != "api_doc_endpoint":
                    continue
                content = str(getattr(record, "content", "") or "").strip()
                method, _, url_text = content.partition(" ")
                if not url_text:
                    continue
                endpoint = UnifiedApiEndpoint(
                    url=url_text,
                    method=method,
                    api_type="rest",
                    source=str(getattr(record, "source", "") or ""),
                    parent_document=str(getattr(record, "source", "") or ""),
                    parent_target=str(getattr(record, "site", "") or ""),
                )
                self.registry.register_endpoint(endpoint)
            except Exception as exc:
                logger.debug(
                    "api endpoint register failed error_type:%s", type(exc).__name__)

    def _harvest_records(self) -> List[Any]:
        records = self.scanner.records
        delta = records[self._harvested_index:]
        self._harvested_index = len(records)
        return list(delta)

    def run(self, wih_records: Optional[List[Any]] = None) -> List[Any]:
        """有界消费循环：任何单文档失败只标记该文档，循环继续（§7.2）。"""

        max_targets = max(1, int(self.config.get("API_DOCUMENT_MAX_TARGETS", 200) or 200))
        max_depth = max(1, int(self.config.get("API_DOCUMENT_MAX_DEPTH", 3) or 3))

        if not self.scanner.allowed_hosts:
            logger.info("api doc unified skip, no allowed hosts")
            return []

        for seed_url in self.scanner.collect_seed_candidates():
            self._register_within_budget(
                seed_url, source="seed", priority=_DOC_PRIORITY_SEED, max_targets=max_targets)
        self._collect_backflow(list(wih_records or []))

        if self.context is not None:
            try:
                self.context.record_metric(
                    "api_document_candidates_total", self.registry.created_document_count)
                self.context.record_metric(
                    "api_document_sources_merged_total", self.registry.merged_source_count)
            except Exception:
                pass

        deadline = self._stage_deadline()
        fetch_fn = self._fetch_fn or self._default_fetch

        while self.fetch_count < max_targets:
            pending = self.registry.pending_documents(limit=1)
            if not pending:
                break
            if self._clock() >= deadline:
                self.stage_timeout_stopped = True
                break
            doc = pending[0]

            if self.registry.mark_document(doc.url, "queued") is None:
                # 迁移边被并发破坏时收敛退出而不是原地打转（pending_documents
                # 只回 discovered，理论不可达；到达即说明状态面已不一致）。
                logger.warning("api doc queue inconsistent state url:%s", str(doc.url)[:160])
                break
            entry = self._ledger_entry(doc)
            if entry is not None and getattr(entry, "status", "") == "covered":
                # worker 重投：上一轮已完整解析过的文档直接跳过（WIH 主扫描先例同窗口口径）。
                self.registry.mark_document(doc.url, "skipped")
                self.resumed_skip_count += 1
                continue
            if self.registry.mark_document(doc.url, "fetching") is None:
                continue

            self.fetch_count += 1
            try:
                text = fetch_fn(doc) or ""
            except Exception as exc:
                self.registry.mark_document(doc.url, "failed", error_type=type(exc).__name__)
                self.parse_failed_count += 1
                self._ledger_finish(doc, "failed")
                self._record_metric("api_document_parse_failed_total")
                logger.debug(
                    "api doc unified fetch failed url:%s error_type:%s",
                    str(doc.url)[:160], type(exc).__name__)
                continue

            if not text:
                self.registry.mark_document(doc.url, "failed", error_type="empty_response")
                self._ledger_finish(doc, "failed")
                continue

            signature = compute_input_signature(
                hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest())
            new_refs: List[str] = []
            try:
                self.scanner.parse_document(doc.url, text, new_refs)
            except Exception as exc:
                self.registry.mark_document(
                    doc.url, "fetched", input_signature=signature)
                self.registry.mark_document(
                    doc.url, "failed", error_type=type(exc).__name__)
                self.parse_failed_count += 1
                self._ledger_finish(doc, "failed")
                self._record_metric("api_document_parse_failed_total")
                logger.debug(
                    "api doc unified parse failed url:%s error_type:%s",
                    str(doc.url)[:160], type(exc).__name__)
                continue

            self.registry.mark_document(doc.url, "fetched", input_signature=signature)
            self.registry.mark_document(doc.url, "parsed")
            self.parse_success_count += 1
            self._record_metric("api_document_parse_success_total")
            self._ledger_finish(doc, "covered")

            delta = self._harvest_records()
            self._register_parsed_endpoints(delta)

            for ref in new_refs:
                if doc.depth + 1 > max_depth:
                    self.skipped_budget_count += 1
                    self._record_metric("api_document_skipped_budget_total")
                    continue
                self._register_within_budget(
                    ref,
                    source="parser",
                    parent_url=doc.url,
                    parent_target=doc.parent_target,
                    depth=doc.depth + 1,
                    priority=_DOC_PRIORITY_SEED,
                    max_targets=max_targets,
                )

        open_docs = self.registry.open_documents()
        if open_docs:
            # 预算耗尽的残余候选保持 discovered/queued：finalizer 的
            # pending_backlog|api|* 下一轮周期显影通道不受本批影响。
            self._record_metric("api_document_pending_residual_total", len(open_docs))
            logger.info(
                "api doc queue budget exhausted task_id:%s residual:%s timeout:%s",
                self.registry.task_id, len(open_docs), self.stage_timeout_stopped)
        if self.context is not None:
            try:
                self.context.record_metric("api_endpoint_discovered_total", self.registry.endpoint_created_count)
                self.context.record_metric("api_endpoint_deduplicated_total", self.registry.endpoint_deduplicated_count)
                self.context.record_metric("api_document_budget_skipped_total", self.skipped_budget_count)
                self.context.record_metric("api_document_resumed_skip_total", self.resumed_skip_count)
            except Exception:
                pass
        return list(self.scanner.records)

    def _record_metric(self, name: str, amount: int = 1) -> None:
        if self.context is None:
            return
        try:
            self.context.record_metric(name, amount)
        except Exception:
            pass


def run_api_document_pipeline(
    sites: List[str],
    wih_records: List[Any],
    waf_guard: Any = None,
    discovery_context: Any = None,
    config: Optional[Dict[str, Any]] = None,
) -> List[Any]:
    """计划 6 第 3 批统一入口；flag 关闭时与 legacy 完全一致。"""

    from .api_doc_scan import run_api_doc_scan

    resolved = dict(config or resolve_unified_api_config())
    if not resolved.get("API_UNIFIED_ENABLE") or not bool(getattr(Config, "API_DOC_ENABLE", True)):
        return run_api_doc_scan(
            sites, wih_records, waf_guard=waf_guard, discovery_context=discovery_context)

    task_id = str(getattr(discovery_context, "task_id", "") or "api-doc-taskless")
    try:
        scanner = ApiDocScanner(
            sites=sites,
            wih_records=wih_records,
            waf_guard=waf_guard,
            discovery_context=discovery_context,
        )
        # 种子上限交给统一预算，legacy max_docs 只保留下限语义。
        scanner.max_docs = max(
            scanner.max_docs, int(resolved.get("API_DOCUMENT_MAX_TARGETS", 200) or 200))
        registry = ApiCandidateRegistry(task_id=task_id, context=discovery_context)
        queue = ApiDocumentQueue(
            scanner=scanner, registry=registry, context=discovery_context, config=resolved)
        records = queue.run(wih_records=wih_records)
        if discovery_context is not None:
            # 第 8 批消费方通过 context 挂载点取统一 Registry；无槽位类， setattr 安全。
            try:
                setattr(discovery_context, "api_candidate_registry", registry)
            except Exception as exc:
                logger.debug(
                    "api registry attach failed error_type:%s", type(exc).__name__)
        logger.info(
            "api doc unified done task_id:%s docs:%s fetch:%s parsed:%s failed:%s endpoints:%s",
            task_id, registry.created_document_count, queue.fetch_count,
            queue.parse_success_count, queue.parse_failed_count,
            registry.endpoint_created_count)
        return records
    except Exception as exc:
        if not resolved.get("API_UNIFIED_FALLBACK_ENABLE", True):
            raise
        logger.exception("api doc unified failed, fallback to legacy: %s", exc)
        if discovery_context is not None:
            try:
                discovery_context.record_metric("api_unified_fallback_total")
            except Exception:
                pass
        return run_api_doc_scan(
            sites, wih_records, waf_guard=waf_guard, discovery_context=discovery_context)


__all__ = [
    "ApiCandidateRegistry",
    "ApiDocumentQueue",
    "api_unified_enabled",
    "document_type_hint",
    "resolve_unified_api_config",
    "run_api_document_pipeline",
    "unified_api_config",
]
