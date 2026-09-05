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
`API_UNIFIED_FALLBACK_ENABLE`（默认 True）作用域（Review P1-09 冻结，两处同名
同一语义）：True 时 stage 级整体异常与单文档统一 Parser 崩溃都回退 legacy 并计
`api_unified_fallback_total`；False 时两处都不回退（stage 异常上抛，Parser 崩溃
文档标 failed、计入统一失败收口，不产生 fallback 事件）。非崩溃的单文档失败
（fetch 异常 / 空响应 / Parser 显式 failed）只影响当前文档（§7.2），一律计入
`parse_failed_count` + `api_document_parse_failed_total`（Review P1-08 统一收口，
含 error_type=empty_response），不触发回退。
"""

from __future__ import annotations

import hashlib
import json
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
    sanitize_source_text,
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
    # 第 7 批：WSDL/SOAP 文档分类（.wsdl / ?wsdl / /wsdl 路径均含 "wsdl"）。
    ("wsdl", "wsdl"),
)

_DOC_PRIORITY_SEED = 10
_DOC_PRIORITY_EVIDENCE = 20  # 来自记录/候选图的真实发现证据优先于路径猜测

# graphql_schema_summary 生产侧冻结契约（附录A §4.13，2026-09-06 用户决策）。
# 消费侧校验枚举 + 白名单投影：契约外键（Schema 原文、变量值等夹带形态）
# 一律不进诊断面，违规候选不回显任何候选字段值。
_SCHEMA_SUMMARY_KINDS = ("sdl", "introspection")
_SCHEMA_SUMMARY_STATUSES = ("ok", "degraded", "failed")
_SCHEMA_SUMMARY_INT_KEYS = ("type_count", "field_count", "summary_bytes")
_SCHEMA_SUMMARY_PROJECTION_KEYS = (
    "record_type", "kind", "status", "error_type", "schema_hash",
    "types", "enums", "inputs", "scalars",
    "type_count", "field_count", "truncated", "summary_bytes",
)
_SCHEMA_SUMMARY_STATUS_METRICS = {
    "ok": "graphql_schema_success_total",
    "degraded": "graphql_schema_degraded_total",
    "failed": "graphql_schema_failed_total",
}
# 诊断面驻留总条数上限：满则丢最旧（摘要可重解析，非持久化事实源）。
SCHEMA_DIAGNOSTICS_MAX_ENTRIES = 16


def _schema_summary_entry_size(entry: Dict[str, Any]) -> int:
    try:
        payload = json.dumps(entry, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError):
        # 不可序列化即不可存储：按超限处理，宁可裁剪不可越界。
        return 1 << 62
    return len(payload.encode("utf-8"))


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
        # P0-04 双通道的诊断面（有界、非持久化事实源——摘要丢失可重新解析，
        # 不落 Mongo、不进 legacy 记录面）；stage metrics 只放整数计数。
        # 消费方经 context.api_candidate_registry 挂载点读取本清单。
        self.schema_diagnostics: List[Dict[str, Any]] = []

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
                    # merge 入口同样过脱敏（P1-10）：直接字段赋值不经 __post_init__，
                    # 此处显式清洗，避免 parent_url 携带敏感 query 绕过构造期守卫。
                    existing.parent_url = sanitize_source_text(parent_url)
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

    # -- Schema 摘要诊断面（P0-04，附录A §4.13） ---------------------------

    def add_schema_diagnostic(self, entry: Dict[str, Any]) -> bool:
        """追加一条 Schema 摘要诊断；返回 True 表示发生了"满则丢最旧"。

        非持久化事实源：条目丢失可重新解析获得，本清单不落 Mongo、不进
        记录面，只经 context.api_candidate_registry 挂载点供诊断消费。
        """
        dropped = False
        with self._lock:
            self.schema_diagnostics.append(entry)
            while len(self.schema_diagnostics) > SCHEMA_DIAGNOSTICS_MAX_ENTRIES:
                self.schema_diagnostics.pop(0)
                dropped = True
        return dropped

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

    # -- 解析分发（第 4 批：统一 Parser 优先，格式外回退 legacy；
    #    崩溃回退受 API_UNIFIED_FALLBACK_ENABLE 约束，P1-09）----

    def _parse_options(self):
        from .api_unified_models import ParseOptions

        cfg = self.config
        return ParseOptions(
            max_depth=int(cfg.get("API_DOCUMENT_MAX_DEPTH", 3) or 3),
            max_ref_count=int(cfg.get("API_DOCUMENT_MAX_REF_COUNT", 500) or 500),
            external_ref_enable=bool(cfg.get("API_EXTERNAL_REF_ENABLE", False)),
            graphql_schema_enable=bool(cfg.get("GRAPHQL_SCHEMA_ENABLE", False)),
            # P0-03 运行时半边：解析链真正消费该预算（缺配置走代码默认 20）。
            graphql_schema_max_depth=int(cfg.get("GRAPHQL_SCHEMA_MAX_DEPTH", 20) or 20),
            wsdl_parse_enable=bool(cfg.get("WSDL_PARSE_ENABLE", True)),
            max_document_bytes=max(1024, int(cfg.get("API_DOCUMENT_MAX_SIZE_BYTES", 5242880) or 5242880)),
        )

    def _parse_one(self, doc: ApiDocumentCandidate, text: str, signature: str) -> bool:
        """统一→legacy 两级解析；返回 True=已解析。单文档失败隔离（§7.2）。

        返回 False 的文档终态必已标 failed（error_type 区分失败路径），由
        run() 计 parse_failed_count + api_document_parse_failed_total；Parser
        崩溃是否回退 legacy 取决于 API_UNIFIED_FALLBACK_ENABLE（P1-09）。
        """

        if bool(self.config.get("API_UNIFIED_ENABLE")) and "<html" not in text[:2048].lower():
            result = None
            try:
                from .api_unified_parser import (
                    UnifiedGraphqlParser,
                    UnifiedOpenApiParser,
                    UnifiedPostmanParser,
                    UnifiedWsdlParser,
                )

                # 解析器链分发：格式互斥由各类 skip 判定，全部 skipped 才回 legacy。
                options = self._parse_options()
                for parser_cls in (UnifiedOpenApiParser, UnifiedPostmanParser,
                                   UnifiedGraphqlParser, UnifiedWsdlParser):
                    kwargs = dict(
                        task_id=self.registry.task_id,
                        doc_url=doc.url,
                        allowed_hosts=self.scanner.allowed_hosts,
                        allowed_flds=self.scanner.allowed_flds,
                    )
                    if parser_cls is UnifiedGraphqlParser:
                        kwargs["schema_max_bytes"] = int(
                            self.config.get("GRAPHQL_SCHEMA_MAX_SIZE_BYTES", 2097152) or 2097152)
                    parser = parser_cls(**kwargs)
                    result = parser.parse(text, options)
                    if result is None or result.diagnostics is None \
                            or result.diagnostics.status != "skipped":
                        break
                else:
                    # P1-11 skipped 观测（best-effort）：schema 开关关闭、全链
                    # skipped 且文档形态证据指向 graphql 才计数。type_hint 来自
                    # URL 关键词分类，是弱证据——真值语义以第 8 批运行时事件
                    # 接入补强；漏计/多计只影响观测面，不影响解析与记录。
                    if not options.graphql_schema_enable \
                            and "graphql" in str(doc.type_hint or ""):
                        self._record_metric("graphql_schema_skipped_total")
            except Exception as exc:
                # P1-09：崩溃回退与 stage 级整体异常同受 API_UNIFIED_FALLBACK_ENABLE
                # 约束（同名单一语义）。开关 False 时不回退、不产生 fallback 事件：
                # 文档标 failed 后返回 False，由 run() 的失败收口统一计
                # parse_failed_count + api_document_parse_failed_total（计数只此一处，
                # 与 fetch 异常路径同口径，避免双重计量）。error_type 取异常类名，
                # 沿用 fetch 异常/legacy 解析崩溃的既有词表，不新造 parser_crash 枚举。
                if not bool(self.config.get("API_UNIFIED_FALLBACK_ENABLE", True)):
                    logger.warning(
                        "unified parser crashed url:%s error_type:%s fallback disabled",
                        str(doc.url)[:160], type(exc).__name__)
                    self.registry.mark_document(
                        doc.url, "fetched", input_signature=signature)
                    self.registry.mark_document(
                        doc.url, "failed", error_type=type(exc).__name__)
                    return False
                # 开关 True：维持原语义，回退 legacy（§十三.3）；异常类型上指标。
                logger.warning(
                    "unified parser crashed url:%s error_type:%s fallback to legacy",
                    str(doc.url)[:160], type(exc).__name__)
                self._record_metric("api_unified_fallback_total")
                result = None
            if result is not None and result.diagnostics is not None:
                status = result.diagnostics.status
                if status in ("ok", "degraded"):
                    self._bridge_parse_result(doc, result)
                    self.registry.mark_document(doc.url, "fetched", input_signature=signature)
                    self.registry.mark_document(doc.url, "parsed")
                    unresolved = int(result.diagnostics.unresolved_ref_count or 0)
                    if unresolved:
                        self._record_metric("api_document_unresolved_ref_total", unresolved)
                    return True
                if status == "failed":
                    # G4：显式失败语义，不回退 legacy（legacy 同样零产出且静默）。
                    self.registry.mark_document(
                        doc.url, "fetched", input_signature=signature)
                    self.registry.mark_document(
                        doc.url, "failed",
                        error_type=result.diagnostics.error_type or "parse_failed")
                    return False
                # skipped：postman/graphql/wsdl 等未接管格式，走 legacy

        new_refs: List[str] = []
        try:
            self.scanner.parse_document(doc.url, text, new_refs)
        except Exception as exc:
            self.registry.mark_document(doc.url, "fetched", input_signature=signature)
            self.registry.mark_document(doc.url, "failed", error_type=type(exc).__name__)
            return False
        self.registry.mark_document(doc.url, "fetched", input_signature=signature)
        self.registry.mark_document(doc.url, "parsed")
        self._register_parsed_endpoints(self._harvest_records())
        self._enqueue_refs(doc, new_refs)
        return True

    def _enqueue_refs(self, doc: ApiDocumentCandidate, refs: List[str]) -> None:
        max_depth = max(1, int(self.config.get("API_DOCUMENT_MAX_DEPTH", 3) or 3))
        max_targets = max(1, int(self.config.get("API_DOCUMENT_MAX_TARGETS", 200) or 200))
        for ref in refs:
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

    def _bridge_parse_result(self, doc: ApiDocumentCandidate, result) -> None:
        """ParseResult → 旧 WihRecord 面 + Endpoint 富资产（附录A §4.6 格式）。

        candidates 走统一安全出口 `_bridge_candidate`（Review P0-01/P0-04）：
        越界 host 只作证据计数，任何候选类型不得被静默丢弃。
        """

        from .api_unified_parser import url_has_template
        from .web_info_intel_utils import safe_site

        for candidate in result.documents:
            self.scanner._append_record(  # noqa: SLF001  (复用冻结的记录格式与 fnv 去重)
                "api_doc_url", candidate.url, candidate.url, safe_site(candidate.url))
        for endpoint in result.endpoints:
            if endpoint.api_type == "graphql":
                # P1-11：一次桥接端点 = 一次可重放的 graphql 请求文档观察，
                # 逐条计数（与资产去重无关，度量的是解析产出面）。
                self._record_metric("graphql_request_total")
            # 富资产直接登记（含参数/auth/追溯）；桥接记录不再经字符串反解。
            self.registry.register_endpoint(endpoint)
            for item in endpoint.to_legacy_records():
                record_type = str(item.get("record_type") or "")
                content = str(item.get("content") or "")
                if record_type == "urlfinder_url" and url_has_template(content):
                    # G1 模板 URL 不可直接请求：只进端点/资产面，不落 URL 资产。
                    continue
                url_part = content
                head_method, _, head_url = content.partition(" ")
                if head_url.lower().startswith(("http://", "https://")):
                    # "METHOD url" 形态（api_doc_endpoint 与 graphql 共用 §二 格式）
                    url_part = head_url
                self.scanner._append_record(
                    record_type, content, str(item.get("source") or ""), safe_site(url_part))
        for candidate in result.candidates:
            self._bridge_candidate(doc, candidate)

    # -- 候选统一安全出口（Review P0-01/P0-04） -----------------------------

    def _bridge_candidate(self, doc: ApiDocumentCandidate, candidate: Dict[str, Any]) -> None:
        """按 record_type 分发候选；任何类型必须计数可观测，不得静默丢弃。"""

        record_type = str(candidate.get("record_type") or "")
        if record_type in ("out_of_scope_domain", "domain"):
            # "domain" 是防御分支：P0-01 后解析器契约只产 out_of_scope_domain，
            # 但旧形态候选（如 postman 解析器）必须走同一证据出口，绝不回灌资产面。
            self._bridge_out_of_scope_domain(doc, candidate)
            return
        if record_type == "wsdl_xsd_import":
            # §6.4：XSD 引用只登记观测、不获取；桥接层计数保证可观测。
            self._record_metric("api_document_wsdl_xsd_import_total")
            return
        if record_type == "graphql_schema_summary":
            # P0-04 已接管存储面：双通道落位后本类型绝不再进 unbridged 观测锚
            # （轮 1 登记的归零口径）。
            self._bridge_graphql_schema_summary(candidate)
            return
        # 尚未接线的类型显式计数：桥接不得静默丢弃任何未知 candidate。
        self._record_metric("api_document_unbridged_candidate_total")

    def _bridge_graphql_schema_summary(self, candidate: Dict[str, Any]) -> None:
        """P0-04 双通道：摘要进 registry 有界诊断面；metrics 只记录状态计数。

        生产侧冻结契约（附录A §4.13）：kind ∈ sdl/introspection、
        status ∈ ok/degraded/failed、type_count/field_count/summary_bytes 为真
        整数。非法 candidate → 计 graphql_schema_failed_total +
        schema_contract_violation 最小诊断，不回显任何候选字段（防契约外键如
        Schema 原文、变量值经诊断面外流），绝不静默成功。
        合法 candidate → 白名单投影 + 逐条字节上限裁剪（超限只留安全头部
        字段并置 summary_dropped），追加进有界诊断面；诊断面是非持久化事实源
        （丢失可重新解析），不落 Mongo、不进 legacy 记录面。
        """
        kind = candidate.get("kind")
        status = candidate.get("status")
        counts_valid = all(
            isinstance(candidate.get(key), int) and not isinstance(candidate.get(key), bool)
            for key in _SCHEMA_SUMMARY_INT_KEYS)
        if kind not in _SCHEMA_SUMMARY_KINDS or status not in _SCHEMA_SUMMARY_STATUSES \
                or not counts_valid:
            self._record_metric("graphql_schema_failed_total")
            self.registry.add_schema_diagnostic({
                "record_type": "graphql_schema_summary",
                "status": "failed",
                "error_type": "schema_contract_violation",
                "truncated": True,
                "summary_dropped": True,
            })
            return
        entry = {key: candidate[key] for key in _SCHEMA_SUMMARY_PROJECTION_KEYS
                 if key in candidate}
        max_bytes = int(self.config.get("GRAPHQL_SCHEMA_SUMMARY_MAX_BYTES", 8192) or 8192)
        if _schema_summary_entry_size(entry) > max_bytes:
            # 字节预算优先于条目完整性：正文（类型/枚举/输入/标量名单）整体
            # 丢弃，只保留可归因的安全头部字段；截断必须显式标记，不得伪装完整。
            entry = {
                "record_type": "graphql_schema_summary",
                "kind": entry.get("kind"),
                "status": entry.get("status"),
                "error_type": entry.get("error_type"),
                "schema_hash": entry.get("schema_hash"),
                "type_count": entry.get("type_count"),
                "field_count": entry.get("field_count"),
                "truncated": True,
                "summary_dropped": True,
            }
        self._record_metric(_SCHEMA_SUMMARY_STATUS_METRICS[status])
        if self.registry.add_schema_diagnostic(entry):
            self._record_metric("api_document_schema_diagnostics_dropped_total")

    def _bridge_out_of_scope_domain(self, doc: ApiDocumentCandidate, candidate: Dict[str, Any]) -> None:
        """越界 host 只作证据计数，绝不写入 in-scope domain 记录（Review P0-01）。

        不可信 API 文档（server/base/soap:address）可指向任意 host；旧桥接
        直接落 `domain` 记录，等于允许文档作者把范围外 host 注入任务资产面，
        被候选图/站点发现/探测消费方当作任务资产。这里复用既有 host/Fld
        校验做二次核验（与 legacy `_emit_domain_records` 同一判定口径）：
        这些候选构造上即范围外（解析器仅在 host 不属于 allowed_hosts 时产出），
        因此一律作为证据；即便二次核验意外通过也不落记录，只留痕供审计
        解析器范围面与队列范围面的不一致。
        """

        from .web_info_intel_utils import extract_host

        host = extract_host(str(candidate.get("content") or ""))
        allowed_hosts = set(getattr(self.scanner, "allowed_hosts", None) or set())
        allowed_flds = set(getattr(self.scanner, "allowed_flds", None) or set())
        try:
            fld = str(utils.get_fld(host) or "") if host and utils.is_valid_domain(host) else ""
        except Exception as exc:
            # 校验异常不改变出口（证据面本就与核验结果无关），只留痕。
            logger.debug(
                "api doc out-of-scope domain validation failed error_type:%s",
                type(exc).__name__)
            fld = ""
        if host and (host in allowed_hosts or (fld and fld in allowed_flds)):
            logger.debug(
                "api doc domain candidate unexpectedly in scope url:%s host:%s",
                str(doc.url)[:160], host[:128])
        self._record_metric("api_document_out_of_scope_domain_total")

    def _harvest_records(self) -> List[Any]:
        records = self.scanner.records
        delta = records[self._harvested_index:]
        self._harvested_index = len(records)
        return list(delta)

    def run(self, wih_records: Optional[List[Any]] = None) -> List[Any]:
        """有界消费循环：任何单文档失败只标记该文档，循环继续（§7.2）。"""

        max_targets = max(1, int(self.config.get("API_DOCUMENT_MAX_TARGETS", 200) or 200))

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
                # P1-08：空响应与 fetch 异常、Parser 显式 failed 同属统一失败收口。
                # 两处都要计数（counter + 指标）的原因：parse_failed_count 是队列
                # 局部运行事实（stage 完成日志的 failed 分母），api_document_parse_failed_total
                # 是跨进程观测面（context 指标），二者消费方不同、缺一即失真；
                # 此前只标态不计数（Review 探针：fetch_count=1 而 parse_failed_count=0），
                # 消费文档数与 success+failed 分母出现无法归因缺口。error_type 保持
                # empty_response 以区分失败性质；状态机迁移与账本收口不变。
                self.registry.mark_document(doc.url, "failed", error_type="empty_response")
                self.parse_failed_count += 1
                self._record_metric("api_document_parse_failed_total")
                self._ledger_finish(doc, "failed")
                continue

            signature = compute_input_signature(
                hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest())
            parsed = self._parse_one(doc, text, signature)
            if parsed:
                self.parse_success_count += 1
                self._record_metric("api_document_parse_success_total")
                self._ledger_finish(doc, "covered")
            else:
                self.parse_failed_count += 1
                self._record_metric("api_document_parse_failed_total")
                self._ledger_finish(doc, "failed")

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
                # P0-04 透出：诊断面驻留条数（整数计数；摘要本体不进 metrics）。
                self.context.record_metric(
                    "api_document_schema_diagnostics_total",
                    len(self.registry.schema_diagnostics))
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
