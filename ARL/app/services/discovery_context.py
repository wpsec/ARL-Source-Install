"""任务级发现上下文。

该模块只提供任务内的状态协调原语，不直接发起网络请求或写入 Mongo。
这样各扫描策略可以共享响应和候选状态，同时保持现有任务入口和结果写回链路不变。
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Set, Tuple
from urllib.parse import urlsplit, urlunsplit


logger = logging.getLogger(__name__)


# 计划 6 §8.2（第 9 批）：API 文档获取与 Endpoint 探测各自独立流量类别，
# WAF 类别熔断互不连坐（文档失败不停探测、探测熔断不停文档）；主机级
# （host_wide）信号仍跨类别暂停该站点全部 API 请求。
# §8.1 请求 profile → 流量类别映射：api_doc→api_doc、graphql_schema_optional→api_doc
# （同一文档获取通道）；api_endpoint_probe/soap_endpoint_observe→endpoint_probe；
# browser→browser（Playwright 自有网络栈=外部边界，不经过本枚举的调度面）。
TRAFFIC_CLASSES = ("normal", "crawler", "wih", "directory", "browser",
                   "api_doc", "endpoint_probe")

# 与各 stage 既有线程并发对齐，只削跨策略叠加峰值，不做低于单 stage 并发的大限。
DEFAULT_TRAFFIC_LIMITS = {
    "normal": 12,
    "crawler": 12,
    "wih": 12,
    "directory": 12,
    "browser": 4,
    # 第 9 批 §8.2：API 文档获取与 Endpoint 探测独立额度——文档批量抓取
    # 不挤占探测并发、探测风暴不吃文档预算（预算另有 API_DOCUMENT_* /
    # API_ENDPOINT_PROBE_MAX_TARGETS 层，此处是进程内并发闸）。
    "api_doc": 6,
    "endpoint_probe": 8,
}
DEFAULT_PER_HOST_LIMIT = 8
DEFAULT_ACQUIRE_WAIT_SEC = 15.0
DEFAULT_SINGLEFLIGHT_WAIT_SEC = 10.0
DEFAULT_MAX_TOTAL_BODY_BYTES = 48 * 1024 * 1024
DEFAULT_CANDIDATE_MAX_ENTRIES = 20000


def traffic_class_for_module(module: Any) -> str:
    """把 waf_module 归入流量类别；与各 stage 传入的模块名保持既有词根约定。

    第 9 批（§8.2）：`api_doc*` 与 `*endpoint_probe*` 从 wih 词根中拆出为独立
    类别——判定顺序必须先于泛 wih 匹配（`wih_endpoint_probe` 同时含两个词根，
    归 endpoint_probe；`api_doc_scan` 归 api_doc）。
    """

    module_name = str(module or "").strip().lower()
    if "file_leak" in module_name or "vhost" in module_name:
        return "directory"
    if "spider" in module_name:
        return "crawler"
    if "screenshot" in module_name:
        return "browser"
    if "endpoint" in module_name:
        return "endpoint_probe"
    if "api_doc" in module_name:
        return "api_doc"
    if any(
        token in module_name
        for token in ("wih", "urlfinder", "page_intel", "js_intel", "trufflehog", "ai_fill")
    ):
        return "wih"
    return "normal"
CANDIDATE_STATUSES = (
    "discovered",
    "queued",
    "fetching",
    "fetched",
    "covered",
    "failed",
    "degraded",
    "pending",
    "skipped",
)


def normalize_url(value: Any) -> str:
    """生成用于任务内去重的 URL。

    这里只做稳定的结构归一化，不执行 DNS、范围判断或网络请求；安全策略由调用方负责。
    """

    text = str(value or "").strip()
    if not text:
        return ""

    try:
        parsed = urlsplit(text)
    except ValueError:
        return text
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return text

    host = parsed.hostname.lower().rstrip(".")
    netloc = host
    try:
        port = parsed.port
    except ValueError:
        return text
    if port:
        default_port = (parsed.scheme.lower() == "http" and port == 80) or (
            parsed.scheme.lower() == "https" and port == 443
        )
        if not default_port:
            netloc = "{}:{}".format(host, port)

    path = parsed.path or "/"
    return urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, ""))


def url_host(value: Any) -> str:
    """提取 URL/主机值，不执行解析。"""

    text = str(value or "").strip()
    if not text:
        return ""
    try:
        parsed = urlsplit(text if "://" in text else "//" + text)
    except ValueError:
        return ""
    return str(parsed.hostname or "").strip().lower().rstrip(".")


def _stable_json_value(value: Any) -> str:
    if isinstance(value, Mapping):
        items = sorted((str(key), _stable_json_value(item)) for key, item in value.items())
        return "{" + ",".join("{}={}".format(key, item) for key, item in items) + "}"
    if isinstance(value, (list, tuple, set)):
        return "[" + ",".join(sorted(_stable_json_value(item) for item in value)) + "]"
    return str(value or "")


_INTEL_CANDIDATE_EVENTS = {
    "domain": ("NewHostDiscovered", "host"),
    "sub_domain": ("NewHostDiscovered", "host"),
    "page_link": ("UrlCandidateDiscovered", "url"),
    "page_url": ("UrlCandidateDiscovered", "page"),
    "urlfinder_url": ("UrlCandidateDiscovered", "url"),
    "path_url": ("UrlCandidateDiscovered", "url"),
    "urlfinder_js": ("UrlCandidateDiscovered", "js"),
    "api_doc_url": ("EndpointCandidateDiscovered", "endpoint"),
    "endpoint": ("EndpointCandidateDiscovered", "endpoint"),
}


def register_intel_candidate(
    discovery_context: Optional["DiscoveryContext"],
    record_type: str,
    content: str,
    source: str,
    site: str = "",
) -> None:
    """把情报记录同步登记进共享候选图。

    仅做观测与后续 stage 复用，任何失败都不允许打断扫描主链路；
    未列出的 record_type（secret、title 等）不进入候选图，避免噪声。
    """

    if discovery_context is None:
        return
    mapping = _INTEL_CANDIDATE_EVENTS.get(str(record_type or "").strip())
    if not mapping:
        return
    event_type, candidate_type = mapping
    try:
        discovery_context.register_candidate(
            event_type=event_type,
            candidate=content,
            candidate_type=candidate_type,
            source=str(source or record_type),
            parent_target=str(site or ""),
            metadata={"intel_record_type": str(record_type or "")},
        )
    except Exception as exc:
        logger.debug(
            "intel candidate register failed record_type:%s error_type:%s",
            record_type,
            type(exc).__name__,
        )
        try:
            discovery_context.record_metric("degraded_count")
        except Exception:
            pass


@dataclass
class ResponseRecord:
    normalized_url: str
    method: str
    request_profile: str
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    content_type: str = ""
    body: bytes = b""
    body_hash: str = ""
    body_truncated: bool = False
    source: str = ""
    fetched_at: float = field(default_factory=time.time)
    consumers: Set[str] = field(default_factory=set)

    def to_dict(self, include_body: bool = True) -> Dict[str, Any]:
        result = {
            "normalized_url": self.normalized_url,
            "method": self.method,
            "request_profile": self.request_profile,
            "status_code": self.status_code,
            "headers": dict(self.headers),
            "content_type": self.content_type,
            "body_hash": self.body_hash,
            "body_truncated": bool(self.body_truncated),
            "source": self.source,
            "fetched_at": self.fetched_at,
            "consumers": sorted(self.consumers),
        }
        if include_body:
            result["body"] = self.body
        return result


class ResponseRegistry:
    """任务内有界响应缓存。"""

    def __init__(
        self,
        max_entries: int = 512,
        max_body_bytes: int = 384 * 1024,
        max_total_body_bytes: int = DEFAULT_MAX_TOTAL_BODY_BYTES,
    ):
        self.max_entries = max(1, int(max_entries or 1))
        self.max_body_bytes = max(1024, int(max_body_bytes or 1024))
        self.max_total_body_bytes = max(self.max_body_bytes, int(max_total_body_bytes or 0) or self.max_body_bytes)
        self._items: "OrderedDict[Tuple[str, str, str], ResponseRecord]" = OrderedDict()
        self._total_body_bytes = 0
        self._lock = threading.RLock()

    @staticmethod
    def key(url: Any, method: Any = "GET", request_profile: Any = "default") -> Tuple[str, str, str]:
        return (
            normalize_url(url),
            str(method or "GET").upper(),
            _stable_json_value(request_profile),
        )

    def get(
        self,
        url: Any,
        method: Any = "GET",
        request_profile: Any = "default",
        consumer: str = "",
    ) -> Optional[ResponseRecord]:
        cache_key = self.key(url, method, request_profile)
        with self._lock:
            item = self._items.get(cache_key)
            if item is None:
                return None
            self._items.move_to_end(cache_key)
            if consumer:
                item.consumers.add(str(consumer))
            return item

    def put(
        self,
        url: Any,
        method: Any = "GET",
        request_profile: Any = "default",
        status_code: int = 0,
        headers: Optional[Mapping[str, Any]] = None,
        content_type: str = "",
        body: Any = b"",
        source: str = "",
        consumer: str = "",
    ) -> Tuple[ResponseRecord, bool]:
        cache_key = self.key(url, method, request_profile)
        raw_body = body.encode("utf-8", "ignore") if isinstance(body, str) else bytes(body or b"")
        body_truncated = len(raw_body) > self.max_body_bytes
        stored_body = raw_body[: self.max_body_bytes]
        item = ResponseRecord(
            normalized_url=cache_key[0],
            method=cache_key[1],
            request_profile=cache_key[2],
            status_code=int(status_code or 0),
            headers={str(key): str(value) for key, value in dict(headers or {}).items()},
            content_type=str(content_type or ""),
            body=stored_body,
            body_hash=hashlib.sha256(stored_body).hexdigest() if stored_body else "",
            body_truncated=body_truncated,
            source=str(source or ""),
        )
        if consumer:
            item.consumers.add(str(consumer))

        with self._lock:
            existing = self._items.get(cache_key)
            if existing is not None:
                if consumer:
                    existing.consumers.add(str(consumer))
                self._items.move_to_end(cache_key)
                return existing, False
            self._items[cache_key] = item
            self._total_body_bytes += len(stored_body)
            while self._items and (
                len(self._items) > self.max_entries
                or self._total_body_bytes > self.max_total_body_bytes
            ):
                _, evicted = self._items.popitem(last=False)
                self._total_body_bytes = max(0, self._total_body_bytes - len(evicted.body))
        return item, True

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)

    def peek(
        self,
        url: Any,
        method: Any = "GET",
        request_profile: Any = "default",
    ) -> Optional[ResponseRecord]:
        """只读命中：不登记 consumer、不移动 LRU、不产生任何指标。

        shadow 观测专用——观测本身不允许改变被观测系统的行为。
        返回不含 body 的轻量快照，consumers 为快照集合。
        """

        cache_key = self.key(url, method, request_profile)
        with self._lock:
            item = self._items.get(cache_key)
            if item is None:
                return None
            return ResponseRecord(
                normalized_url=item.normalized_url,
                method=item.method,
                request_profile=item.request_profile,
                status_code=item.status_code,
                headers=dict(item.headers),
                content_type=item.content_type,
                body=b"",
                body_hash=item.body_hash,
                body_truncated=item.body_truncated,
                source=item.source,
                fetched_at=item.fetched_at,
                consumers=frozenset(item.consumers),
            )


@dataclass
class CandidateRecord:
    candidate_key: str
    candidate: str
    candidate_type: str
    request_profile: str = "default"
    sources: Set[str] = field(default_factory=set)
    source_details: Dict[str, str] = field(default_factory=dict)
    parent_target: str = ""
    depth: int = 0
    priority: int = 0
    status: str = "discovered"
    metadata: Dict[str, Any] = field(default_factory=dict)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidate_key": self.candidate_key,
            "candidate": self.candidate,
            "candidate_type": self.candidate_type,
            "request_profile": self.request_profile,
            "sources": sorted(self.sources),
            "source_details": dict(self.source_details),
            "parent_target": self.parent_target,
            "depth": self.depth,
            "priority": self.priority,
            "status": self.status,
            "metadata": dict(self.metadata),
            "updated_at": self.updated_at,
        }


class CandidateRegistry:
    """候选资产图的任务内实现。

    候选图是观测与来源聚合结构，不是结果事实源：超过 max_entries 时按最早插入驱逐，
    防止日历翻页/SessionID 等无界 URL 形态把 Celery worker 内存撑爆。
    """

    def __init__(self, max_entries: int = DEFAULT_CANDIDATE_MAX_ENTRIES, on_evict: Optional[Callable[[int], None]] = None):
        self.max_entries = max(100, int(max_entries or 100))
        self.evicted_count = 0
        self._on_evict = on_evict if callable(on_evict) else None
        self._items: "OrderedDict[str, CandidateRecord]" = OrderedDict()
        self._lock = threading.RLock()

    @staticmethod
    def key(candidate: Any, candidate_type: Any, request_profile: Any = "default") -> str:
        candidate_text = str(candidate or "").strip()
        if str(candidate_type or "").lower() in {"url", "site", "page", "page_url", "endpoint", "api", "js"}:
            candidate_text = normalize_url(candidate_text)
        return "{}|{}|{}".format(
            str(candidate_type or "unknown").strip().lower(),
            candidate_text,
            _stable_json_value(request_profile),
        )

    def upsert(
        self,
        candidate: Any,
        candidate_type: Any,
        source: str,
        request_profile: Any = "default",
        source_detail: str = "",
        parent_target: str = "",
        depth: int = 0,
        priority: int = 0,
        status: str = "discovered",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Tuple[CandidateRecord, bool, bool]:
        candidate_text = str(candidate or "").strip()
        candidate_type_text = str(candidate_type or "unknown").strip().lower()
        if candidate_type_text in {"url", "site", "page", "page_url", "endpoint", "api", "js"}:
            candidate_text = normalize_url(candidate_text)
        if not candidate_text:
            raise ValueError("candidate must not be empty")
        if status not in CANDIDATE_STATUSES:
            raise ValueError("unsupported candidate status: {}".format(status))

        profile_text = _stable_json_value(request_profile)
        candidate_key = self.key(candidate_text, candidate_type_text, profile_text)
        source_text = str(source or "").strip()
        with self._lock:
            item = self._items.get(candidate_key)
            if item is None:
                item = CandidateRecord(
                    candidate_key=candidate_key,
                    candidate=candidate_text,
                    candidate_type=candidate_type_text,
                    request_profile=profile_text,
                    sources=set(),
                    parent_target=str(parent_target or ""),
                    depth=max(0, int(depth or 0)),
                    priority=int(priority or 0),
                    status=status,
                    metadata=dict(metadata or {}),
                )
                self._items[candidate_key] = item
                created = True
            else:
                created = False
                self._items.move_to_end(candidate_key)
                item.depth = min(item.depth, max(0, int(depth or 0)))
                item.priority = max(item.priority, int(priority or 0))
                if parent_target and not item.parent_target:
                    item.parent_target = str(parent_target)
                if metadata:
                    item.metadata.update(dict(metadata))

            source_added = bool(source_text and source_text not in item.sources)
            if source_text:
                item.sources.add(source_text)
                if source_detail:
                    item.source_details[source_text] = str(source_detail)
            item.updated_at = time.time()

            evicted_now = 0
            evicted_records = []
            while len(self._items) > self.max_entries:
                _, dropped = self._items.popitem(last=False)
                evicted_records.append(dropped)
                evicted_now += 1
            if evicted_now:
                self.evicted_count += evicted_now
                if self._on_evict is not None:
                    try:
                        self._on_evict(evicted_now, evicted_records)
                    except Exception as exc:
                        # 回调失败=这批候选没落进 overflow 账本，跨重启
                        # 恢复面直接缺失，必须计数可观测而非静默吞。
                        self.evict_callback_failed_count = (
                            getattr(self, "evict_callback_failed_count", 0) + 1)
                        logger.warning(
                            "candidate evict callback failed count:%d error_type:%s",
                            evicted_now, type(exc).__name__)
            return item, created, source_added

    def get(self, candidate_key: str) -> Optional[CandidateRecord]:
        with self._lock:
            return self._items.get(str(candidate_key or ""))

    def set_status(self, candidate_key: str, status: str, metadata: Optional[Mapping[str, Any]] = None) -> CandidateRecord:
        if status not in CANDIDATE_STATUSES:
            raise ValueError("unsupported candidate status: {}".format(status))
        with self._lock:
            item = self._items.get(str(candidate_key or ""))
            if item is None:
                raise KeyError("candidate not found: {}".format(candidate_key))
            item.status = status
            if metadata:
                item.metadata.update(dict(metadata))
            item.updated_at = time.time()
            return item

    def values(self) -> List[CandidateRecord]:
        with self._lock:
            return list(self._items.values())

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)


@dataclass
class DiscoveryEvent:
    event_type: str
    candidate: str
    candidate_key: str
    source: str
    source_detail: str = ""
    parent_target: str = ""
    depth: int = 0
    priority: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    # 一级审计字段：事件脱离 Context（日志/订阅者透传）后仍可归属任务与输入。
    # 带默认值追加在尾部，不破坏既有位置参数构造。
    task_id: str = ""
    input_signature: str = ""


@dataclass
class LedgerEntry:
    idempotency_key: str
    status: str = "pending"
    input_count: int = 0
    output_count: int = 0
    error_type: str = ""
    updated_at: float = field(default_factory=time.time)
    # owner/lease 供持久化后端做写回 fencing：过期 worker 不得覆盖接管者的结果。
    owner: str = ""
    lease_expires_at: float = 0.0
    # 溢出候选等轻量元数据；不作为业务结果事实源。
    payload: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "idempotency_key": self.idempotency_key,
            "status": self.status,
            "input_count": self.input_count,
            "output_count": self.output_count,
            "error_type": self.error_type,
            "updated_at": self.updated_at,
        }


class DiscoveryLedger:
    """持久化账本的最小接口和内存实现。

    后续可以注入 Mongo repository；上下文本身不绑定数据库，便于单测和隔离回归。
    """

    def __init__(self, backend: Any = None):
        self.backend = backend
        self._items: Dict[str, LedgerEntry] = {}
        self._lock = threading.RLock()

    def get(self, idempotency_key: str) -> Optional[LedgerEntry]:
        key = str(idempotency_key or "")
        if self.backend is not None and hasattr(self.backend, "get"):
            return self.backend.get(key)
        with self._lock:
            return self._items.get(key)

    def upsert(self, entry: LedgerEntry) -> LedgerEntry:
        if self.backend is not None and hasattr(self.backend, "upsert"):
            return self.backend.upsert(entry)
        with self._lock:
            self._items[entry.idempotency_key] = entry
            return entry

    def list_by_prefix(self, prefix: str, statuses=("blocked",), limit: int = 2000):
        """按 key 前缀与状态读取条目 [(key, payload)]，供 WAF 状态回灌。"""
        prefix_text = str(prefix or "")
        if not prefix_text:
            return []
        status_set = set(str(item or "") for item in (statuses or ()))
        if self.backend is not None and hasattr(self.backend, "list_by_prefix"):
            try:
                return list(self.backend.list_by_prefix(prefix_text, tuple(status_set), limit))
            except Exception:
                return []
        with self._lock:
            return [
                (key, dict(entry.payload or {}))
                for key, entry in self._items.items()
                if key.startswith(prefix_text) and entry.status in status_set
            ]

    def claim(self, idempotency_key: str, input_count: int = 0) -> bool:
        key = str(idempotency_key or "")
        if not key:
            raise ValueError("idempotency_key must not be empty")
        # 持久化后端自带原子 claim（唯一键 + 状态过滤），避免跨进程读改写竞态。
        if self.backend is not None and hasattr(self.backend, "claim"):
            return bool(self.backend.claim(key, input_count=input_count))
        with self._lock:
            existing = self.get(key)
            if existing is not None and existing.status in {"fetching", "queued", "covered"}:
                return False
            self.upsert(
                LedgerEntry(
                    idempotency_key=key,
                    status="fetching",
                    input_count=max(0, int(input_count or 0)),
                )
            )
            return True

    def finish(
        self,
        idempotency_key: str,
        status: str,
        input_count: int = 0,
        output_count: int = 0,
        error: Optional[BaseException] = None,
    ) -> LedgerEntry:
        if status not in CANDIDATE_STATUSES:
            raise ValueError("unsupported ledger status: {}".format(status))
        entry = LedgerEntry(
            idempotency_key=str(idempotency_key or ""),
            status=status,
            input_count=max(0, int(input_count or 0)),
            output_count=max(0, int(output_count or 0)),
            error_type=type(error).__name__ if error is not None else "",
        )
        # 持久化后端提供带 owner fencing 的 finish：过期 worker 的回写会被拒绝。
        if self.backend is not None and hasattr(self.backend, "finish"):
            return self.backend.finish(
                idempotency_key, status,
                input_count=input_count, output_count=output_count, error=error)
        return self.upsert(entry)


class WafPolicy:
    """按主机和流量类别隔离 WAF 熔断状态。"""

    def __init__(self, threshold: int = 3):
        self.threshold = max(1, int(threshold or 1))
        self._class_blocks: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._host_blocks: Dict[str, str] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _traffic_class(value: str) -> str:
        traffic_class = str(value or "normal").strip().lower()
        if traffic_class not in TRAFFIC_CLASSES:
            raise ValueError("unsupported traffic class: {}".format(traffic_class))
        return traffic_class

    def allow(self, target: Any, traffic_class: str) -> bool:
        host = url_host(target)
        category = self._traffic_class(traffic_class)
        with self._lock:
            if host in self._host_blocks:
                return False
            state = self._class_blocks.get((host, category))
            return not bool(state and state.get("blocked"))

    def is_host_blocked(self, target: Any) -> bool:
        """主机级封禁确认查询（第 9 批 §8.2）。

        消费方（endpoint 探测/文档获取）在 blocked 回报时区分"类别熔断"与
        "主机级封禁"：后者才标 `degraded/host_waf_blocked` 并暂停该站点全部
        API 请求；类别阻断只暂停对应流量类别，不得升级为主机级结论。
        """

        host = url_host(target)
        with self._lock:
            return host in self._host_blocks

    def record_signal(
        self,
        target: Any,
        traffic_class: str,
        reason: str = "",
        host_wide: bool = False,
        force: bool = False,
    ) -> Dict[str, Any]:
        host = url_host(target)
        category = self._traffic_class(traffic_class)
        reason_text = str(reason or "waf_signal")[:160]
        with self._lock:
            if host_wide:
                was_blocked = host in self._host_blocks
                self._host_blocks[host] = reason_text
                return {
                    "host": host, "traffic_class": category,
                    "blocked": True, "scope": "host",
                    "newly_blocked": not was_blocked,
                }
            state = self._class_blocks.setdefault(
                (host, category),
                {"count": 0, "blocked": False, "reason": reason_text},
            )
            was_blocked = bool(state.get("blocked"))
            state["count"] = int(state.get("count", 0) or 0) + 1
            state["reason"] = reason_text
            # force 用于已确认的子进程/外部证据（如目录 worker 内 guard 已判定阻断），
            # 属该类别的确定性证据，不再走计数阈值。
            if force or state["count"] >= self.threshold:
                state["blocked"] = True
            return {
                "host": host,
                "traffic_class": category,
                "blocked": bool(state["blocked"]),
                "newly_blocked": bool(state["blocked"]) and not was_blocked,
                "scope": "traffic_class",
                "count": state["count"],
            }

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "host_blocks": dict(self._host_blocks),
                "traffic_class_blocks": {
                    "{}|{}".format(host, category): dict(state)
                    for (host, category), state in self._class_blocks.items()
                },
            }


class RequestLease:
    def __init__(self, release: Callable[[], None]):
        self._release = release
        self._released = False

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        self._release()

    def __enter__(self) -> "RequestLease":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.release()


class RequestScheduler:
    """请求准入控制器，不负责实际 HTTP 请求。"""

    DEFAULT_LIMITS = dict(DEFAULT_TRAFFIC_LIMITS)

    def __init__(
        self,
        context: "DiscoveryContext",
        limits: Optional[Mapping[str, int]] = None,
        per_host_limit: int = DEFAULT_PER_HOST_LIMIT,
    ):
        self.context = context
        self.limits = dict(self.DEFAULT_LIMITS)
        for key, value in dict(limits or {}).items():
            category = WafPolicy._traffic_class(key)
            self.limits[category] = max(1, int(value or 1))
        self.per_host_limit = max(1, int(per_host_limit or 1))
        self._in_flight: Dict[str, int] = {key: 0 for key in TRAFFIC_CLASSES}
        self._host_in_flight: Dict[Tuple[str, str], int] = {}
        self._lock = threading.RLock()
        self._cond = threading.Condition(self._lock)

    def _try_grant(self, host: str, category: str) -> Optional[RequestLease]:
        host_key = (host, category)
        with self._lock:
            if self._in_flight[category] >= self.limits[category]:
                return None
            if self._host_in_flight.get(host_key, 0) >= self.per_host_limit:
                return None
            self._in_flight[category] += 1
            self._host_in_flight[host_key] = self._host_in_flight.get(host_key, 0) + 1
            # granted 租约 ≈ 一次真实网络请求发起；与缓存层的
            # cache_miss_count/duplicate 口径分开，避免"miss 当请求数"。
            self.context.record_metric("network_request_count")

        def _release() -> None:
            with self._cond:
                self._in_flight[category] = max(0, self._in_flight[category] - 1)
                self._host_in_flight[host_key] = max(0, self._host_in_flight.get(host_key, 0) - 1)
                self._cond.notify_all()

        return RequestLease(_release)

    def acquire(self, target: Any, traffic_class: str) -> Optional[RequestLease]:
        category = WafPolicy._traffic_class(traffic_class)
        host = url_host(target)
        if not self.context.waf_policy.allow(target, category):
            self.context.record_metric("waf_block_count")
            return None
        lease = self._try_grant(host, category)
        if lease is None:
            self.context.record_metric("pending_count")
        return lease

    def acquire_wait(
        self,
        target: Any,
        traffic_class: str,
        wait_sec: Optional[float] = None,
    ) -> Tuple[Optional[RequestLease], str]:
        """等待类别配额；返回 (lease, reason)。

        reason 为 granted/blocked/over_limit。over_limit 表示等待超时，调用方应选择
        fail-open 继续请求并计数：静默丢弃候选会把限流伪装成“该路径不存在”。
        """

        category = WafPolicy._traffic_class(traffic_class)
        host = url_host(target)
        if not self.context.waf_policy.allow(target, category):
            self.context.record_metric("waf_block_count")
            return None, "blocked"

        budget = DEFAULT_ACQUIRE_WAIT_SEC if wait_sec is None else max(0.0, float(wait_sec))
        deadline = time.monotonic() + budget
        lease = self._try_grant(host, category)
        while lease is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.context.record_metric("over_limit_request_count")
                return None, "over_limit"
            with self._cond:
                lease = self._try_grant(host, category)
                if lease is None:
                    self._cond.wait(min(remaining, 1.0))
        return lease, "granted"


class DiscoveryContext:
    """同一 Task ID 内共享发现状态的门面。"""

    def __init__(
        self,
        task_id: str,
        allowed_hosts: Optional[Iterable[str]] = None,
        response_max_entries: int = 512,
        response_max_body_bytes: int = 384 * 1024,
        response_max_total_body_bytes: int = DEFAULT_MAX_TOTAL_BODY_BYTES,
        waf_threshold: int = 3,
        ledger: Optional[DiscoveryLedger] = None,
        scheduler_limits: Optional[Mapping[str, int]] = None,
        scheduler_per_host_limit: int = DEFAULT_PER_HOST_LIMIT,
        candidate_max_entries: int = DEFAULT_CANDIDATE_MAX_ENTRIES,
    ):
        self.task_id = str(task_id or "").strip()
        if not self.task_id:
            raise ValueError("task_id must not be empty")
        self.allowed_hosts = {
            url_host(host) for host in list(allowed_hosts or []) if url_host(host)
        }
        self.response_registry = ResponseRegistry(
            response_max_entries,
            response_max_body_bytes,
            response_max_total_body_bytes,
        )
        self.candidate_registry = CandidateRegistry(
            max_entries=candidate_max_entries,
            on_evict=self._on_candidates_evicted,
        )
        self.ledger = ledger or DiscoveryLedger()
        # A5：账本后端 fail-open 计数汇入本任务 metrics（阈值判定在 TaskFinalizer）。
        backend = getattr(self.ledger, "backend", None)
        attach = getattr(backend, "attach_metrics_sink", None)
        if callable(attach):
            attach(self.record_metric)
        self.waf_policy = WafPolicy(waf_threshold)
        self.request_scheduler = RequestScheduler(
            self,
            limits=scheduler_limits,
            per_host_limit=scheduler_per_host_limit,
        )
        self.metrics: Dict[str, int] = {
            "network_request_count": 0,
            "cache_miss_count": 0,
            "cache_hit_count": 0,
            "actual_duplicate_request_count": 0,
            "cross_strategy_reuse_count": 0,
            "candidate_discovered_count": 0,
            "candidate_source_merge_count": 0,
            "candidate_evicted_count": 0,
            "waf_block_count": 0,
            "pending_count": 0,
            "over_limit_request_count": 0,
            "failed_count": 0,
            "degraded_count": 0,
            "event_listener_error_count": 0,
        }
        self.event_counts: Dict[str, int] = {}
        self._subscribers: Dict[str, List[Callable[[DiscoveryEvent], None]]] = {}
        # 并发请求合并：同 URL 并发 miss 时只有一个线程真实请求，其余等其结果。
        self._inflight: Dict[Tuple[str, str, str], threading.Event] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _fetch_slot_key(url, method, request_profile) -> Tuple[str, str, str]:
        # 必须与 ResponseRegistry.key 同源，put_response 释放才能命中。
        return ResponseRegistry.key(url, method, request_profile)

    def acquire_fetch_slot(
        self,
        url: Any,
        method: Any = "GET",
        request_profile: Any = "default",
    ) -> Optional[threading.Event]:
        """single-flight：返回 None=抢到坑(自行 fetch)；Event=等待先行者结果。"""
        key = self._fetch_slot_key(url, method, request_profile)
        with self._lock:
            running = self._inflight.get(key)
            if running is None:
                self._inflight[key] = threading.Event()
                return None
            return running

    def release_fetch_slot(
        self,
        url: Any,
        method: Any = "GET",
        request_profile: Any = "default",
    ) -> bool:
        key = self._fetch_slot_key(url, method, request_profile)
        with self._lock:
            event = self._inflight.pop(key, None)
        if event is None:
            return False
        event.set()
        return True

    def await_singleflight_leader(
        self,
        url: Any,
        method: Any = "GET",
        request_profile: Any = "default",
        consumer: str = "",
        wait_sec: Optional[float] = None,
    ) -> Tuple[Optional[ResponseRecord], bool]:
        """缓存 miss 后的排队前奏：返回 (可复用响应|None, 是否等待方)。

        等待方拿到先行者结果则直接消费缓存；超时则调用方自行抓取。
        put_response 成功后统一释放槽位唤醒等待方。

        未显式传 wait_sec 时，等待上界收敛到 min(10s, 阶段剩余预算)：
        先行者若拖满预算必然带 deadline 失败，等待方干等满 10s 后再
        重复发一次请求纯属放大；提前止损并保留最小 1s 让快响应可复用。
        """
        waiter = self.acquire_fetch_slot(url, method, request_profile)
        if waiter is None:
            return None, False
        if wait_sec is not None:
            timeout = float(wait_sec)
        else:
            timeout = DEFAULT_SINGLEFLIGHT_WAIT_SEC
            try:
                from app.utils.provider_http import current_stage_remaining_sec
                stage_remaining = current_stage_remaining_sec()
            except Exception as exc:
                stage_remaining = None
                logger.debug(
                    "singleflight stage budget unavailable error_type:%s",
                    type(exc).__name__)
            if stage_remaining is not None:
                timeout = max(1.0, min(timeout, stage_remaining))
        if waiter.wait(timeout):
            cached = self.get_response(
                url, method, request_profile, consumer=consumer)
            if cached is not None:
                return cached, True
        return None, True

    def subscribe_candidate_event(
        self,
        event_type: str,
        handler: Callable[[DiscoveryEvent], None],
    ) -> None:
        """事件订阅 API（同步）。处理器异常被捕获并计数，不影响发布方。"""

        def _safe(event: DiscoveryEvent) -> None:
            try:
                handler(event)
            except Exception as exc:
                self.record_metric("event_listener_error_count")
                logger.warning(
                    "discovery event handler failed type:%s error_type:%s",
                    event.event_type,
                    type(exc).__name__,
                )

        self.subscribe(event_type, _safe)

    def _on_candidates_evicted(self, count, evicted_records) -> None:
        """驱逐前把未完成候选持久化到账本 overflow 区，防止大任务丢待办。"""
        self.record_metric("candidate_evicted_count", count)
        for record in evicted_records or []:
            if str(getattr(record, "status", "") or "") not in ("discovered", "queued"):
                continue
            try:
                self.ledger.upsert(LedgerEntry(
                    idempotency_key="candidate_overflow|{}".format(record.candidate_key),
                    status="pending",
                    payload={
                        "candidate": record.candidate,
                        "candidate_type": record.candidate_type,
                        "source": sorted(record.sources)[:1] or ["ledger_overflow"],
                        "parent_target": record.parent_target,
                    },
                ))
                self.record_metric("candidate_overflow_persisted_count")
            except Exception:
                # overflow 持久化失败只影响恢复完整性，不阻断扫描。
                self.record_metric("candidate_overflow_failed_count")

    def restore_overflow_candidates(self, limit=2000) -> int:
        """任务启动时把账本 overflow 候选读回共享图（幂等 upsert，可重复调用）。"""
        backend = getattr(self.ledger, "backend", None)
        if backend is None or not hasattr(backend, "list_pending"):
            return 0
        try:
            items = backend.list_pending("candidate_overflow|", limit=limit)
        except Exception:
            return 0
        restored = 0
        for _key, payload in items or []:
            candidate = str((payload or {}).get("candidate") or "").strip()
            candidate_type = str((payload or {}).get("candidate_type") or "").strip()
            if not candidate or not candidate_type:
                continue
            try:
                self.register_candidate(
                    "CandidateOverflowRestored",
                    candidate,
                    candidate_type,
                    "ledger_overflow",
                    parent_target=str((payload or {}).get("parent_target") or ""),
                )
                restored += 1
            except Exception:
                continue
        if restored:
            self.record_metric("candidate_overflow_restored_count", restored)
        return restored

    def record_metric(self, name: str, amount: int = 1) -> None:
        with self._lock:
            self.metrics[name] = int(self.metrics.get(name, 0) or 0) + int(amount or 0)

    def idempotency_key(
        self,
        stage: str,
        target: Any,
        scan_profile: Any = "default",
        input_signature: Any = "",
    ) -> str:
        return "{}|{}|{}|{}|{}".format(
            self.task_id,
            str(stage or "").strip(),
            normalize_url(target) or str(target or "").strip(),
            _stable_json_value(scan_profile),
            str(input_signature or ""),
        )

    def get_response(
        self,
        url: Any,
        method: Any = "GET",
        request_profile: Any = "default",
        consumer: str = "",
    ) -> Optional[ResponseRecord]:
        item = self.response_registry.get(url, method, request_profile)
        if item is None:
            # 口径说明：miss ≠ 网络请求（single-flight 跟随者、驱逐后重取
            # 都计 miss），真实发起数看 network_request_count。
            self.record_metric("cache_miss_count")
            return None
        self.record_metric("cache_hit_count")
        consumer_text = str(consumer or "")
        if consumer_text:
            # 复用判定基于记录自身 consumers（随条目驱逐消失），
            # 不再有全局字典的跨条目污染。
            with self._lock:
                had_other_consumers = bool(item.consumers) and consumer_text not in item.consumers
                item.consumers.add(consumer_text)
            if had_other_consumers:
                self.record_metric("cross_strategy_reuse_count")
        return item

    def peek_response(
        self,
        url: Any,
        method: Any = "GET",
        request_profile: Any = "default",
    ) -> Optional[ResponseRecord]:
        """shadow 观测用只读查询，语义见 ResponseRegistry.peek。"""

        return self.response_registry.peek(url, method, request_profile)

    def put_response(
        self,
        url: Any,
        method: Any = "GET",
        request_profile: Any = "default",
        status_code: int = 0,
        headers: Optional[Mapping[str, Any]] = None,
        content_type: str = "",
        body: Any = b"",
        source: str = "",
        consumer: str = "",
    ) -> ResponseRecord:
        cache_key = self.response_registry.key(url, method, request_profile)
        item, created = self.response_registry.put(
            url=url,
            method=method,
            request_profile=request_profile,
            status_code=status_code,
            headers=headers,
            content_type=content_type,
            body=body,
            source=source,
            consumer=consumer,
        )
        if not created:
            # put 时 key 已存在 = 同一资源被再次真实抓取回写
            # （leader 竞态兜底或驱逐后重取），这才是有意义的"重复请求"。
            self.record_metric("actual_duplicate_request_count")
        if created:
            # PageFetched 只对新登记的响应发布一次，重复登记不产生第二份事件。
            self.publish(
                DiscoveryEvent(
                    event_type="PageFetched",
                    candidate=item.normalized_url,
                    candidate_key="response|{}|{}|{}".format(*cache_key),
                    source=str(source or consumer or ""),
                    metadata={
                        "status_code": item.status_code,
                        "content_type": item.content_type,
                        "request_profile": item.request_profile,
                    },
                    task_id=self.task_id,
                )
            )
        # 无论新旧记录，写入即代表本 (url,method,profile) 的在途请求已结束。
        self.release_fetch_slot(url, method, request_profile)
        return item

    def acquire_request(
        self,
        target: Any,
        traffic_class: str,
        wait_sec: Optional[float] = None,
    ) -> Tuple[Optional[RequestLease], str]:
        return self.request_scheduler.acquire_wait(target, traffic_class, wait_sec=wait_sec)

    def mark_candidate_status(
        self,
        candidate: Any,
        candidate_type: str,
        status: str,
        request_profile: Any = "default",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Optional[CandidateRecord]:
        """按候选值迁移状态；未登记的候选返回 None，不隐式创建。"""

        candidate_key = self.candidate_registry.key(candidate, candidate_type, request_profile)
        try:
            return self.candidate_registry.set_status(candidate_key, status, metadata=metadata)
        except KeyError:
            return None

    def subscribe(self, event_type: str, callback: Callable[[DiscoveryEvent], None]) -> None:
        key = str(event_type or "*").strip() or "*"
        if not callable(callback):
            raise TypeError("callback must be callable")
        with self._lock:
            self._subscribers.setdefault(key, []).append(callback)

    def publish(self, event: DiscoveryEvent) -> None:
        callbacks = []
        with self._lock:
            self.event_counts[event.event_type] = int(self.event_counts.get(event.event_type, 0) or 0) + 1
            callbacks.extend(self._subscribers.get(event.event_type, []))
            callbacks.extend(self._subscribers.get("*", []))
        for callback in callbacks:
            try:
                callback(event)
            except Exception as exc:
                self.record_metric("event_listener_error_count")
                logger.warning(
                    "discovery event listener failed task_id:%s event:%s error_type:%s",
                    self.task_id,
                    event.event_type,
                    type(exc).__name__,
                )

    def register_candidate(
        self,
        event_type: str,
        candidate: Any,
        candidate_type: str,
        source: str,
        request_profile: Any = "default",
        source_detail: str = "",
        parent_target: str = "",
        depth: int = 0,
        priority: int = 0,
        status: str = "discovered",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> CandidateRecord:
        item, created, source_added = self.candidate_registry.upsert(
            candidate=candidate,
            candidate_type=candidate_type,
            source=source,
            request_profile=request_profile,
            source_detail=source_detail,
            parent_target=parent_target,
            depth=depth,
            priority=priority,
            status=status,
            metadata=metadata,
        )
        if created:
            self.record_metric("candidate_discovered_count")
        elif source_added:
            self.record_metric("candidate_source_merge_count")
        if created:
            self.publish(
                DiscoveryEvent(
                    event_type=str(event_type or "CandidateDiscovered"),
                    candidate=item.candidate,
                    candidate_key=item.candidate_key,
                    source=str(source or ""),
                    source_detail=str(source_detail or ""),
                    parent_target=str(parent_target or ""),
                    depth=item.depth,
                    priority=item.priority,
                    metadata=dict(metadata or {}),
                    task_id=self.task_id,
                    input_signature=str((metadata or {}).get("input_signature") or ""),
                )
            )
        return item

    def record_waf_signal(
        self,
        target: Any,
        traffic_class: str,
        reason: str = "",
        host_wide: bool = False,
        force: bool = False,
    ) -> Dict[str, Any]:
        result = self.waf_policy.record_signal(target, traffic_class, reason, host_wide, force=force)
        if result.get("blocked"):
            self.record_metric("waf_block_count")
        if result.get("newly_blocked"):
            # 首次进入阻断态才落账本（幂等写去抖），worker 重投后回灌。
            self._persist_waf_block(result)
        self.publish(
            DiscoveryEvent(
                event_type="WafSignalDetected",
                candidate=str(result.get("host") or "") or str(target or "")[:200],
                candidate_key="waf|{}|{}".format(result.get("host", ""), traffic_class),
                source=str(reason or "waf_signal"),
                metadata=dict(result),
                task_id=self.task_id,
            )
        )
        return result

    @staticmethod
    def _waf_block_ledger_key(host: str, category: str) -> str:
        return "waf_block|{}|{}".format(host, category or "*")

    def _persist_waf_block(self, result: Mapping[str, Any]) -> None:
        ledger = self.ledger
        host = str((result or {}).get("host") or "")
        if ledger is None or not host:
            return
        scope = str((result or {}).get("scope") or "")
        category = "*" if scope == "host" else str((result or {}).get("traffic_class") or "")
        try:
            ledger.upsert(LedgerEntry(
                idempotency_key=self._waf_block_ledger_key(host, category),
                status="blocked",
                payload={
                    "host": host,
                    "class": category,
                    "reason": str((result or {}).get("reason") or "")[:160],
                },
            ))
        except Exception as exc:
            self.record_metric("waf_persist_failed_count")
            logger.debug(
                "waf block persist failed host:%s error_type:%s",
                host[:120], type(exc).__name__)

    def restore_waf_state(self) -> int:
        """从账本回灌已确认的 WAF 阻断（worker 重启/消息重投后不留空窗）。

        直接写 WafPolicy，绕开 record_waf_signal：避免重放事件与重复落账。
        """
        ledger = self.ledger
        if ledger is None or not hasattr(ledger, "list_by_prefix"):
            return 0
        try:
            entries = ledger.list_by_prefix("waf_block|", statuses=("blocked",))
        except Exception as exc:
            logger.debug(
                "waf state restore failed error_type:%s", type(exc).__name__)
            return 0
        restored = 0
        for _key, payload in entries or []:
            if not isinstance(payload, dict):
                continue
            host = str(payload.get("host") or "").strip()
            category = str(payload.get("class") or "*").strip()
            if not host:
                continue
            try:
                reason = str(payload.get("reason") or "ledger_restore")
                if category in ("", "*"):
                    self.waf_policy.record_signal(
                        host, "normal", reason=reason, host_wide=True)
                else:
                    self.waf_policy.record_signal(
                        host, category, reason=reason, force=True)
                restored += 1
            except Exception as exc:
                logger.debug(
                    "waf state restore entry skipped host:%s error_type:%s",
                    host[:120], type(exc).__name__)
        if restored:
            self.record_metric("waf_state_restored_count", restored)
            logger.info(
                "waf state restored from ledger task_id:%s blocks:%s",
                self.task_id, restored)
        return restored

    def iter_candidates(
        self,
        candidate_type: Optional[str] = None,
        status: Optional[str] = None,
        source: Optional[str] = None,
        limit: int = 0,
    ) -> List[CandidateRecord]:
        """按优先级和更新时间返回候选，供后续 stage 消费共享候选图。"""

        type_filter = str(candidate_type or "").strip().lower()
        status_filter = str(status or "").strip().lower()
        source_filter = str(source or "").strip()
        items = [
            item
            for item in self.candidate_registry.values()
            if (not type_filter or item.candidate_type == type_filter)
            and (not status_filter or item.status == status_filter)
            and (not source_filter or source_filter in item.sources)
        ]
        items.sort(key=lambda item: (-int(item.priority or 0), -float(item.updated_at or 0.0)))
        if limit and limit > 0:
            return items[: int(limit)]
        return items

    def metrics_snapshot(self) -> Dict[str, int]:
        with self._lock:
            return dict(self.metrics)

    def observation_snapshot(self) -> Dict[str, Any]:
        """收尾观测输出：只做诊断日志，不进入 Mongo 文档，避免改变对外结果。"""

        return {
            "task_id": self.task_id,
            "metrics": self.metrics_snapshot(),
            "events": dict(self.event_counts),
            "responses": len(self.response_registry),
            "candidates": len(self.candidate_registry),
            "candidate_evict_callback_failures": getattr(
                self.candidate_registry, "evict_callback_failed_count", 0),
            "waf": self.waf_policy.snapshot(),
        }

    def is_host_allowed(self, value: Any) -> bool:
        """检查候选是否位于任务允许的主机集合内。空集合表示由上层策略决定。"""

        if not self.allowed_hosts:
            return True
        return url_host(value) in self.allowed_hosts
