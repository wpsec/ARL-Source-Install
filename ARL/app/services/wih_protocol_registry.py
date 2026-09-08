"""WIH 非 REST 协议的有界观察注册表。

该注册表只接收已经产生的观测事件，不发起 WebSocket、SSE、GraphQL 或 SOAP
请求。GraphQL/SOAP 的可调用 Endpoint 仍进入计划 6 的 ApiCandidateRegistry；
这里保存协议层的握手、操作和事件摘要，避免为 WebSocket/SSE 强行套用 REST
资产模型。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

from .api_candidate_registry import host_in_scope
from .api_unified_models import sanitize_url_secrets
from .discovery_context import normalize_url, url_host


PROTOCOLS = ("graphql", "soap", "websocket", "sse")
STATUSES = ("observed", "pending", "blocked", "failed", "skipped")
_STATUS_PRIORITY = {
    "skipped": 0,
    "pending": 1,
    "failed": 2,
    "blocked": 2,
    "observed": 3,
}
DEFAULT_MAX_OBSERVATIONS = 512
MAX_SOURCES_PER_OBSERVATION = 32
MAX_EVIDENCE_IDS_PER_OBSERVATION = 32


@dataclass
class ProtocolObservation:
    url: str
    protocol: str
    event: str = "handshake"
    method: str = ""
    operation: str = ""
    source: str = "runtime"
    sources: set = field(default_factory=set)
    evidence_ids: set = field(default_factory=set)
    status: str = "observed"
    confidence: int = 50

    def __post_init__(self) -> None:
        raw_url = sanitize_url_secrets(self.url)
        self.url = _normalize_protocol_url(raw_url)
        if not self.url:
            raise ValueError("protocol observation url must not be empty")
        self.protocol = str(self.protocol or "").strip().lower()
        if self.protocol not in PROTOCOLS:
            raise ValueError("unsupported protocol: {}".format(self.protocol))
        self.event = _safe_label(self.event, 64) or "handshake"
        self.method = str(self.method or "").strip().upper()[:16]
        self.operation = _safe_label(self.operation, 128)
        self.source = _safe_label(self.source, 64) or "runtime"
        self.sources = _safe_set(self.sources, self.source, 32, 64)
        self.evidence_ids = _safe_set(self.evidence_ids, "", 32, 128)
        self.status = str(self.status or "observed").strip().lower()
        if self.status not in STATUSES:
            self.status = "observed"
        try:
            self.confidence = max(0, min(100, int(self.confidence or 0)))
        except (TypeError, ValueError):
            self.confidence = 0

    @property
    def idempotency_key(self) -> str:
        # 握手是连接级观测，operation 只是可能附带的首条消息信息；把它
        # 放进握手幂等键会让不同采集器对同一连接产生重复资产。真正的
        # operation 事件仍保留 operation 维度，避免吞并同一地址的不同操作。
        operation_key = "" if self.event == "handshake" else self.operation
        return "|".join((self.protocol, self.url, self.method, self.event, operation_key))

    def add_source(self, source: Any) -> bool:
        value = _safe_label(source, 64)
        if not value or value in self.sources:
            return False
        self.sources.add(value)
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol_id": _digest(self.idempotency_key),
            "url": self.url,
            "protocol": self.protocol,
            "event": self.event,
            "method": self.method,
            "operation": self.operation,
            "source": self.source,
            "sources": sorted(self.sources),
            "evidence_ids": sorted(self.evidence_ids),
            "status": self.status,
            "confidence": self.confidence,
            "host": url_host(self.url),
        }


class ProtocolRegistry:
    """任务内协议观察登记，范围闸和来源合并集中在此处。"""

    def __init__(
        self,
        allowed_hosts: Optional[Iterable[str]] = None,
        max_observations: int = DEFAULT_MAX_OBSERVATIONS,
    ):
        self.allowed_hosts = allowed_hosts
        try:
            self.max_observations = max(0, int(max_observations))
        except (TypeError, ValueError):
            self.max_observations = DEFAULT_MAX_OBSERVATIONS
        self._items: Dict[str, ProtocolObservation] = {}
        self.out_of_scope_count = 0
        self.created_count = 0
        self.merged_count = 0
        self.capacity_count = 0

    def register(self, observation: ProtocolObservation) -> Tuple[Optional[ProtocolObservation], str]:
        if not host_in_scope(observation.url, self.allowed_hosts):
            self.out_of_scope_count += 1
            return None, "out_of_scope"
        key = observation.idempotency_key
        existing = self._items.get(key)
        if existing is None:
            if len(self._items) >= self.max_observations:
                self.capacity_count += 1
                return None, "capacity"
            self._items[key] = observation
            self.created_count += 1
            return observation, "created"
        self.merged_count += 1
        existing.sources.update(observation.sources)
        existing.evidence_ids.update(observation.evidence_ids)
        existing.sources = set(sorted(existing.sources)[:MAX_SOURCES_PER_OBSERVATION])
        existing.evidence_ids = set(
            sorted(existing.evidence_ids)[:MAX_EVIDENCE_IDS_PER_OBSERVATION]
        )
        if not existing.operation and observation.operation:
            existing.operation = observation.operation
        if _STATUS_PRIORITY.get(observation.status, 0) > _STATUS_PRIORITY.get(existing.status, 0):
            existing.status = observation.status
        existing.confidence = max(existing.confidence, observation.confidence)
        return existing, "merged"

    def snapshot(self) -> list:
        return [item.to_dict() for item in sorted(self._items.values(), key=lambda item: item.idempotency_key)]

    def __len__(self) -> int:
        return len(self._items)


def get_or_create_protocol_registry(discovery_context: Any) -> Optional[ProtocolRegistry]:
    if discovery_context is None:
        return None
    registry = getattr(discovery_context, "protocol_registry", None)
    if isinstance(registry, ProtocolRegistry):
        return registry
    allowed_hosts = getattr(discovery_context, "allowed_hosts", None)
    registry = ProtocolRegistry(allowed_hosts=allowed_hosts)
    try:
        setattr(discovery_context, "protocol_registry", registry)
    except (AttributeError, TypeError):
        return None
    return registry


def ingest_protocol_events(
    registry: ProtocolRegistry, events: Iterable[Mapping[str, Any]]
) -> Dict[str, int]:
    summary = {
        "created": 0,
        "merged": 0,
        "out_of_scope": 0,
        "capacity": 0,
        "skipped": 0,
    }
    for event in events or ():
        if not isinstance(event, Mapping):
            summary["skipped"] += 1
            continue
        try:
            observation = ProtocolObservation(
                url=event.get("url"),
                protocol=event.get("protocol"),
                event=event.get("event") or "handshake",
                method=event.get("method") or "",
                operation=event.get("operation") or event.get("operation_name") or "",
                source=event.get("source") or "runtime",
                sources=event.get("sources") or (),
                evidence_ids=event.get("evidence_ids") or (),
                status=event.get("status") or "observed",
                confidence=event.get("confidence", 50),
            )
            _stored, outcome = registry.register(observation)
            summary[outcome] = summary.get(outcome, 0) + 1
        except (TypeError, ValueError, KeyError):
            summary["skipped"] += 1
    return summary


def _safe_label(value: Any, limit: int) -> str:
    return str(value or "").strip().replace("\n", " ").replace("\r", " ")[:limit]


def _safe_set(values: Any, first: str, limit: int, item_limit: int) -> set:
    source_values = []
    if first:
        source_values.append(first)
    if isinstance(values, (str, bytes)):
        source_values.append(values)
    elif values:
        source_values.extend(list(values)[:limit])
    return {
        _safe_label(value, item_limit)
        for value in source_values
        if _safe_label(value, item_limit)
    }


def _digest(value: str) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8", "replace")).hexdigest()[:32]


def _normalize_protocol_url(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if text.lower().startswith(("http://", "https://")):
        normalized = normalize_url(text)[:2048]
        return normalized if url_host(normalized) else ""
    try:
        parsed = urlsplit(text)
    except ValueError:
        return ""
    scheme = parsed.scheme.lower()
    if scheme not in {"ws", "wss"} or not parsed.hostname:
        return ""
    host = parsed.hostname.lower().rstrip(".")
    if ":" in host and not host.startswith("["):
        host = "[{}]".format(host)
    try:
        port = parsed.port
    except ValueError:
        return ""
    default_port = (scheme == "ws" and port == 80) or (scheme == "wss" and port == 443)
    netloc = host if not port or default_port else "{}:{}".format(host, port)
    return urlunsplit((scheme, netloc, parsed.path or "/", parsed.query, ""))[:2048]


__all__ = [
    "PROTOCOLS",
    "ProtocolObservation",
    "ProtocolRegistry",
    "get_or_create_protocol_registry",
    "ingest_protocol_events",
]
