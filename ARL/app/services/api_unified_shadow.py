"""API 请求复用的 shadow 观测（计划 6 第 2 批）。

只记指标、不改行为：文档获取与 Endpoint 探测在真实请求前用
`peek_response`（无副作用只读）对照统一 profile 桶与现行 `html_get`
桶，产出总请求/唯一请求/缓存命中/重复请求/跨策略复用计数。
指标随 `DiscoveryContext.metrics` 进入 `commonTask` 的诊断日志
（`observation_snapshot`），不落 Mongo、不改变任何扫描输出。

第 3 批起统一层真实接管获取路径后，本模块的 api_doc 桶命中数
（*_cross_bucket_hit_total）应从 0 变为有效值，作为切换生效的证据锚。
"""

from __future__ import annotations

import threading
import weakref
from typing import Any, Dict, FrozenSet, Optional

from app.services.discovery_context import DiscoveryContext, normalize_url

DOCUMENT_PROFILE = "api_doc"
LEGACY_SHARED_PROFILE = "html_get"
DOCUMENT_CONSUMER = "api_doc_scan"
PROBE_CONSUMER = "wih_endpoint_probe"

_OBSERVER_LOCK = threading.Lock()
# 观测状态挂在 context 生命周期上：任务结束即释放，不引入新的全局存活。
_SEEN_STATE: "weakref.WeakKeyDictionary[DiscoveryContext, Dict[str, Any]]" = (
    weakref.WeakKeyDictionary()
)


def _state_for(context: DiscoveryContext) -> Dict[str, Any]:
    with _OBSERVER_LOCK:
        state = _SEEN_STATE.get(context)
        if state is None:
            state = {"seen_documents": set(), "seen_probes": set(), "lock": threading.Lock()}
            _SEEN_STATE[context] = state
        return state


def _is_foreign_consumer(consumers: FrozenSet[str], consumer: str) -> bool:
    return bool(consumers) and bool(consumers - {consumer})


def _bump(context: DiscoveryContext, name: str) -> None:
    context.record_metric(name)


def shadow_document_fetch_start(
    context: Optional[DiscoveryContext],
    url: str,
    consumer: str = DOCUMENT_CONSUMER,
) -> None:
    """文档真实获取发起前调用；任何观测失败不得影响扫描主链路。"""

    if context is None:
        return
    try:
        normalized = normalize_url(url)
        if not normalized:
            return
        _bump(context, "api_document_fetch_total")
        state = _state_for(context)
        with state["lock"]:
            seen = state["seen_documents"]
            if normalized in seen:
                _bump(context, "api_document_repeat_total")
            else:
                seen.add(normalized)
                _bump(context, "api_document_unique_total")

        # 对照桶查询必须在 fetch_text 之前：之后现行链路必然登记自身为 consumer。
        legacy = context.peek_response(normalized, "GET", LEGACY_SHARED_PROFILE)
        if legacy is not None:
            _bump(context, "api_document_cache_hit_total")
            if _is_foreign_consumer(legacy.consumers, consumer):
                _bump(context, "api_document_cross_strategy_reuse_total")
        unified = context.peek_response(normalized, "GET", DOCUMENT_PROFILE)
        if unified is not None:
            _bump(context, "api_document_cross_bucket_hit_total")
        if legacy is None and unified is None:
            _bump(context, "api_document_expected_network_total")
    except Exception as exc:
        _observe_degraded(context, exc)


def shadow_document_fetch_result(
    context: Optional[DiscoveryContext],
    url: str,
    ok: bool,
) -> None:
    if context is None:
        return
    try:
        if not ok:
            context.record_metric("api_document_fetch_empty_total")
    except Exception as exc:
        _observe_degraded(context, exc)


def shadow_probe_start(
    context: Optional[DiscoveryContext],
    url: str,
    method: str = "GET",
    profile: str = LEGACY_SHARED_PROFILE,
    consumer: str = PROBE_CONSUMER,
) -> None:
    """Endpoint 探测（含缓存解析前）观测。"""

    if context is None:
        return
    try:
        normalized = normalize_url(url)
        if not normalized:
            return
        method_text = str(method or "GET").strip().upper() or "GET"
        _bump(context, "api_probe_total")
        state = _state_for(context)
        probe_key = "{}|{}|{}".format(normalized, method_text, profile)
        with state["lock"]:
            seen = state["seen_probes"]
            if probe_key in seen:
                _bump(context, "api_probe_repeat_total")
            else:
                seen.add(probe_key)
                _bump(context, "api_probe_unique_total")

        cached = context.peek_response(normalized, method_text, profile)
        if cached is not None:
            _bump(context, "api_probe_cache_hit_total")
            if _is_foreign_consumer(cached.consumers, consumer):
                _bump(context, "api_probe_cross_strategy_reuse_total")
        else:
            _bump(context, "api_probe_expected_network_total")
    except Exception as exc:
        _observe_degraded(context, exc)


def shadow_probe_failed(context: Optional[DiscoveryContext]) -> None:
    if context is None:
        return
    try:
        context.record_metric("api_probe_failed_total")
    except Exception as exc:
        _observe_degraded(context, exc)


def _observe_degraded(context: DiscoveryContext, exc: Exception) -> None:
    # 观测失败不阻断扫描，但必须在指标面显影（禁止静默吞）。
    try:
        context.record_metric("degraded_count")
        context.record_metric("api_shadow_error_total")
    except Exception:
        pass


__all__ = [
    "DOCUMENT_PROFILE",
    "LEGACY_SHARED_PROFILE",
    "DOCUMENT_CONSUMER",
    "PROBE_CONSUMER",
    "shadow_document_fetch_start",
    "shadow_document_fetch_result",
    "shadow_probe_start",
    "shadow_probe_failed",
]
