"""第三方 provider 请求上下文和轻量限速工具。

该模块不负责 provider 业务，只为现有插件提供统一的请求预算和观测边界。
"""

from contextlib import contextmanager
import threading
import time


_state = threading.local()
_limiter_lock = threading.Lock()
_next_request_at = {}


def _current_context():
    return getattr(_state, "context", None)


def _current_stage_context():
    return getattr(_state, "stage_context", None)


@contextmanager
def stage_execution_context(stage="", budget_sec=None):
    """让同一执行线程中的 provider 请求继承阶段 deadline。"""
    previous = _current_stage_context()
    try:
        budget = max(0.0, float(budget_sec or 0.0))
    except (TypeError, ValueError):
        budget = 0.0

    started_monotonic = time.monotonic()
    parent_deadline = previous.get("deadline") if previous else None
    deadline = started_monotonic + budget if budget > 0 else parent_deadline
    if parent_deadline is not None and deadline is not None:
        deadline = min(deadline, parent_deadline)

    _state.stage_context = {
        "stage": str(stage or "").strip(),
        "started_at": started_monotonic,
        "deadline": deadline,
    }
    try:
        yield _state.stage_context
    finally:
        _state.stage_context = previous


def current_stage_remaining_sec():
    context = _current_stage_context()
    deadline = context.get("deadline") if context else None
    if deadline is None:
        return None
    return max(0.0, deadline - time.monotonic())


def current_provider_remaining_sec():
    context = _current_context()
    deadline = context.get("deadline") if context else None
    if deadline is None:
        return current_stage_remaining_sec()
    remaining = max(0.0, deadline - time.monotonic())
    stage_remaining = current_stage_remaining_sec()
    if stage_remaining is not None:
        return min(remaining, stage_remaining)
    return remaining


@contextmanager
def provider_request_context(provider, mode="", target="", stage_timeout_sec=None):
    """为当前线程设置 provider 请求上下文，并在退出时返回累计 metrics。"""
    previous = _current_context()
    stage_context = _current_stage_context()
    parent_provider_deadline = previous.get("deadline") if previous else None
    try:
        stage_timeout = max(0.0, float(stage_timeout_sec or 0.0))
    except (TypeError, ValueError):
        stage_timeout = 0.0
    started_monotonic = time.monotonic()
    deadline = started_monotonic + stage_timeout if stage_timeout > 0 else None
    stage_deadline = stage_context.get("deadline") if stage_context else None
    if deadline is None:
        deadline_candidates = [
            item for item in (stage_deadline, parent_provider_deadline)
            if item is not None
        ]
        deadline = min(deadline_candidates) if deadline_candidates else None
    else:
        if stage_deadline is not None:
            deadline = min(deadline, stage_deadline)
        if parent_provider_deadline is not None:
            deadline = min(deadline, parent_provider_deadline)

    context = {
        "provider": str(provider or "-").strip() or "-",
        "mode": str(mode or "").strip(),
        "target": str(target or "").strip(),
        "started_at": started_monotonic,
        "deadline": deadline,
        "stats": {
            "request_count": 0,
            "success_count": 0,
            "error_count": 0,
            "timeout_count": 0,
            "retry_count": 0,
            "proxy_fallback_count": 0,
            "network_wait_sec": 0.0,
        },
    }
    _state.context = context
    try:
        yield context["stats"]
    finally:
        context["stats"]["elapsed_sec"] = round(
            max(0.0, time.monotonic() - context["started_at"]), 6
        )
        _state.context = previous


def current_provider_context():
    return _current_context()


def provider_deadline_exceeded():
    context = _current_context()
    deadline = context.get("deadline") if context else None
    if deadline is None:
        stage_context = _current_stage_context()
        deadline = stage_context.get("deadline") if stage_context else None
    return bool(deadline is not None and time.monotonic() >= deadline)


def record_request(success=False, timeout=False, retry=False, proxy_fallback=False, elapsed_sec=0.0):
    context = _current_context()
    if not context:
        return

    stats = context["stats"]
    stats["request_count"] += 1
    stats["network_wait_sec"] = round(
        stats["network_wait_sec"] + max(0.0, float(elapsed_sec or 0.0)), 6
    )
    if success:
        stats["success_count"] += 1
    else:
        stats["error_count"] += 1
    if timeout:
        stats["timeout_count"] += 1
    if retry:
        stats["retry_count"] += 1
    if proxy_fallback:
        stats["proxy_fallback_count"] += 1


def provider_timeout(timeout):
    """将插件自带的宽松 timeout 收敛到全局 provider 请求预算。"""
    try:
        from app.config import Config

        connect_limit = max(
            1.0,
            float(getattr(Config, "SEARCH_PROVIDER_CONNECT_TIMEOUT_SEC", 5) or 5),
        )
        read_limit = max(
            1.0,
            float(getattr(Config, "SEARCH_PROVIDER_READ_TIMEOUT_SEC", 15) or 15),
        )
    except Exception:
        connect_limit, read_limit = 5.0, 15.0

    remaining = current_provider_remaining_sec()
    if isinstance(timeout, (tuple, list)):
        raw_connect = timeout[0] if len(timeout) > 0 else connect_limit
        raw_read = timeout[1] if len(timeout) > 1 else raw_connect
        try:
            raw_connect = float(raw_connect)
        except (TypeError, ValueError):
            raw_connect = connect_limit
        try:
            raw_read = float(raw_read)
        except (TypeError, ValueError):
            raw_read = read_limit
        connect_value = min(max(raw_connect, 0.1), connect_limit)
        read_value = min(max(raw_read, 0.1), read_limit)
        if remaining is not None:
            if remaining <= 0:
                return (0.001, 0.001)
            connect_value = min(connect_value, remaining)
            read_value = min(read_value, remaining)
        return (connect_value, read_value)

    try:
        value = float(timeout)
    except (TypeError, ValueError):
        value = read_limit
    value = min(max(value, 0.1), read_limit)
    if remaining is not None:
        return 0.001 if remaining <= 0 else min(value, remaining)
    return value


def provider_proxy_fallback_enabled():
    try:
        from app.config import Config

        return bool(getattr(Config, "SEARCH_PROVIDER_PROXY_FALLBACK_ENABLE", True))
    except Exception:
        return True


def acquire_provider_slot(provider, interval_sec=0.0):
    """限制并发请求的启动速率，不锁住请求本身。"""
    try:
        interval = max(0.0, float(interval_sec or 0.0))
    except (TypeError, ValueError):
        interval = 0.0
    if interval <= 0:
        return 0.0

    key = str(provider or "-").strip() or "-"
    with _limiter_lock:
        now = time.monotonic()
        wait = max(0.0, _next_request_at.get(key, 0.0) - now)
        _next_request_at[key] = max(now, _next_request_at.get(key, 0.0)) + interval
    if wait > 0:
        time.sleep(wait)
    return wait
