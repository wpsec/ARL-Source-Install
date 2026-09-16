"""NPoC 请求级取消、deadline 和观测上下文。"""

import contextlib
import threading
import time


_LOCAL = threading.local()


class NPoCRequestSkipped(Exception):
    """请求被主机级 NPoC 熔断跳过。"""


class NPoCExecutionTimeout(TimeoutError):
    """请求、插件或目标达到 deadline。"""


def current_request_context():
    return getattr(_LOCAL, "context", None)


class RequestExecutionContext(object):
    """在线程内提供当前插件的可取消请求上下文。"""

    def __init__(
        self,
        guard=None,
        module="npoc",
        plugin_timeout_sec=0,
        target_timeout_sec=0,
        stage_timeout_sec=0,
    ):
        self.guard = guard
        self.module = str(module or "npoc").strip() or "npoc"
        self.plugin_timeout_sec = max(0.0, float(plugin_timeout_sec or 0))
        self.target_timeout_sec = max(0.0, float(target_timeout_sec or 0))
        self.stage_timeout_sec = max(0.0, float(stage_timeout_sec or 0))
        self.stage_deadline = (
            time.monotonic() + self.stage_timeout_sec
            if self.stage_timeout_sec > 0
            else None
        )
        self.cancel_event = threading.Event()
        self._lock = threading.Lock()
        self._target_deadlines = {}
        self._target_deadline_lock = threading.Lock()
        self._metrics = {
            "request_count": 0,
            "response_count": 0,
            "timeout_count": 0,
            "plugin_timeout_count": 0,
            "target_timeout_count": 0,
            "waf_skipped_count": 0,
        }

    @contextlib.contextmanager
    def bind(self, plugin_name, target, target_deadline=None):
        previous_context = getattr(_LOCAL, "context", None)
        previous_execution = getattr(_LOCAL, "execution", None)
        now = time.monotonic()
        plugin_deadline = (
            now + self.plugin_timeout_sec
            if self.plugin_timeout_sec > 0
            else None
        )
        if target_deadline is None:
            target_deadline = self.target_deadline_for(target, now=now)
        _LOCAL.context = self
        _LOCAL.execution = {
            "plugin_name": str(plugin_name or "").strip(),
            "target": str(target or "").strip(),
            "plugin_deadline": plugin_deadline,
            "target_deadline": target_deadline,
            "plugin_timeout_recorded": False,
            "target_timeout_recorded": False,
            "observed_error_ids": set(),
        }
        try:
            self._raise_if_expired()
            yield self
        finally:
            execution = getattr(_LOCAL, "execution", None) or {}
            if self._deadline_expired(execution.get("plugin_deadline")):
                if not execution.get("plugin_timeout_recorded"):
                    self._record("plugin_timeout_count")
                    execution["plugin_timeout_recorded"] = True
            if self._deadline_expired(execution.get("target_deadline")):
                if not execution.get("target_timeout_recorded"):
                    self._record("target_timeout_count")
                    execution["target_timeout_recorded"] = True
            _LOCAL.context = previous_context
            _LOCAL.execution = previous_execution

    def target_deadline_for(self, target, now=None):
        """为同一目标复用 deadline，避免插件优先调度重复放大目标预算。"""
        if self.target_timeout_sec <= 0:
            return None
        target_key = str(target or "").strip()
        if not target_key:
            return (now or time.monotonic()) + self.target_timeout_sec
        with self._target_deadline_lock:
            deadline = self._target_deadlines.get(target_key)
            if deadline is None:
                deadline = (now or time.monotonic()) + self.target_timeout_sec
                self._target_deadlines[target_key] = deadline
            return deadline

    @staticmethod
    def _deadline_expired(deadline):
        return deadline is not None and time.monotonic() >= deadline

    def _record(self, name, amount=1):
        with self._lock:
            self._metrics[name] = self._metrics.get(name, 0) + int(amount or 0)

    def _current_deadline(self):
        execution = getattr(_LOCAL, "execution", None) or {}
        deadlines = [self.stage_deadline]
        deadlines.extend(
            execution.get(key)
            for key in ("target_deadline", "plugin_deadline")
        )
        deadlines = [item for item in deadlines if item is not None]
        return min(deadlines) if deadlines else None

    def remaining_sec(self):
        deadline = self._current_deadline()
        if deadline is None:
            return None
        return deadline - time.monotonic()

    def _raise_if_expired(self):
        if self.cancel_event.is_set():
            raise NPoCExecutionTimeout("NPoC cancelled")
        remaining = self.remaining_sec()
        if remaining is not None and remaining <= 0:
            raise NPoCExecutionTimeout("NPoC execution deadline exceeded")

    def before_request(self, url):
        self._raise_if_expired()
        if self.guard is not None:
            should_skip, detail = self.guard.should_skip(url, module=self.module)
            if should_skip:
                self._record("waf_skipped_count")
                reason = str((detail or {}).get("reason") or "waf circuit breaker")
                raise NPoCRequestSkipped(reason)
        self._record("request_count")
        return self.remaining_sec()

    def limit_timeout(self, timeout):
        remaining = self.remaining_sec()
        if remaining is None:
            return timeout
        remaining = max(0.1, remaining)
        if isinstance(timeout, (tuple, list)):
            values = []
            for item in list(timeout)[:2]:
                try:
                    values.append(max(0.1, min(float(item), remaining)))
                except (TypeError, ValueError):
                    values.append(remaining)
            return tuple(values or [remaining])
        try:
            return max(0.1, min(float(timeout), remaining))
        except (TypeError, ValueError):
            return remaining

    def observe_response(self, url, response):
        self._record("response_count")
        if self.guard is not None:
            self.guard.observe_response(url, response, module=self.module)

    def observe_error(self, url, error):
        execution = getattr(_LOCAL, "execution", None) or {}
        error_ids = execution.get("observed_error_ids")
        if error_ids is not None:
            error_id = id(error)
            if error_id in error_ids:
                return
            error_ids.add(error_id)
        if self.guard is not None:
            if self._is_timeout_error(error):
                self.guard.observe_timeout(url, error, module=self.module)
            else:
                reset_timeout = getattr(self.guard, "reset_timeout", None)
                if callable(reset_timeout):
                    reset_timeout(url, module=self.module)
        if self._is_timeout_error(error):
            self._record("timeout_count")

    @staticmethod
    def _is_timeout_error(error):
        if isinstance(error, (TimeoutError, IOError)):
            text = str(error or "").lower()
            return isinstance(error, TimeoutError) or any(
                token in text for token in ("timeout", "timed out", "time out")
            )
        name = type(error).__name__.lower()
        text = str(error or "").lower()
        return "timeout" in name or any(
            token in text for token in ("timeout", "timed out", "time out")
        )

    def deadline_reached(self):
        if self.cancel_event.is_set():
            return True
        remaining = self.remaining_sec()
        return remaining is not None and remaining <= 0

    def snapshot(self):
        with self._lock:
            return dict(self._metrics)
