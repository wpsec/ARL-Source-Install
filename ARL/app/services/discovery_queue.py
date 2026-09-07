"""事件驱动的发现队列。

功能说明：
- NewHostQueue 作为 NewHostDiscovered 事件的生产端订阅者：
  情报层(page_intel/urlfinder/js/WIH)登记的 domain 候选经事件进入队列，
  消费方(WIH 主扫描、WAF scope 动态扩展)按容量与去重取用。
- 候选图仍是状态的唯一事实源；队列只做有序镜像，不另存业务结果。
"""

from collections import deque
from threading import RLock

from app import utils

from .discovery_context import DiscoveryEvent, normalize_url, url_host


logger = utils.get_logger()


class NewHostQueue(object):
    """新子域发现队列（任务内、有界、幂等）。"""

    def __init__(self, context, waf_guard=None, max_hosts=50, allowed_hosts=None):
        self.context = context
        self.waf_guard = waf_guard
        self.max_hosts = max(0, int(max_hosts or 0))
        self.allowed_hosts = set(allowed_hosts or set())
        self._hosts = deque()
        self._seen = set()
        self._wih_taken = set()
        self.enabled = self.max_hosts > 0
        if self.enabled and context is not None:
            context.subscribe_candidate_event("NewHostDiscovered", self._on_event)

    def _on_event(self, event: DiscoveryEvent) -> None:
        if not self.enabled:
            return
        host = url_host(event.candidate) or str(event.candidate or "").strip().lower()
        if not host or host in self._seen:
            return
        # 允许集合(任务站点 host/FLD)校验：队列只收任务相关主机。
        if self.allowed_hosts and not self._host_allowed(host):
            return
        if len(self._hosts) >= self.max_hosts:
            self.context.record_metric("new_host_queue_dropped_count")
            return
        self._seen.add(host)
        self._hosts.append(host)
        self.context.record_metric("new_host_discovered_count")
        # 动态扩 WAF 观测范围：新主机同样享有智能跳过/熔断保护。
        if self.waf_guard is not None:
            try:
                self.waf_guard.add_scope_host(host)
            except Exception as exc:
                logger.debug(
                    "waf scope extend failed host:{} error_type:{}".format(
                        host, type(exc).__name__)
                )

    def _host_allowed(self, host: str) -> bool:
        for allowed in self.allowed_hosts:
            if host == allowed or host.endswith("." + allowed):
                return True
        return False

    def pending_hosts(self):
        return list(self._hosts)

    def has_untaken(self):
        """队列中是否还有未被 WIH 取用的主机（收尾 drain 的触发判据）。"""

        return any(host not in self._wih_taken for host in self._hosts)

    def is_queued(self, host: str) -> bool:
        """主机是否曾进入本队列（含已取用）；容量丢弃/范围外主机不在其中。"""

        return str(host or "").strip().lower() in self._seen

    def untaken_hosts(self):
        """尚未被 WIH 取用的主机列表；deque 本身是观测镜像不收缩。"""

        return [host for host in self._hosts if host not in self._wih_taken]

    def take_for_wih(self):
        """为 WIH 主扫描取用尚未注入的 https 目标；每个主机只取一次。"""
        targets = []
        for host in self._hosts:
            if host in self._wih_taken:
                continue
            self._wih_taken.add(host)
            targets.append("https://{}".format(host))
        return targets

    def snapshot(self):
        return {
            "seen": len(self._seen),
            "pending": len(self._hosts),
            "wih_taken": len(self._wih_taken),
        }


class DiscoveryEventConsumer(object):
    """把站点和页面事件转换为阶段可消费的有界队列。"""

    def __init__(self, context, max_events=2000, allowed_hosts=None):
        self.context = context
        self.max_events = max(0, int(max_events or 0))
        self.allowed_hosts = set(allowed_hosts or set())
        self._sites = deque()
        self._pages = deque()
        self._seen = set()
        self._lock = RLock()
        self.enabled = self.max_events > 0 and context is not None
        if self.enabled:
            context.subscribe_candidate_event("SiteDiscovered", self._on_site)
            context.subscribe_candidate_event("PageFetched", self._on_page)

    def _host_allowed(self, host):
        if not self.allowed_hosts:
            return True
        return any(host == allowed or host.endswith("." + allowed) for allowed in self.allowed_hosts)

    def _event_value(self, event):
        value = normalize_url(event.candidate)
        return value or str(event.candidate or "").strip()

    def _enqueue(self, event, queue, metric_name):
        if not self.enabled:
            return
        value = self._event_value(event)
        host = url_host(value)
        if not value or (host and not self._host_allowed(host)):
            return
        event_key = "{}|{}".format(event.event_type, event.candidate_key or value)
        with self._lock:
            if event_key in self._seen:
                return
            if len(queue) >= self.max_events:
                self.context.record_metric("discovery_event_queue_dropped_count")
                return
            self._seen.add(event_key)
            queue.append(event)
        self.context.record_metric(metric_name)

    def _on_site(self, event: DiscoveryEvent):
        self._enqueue(event, self._sites, "site_discovered_event_queued_count")

    def _on_page(self, event: DiscoveryEvent):
        self._enqueue(event, self._pages, "page_fetched_event_queued_count")
        # PageFetched 本身只表达响应已登记；镜像候选使用不同事件名，避免回调递归。
        try:
            self.context.register_candidate(
                event_type="PageFetchedObserved",
                candidate=self._event_value(event),
                candidate_type="page",
                source=str(event.source or "response_registry"),
                parent_target=str(event.parent_target or ""),
                status="fetched",
                metadata={
                    "request_profile": str((event.metadata or {}).get("request_profile") or "default"),
                    "response_observed": True,
                },
            )
        except Exception as exc:
            self.context.record_metric("discovery_event_consumer_error_count")
            logger.debug("page fetched candidate mirror failed error_type:%s", type(exc).__name__)

    @staticmethod
    def _drain(queue, limit=0):
        count = len(queue) if not limit or limit < 0 else min(len(queue), int(limit))
        return [queue.popleft() for _ in range(count)]

    def drain_sites(self, limit=0):
        with self._lock:
            events = self._drain(self._sites, limit)
        for event in events:
            try:
                self.context.mark_candidate_status(event.candidate, "site", "queued")
            except Exception as exc:
                logger.debug("site event status update failed error_type:%s", type(exc).__name__)
        if events:
            self.context.record_metric("site_discovered_event_consumed_count", len(events))
        return events

    def drain_pages(self, limit=0):
        with self._lock:
            events = self._drain(self._pages, limit)
        if events:
            self.context.record_metric("page_fetched_event_consumed_count", len(events))
        return events

    def snapshot(self):
        with self._lock:
            return {
                "enabled": self.enabled,
                "site_pending": len(self._sites),
                "page_pending": len(self._pages),
                "seen": len(self._seen),
                "max_events": self.max_events,
            }
