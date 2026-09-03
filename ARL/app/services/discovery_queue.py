"""事件驱动的发现队列。

功能说明：
- NewHostQueue 作为 NewHostDiscovered 事件的生产端订阅者：
  情报层(page_intel/urlfinder/js/WIH)登记的 domain 候选经事件进入队列，
  消费方(WIH 主扫描、WAF scope 动态扩展)按容量与去重取用。
- 候选图仍是状态的唯一事实源；队列只做有序镜像，不另存业务结果。
"""

from collections import deque

from app import utils

from .discovery_context import DiscoveryEvent, url_host


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
