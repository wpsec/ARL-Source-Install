"""
WAF 智能跳过守卫

功能说明：
- 按 host 追踪疑似 WAF 拦截信号
- 达到阈值后对该 host 的后续 HTTP 请求本地跳过
- 输出可落库的统计摘要，便于任务结果提示
"""
import re
import threading
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from requests import Response
from requests.structures import CaseInsensitiveDict

from app import utils

logger = utils.get_logger()


class WAFSmartSkipGuard(object):
    """
    按任务维度执行 WAF 智能跳过。
    """

    # 常见被拦截状态码（弱信号）
    WAF_STATUS_CODES = {403, 406, 429, 503}
    # Header 命中这些关键字视为强信号
    STRONG_HEADER_KEYWORDS = (
        "cf-ray",
        "x-sucuri-id",
        "x-waf-",
        "x-akamai",
        "x-cdn-waf",
        "x-denied-reason",
        "x-firewall",
    )
    # Body 命中这些关键字视为强信号
    STRONG_BODY_KEYWORDS = (
        "access denied",
        "request blocked",
        "forbidden by security policy",
        "security check",
        "web application firewall",
        "cloudflare ray id",
        "访问拦截",
        "网络防火墙",
        "请求含有不合法的参数",
        "您的请求已被拦截",
    )
    MAX_BODY_CHECK_BYTES = 4096

    def __init__(
        self,
        enabled: bool = False,
        task_id: str = "",
        scope_sites: Optional[List[str]] = None,
        weak_block_threshold: int = 3,
    ):
        self.enabled = bool(enabled)
        self.task_id = str(task_id or "").strip()
        self.scope_hosts = self._build_scope_hosts(scope_sites or [])
        self.weak_block_threshold = max(2, int(weak_block_threshold or 3))

        self._lock = threading.Lock()
        self._host_state: Dict[str, Dict] = {}
        self._event_total = 0

    @staticmethod
    def _extract_host(value: str) -> str:
        text = str(value or "").strip()
        if not text:
            return ""

        parsed = urlparse(text)
        host = str(parsed.hostname or "").strip().lower().rstrip(".")
        if host:
            return host

        parsed = urlparse("//{}".format(text))
        return str(parsed.hostname or "").strip().lower().rstrip(".")

    def _build_scope_hosts(self, scope_sites: List[str]) -> set:
        hosts = set()
        for site in scope_sites:
            host = self._extract_host(site)
            if host:
                hosts.add(host)
        return hosts

    def _in_scope(self, host: str) -> bool:
        if not host:
            return False
        if not self.scope_hosts:
            return True
        return host in self.scope_hosts

    def _get_state(self, host: str) -> Dict:
        state = self._host_state.get(host)
        if state is None:
            state = {
                "host": host,
                "request_count": 0,
                "hit_count": 0,
                "skip_count": 0,
                "blocked": False,
                "reason": "",
                "rule": "",
                "module": "",
                "last_status": 0,
                "last_url": "",
                "signals": [],
            }
            self._host_state[host] = state
        return state

    @classmethod
    def _collect_signals(cls, response: Response) -> Tuple[bool, List[str]]:
        signals: List[str] = []
        strong_hit = False

        status_code = int(getattr(response, "status_code", 0) or 0)
        if status_code in cls.WAF_STATUS_CODES:
            signals.append("status:{}".format(status_code))

        header_obj = getattr(response, "headers", {}) or {}
        header_names = [str(name or "").strip().lower() for name in header_obj.keys()]
        header_text = " ".join(header_names)
        server_text = str(header_obj.get("Server", "") or "").strip().lower()
        if server_text:
            header_text = "{} {}".format(header_text, server_text)

        for keyword in cls.STRONG_HEADER_KEYWORDS:
            if keyword in header_text:
                signals.append("header:{}".format(keyword))
                strong_hit = True

        body = bytes(getattr(response, "content", b"") or b"")[: cls.MAX_BODY_CHECK_BYTES]
        if body:
            body_text = re.sub(r"\s+", " ", body.decode("utf-8", errors="ignore").lower())
            for keyword in cls.STRONG_BODY_KEYWORDS:
                if keyword in body_text:
                    signals.append("body:{}".format(keyword))
                    strong_hit = True
                    break

        return strong_hit, signals

    def should_skip(self, url: str) -> Tuple[bool, Dict]:
        if not self.enabled:
            return False, {}

        host = self._extract_host(url)
        if not self._in_scope(host):
            return False, {}

        with self._lock:
            state = self._get_state(host)
            if not state.get("blocked"):
                return False, {}

            state["skip_count"] += 1
            self._event_total += 1
            detail = {
                "host": host,
                "reason": state.get("reason", ""),
                "rule": state.get("rule", ""),
                "module": state.get("module", ""),
            }
            return True, detail

    @staticmethod
    def build_skip_response(url: str, detail: Optional[Dict] = None) -> Response:
        detail = detail or {}
        response = Response()
        response.status_code = 444
        response.url = str(url or "")
        response.reason = "WAF SMART SKIP"
        response._content = b""
        response.encoding = "utf-8"
        response.headers = CaseInsensitiveDict(
            {
                "X-ARL-WAF-SMART-SKIP": "1",
                "X-ARL-WAF-SMART-SKIP-HOST": str(detail.get("host", "") or ""),
                "X-ARL-WAF-SMART-SKIP-REASON": str(detail.get("reason", "") or ""),
            }
        )
        return response

    def observe_response(self, url: str, response: Response, module: str = ""):
        if not self.enabled or response is None:
            return

        host = self._extract_host(url)
        if not self._in_scope(host):
            return

        # 本地跳过构造响应无需再次判定
        if str((getattr(response, "headers", {}) or {}).get("X-ARL-WAF-SMART-SKIP", "")) == "1":
            return

        module_name = str(module or "").strip()
        status_code = int(getattr(response, "status_code", 0) or 0)
        strong_hit, signals = self._collect_signals(response)
        weak_hit = status_code in self.WAF_STATUS_CODES

        with self._lock:
            state = self._get_state(host)
            state["request_count"] += 1
            state["last_status"] = status_code
            state["last_url"] = str(url or "")

            if weak_hit or strong_hit:
                state["hit_count"] += 1
                state["signals"] = signals[-4:]
                state["module"] = module_name

            if state.get("blocked"):
                return

            should_block = False
            rule = ""
            if strong_hit:
                should_block = True
                rule = "strong_signal"
            elif weak_hit and state["hit_count"] >= self.weak_block_threshold:
                should_block = True
                rule = "weak_status_threshold"

            if not should_block:
                return

            state["blocked"] = True
            state["rule"] = rule
            if strong_hit and signals:
                state["reason"] = ",".join(signals[:3])
            else:
                state["reason"] = "status:{} hit_count:{}".format(status_code, state["hit_count"])
            self._event_total += 1

            logger.info(
                "task_id:{} waf smart skip block host:{} module:{} rule:{} reason:{} url:{}".format(
                    self.task_id,
                    host,
                    module_name or "-",
                    rule,
                    state.get("reason", ""),
                    state.get("last_url", ""),
                )
            )

    def is_blocked_host(self, host: str) -> bool:
        normalized_host = self._extract_host(host)
        if not normalized_host:
            return False
        with self._lock:
            state = self._host_state.get(normalized_host)
            return bool(state and state.get("blocked"))

    def filter_targets(self, targets: List[str]) -> Tuple[List[str], int]:
        if not self.enabled:
            return list(targets or []), 0

        keep_targets = []
        skipped = 0
        for target in targets or []:
            host = self._extract_host(target)
            if host and self.is_blocked_host(host):
                skipped += 1
                continue
            keep_targets.append(target)
        return keep_targets, skipped

    def summary(self) -> Dict:
        with self._lock:
            blocked_hosts = []
            skip_request_count = 0
            for host, state in self._host_state.items():
                skip_request_count += int(state.get("skip_count", 0) or 0)
                if not state.get("blocked"):
                    continue

                blocked_hosts.append(
                    {
                        "host": host,
                        "reason": state.get("reason", ""),
                        "rule": state.get("rule", ""),
                        "module": state.get("module", ""),
                        "hit_count": int(state.get("hit_count", 0) or 0),
                        "skip_count": int(state.get("skip_count", 0) or 0),
                        "last_status": int(state.get("last_status", 0) or 0),
                        "last_url": state.get("last_url", ""),
                    }
                )

            blocked_hosts.sort(key=lambda item: (item.get("skip_count", 0), item.get("hit_count", 0)), reverse=True)
            return {
                "enabled": self.enabled,
                "blocked_host_count": len(blocked_hosts),
                "skip_request_count": int(skip_request_count),
                "blocked_hosts": blocked_hosts,
                "event_total": int(self._event_total),
            }

    def summary_text(self) -> str:
        data = self.summary()
        if not data.get("enabled"):
            return "未启用"
        blocked_count = int(data.get("blocked_host_count", 0) or 0)
        skipped = int(data.get("skip_request_count", 0) or 0)
        if blocked_count <= 0:
            return "已启用，未触发跳过"

        host_preview = []
        for item in data.get("blocked_hosts", [])[:3]:
            host = str(item.get("host", "") or "").strip()
            if host:
                host_preview.append(host)
        suffix = "，主机:{}".format(",".join(host_preview)) if host_preview else ""
        return "已启用，阻断主机:{}，跳过请求:{}{}".format(blocked_count, skipped, suffix)
