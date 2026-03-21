"""
WAF 观测与智能跳过守卫。

功能说明：
- 按 host 追踪疑似 WAF 拦截信号与厂商特征
- 在保留智能跳过能力的同时，输出可解释的观测摘要
- 为主动渗透链路提供有限的 Header/节流型试探绕过入口
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
    按任务维度执行 WAF 观测、智能跳过与有限试探绕过。
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
        "x-iinfo",
        "x-safedog",
        "x-yunaq",
        "x-dbapp",
        "x-chaitin",
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
        "safeline",
        "yundun waf",
    )
    # 仅允许主动渗透链路做有限试探绕过，其余链路继续以保守跳过为主。
    ACTIVE_BYPASS_MODULES = {"penetration_test"}
    BOT_USER_AGENTS = (
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        "Mozilla/5.0 (compatible; DuckDuckBot/1.0; +http://duckduckgo.com/duckduckbot.html)",
    )
    # 厂商画像按“通用安全知识 + 项目自有观测”组织，只保留可解释 token，不直接引入外部规则文件。
    WAF_VENDOR_PROFILES = {
        "Cloudflare": ("cf-ray", "cf-cache-status", "__cf_bm", "cloudflare"),
        "Akamai": ("akamai", "akamaighost", "x-akamai", "aka_debug"),
        "AWS WAF": ("x-amzn-trace-id", "x-amz-cf-id", "awselb", "aws-waf"),
        "Imperva": ("imperva", "incap_ses", "visid_incap", "x-iinfo"),
        "Sucuri": ("sucuri", "x-sucuri-id", "x-sucuri-cache", "cloudproxy"),
        "ModSecurity": ("modsecurity", "mod_security", "nocdwatcher"),
        "F5 BIG-IP": ("bigipserver", "x-wa-info", "big-ip"),
        "Barracuda": ("barracuda", "barra_counter_session", "x-barracuda"),
        "Citrix": ("citrix", "x-citrix", "ns_af"),
        "Fortinet": ("fortigate", "fortiweb", "fortinet", "x-fortinet"),
        "Radware": ("radware", "x-rdwr", "x-radware"),
        "Wordfence": ("wordfence", "wfvt_", "wfwaf"),
        "阿里云WAF": ("aliyungf_tc", "x-aliyun", "aliyun waf", "waf.aliyun"),
        "腾讯云WAF": ("x-tencent", "x-qcloud", "waf.tencent", "tencent waf"),
        "华为云WAF": ("x-hw", "huaweicloud", "waf.huaweicloud", "huawei waf"),
        "百度云WAF": ("x-bce", "baiduyun", "yunjiasu", "baidu waf"),
        "安全狗": ("safedog", "x-safedog", "safedog-site", "waf/2.0"),
        "云锁": ("yunsuo", "x-yunsuo", "yunsuo_session"),
        "360网站卫士": ("360safe", "360waf", "x-360waf", "360wzb"),
        "知道创宇": ("yunaq", "x-yunaq", "knownsec", "zhidaochuangyu"),
        "安恒WAF": ("dbapp", "x-dbapp", "dbappsecurity"),
        "长亭WAF": ("chaitin", "safeline", "x-chaitin"),
        "绿盟WAF": ("nsfocus", "x-nsfocus", "nsfocus waf"),
        "启明星辰WAF": ("venustech", "x-venustech", "venustech waf"),
        "深信服WAF": ("sangfor", "x-sangfor", "sangfor waf"),
        "天融信WAF": ("topsec", "x-topsec", "topsec waf"),
    }
    MAX_BODY_CHECK_BYTES = 4096

    def __init__(
        self,
        enabled: bool = False,
        task_id: str = "",
        scope_sites: Optional[List[str]] = None,
        weak_block_threshold: int = 3,
        smart_skip_enabled: Optional[bool] = None,
        bypass_enabled: bool = False,
        bypass_attempt_limit: int = 3,
    ):
        self.enabled = bool(enabled)
        self.smart_skip_enabled = bool(enabled if smart_skip_enabled is None else smart_skip_enabled)
        self.bypass_enabled = bool(bypass_enabled)
        self.task_id = str(task_id or "").strip()
        self.scope_hosts = self._build_scope_hosts(scope_sites or [])
        self.weak_block_threshold = max(2, int(weak_block_threshold or 3))
        self.bypass_attempt_limit = max(1, int(bypass_attempt_limit or 3))

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

    @staticmethod
    def _confidence_rank(level: str) -> int:
        rank_map = {"low": 1, "medium": 2, "high": 3}
        return rank_map.get(str(level or "").strip().lower(), 0)

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
                "waf_name": "",
                "waf_confidence": "",
                "waf_evidence": [],
                "bypass_attempts": 0,
                "bypass_success_count": 0,
            }
            self._host_state[host] = state
        return state

    @classmethod
    def _extract_response_context(cls, response: Response) -> Tuple[List[Tuple[str, str]], str, str]:
        header_obj = getattr(response, "headers", {}) or {}
        header_pairs = []
        text_parts = []
        for name, value in getattr(header_obj, "items", lambda: [])():
            key_text = str(name or "").strip().lower()
            value_text = str(value or "").strip().lower()
            if not key_text:
                continue
            header_pairs.append((key_text, value_text))
            text_parts.append(key_text)
            if value_text:
                text_parts.append(value_text)

        body = bytes(getattr(response, "content", b"") or b"")[: cls.MAX_BODY_CHECK_BYTES]
        body_text = ""
        if body:
            body_text = re.sub(r"\s+", " ", body.decode("utf-8", errors="ignore").lower())
            if body_text:
                text_parts.append(body_text)

        combined_text = " ".join(text_parts)
        return header_pairs, body_text, combined_text

    @classmethod
    def _collect_signals(cls, response: Response) -> Tuple[bool, List[str], str]:
        signals: List[str] = []
        strong_hit = False

        status_code = int(getattr(response, "status_code", 0) or 0)
        if status_code in cls.WAF_STATUS_CODES:
            signals.append("status:{}".format(status_code))

        header_pairs, body_text, combined_text = cls._extract_response_context(response)

        for keyword in cls.STRONG_HEADER_KEYWORDS:
            if keyword in combined_text:
                signals.append("header:{}".format(keyword))
                strong_hit = True

        for keyword in cls.STRONG_BODY_KEYWORDS:
            if keyword in body_text:
                signals.append("body:{}".format(keyword))
                strong_hit = True
                break

        return strong_hit, signals[:6], combined_text

    @classmethod
    def _identify_vendor(cls, combined_text: str) -> Tuple[str, str, List[str]]:
        normalized = str(combined_text or "").strip().lower()
        if not normalized:
            return "", "", []

        best_name = ""
        best_evidence: List[str] = []
        for waf_name, keywords in cls.WAF_VENDOR_PROFILES.items():
            matched = []
            for keyword in keywords:
                key_text = str(keyword or "").strip().lower()
                if key_text and key_text in normalized:
                    matched.append(key_text)

            if len(matched) > len(best_evidence):
                best_name = waf_name
                best_evidence = matched[:4]

        if not best_name:
            return "", "", []

        match_count = len(best_evidence)
        if match_count >= 3:
            confidence = "high"
        elif match_count >= 2:
            confidence = "medium"
        else:
            confidence = "low"

        return best_name, confidence, best_evidence

    def _module_allows_bypass(self, module: str) -> bool:
        if not self.bypass_enabled:
            return False
        module_name = str(module or "").strip()
        return module_name in self.ACTIVE_BYPASS_MODULES

    def _can_apply_bypass(self, state: Dict, module: str) -> bool:
        if not self._module_allows_bypass(module):
            return False
        if not state.get("blocked"):
            return False
        if int(state.get("bypass_success_count", 0) or 0) > 0:
            return True
        return int(state.get("bypass_attempts", 0) or 0) < self.bypass_attempt_limit

    @staticmethod
    def _pick_user_agent(host: str) -> str:
        host_text = str(host or "").strip().lower()
        if not host_text:
            return WAFSmartSkipGuard.BOT_USER_AGENTS[0]
        index = sum(ord(ch) for ch in host_text) % len(WAFSmartSkipGuard.BOT_USER_AGENTS)
        return WAFSmartSkipGuard.BOT_USER_AGENTS[index]

    def should_skip(self, url: str, module: str = "") -> Tuple[bool, Dict]:
        if not self.enabled:
            return False, {}

        host = self._extract_host(url)
        if not self._in_scope(host):
            return False, {}

        with self._lock:
            state = self._get_state(host)
            if not state.get("blocked"):
                return False, {}

            if self._can_apply_bypass(state, module):
                return False, {}

            if not self.smart_skip_enabled:
                return False, {}

            state["skip_count"] += 1
            self._event_total += 1
            detail = {
                "host": host,
                "reason": state.get("reason", ""),
                "rule": state.get("rule", ""),
                "module": state.get("module", ""),
                "waf_name": state.get("waf_name", ""),
            }
            return True, detail

    def prepare_request(
        self,
        url: str,
        module: str = "",
        method: str = "GET",
        headers: Optional[Dict] = None,
    ) -> Tuple[Dict, float, Dict]:
        """
        为允许试探绕过的主动模块补充轻量 Header 与节流参数。
        """
        prepared_headers = dict(headers or {})
        if not self.enabled:
            return prepared_headers, 0.0, {}

        host = self._extract_host(url)
        if not self._in_scope(host):
            return prepared_headers, 0.0, {}

        with self._lock:
            state = self._get_state(host)
            if not self._can_apply_bypass(state, module):
                return prepared_headers, 0.0, {}

            if int(state.get("bypass_success_count", 0) or 0) <= 0:
                state["bypass_attempts"] = int(state.get("bypass_attempts", 0) or 0) + 1

            prepared_headers.setdefault("X-Forwarded-For", "127.0.0.1")
            prepared_headers.setdefault("X-Real-IP", "127.0.0.1")
            prepared_headers.setdefault("X-Client-IP", "127.0.0.1")
            prepared_headers.setdefault("X-Forwarded-Host", host)
            prepared_headers.setdefault("User-Agent", self._pick_user_agent(host))

            parsed = urlparse(str(url or "").strip())
            if parsed.path:
                prepared_headers.setdefault("X-Original-URL", parsed.path)
                prepared_headers.setdefault("X-Rewrite-URL", parsed.path)

            delay = min(1.0, 0.2 * max(1, int(state.get("hit_count", 1) or 1)))
            detail = {
                "host": host,
                "module": str(module or "").strip(),
                "waf_name": state.get("waf_name", ""),
                "attempt": int(state.get("bypass_attempts", 0) or 0),
                "method": str(method or "GET").strip().upper(),
            }
            return prepared_headers, delay, detail

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
                "X-ARL-WAF-NAME": str(detail.get("waf_name", "") or ""),
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
        strong_hit, signals, combined_text = self._collect_signals(response)
        weak_hit = status_code in self.WAF_STATUS_CODES
        waf_name, confidence, evidence = self._identify_vendor(combined_text)

        with self._lock:
            state = self._get_state(host)
            state["request_count"] += 1
            state["last_status"] = status_code
            state["last_url"] = str(url or "")

            if waf_name:
                prev_rank = self._confidence_rank(state.get("waf_confidence", ""))
                curr_rank = self._confidence_rank(confidence)
                if curr_rank >= prev_rank:
                    state["waf_name"] = waf_name
                    state["waf_confidence"] = confidence
                    state["waf_evidence"] = evidence[:4]

            if weak_hit or strong_hit:
                state["hit_count"] += 1
                state["signals"] = signals[-4:]
                state["module"] = module_name

            # 当主动渗透链路上的轻量绕过请求不再触发拦截信号时，允许继续沿用该模式。
            if state.get("blocked") and self._module_allows_bypass(module_name):
                if weak_hit or strong_hit:
                    state["bypass_success_count"] = 0
                elif int(state.get("bypass_attempts", 0) or 0) > 0:
                    state["bypass_success_count"] = int(state.get("bypass_success_count", 0) or 0) + 1

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
                "task_id:{} waf observe host:{} module:{} rule:{} waf:{} confidence:{} reason:{} url:{}".format(
                    self.task_id,
                    host,
                    module_name or "-",
                    rule,
                    state.get("waf_name", "") or "-",
                    state.get("waf_confidence", "") or "-",
                    state.get("reason", ""),
                    state.get("last_url", ""),
                )
            )

    def is_blocked_host(self, host: str) -> bool:
        normalized_host = self._extract_host(host)
        if not normalized_host or not self.smart_skip_enabled:
            return False
        with self._lock:
            state = self._host_state.get(normalized_host)
            return bool(state and state.get("blocked"))

    def filter_targets(self, targets: List[str]) -> Tuple[List[str], int]:
        if not self.enabled or not self.smart_skip_enabled:
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
            detected_hosts = []
            blocked_hosts = []
            skip_request_count = 0
            bypass_success_host_count = 0

            for host, state in self._host_state.items():
                skip_request_count += int(state.get("skip_count", 0) or 0)
                if int(state.get("bypass_success_count", 0) or 0) > 0:
                    bypass_success_host_count += 1

                has_detection = bool(state.get("blocked") or state.get("waf_name") or state.get("hit_count"))
                if not has_detection:
                    continue

                host_item = {
                    "host": host,
                    "reason": state.get("reason", ""),
                    "rule": state.get("rule", ""),
                    "module": state.get("module", ""),
                    "hit_count": int(state.get("hit_count", 0) or 0),
                    "skip_count": int(state.get("skip_count", 0) or 0),
                    "last_status": int(state.get("last_status", 0) or 0),
                    "last_url": state.get("last_url", ""),
                    "waf_name": state.get("waf_name", ""),
                    "waf_confidence": state.get("waf_confidence", ""),
                    "waf_evidence": list(state.get("waf_evidence", []) or []),
                    "bypass_attempts": int(state.get("bypass_attempts", 0) or 0),
                    "bypass_success_count": int(state.get("bypass_success_count", 0) or 0),
                }
                detected_hosts.append(host_item)
                if state.get("blocked") and self.smart_skip_enabled:
                    blocked_hosts.append(host_item)

            detected_hosts.sort(
                key=lambda item: (
                    item.get("bypass_success_count", 0),
                    item.get("hit_count", 0),
                    item.get("skip_count", 0),
                ),
                reverse=True,
            )
            blocked_hosts.sort(key=lambda item: (item.get("skip_count", 0), item.get("hit_count", 0)), reverse=True)
            return {
                "enabled": self.enabled,
                "smart_skip_enabled": self.smart_skip_enabled,
                "bypass_enabled": self.bypass_enabled,
                "detected_host_count": len(detected_hosts),
                "blocked_host_count": len(blocked_hosts),
                "bypass_success_host_count": int(bypass_success_host_count),
                "skip_request_count": int(skip_request_count),
                "blocked_hosts": blocked_hosts,
                "detected_hosts": detected_hosts[:20],
                "event_total": int(self._event_total),
            }

    def summary_text(self) -> str:
        data = self.summary()
        if not data.get("enabled"):
            return "未启用"

        detected_count = int(data.get("detected_host_count", 0) or 0)
        blocked_count = int(data.get("blocked_host_count", 0) or 0)
        skipped = int(data.get("skip_request_count", 0) or 0)
        bypass_success = int(data.get("bypass_success_host_count", 0) or 0)

        if detected_count <= 0:
            return "已启用，未识别WAF"

        parts = ["已识别主机:{}".format(detected_count)]
        if self.smart_skip_enabled:
            parts.append("跳过主机:{}".format(blocked_count))
            parts.append("跳过请求:{}".format(skipped))
        if self.bypass_enabled:
            parts.append("绕过放行:{}".format(bypass_success))

        host_preview = []
        for item in data.get("detected_hosts", [])[:3]:
            host = str(item.get("host", "") or "").strip()
            waf_name = str(item.get("waf_name", "") or "").strip()
            if host:
                host_preview.append("{}({})".format(host, waf_name or "unknown"))
        if host_preview:
            parts.append("主机:{}".format(",".join(host_preview)))

        return "，".join(parts)
