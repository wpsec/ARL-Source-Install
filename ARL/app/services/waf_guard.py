"""
WAF 观测与智能跳过守卫。

功能说明：
- 按 host 追踪疑似 WAF 拦截信号与厂商特征
- 支持响应头/响应体和 DNS CNAME 两类证据，输出可解释的观测摘要
- 在保留智能跳过能力的同时，避免把单个通用字符串当成确定性厂商结论
"""
import re
import threading
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from requests import Response
from requests.structures import CaseInsensitiveDict

from app import utils
from .discovery_context import traffic_class_for_module

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
        "x-yundun",
        "yundun",
        "wswaf",
        "cdn cache server v2.0",
        "anquanbao",
        "anyu",
        "x-anyu",
        "bytedns",
        "x-bytedance",
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
        "Akamai": (
            "akamai",
            "akamaighost",
            "x-akamai",
            "akamai-origin-hop",
            "aka_debug",
        ),
        "AWS CloudFront/WAF": ("x-amz-cf-id", "x-amz-cf-pop", "cloudfront", "x-amzn-waf-action"),
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
        "知道创宇": (
            "yunaq",
            "x-yunaq",
            "yundun",
            "x-yundun",
            "knownsec",
            "zhidaochuangyu",
            "365cyd.cn",
        ),
        "网宿WAF": ("wswaf", "cdn cache server v2.0", "ws waf"),
        "安全宝/Anquanbao": ("anquanbao", "anquanbao waf"),
        "安域/AnYu": ("anyu", "x-anyu", "anyu waf"),
        "字节跳动CDN/WAF": ("bytedance", "bytedns", "bytedns1.com", "bytecdn"),
        "安恒WAF": ("dbapp", "x-dbapp", "dbappsecurity"),
        "长亭WAF": ("chaitin", "safeline", "x-chaitin"),
        "绿盟WAF": ("nsfocus", "x-nsfocus", "nsfocus waf"),
        "启明星辰WAF": ("venustech", "x-venustech", "venustech waf"),
        "深信服WAF": ("sangfor", "x-sangfor", "sangfor waf"),
        "天融信WAF": ("topsec", "x-topsec", "topsec waf"),
        "Vercel WAF": ("x-vercel-id", "x-vercel-cache", "vercel"),
        "腾讯云EdgeOne": ("edgeone", "x-edgeone", "edgeone waf", "edgeonecdn"),
        "阿里云DCDN/WAF": ("aliyungf_tc", "x-aliyun", "aliyun waf", "waf.aliyun"),
        "Azure Front Door/WAF": ("x-azure-ref", "x-fd-healthprobe", "azure front door"),
        "Wallarm WAF": ("wallarm", "x-wallarm"),
        "DDoS-Guard": ("ddos-guard", "x-ddos-guard"),
        "Cloudbric WAF": ("cloudbric", "x-cloudbric"),
        "Reblaze WAF": ("reblaze", "x-reblaze"),
    }
    # DNS 证据必须按完整标签或域名后缀匹配；不能把任意响应文本中的 token
    # 当作 CNAME 厂商证据。通用 CDN 域名只在这里做识别，不直接等同于 WAF 拦截。
    DNS_VENDOR_PROFILES = {
        "知道创宇/创宇盾": (
            "365cyd.cn",
            "knownsec.com",
            "yunaq.com",
            "yundunwaf1.com",
            "yundunwaf2.com",
            "yundunwaf3.com",
        ),
        "字节跳动CDN/WAF": ("bytedns1.com", "bytedns.com"),
        "网宿WAF": ("wswaf", "wscdn.cn"),
        "腾讯云CDN": ("cdn.dnsv1.com", "qcloudcdn.com"),
        "阿里云CDN": ("alicdn.com", "kunlungr.com", "aliyuncs.com"),
        "华为云CDN": ("hwclouds-dns.com", "hwcdn.net"),
        "360网站卫士": ("360wzb.com", "360waf.com"),
        "ChinaCache CDN": ("chinacache.net", "chinacache.com"),
        "Cloudflare CDN/WAF": ("cloudflare.net", "cloudflare.com"),
        "Akamai CDN/WAF": ("akamai.net", "akamaized.net", "akamaiedge.net"),
        "AWS CloudFront": ("cloudfront.net",),
        "Fastly CDN": ("fastly.net",),
        "Azure Front Door": ("azurefd.net",),
        "百度云加速": ("yunjiasu-cdn.com", "yunjiasu.com"),
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
        signal_sink=None,
    ):
        self.enabled = bool(enabled)
        self.smart_skip_enabled = bool(enabled if smart_skip_enabled is None else smart_skip_enabled)
        self.bypass_enabled = bool(bypass_enabled)
        self.task_id = str(task_id or "").strip()
        self.scope_hosts = self._build_scope_hosts(scope_sites or [])
        self.weak_block_threshold = max(2, int(weak_block_threshold or 3))
        self.bypass_attempt_limit = max(1, int(bypass_attempt_limit or 3))
        # signal_sink(url, module, reason)：确认阻断时把证据回流给任务级发现上下文，
        # 由 DiscoveryContext 做流量类别隔离；回调异常不得影响守卫本身。
        self._signal_sink = signal_sink if callable(signal_sink) else None

        self._lock = threading.Lock()
        self._host_state: Dict[str, Dict] = {}
        self._event_total = 0
        self._observation_elapsed_sec = 0.0
        self._observed_sites = set()
        self._skipped_sites = set()

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

    @classmethod
    def _extract_site(cls, value: str) -> str:
        parsed = urlparse(str(value or "").strip())
        if parsed.scheme and parsed.netloc:
            return "{}://{}".format(parsed.scheme.lower(), parsed.netloc.lower())
        return cls._extract_host(value)

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
                "dns_evidence": [],
                "bypass_attempts": 0,
                "bypass_success_count": 0,
                "blocked_classes": set(),
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
        header_text = " ".join(
            "{} {}".format(name, value).strip()
            for name, value in header_pairs
        )

        for keyword in cls.STRONG_HEADER_KEYWORDS:
            if keyword in header_text:
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

    @staticmethod
    def _normalize_dns_name(value: str) -> str:
        text = str(value or "").strip().lower().rstrip(".")
        if text.startswith("*."):
            text = text[2:]
        return text

    @classmethod
    def _dns_pattern_matches(cls, dns_name: str, pattern: str) -> bool:
        name = cls._normalize_dns_name(dns_name)
        token = cls._normalize_dns_name(pattern)
        if not name or not token:
            return False
        if "." in token:
            return name == token or name.endswith("." + token)
        return token in name.split(".")

    @classmethod
    def identify_vendor_from_dns(
        cls,
        cname: str = "",
        dns_names: Optional[List[str]] = None,
    ) -> Tuple[str, str, List[str]]:
        """从 CNAME/DNS 名称提取厂商证据，不把通用 CDN 当成确定性 WAF。"""
        if isinstance(dns_names, str):
            dns_candidates = [dns_names]
        else:
            dns_candidates = list(dns_names or [])
        candidates = [cname] + dns_candidates
        normalized_names = [cls._normalize_dns_name(item) for item in candidates]
        normalized_names = [item for item in normalized_names if item]
        if not normalized_names:
            return "", "", []

        best_name = ""
        best_matches = []
        best_specificity = 0
        for vendor_name, patterns in cls.DNS_VENDOR_PROFILES.items():
            matched = []
            specificity = 0
            for pattern in patterns:
                if any(cls._dns_pattern_matches(name, pattern) for name in normalized_names):
                    matched.append(str(pattern).lower())
                    specificity += 2 if "." in str(pattern) else 1
            if (specificity, len(matched)) > (best_specificity, len(best_matches)):
                best_name = vendor_name
                best_matches = matched[:4]
                best_specificity = specificity

        if not best_name:
            return "", "", []

        # 精确后缀属于高特异性证据；裸标签（如 wswaf）保守标为 medium。
        confidence = "high" if best_specificity >= 2 and any("." in item for item in best_matches) else "medium"
        evidence = ["dns:{}".format(item) for item in best_matches]
        return best_name, confidence, evidence

    def observe_dns(
        self,
        host: str,
        cname: str = "",
        dns_names: Optional[List[str]] = None,
        module: str = "dns",
    ) -> Dict:
        """记录 DNS 厂商证据；仅更新观测状态，不触发网络请求或自动跳过。"""
        if not self.enabled:
            return {}

        normalized_host = self._extract_host(host)
        if not normalized_host or not self._in_scope(normalized_host):
            return {}

        waf_name, confidence, evidence = self.identify_vendor_from_dns(cname, dns_names)
        if not waf_name:
            return {}

        with self._lock:
            state = self._get_state(normalized_host)
            previous_rank = self._confidence_rank(state.get("waf_confidence", ""))
            current_rank = self._confidence_rank(confidence)
            if current_rank >= previous_rank:
                state["waf_name"] = waf_name
                state["waf_confidence"] = confidence
                state["dns_evidence"] = evidence[:4]
                state["module"] = str(module or "dns").strip() or "dns"
            return {
                "host": normalized_host,
                "waf_name": state.get("waf_name", ""),
                "waf_confidence": state.get("waf_confidence", ""),
                "evidence": list(state.get("dns_evidence", []) or []),
            }

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
            module_class = traffic_class_for_module(module)
            class_only_block = module_class in state.get("blocked_classes", set())
            if not state.get("blocked") and not class_only_block:
                return False, {}

            if self._can_apply_bypass(state, module):
                return False, {}

            if not self.smart_skip_enabled:
                return False, {}

            site = self._extract_site(url)
            if site:
                self._skipped_sites.add(site)
            state["skip_count"] += 1
            self._event_total += 1
            detail = {
                "host": host,
                "reason": state.get("reason", "") if state.get("blocked") else "directory queue paused",
                "rule": state.get("rule", ""),
                "module": state.get("module", ""),
                "waf_name": state.get("waf_name", ""),
                "scope": "host" if state.get("blocked") else "directory_class",
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
        observation_started = time.perf_counter()
        strong_hit, signals, combined_text = self._collect_signals(response)
        weak_hit = status_code in self.WAF_STATUS_CODES
        waf_name, confidence, evidence = self._identify_vendor(combined_text)
        observation_elapsed = max(0.0, time.perf_counter() - observation_started)

        with self._lock:
            self._observation_elapsed_sec += observation_elapsed
            site = self._extract_site(url)
            if site:
                self._observed_sites.add(site)
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

            module_class = traffic_class_for_module(module_name)
            if state.get("blocked") or module_class in state.get("blocked_classes", set()):
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

            if module_class == "directory":
                # 字典爆破流量触发的疑似 WAF 只暂停该主机的 directory 队列。
                state.setdefault("blocked_classes", set()).add("directory")
                block_scope = "directory_class"
            elif rule == "strong_signal":
                # 只有强证据（厂商特征/拦截文案命中）才升级为整主机阻断。
                state["blocked"] = True
                block_scope = "host"
            else:
                # 弱证据（状态码阈值）只暂停来源流量类别，避免误连坐其它策略。
                state.setdefault("blocked_classes", set()).add(module_class)
                block_scope = "{}_class".format(module_class)
            state["rule"] = rule
            if strong_hit and signals:
                state["reason"] = ",".join(signals[:3])
            else:
                state["reason"] = "status:{} hit_count:{}".format(status_code, state["hit_count"])
            self._event_total += 1

            logger.info(
                "task_id:{} waf observe host:{} module:{} rule:{} scope:{} waf:{} confidence:{} reason:{} url:{}".format(
                    self.task_id,
                    host,
                    module_name or "-",
                    rule,
                    block_scope,
                    state.get("waf_name", "") or "-",
                    state.get("waf_confidence", "") or "-",
                    state.get("reason", ""),
                    state.get("last_url", ""),
                )
            )

        if self._signal_sink is not None:
            try:
                self._signal_sink(
                    url, module_name,
                    str(state.get("reason", "") or rule),
                    block_scope,
                )
            except Exception as exc:
                logger.warning(
                    "waf signal sink failed host:{} module:{} error_type:{}".format(
                        host, module_name or "-", type(exc).__name__
                    )
                )

    def add_scope_host(self, host: str) -> bool:
        """动态纳入发现的新子域，使 WAF 观测/跳过状态覆盖后续队列注入的主机。

        scope_hosts 为空表示“不限制主机”，此时追加反而会收窄范围，直接跳过。
        """
        normalized_host = self._extract_host(host)
        if not normalized_host:
            return False
        with self._lock:
            if not self.scope_hosts:
                return False
            if normalized_host in self.scope_hosts:
                return False
            self.scope_hosts.add(normalized_host)
            self._get_state(normalized_host)
        return True

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
                site = self._extract_site(target)
                if site:
                    with self._lock:
                        self._skipped_sites.add(site)
                skipped += 1
                continue
            keep_targets.append(target)
        return keep_targets, skipped

    def summary(self) -> Dict:
        with self._lock:
            detected_hosts = []
            blocked_hosts = []
            class_blocked_hosts = []
            skip_request_count = 0
            request_count = 0
            bypass_success_host_count = 0

            for host, state in self._host_state.items():
                request_count += int(state.get("request_count", 0) or 0)
                skip_request_count += int(state.get("skip_count", 0) or 0)
                if int(state.get("bypass_success_count", 0) or 0) > 0:
                    bypass_success_host_count += 1

                blocked_classes = sorted(str(cls) for cls in (state.get("blocked_classes") or set()))
                has_detection = bool(
                    state.get("blocked") or blocked_classes or state.get("waf_name") or state.get("hit_count")
                )
                if not has_detection:
                    continue

                host_item = {
                    "host": host,
                    "reason": state.get("reason", ""),
                    "rule": state.get("rule", ""),
                    "module": state.get("module", ""),
                    "blocked_classes": blocked_classes,
                    "hit_count": int(state.get("hit_count", 0) or 0),
                    "skip_count": int(state.get("skip_count", 0) or 0),
                    "last_status": int(state.get("last_status", 0) or 0),
                    "last_url": state.get("last_url", ""),
                    "waf_name": state.get("waf_name", ""),
                    "waf_confidence": state.get("waf_confidence", ""),
                    "waf_evidence": list(state.get("waf_evidence", []) or []),
                    "dns_evidence": list(state.get("dns_evidence", []) or []),
                    "bypass_attempts": int(state.get("bypass_attempts", 0) or 0),
                    "bypass_success_count": int(state.get("bypass_success_count", 0) or 0),
                }
                detected_hosts.append(host_item)
                if not self.smart_skip_enabled:
                    continue
                if state.get("blocked"):
                    blocked_hosts.append(host_item)
                elif blocked_classes:
                    # 仅类别阻断（如目录队列暂停）单独归类，不改变 blocked_hosts 的主机级口径。
                    class_blocked_hosts.append(host_item)

            detected_hosts.sort(
                key=lambda item: (
                    item.get("bypass_success_count", 0),
                    item.get("hit_count", 0),
                    item.get("skip_count", 0),
                ),
                reverse=True,
            )
            blocked_hosts.sort(key=lambda item: (item.get("skip_count", 0), item.get("hit_count", 0)), reverse=True)
            class_blocked_hosts.sort(
                key=lambda item: (item.get("skip_count", 0), item.get("hit_count", 0)), reverse=True
            )
            return {
                "enabled": self.enabled,
                "smart_skip_enabled": self.smart_skip_enabled,
                "bypass_enabled": self.bypass_enabled,
                "detected_host_count": len(detected_hosts),
                "blocked_host_count": len(blocked_hosts),
                "class_blocked_host_count": len(class_blocked_hosts),
                "bypass_success_host_count": int(bypass_success_host_count),
                "request_count": int(request_count),
                "skip_request_count": int(skip_request_count),
                "observed_site_count": len(self._observed_sites),
                "skip_site_count": len(self._skipped_sites),
                "observation_elapsed_sec": round(max(0.0, self._observation_elapsed_sec), 6),
                "blocked_hosts": blocked_hosts,
                "class_blocked_hosts": class_blocked_hosts,
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
        observed_sites = int(data.get("observed_site_count", 0) or 0)
        skipped_sites = int(data.get("skip_site_count", 0) or 0)
        bypass_success = int(data.get("bypass_success_host_count", 0) or 0)
        observation_elapsed = float(data.get("observation_elapsed_sec", 0.0) or 0.0)

        if detected_count <= 0:
            return "已启用，未识别WAF，站点:{}，请求:{}，检测耗时:{:.3f}s".format(
                observed_sites,
                int(data.get("request_count", 0) or 0),
                observation_elapsed,
            )

        parts = [
            "已识别主机:{}".format(detected_count),
            "观测站点:{}".format(observed_sites),
            "检测耗时:{:.3f}s".format(observation_elapsed),
        ]
        if self.smart_skip_enabled:
            parts.append("跳过主机:{}".format(blocked_count))
            parts.append("跳过站点:{}".format(skipped_sites))
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
