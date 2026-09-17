"""
WAF 观测与智能跳过守卫。

功能说明：
- 按 host 追踪疑似 WAF 拦截信号与厂商特征
- 支持响应头/响应体和 DNS CNAME 两类证据，输出可解释的观测摘要
- 在保留智能跳过能力的同时，避免把单个通用字符串当成确定性厂商结论
"""
import re
import socket
import threading
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from requests import Response
from requests.structures import CaseInsensitiveDict

from app import utils
from app.utils.log_safety import safe_error_text
from .discovery_context import traffic_class_for_module

logger = utils.get_logger()


class WAFSmartSkipGuard(object):
    """
    按任务维度执行 WAF 观测与保守智能跳过。
    """

    # 常见被拦截状态码（弱信号）
    WAF_STATUS_CODES = {403, 406, 429, 503}
    # Header 关键字用于记录厂商/边界证据；其中仅部分关键字本身代表拦截。
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
        "cf-mitigated",
        "x-amzn-waf-action",
    )
    STRONG_BLOCK_HEADER_KEYWORDS = (
        "x-waf-",
        "x-cdn-waf",
        "x-denied-reason",
        "x-firewall",
        "x-safedog",
        "x-yunaq",
        "x-yundun",
        "yundun",
        "wswaf",
        "anquanbao",
        "anyu",
        "x-anyu",
        "x-dbapp",
        "x-chaitin",
        "x-amzn-waf-action",
        "cf-mitigated",
    )
    # Body 命中这些关键字视为强信号。产品名/边界标识本身不能证明请求被拦截，
    # 只有和拦截状态码同时出现时才升级，避免普通页面正文误触发熔断。
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
    BODY_KEYWORDS_REQUIRING_BLOCK_STATUS = (
        "security check",
        "web application firewall",
        "cloudflare ray id",
        "safeline",
        "yundun waf",
    )
    # 厂商画像按“通用安全知识 + 项目自有观测”组织，只保留可解释 token，不直接引入外部规则文件。
    WAF_VENDOR_PROFILES = {
        "Cloudflare": (
            "cf-ray",
            "cf-cache-status",
            "cf-mitigated",
            "__cf_bm",
            "cloudflare",
        ),
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
        "腾讯云EdgeOne": (
            "edgeone",
            "x-edgeone",
            "edgeone waf",
            "edgeonecdn",
            "dnse0.com",
        ),
        "阿里云DCDN/WAF": ("aliyungf_tc", "x-aliyun", "aliyun waf", "waf.aliyun"),
        "Azure Front Door/WAF": (
            "x-azure-ref",
            "x-azure-fdid",
            "x-fd-healthprobe",
            "azure front door",
        ),
        "Fastly CDN": ("x-served-by", "x-cache-hits", "x-timer", "fastly"),
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
        "网宿CDN": ("wscdn.cn",),
        "网宿WAF": ("wswaf",),
        "腾讯云CDN": ("cdn.dnsv1.com", "qcloudcdn.com"),
        "阿里云CDN": (
            "alicdn.com",
            "kunlungr.com",
            "alikunlun.com",
            "kunlun.com",
            "kunlunle.com",
            "kunlunaq.com",
            "aliyuncs.com",
        ),
        "华为云CDN": ("hwclouds-dns.com", "hwcdn.net"),
        "360网站卫士": ("360wzb.com", "360waf.com"),
        "ChinaCache CDN": ("chinacache.net", "chinacache.com"),
        "Cloudflare CDN/WAF": ("cloudflare.net", "cloudflare.com"),
        "Akamai CDN/WAF": (
            "akamai.net",
            "akamaized.net",
            "akamaiedge.net",
            "edgesuite.net",
            "edgekey.net",
        ),
        "AWS CloudFront": ("cloudfront.net",),
        "Fastly CDN": ("fastly.net",),
        "腾讯云EdgeOne": ("dnse0.com", "edgeone.ai", "edgeone.cn"),
        "Azure Front Door": ("azurefd.net",),
        "百度云加速": ("yunjiasu-cdn.com", "yunjiasu.com"),
    }
    # DNS 只能说明流量经过边界，不能把 CDN 直接当成 WAF。这里按具体 CNAME
    # 标签维护分型，尤其拆开网宿的 wscdn 与 wswaf 两类证据。
    DNS_WAF_PATTERNS = (
        "365cyd.cn",
        "knownsec.com",
        "yunaq.com",
        "yundunwaf1.com",
        "yundunwaf2.com",
        "yundunwaf3.com",
        "wswaf",
        "360wzb.com",
        "360waf.com",
    )
    DNS_CDN_PATTERNS = (
        "bytedns1.com",
        "bytedns.com",
        "wscdn.cn",
        "cdn.dnsv1.com",
        "qcloudcdn.com",
        "alicdn.com",
        "kunlungr.com",
        "aliyuncs.com",
        "alikunlun.com",
        "kunlun.com",
        "kunlunle.com",
        "kunlunaq.com",
        "hwclouds-dns.com",
        "hwcdn.net",
        "chinacache.net",
        "chinacache.com",
        "cloudflare.net",
        "cloudflare.com",
        "akamai.net",
        "akamaized.net",
        "akamaiedge.net",
        "edgesuite.net",
        "edgekey.net",
        "cloudfront.net",
        "fastly.net",
        "dnse0.com",
        "edgeone.ai",
        "edgeone.cn",
        "azurefd.net",
        "yunjiasu-cdn.com",
        "yunjiasu.com",
    )
    MAX_BODY_CHECK_BYTES = 4096

    def __init__(
        self,
        enabled: bool = False,
        task_id: str = "",
        scope_sites: Optional[List[str]] = None,
        weak_block_threshold: int = 3,
        smart_skip_enabled: Optional[bool] = None,
        signal_sink=None,
        timeout_block_threshold: Optional[int] = None,
    ):
        self.enabled = bool(enabled)
        self.smart_skip_enabled = bool(enabled if smart_skip_enabled is None else smart_skip_enabled)
        self.task_id = str(task_id or "").strip()
        self.scope_hosts = self._build_scope_hosts(scope_sites or [])
        self.weak_block_threshold = max(2, int(weak_block_threshold or 3))
        self.timeout_block_threshold = max(
            2,
            int(timeout_block_threshold or self.weak_block_threshold),
        )
        # signal_sink(url, module, reason)：确认阻断时把证据回流给任务级发现上下文，
        # 由 DiscoveryContext 做流量类别隔离；回调异常不得影响守卫本身。
        self._signal_sink = signal_sink if callable(signal_sink) else None

        self._lock = threading.Lock()
        self._host_state: Dict[str, Dict] = {}
        self._event_total = 0
        self._observation_elapsed_sec = 0.0
        self._observed_sites = set()
        self._skipped_sites = set()
        self._preclassified_count = 0
        self._npoc_promoted_count = 0
        self._wafw00f_metrics = {
            "wafw00f_checked_total": 0,
            "wafw00f_detected_total": 0,
            "wafw00f_not_detected_total": 0,
            "wafw00f_timeout_total": 0,
            "wafw00f_error_total": 0,
            "wafw00f_skipped_by_passive_total": 0,
            "wafw00f_target_cap_skipped_total": 0,
            "wafw00f_request_total": 0,
            "wafw00f_elapsed_sec": 0.0,
        }
        self._active_risk_filter_stats = {}

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

    @staticmethod
    def _module_class(module: str) -> str:
        module_name = str(module or "").strip().lower()
        if "npoc" in module_name or module_name in {"poc", "risk_cruising"}:
            return "npoc"
        return traffic_class_for_module(module)

    @classmethod
    def _is_timeout_error(cls, error) -> bool:
        if isinstance(error, (requests.exceptions.Timeout, socket.timeout, TimeoutError)):
            return True
        error_name = type(error).__name__.lower()
        error_text = str(error or "").lower()
        if "timeout" in error_name:
            return True
        return any(token in error_text for token in ("timed out", "timeout", "time out"))

    @classmethod
    def _is_waf_vendor(cls, waf_name: str, evidence: Optional[List[str]] = None) -> bool:
        """只把高置信度安全防护厂商当作 Web PoC 预分类依据。"""
        name = str(waf_name or "").strip().lower()
        if not name:
            return False
        dns_edge_kind = cls._dns_edge_kind_from_evidence(evidence)
        if dns_edge_kind == "cdn":
            return False
        cdn_only_names = {
            "腾讯云cdn",
            "阿里云cdn",
            "华为云cdn",
            "chinacache cdn",
            "cloudflare cdn/waf",
            "akamai cdn/waf",
            "aws cloudfront",
            "fastly cdn",
            "azure front door",
            "百度云加速",
            "字节跳动cdn/waf",
            "网宿cdn",
        }
        if name in cdn_only_names:
            return False
        return any(
            token in name
            for token in (
                "waf", "防护", "防火墙", "安全狗", "云锁", "卫士", "创宇",
                "安全宝", "安域", "360", "knownsec", "safedog", "yunsuo",
                "modsecurity", "imperva", "sucuri", "big-ip", "barracuda",
                "citrix", "forti", "radware", "wordfence", "dbapp",
                "chaitin", "nsfocus", "venustech", "sangfor", "topsec",
                "wallarm", "ddos-guard", "cloudbric", "reblaze",
                "cloudflare", "akamai",
            )
        )

    @staticmethod
    def _merge_edge_kind(current: str, incoming: str) -> str:
        current = str(current or "").strip().lower()
        incoming = str(incoming or "").strip().lower()
        if not current:
            return incoming
        if not incoming or current == incoming:
            return current
        if "mixed" in {current, incoming}:
            return "mixed"
        if {current, incoming} == {"cdn", "waf"}:
            return "mixed"
        return incoming

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
                "http_waf_name": "",
                "http_waf_confidence": "",
                "http_waf_evidence": [],
                "dns_evidence": [],
                "dns_waf_name": "",
                "dns_waf_confidence": "",
                "dns_edge_kind": "",
                "response_edge_kind": "",
                "edge_kind": "",
                "blocked_classes": set(),
                "timeout_count": 0,
                "timeout_by_class": {},
                "consecutive_timeout_count": 0,
                "consecutive_block_count": 0,
                "block_by_class": {},
                "preclassified_classes": set(),
                "detection_sources": set(),
                "wafw00f_status": "",
                "wafw00f_names": [],
                "wafw00f_confidence": "",
                "wafw00f_evidence": [],
                "wafw00f_request_count": 0,
                "wafw00f_elapsed_sec": 0.0,
                "wafw00f_checked_at": "",
                "wafw00f_active_risk_blocked": False,
                "wafw00f_endpoints": {},
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

        if (
            status_code in cls.WAF_STATUS_CODES
            and any(
                keyword in header_text
                for keyword in cls.STRONG_BLOCK_HEADER_KEYWORDS
            )
        ):
            strong_hit = True

        # Cloudflare 文档明确将 cf-mitigated: challenge 作为 Challenge Page
        # 的可靠识别标志；它不依赖具体状态码或页面文案。
        if any(
            name == "cf-mitigated" and value == "challenge"
            for name, value in header_pairs
        ):
            signals.append("header:cf-mitigated")
            strong_hit = True

        for keyword in cls.STRONG_BODY_KEYWORDS:
            if keyword in body_text:
                if (
                    status_code not in cls.WAF_STATUS_CODES
                    and keyword in cls.BODY_KEYWORDS_REQUIRING_BLOCK_STATUS
                ):
                    continue
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
    def _dns_edge_kind_from_evidence(cls, evidence: Optional[List[str]]) -> str:
        """根据已确认的 dns: 证据区分 CDN、WAF 或混合边界。"""
        kinds = set()
        for item in evidence or []:
            value = str(item or "").strip().lower()
            if value.startswith("dns:"):
                value = value[4:]
            if not value:
                continue
            if any(cls._dns_pattern_matches(value, pattern) for pattern in cls.DNS_WAF_PATTERNS):
                kinds.add("waf")
            if any(cls._dns_pattern_matches(value, pattern) for pattern in cls.DNS_CDN_PATTERNS):
                kinds.add("cdn")
        if len(kinds) == 1:
            return next(iter(kinds))
        if len(kinds) > 1:
            return "mixed"
        return ""

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
        edge_kind = self._dns_edge_kind_from_evidence(evidence)

        with self._lock:
            state = self._get_state(normalized_host)
            dns_previous_rank = self._confidence_rank(state.get("dns_waf_confidence", ""))
            aggregate_previous_rank = self._confidence_rank(state.get("waf_confidence", ""))
            aggregate_previous_edge_kind = state.get("edge_kind", "")
            current_rank = self._confidence_rank(confidence)
            existing_evidence = list(state.get("dns_evidence", []) or [])
            for item in evidence:
                if item not in existing_evidence:
                    existing_evidence.append(item)
            state["dns_evidence"] = existing_evidence[:8]
            state.setdefault("detection_sources", set()).add("dns")
            state["dns_edge_kind"] = self._merge_edge_kind(
                state.get("dns_edge_kind", ""), edge_kind
            )
            state["edge_kind"] = self._merge_edge_kind(
                state.get("edge_kind", ""), edge_kind
            )
            if current_rank >= dns_previous_rank:
                state["dns_waf_name"] = waf_name
                state["dns_waf_confidence"] = confidence
            aggregate_should_update = current_rank > aggregate_previous_rank
            if current_rank == aggregate_previous_rank:
                aggregate_should_update = not (
                    edge_kind == "cdn"
                    and aggregate_previous_edge_kind in {"waf", "mixed"}
                )
            if aggregate_should_update:
                state["waf_name"] = waf_name
                state["waf_confidence"] = confidence
                state["module"] = str(module or "dns").strip() or "dns"
            return {
                "host": normalized_host,
                "waf_name": state.get("waf_name", ""),
                "waf_confidence": state.get("waf_confidence", ""),
                "evidence": list(state.get("dns_evidence", []) or []),
                "edge_kind": state.get("dns_edge_kind", ""),
            }

    def should_skip(self, url: str, module: str = "") -> Tuple[bool, Dict]:
        if not self.enabled:
            return False, {}

        host = self._extract_host(url)
        if not self._in_scope(host):
            return False, {}

        with self._lock:
            state = self._get_state(host)
            module_class = self._module_class(module)
            if (
                self._is_active_risk_module(module)
                and state.get("wafw00f_active_risk_blocked")
                and self.smart_skip_enabled
            ):
                site = self._extract_site(url)
                if site:
                    self._skipped_sites.add(site)
                state["skip_count"] += 1
                self._event_total += 1
                return True, {
                    "host": host,
                    "reason": "wafw00f:{}".format(",".join(state.get("wafw00f_names") or []) or "detected"),
                    "rule": "wafw00f_named_waf",
                    "module": str(module or module_class),
                    "waf_name": state.get("waf_name", ""),
                    "scope": "wafw00f_active_risk",
                }
            class_only_block = module_class in state.get("blocked_classes", set())
            if not state.get("blocked") and not class_only_block:
                return False, {}

            if not self.smart_skip_enabled:
                return False, {}

            site = self._extract_site(url)
            if site:
                self._skipped_sites.add(site)
            state["skip_count"] += 1
            self._event_total += 1
            block_scope = "host" if state.get("blocked") else "{}_class".format(module_class)
            block_reason = (
                state.get("reason", "")
                if state.get("blocked")
                else "{} queue paused".format(module_class)
            )
            detail = {
                "host": host,
                "reason": block_reason,
                "rule": state.get("rule", ""),
                "module": state.get("module", ""),
                "waf_name": state.get("waf_name", ""),
                "scope": block_scope,
            }
            return True, detail

    @classmethod
    def _is_active_risk_module(cls, module: str) -> bool:
        name = str(module or "").strip().lower()
        return any(token in name for token in ("npoc", "nuclei", "afrog", "risk_cruising")) or name in {
            "poc", "poc_run", "active_risk",
        }

    def _record_filter_stat_locked(
        self, stage_name, input_count=0, output_count=0, skipped_count=0, reason="", skip_reasons=None
    ):
        key = str(stage_name or "waf_filter").strip() or "waf_filter"
        item = self._active_risk_filter_stats.setdefault(
            key,
            {
                "input_count": 0,
                "output_count": 0,
                "skipped_count": 0,
                "skip_reasons": {},
            },
        )
        item["input_count"] += max(0, int(input_count or 0))
        item["output_count"] += max(0, int(output_count or 0))
        item["skipped_count"] += max(0, int(skipped_count or 0))
        if reason and skipped_count:
            reasons = item.setdefault("skip_reasons", {})
            reasons[reason] = int(reasons.get(reason, 0) or 0) + int(skipped_count)
        for reason_name, count in (skip_reasons or {}).items():
            if not reason_name or not count:
                continue
            reasons = item.setdefault("skip_reasons", {})
            reasons[reason_name] = int(reasons.get(reason_name, 0) or 0) + int(count)

    def can_probe_wafw00f(self, target: str) -> bool:
        """判断目标是否仍需补充识别，状态以 endpoint 为缓存粒度。"""
        if not self.enabled or not self.smart_skip_enabled:
            return False
        host = self._extract_host(target)
        if not host or not self._in_scope(host):
            return False
        from .wafw00f_adapter import WAFW00FAdapter

        endpoint = WAFW00FAdapter.endpoint_key(target)
        if not endpoint:
            return False
        with self._lock:
            state = self._get_state(host)
            if endpoint in (state.get("wafw00f_endpoints") or {}):
                return False
            if state.get("blocked") or state.get("blocked_classes"):
                return False
            return not self.has_high_confidence_waf(host, _locked=True)

    def has_high_confidence_waf(self, host: str, _locked=False) -> bool:
        normalized_host = self._extract_host(host)
        if not normalized_host:
            return False
        def check():
            state = self._get_state(normalized_host)
            return bool(
                self._confidence_rank(state.get("waf_confidence", "")) >= 3
                and self._is_waf_vendor(
                    state.get("waf_name", ""),
                    state.get("waf_evidence", []),
                )
            ) or bool(
                self._confidence_rank(state.get("dns_waf_confidence", "")) >= 3
                and state.get("dns_edge_kind") in {"waf", "mixed"}
            )
        if _locked:
            return check()
        with self._lock:
            return check()

    def record_wafw00f_result(self, target: str, result: Optional[Dict]) -> bool:
        """合并一次 endpoint 结果；重复恢复数据不增加计数。"""
        if not self.enabled:
            return False
        from .wafw00f_adapter import WAFW00FAdapter

        endpoint = WAFW00FAdapter.endpoint_key(target)
        host = self._extract_host(target)
        if not endpoint or not host or not self._in_scope(host):
            return False
        item = result if isinstance(result, dict) else {}
        status = str(item.get("status", "error") or "error").strip().lower()
        if status not in {"detected", "generic", "not_detected", "timeout", "error"}:
            status = "error"
        names = [str(value).strip()[:120] for value in (item.get("names") or []) if str(value).strip()]
        evidence = [str(value).strip()[:180] for value in (item.get("evidence") or []) if str(value).strip()]
        checked_at = str(item.get("checked_at") or utils.curr_date())
        with self._lock:
            state = self._get_state(host)
            endpoint_map = state.setdefault("wafw00f_endpoints", {})
            if endpoint in endpoint_map:
                return False
            endpoint_map[endpoint] = {
                "status": status,
                "names": names[:8],
                "confidence": str(item.get("confidence", "") or "")[:16],
                "evidence": evidence[:8],
                "request_count": max(0, int(item.get("request_count", 0) or 0)),
                "elapsed_sec": round(max(0.0, float(item.get("elapsed_sec", 0.0) or 0.0)), 6),
                "checked_at": checked_at,
            }
            state["wafw00f_request_count"] += endpoint_map[endpoint]["request_count"]
            state["wafw00f_elapsed_sec"] += endpoint_map[endpoint]["elapsed_sec"]
            state["wafw00f_checked_at"] = checked_at
            state["wafw00f_status"] = self._merge_wafw00f_status(
                state.get("wafw00f_status", ""), status
            )
            state["wafw00f_confidence"] = (
                "high" if status == "detected" else state.get("wafw00f_confidence", "") or str(item.get("confidence", ""))
            )
            for value in names:
                if value not in state["wafw00f_names"]:
                    state["wafw00f_names"].append(value)
            for value in evidence:
                if value not in state["wafw00f_evidence"]:
                    state["wafw00f_evidence"].append(value)
            state.setdefault("detection_sources", set()).add("wafw00f")
            if status == "detected":
                state["wafw00f_active_risk_blocked"] = True
                state["edge_kind"] = self._merge_edge_kind(state.get("edge_kind", ""), "waf")
                if self._confidence_rank(state.get("waf_confidence", "")) < 3:
                    state["waf_name"] = names[0] if names else state.get("waf_name", "")
                    state["waf_confidence"] = "high"
                for value in evidence:
                    if value not in state["waf_evidence"]:
                        state["waf_evidence"].append(value)
        return True

    @staticmethod
    def _merge_wafw00f_status(current, incoming):
        rank = {"": 0, "error": 1, "timeout": 2, "not_detected": 3, "generic": 4, "detected": 5}
        current = str(current or "")
        incoming = str(incoming or "")
        return incoming if rank.get(incoming, 0) >= rank.get(current, 0) else current

    def record_wafw00f_metrics(self, metrics: Optional[Dict]):
        if not isinstance(metrics, dict):
            return
        mapping = {
            "checked_count": "wafw00f_checked_total",
            "detected_count": "wafw00f_detected_total",
            "not_detected_count": "wafw00f_not_detected_total",
            "timeout_count": "wafw00f_timeout_total",
            "error_count": "wafw00f_error_total",
            "skipped_by_passive_count": "wafw00f_skipped_by_passive_total",
            "target_cap_skipped_count": "wafw00f_target_cap_skipped_total",
            "request_count": "wafw00f_request_total",
            "elapsed_sec": "wafw00f_elapsed_sec",
        }
        with self._lock:
            for source_key, target_key in mapping.items():
                value = metrics.get(source_key, 0)
                if target_key.endswith("elapsed_sec"):
                    self._wafw00f_metrics[target_key] += max(0.0, float(value or 0.0))
                else:
                    self._wafw00f_metrics[target_key] += max(0, int(value or 0))

    def observe_timeout(self, url: str, error, module: str = ""):
        """把连续网络超时转为当前流量类别熔断，避免继续消耗 worker。"""
        if not self.enabled or not self.smart_skip_enabled or not self._is_timeout_error(error):
            return

        host = self._extract_host(url)
        if not host or not self._in_scope(host):
            return
        module_name = str(module or "").strip()
        module_class = self._module_class(module_name)

        should_signal = False
        reason = ""
        block_scope = "{}_class".format(module_class)
        with self._lock:
            state = self._get_state(host)
            state["request_count"] += 1
            state["timeout_count"] += 1
            timeout_by_class = state.setdefault("timeout_by_class", {})
            current_count = int(timeout_by_class.get(module_class, 0) or 0) + 1
            timeout_by_class[module_class] = current_count
            # 保留旧字段，供旧版落库/监控继续读取；新逻辑以类别计数为准。
            state["consecutive_timeout_count"] = current_count
            state["last_url"] = safe_error_text(url)
            state["module"] = module_name or module_class
            if module_class in state.get("blocked_classes", set()):
                return
            if current_count < self.timeout_block_threshold:
                return

            state.setdefault("blocked_classes", set()).add(module_class)
            state["rule"] = "timeout_threshold"
            reason = "timeout_count:{} threshold:{}".format(
                current_count, self.timeout_block_threshold
            )
            state["reason"] = reason
            self._event_total += 1
            should_signal = True

            logger.info(
                "task_id:{} waf observe host:{} module:{} rule:{} scope:{} reason:{} url:{}".format(
                    self.task_id,
                    host,
                    module_name or "-",
                    state["rule"],
                    block_scope,
                    reason,
                    state["last_url"],
                )
            )

        if should_signal and self._signal_sink is not None:
            try:
                self._signal_sink(url, module_name or module_class, reason, block_scope)
            except Exception as exc:
                logger.warning(
                    "waf timeout signal sink failed host:{} module:{} error_type:{}".format(
                        host, module_name or module_class, type(exc).__name__
                    )
                )

    def reset_timeout(self, url: str, module: str = ""):
        """非超时网络错误打断连续性，避免把不相邻故障累计成 WAF 熔断。"""
        if not self.enabled:
            return
        host = self._extract_host(url)
        if not host or not self._in_scope(host):
            return
        module_class = self._module_class(module)
        with self._lock:
            state = self._get_state(host)
            timeout_by_class = state.setdefault("timeout_by_class", {})
            timeout_by_class[module_class] = 0
            state["consecutive_timeout_count"] = 0

    def observe_error(self, url: str, error, module: str = ""):
        """统一处理请求异常，让所有使用 app HTTP 栈的阶段共享熔断语义。"""
        if self._is_timeout_error(error):
            self.observe_timeout(url, error, module=module)
        else:
            self.reset_timeout(url, module=module)

    def _preclassify_target(self, target: str, module: str) -> Tuple[bool, Dict]:
        """根据已有 DNS 高置信度 WAF 证据预先熔断 NPoC，不把 CDN 当成 WAF。"""
        host = self._extract_host(target)
        if not host or not self._in_scope(host):
            return False, {}
        module_class = self._module_class(module)
        if module_class != "npoc":
            return False, {}

        with self._lock:
            state = self._get_state(host)
            if (
                self._confidence_rank(state.get("dns_waf_confidence", "")) < 3
                or state.get("dns_edge_kind", "") not in {"waf", "mixed"}
            ):
                return False, {}
            if module_class not in state.setdefault("preclassified_classes", set()):
                state["preclassified_classes"].add(module_class)
                state.setdefault("blocked_classes", set()).add(module_class)
                state["rule"] = "dns_waf_preclassify"
                state["module"] = str(module or "npoc")
                state["reason"] = "dns_waf:{} confidence:high".format(
                    state.get("dns_waf_name", "unknown")
                )
                self._preclassified_count += 1
                self._event_total += 1
            return True, {
                "host": host,
                "reason": state.get("reason", ""),
                "rule": state.get("rule", "dns_waf_preclassify"),
                "module": state.get("module", "npoc"),
                "waf_name": state.get("waf_name", ""),
                "scope": "npoc_class",
            }

    def prepare_request(
        self,
        url: str,
        module: str = "",
        method: str = "GET",
        headers: Optional[Dict] = None,
    ) -> Tuple[Dict, float, Dict]:
        """兼容既有调用点的直通实现。

        旧 `penetration_test` 试探绕过语义已随计划 1 收口删除；
        守卫只做保守跳过，不再改写请求 Header 或注入节流延迟。
        """

        return dict(headers or {}), 0.0, {}

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
        module_class = self._module_class(module_name)
        has_block_header_signal = any(
            signal.startswith("header:")
            and signal[7:] in self.STRONG_BLOCK_HEADER_KEYWORDS
            for signal in signals
        )
        strong_hostwide = bool(
            strong_hit and (waf_name or has_block_header_signal)
        )
        response_waf_evidence = bool(
            strong_hostwide
            or (
                status_code in self.WAF_STATUS_CODES
                and (
                    self._is_waf_vendor(waf_name, evidence)
                    or has_block_header_signal
                )
            )
        )
        response_cdn_evidence = any(
            item in {
                "cf-ray",
                "cf-cache-status",
                "x-amz-cf-id",
                "x-amz-cf-pop",
                "cloudfront",
                "akamaighost",
                "x-akamai",
                "x-azure-ref",
                "x-azure-fdid",
                "x-served-by",
                "x-cache-hits",
                "x-timer",
                "fastly",
                "x-vercel-id",
                "x-vercel-cache",
            }
            for item in evidence
        )
        response_edge_kind = ""
        if response_waf_evidence:
            response_edge_kind = "waf"
        elif response_cdn_evidence:
            response_edge_kind = "cdn"
        observation_elapsed = max(0.0, time.perf_counter() - observation_started)

        signal_reason = ""
        block_scope = ""
        with self._lock:
            self._observation_elapsed_sec += observation_elapsed
            site = self._extract_site(url)
            if site:
                self._observed_sites.add(site)
            state = self._get_state(host)
            state["request_count"] += 1
            state["last_status"] = status_code
            state["last_url"] = safe_error_text(url)
            if response_waf_evidence or response_edge_kind:
                state.setdefault("detection_sources", set()).add("http")
            timeout_by_class = state.setdefault("timeout_by_class", {})
            timeout_by_class[module_class] = 0
            state["consecutive_timeout_count"] = 0
            block_by_class = state.setdefault("block_by_class", {})

            if waf_name:
                state.setdefault("detection_sources", set()).add("http")
                http_prev_rank = self._confidence_rank(state.get("http_waf_confidence", ""))
                curr_rank = self._confidence_rank(confidence)
                if curr_rank >= http_prev_rank:
                    state["http_waf_name"] = waf_name
                    state["http_waf_confidence"] = confidence
                    state["http_waf_evidence"] = evidence[:4]
                prev_rank = self._confidence_rank(state.get("waf_confidence", ""))
                if curr_rank >= prev_rank:
                    state["waf_name"] = waf_name
                    state["waf_confidence"] = confidence
                    state["waf_evidence"] = evidence[:4]

            if response_edge_kind:
                state["response_edge_kind"] = self._merge_edge_kind(
                    state.get("response_edge_kind", ""), response_edge_kind
                )
                state["edge_kind"] = self._merge_edge_kind(
                    state.get("edge_kind", ""), response_edge_kind
                )

            if weak_hit or strong_hit:
                state["hit_count"] += 1
                current_block_count = int(block_by_class.get(module_class, 0) or 0) + 1
                block_by_class[module_class] = current_block_count
                state["consecutive_block_count"] = current_block_count
                state["signals"] = signals[-4:]
                state["module"] = module_name or module_class
            else:
                block_by_class[module_class] = 0
                state["consecutive_block_count"] = 0

            if state.get("blocked") or module_class in state.get("blocked_classes", set()):
                return

            should_block = False
            rule = ""
            if strong_hit:
                should_block = True
                rule = "strong_signal"
            elif weak_hit and current_block_count >= self.weak_block_threshold:
                should_block = True
                rule = "weak_status_threshold"

            if not should_block:
                return

            if module_class == "directory":
                # 字典爆破流量触发的疑似 WAF 只暂停该主机的 directory 队列。
                state.setdefault("blocked_classes", set()).add("directory")
                block_scope = "directory_class"
            elif rule == "strong_signal" and strong_hostwide:
                # 带厂商/拦截头证据的强信号才升级为整主机阻断；纯正文文案
                # 只暂停来源类别，避免普通站点自定义 403 页面造成连坐。
                state["blocked"] = True
                block_scope = "host"
            else:
                # 弱证据或无法确认边界归属的正文信号只暂停来源类别。
                state.setdefault("blocked_classes", set()).add(module_class)
                block_scope = "{}_class".format(module_class)
            state["rule"] = rule
            if strong_hit and signals:
                state["reason"] = ",".join(signals[:3])
            else:
                state["reason"] = "status:{} consecutive_count:{}".format(
                    status_code, current_block_count
                )

            # 已有中置信度 WAF 身份且来源类别达到阻断阈值时，同步暂停 NPoC。
            # 这只增加 npoc 类别，不扩大为主机级阻断，避免把 CDN/普通 403
            # 误当成 WAF，也避免 NPoC 继续消耗被封锁目标。
            npoc_evidence_confirmed = bool(
                self._confidence_rank(state.get("http_waf_confidence", "")) >= 2
                and (
                    self._is_waf_vendor(
                        state.get("http_waf_name", ""),
                        state.get("http_waf_evidence", []),
                    )
                    or has_block_header_signal
                )
            )
            if (
                module_class not in {"directory", "npoc"}
                and "npoc" not in state.setdefault("blocked_classes", set())
                and npoc_evidence_confirmed
                and (rule == "weak_status_threshold" or strong_hit)
            ):
                state["blocked_classes"].add("npoc")
                state["npoc_promotion_rule"] = "waf_evidence_to_npoc"
                self._npoc_promoted_count += 1

            self._event_total += 1
            signal_reason = str(state.get("reason", "") or rule)

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

        if signal_reason and self._signal_sink is not None:
            try:
                self._signal_sink(
                    url, module_name,
                    signal_reason,
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

    def filter_targets(
        self,
        targets: List[str],
        module: str = "",
        preclassify: bool = False,
        stage_name: str = "",
    ) -> Tuple[List[str], int]:
        if not self.enabled or not self.smart_skip_enabled:
            return list(targets or []), 0

        keep_targets = []
        skipped = 0
        skip_reasons = {}
        module_name = str(module or "").strip()
        for target in targets or []:
            host = self._extract_host(target)
            if module_name and preclassify:
                self._preclassify_target(target, module_name)
            if module_name:
                should_skip, detail = self.should_skip(target, module=module_name)
            else:
                should_skip = bool(host and self.is_blocked_host(host))
                detail = {}
            if should_skip:
                site = self._extract_site(target)
                if site:
                    with self._lock:
                        self._skipped_sites.add(site)
                skipped += 1
                reason = str(detail.get("scope") or detail.get("rule") or "waf_guard")
                skip_reasons[reason] = int(skip_reasons.get(reason, 0) or 0) + 1
                continue
            keep_targets.append(target)
        with self._lock:
            self._record_filter_stat_locked(
                stage_name or module or "waf_filter",
                input_count=len(targets or []),
                output_count=len(keep_targets),
                skipped_count=skipped,
                reason="",
                skip_reasons=skip_reasons,
            )
        return keep_targets, skipped

    def filter_target_items(self, targets, module="", stage_name=""):
        keep_targets = []
        skipped = 0
        skip_reasons = {}
        for item in targets or []:
            target = item.get("target", "") if isinstance(item, dict) else item
            should_skip, detail = self.should_skip(target, module=module)
            if should_skip:
                skipped += 1
                reason = str(detail.get("scope") or detail.get("rule") or "waf_guard")
                skip_reasons[reason] = int(skip_reasons.get(reason, 0) or 0) + 1
                continue
            keep_targets.append(item)
        with self._lock:
            self._record_filter_stat_locked(
                stage_name or module or "waf_filter",
                input_count=len(targets or []),
                output_count=len(keep_targets),
                skipped_count=skipped,
                reason="",
                skip_reasons=skip_reasons,
            )
        return keep_targets, skipped

    def summary(self, include_all: bool = False) -> Dict:
        with self._lock:
            detected_hosts = []
            blocked_hosts = []
            class_blocked_hosts = []
            skip_request_count = 0
            request_count = 0
            timeout_count = 0
            timeout_by_class = {}
            cdn_detected_count = 0
            waf_detected_count = 0

            for host, state in self._host_state.items():
                request_count += int(state.get("request_count", 0) or 0)
                skip_request_count += int(state.get("skip_count", 0) or 0)
                timeout_count += int(state.get("timeout_count", 0) or 0)
                for traffic_class, count in (state.get("timeout_by_class") or {}).items():
                    timeout_by_class[traffic_class] = (
                        int(timeout_by_class.get(traffic_class, 0) or 0)
                        + int(count or 0)
                    )

                blocked_classes = sorted(str(cls) for cls in (state.get("blocked_classes") or set()))
                has_detection = bool(
                    state.get("blocked")
                    or blocked_classes
                    or state.get("waf_name")
                    or state.get("edge_kind")
                    or state.get("hit_count")
                    or state.get("timeout_count")
                    or state.get("wafw00f_status")
                )
                if not has_detection:
                    continue

                host_item = {
                    "host": host,
                    "blocked": bool(state.get("blocked")),
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
                    "http_waf_name": state.get("http_waf_name", ""),
                    "http_waf_confidence": state.get("http_waf_confidence", ""),
                    "http_waf_evidence": list(state.get("http_waf_evidence", []) or []),
                    "dns_waf_name": state.get("dns_waf_name", ""),
                    "dns_waf_confidence": state.get("dns_waf_confidence", ""),
                    "dns_evidence": list(state.get("dns_evidence", []) or []),
                    "dns_edge_kind": state.get("dns_edge_kind", ""),
                    "response_edge_kind": state.get("response_edge_kind", ""),
                    "edge_kind": state.get("edge_kind", ""),
                    "timeout_count": int(state.get("timeout_count", 0) or 0),
                    "timeout_by_class": {
                        str(key): int(value or 0)
                        for key, value in (state.get("timeout_by_class") or {}).items()
                    },
                    "block_by_class": {
                        str(key): int(value or 0)
                        for key, value in (state.get("block_by_class") or {}).items()
                    },
                    "consecutive_timeout_count": int(
                        state.get("consecutive_timeout_count", 0) or 0
                    ),
                    "consecutive_block_count": int(
                        state.get("consecutive_block_count", 0) or 0
                    ),
                    "detection_sources": sorted(state.get("detection_sources") or set())
                    or self._inferred_detection_sources(state),
                    "wafw00f_status": state.get("wafw00f_status", ""),
                    "wafw00f_names": list(state.get("wafw00f_names", []) or []),
                    "wafw00f_confidence": state.get("wafw00f_confidence", ""),
                    "wafw00f_evidence": list(state.get("wafw00f_evidence", []) or []),
                    "wafw00f_request_count": int(state.get("wafw00f_request_count", 0) or 0),
                    "wafw00f_elapsed_sec": round(float(state.get("wafw00f_elapsed_sec", 0.0) or 0.0), 6),
                    "wafw00f_checked_at": state.get("wafw00f_checked_at", ""),
                    "wafw00f_active_risk_blocked": bool(state.get("wafw00f_active_risk_blocked")),
                    "wafw00f_endpoints": dict(state.get("wafw00f_endpoints") or {}),
                }
                detected_hosts.append(host_item)
                if host_item["edge_kind"] in {"waf", "mixed"}:
                    waf_detected_count += 1
                if host_item["edge_kind"] in {"cdn", "mixed"}:
                    cdn_detected_count += 1
                if not self.smart_skip_enabled:
                    continue
                if state.get("blocked"):
                    blocked_hosts.append(host_item)
                elif blocked_classes:
                    # 仅类别阻断（如目录队列暂停）单独归类，不改变 blocked_hosts 的主机级口径。
                    class_blocked_hosts.append(host_item)

            detected_hosts.sort(
                key=lambda item: (
                    item.get("hit_count", 0),
                    item.get("skip_count", 0),
                ),
                reverse=True,
            )
            blocked_hosts.sort(key=lambda item: (item.get("skip_count", 0), item.get("hit_count", 0)), reverse=True)
            class_blocked_hosts.sort(
                key=lambda item: (item.get("skip_count", 0), item.get("hit_count", 0)), reverse=True
            )
            result = {
                "enabled": self.enabled,
                "smart_skip_enabled": self.smart_skip_enabled,
                "detected_host_count": len(detected_hosts),
                "blocked_host_count": len(blocked_hosts),
                "class_blocked_host_count": len(class_blocked_hosts),
                "request_count": int(request_count),
                "skip_request_count": int(skip_request_count),
                "timeout_count": int(timeout_count),
                "timeout_by_class": timeout_by_class,
                "cdn_detected_host_count": int(cdn_detected_count),
                "waf_detected_host_count": int(waf_detected_count),
                "observed_site_count": len(self._observed_sites),
                "skip_site_count": len(self._skipped_sites),
                "observation_elapsed_sec": round(max(0.0, self._observation_elapsed_sec), 6),
                "blocked_hosts": blocked_hosts,
                "class_blocked_hosts": class_blocked_hosts,
                "detected_hosts": detected_hosts,
                "event_total": int(self._event_total),
                "preclassified_count": int(self._preclassified_count),
                "npoc_promoted_count": int(self._npoc_promoted_count),
                "active_risk_filter_stats": dict(self._active_risk_filter_stats),
                "wafw00f_checked_host_count": sum(
                    1 for item in detected_hosts if item.get("wafw00f_status")
                ),
                **dict(self._wafw00f_metrics),
            }
            if include_all:
                result["all_hosts"] = detected_hosts
                result["observed_sites"] = sorted(self._observed_sites)
                result["skipped_sites"] = sorted(self._skipped_sites)
            return result

    @staticmethod
    def _inferred_detection_sources(state):
        sources = []
        if state.get("http_waf_name") or state.get("http_waf_evidence") or state.get("response_edge_kind"):
            sources.append("http")
        if state.get("dns_waf_name") or state.get("dns_evidence") or state.get("dns_edge_kind"):
            sources.append("dns")
        return sources

    def merge_summary(self, summary: Optional[Dict]):
        """合并隔离子进程的 WAF 观测，保证阶段超时隔离后主任务仍可落库。"""
        if not isinstance(summary, dict):
            return
        host_items = summary.get("all_hosts") or summary.get("detected_hosts") or []
        with self._lock:
            for item in host_items:
                host = self._extract_host(item.get("host", ""))
                if not host or not self._in_scope(host):
                    continue
                state = self._get_state(host)
                for key in ("request_count", "hit_count", "skip_count", "timeout_count"):
                    incoming = int(item.get(key, 0) or 0)
                    state[key] = max(int(state.get(key, 0) or 0), incoming)
                for key in ("timeout_by_class", "block_by_class"):
                    target_values = state.setdefault(key, {})
                    for traffic_class, value in (item.get(key) or {}).items():
                        target_values[traffic_class] = max(
                            int(target_values.get(traffic_class, 0) or 0),
                            int(value or 0),
                        )
                state["consecutive_timeout_count"] = max(
                    int(state.get("consecutive_timeout_count", 0) or 0),
                    int(item.get("consecutive_timeout_count", 0) or 0),
                )
                state["consecutive_block_count"] = max(
                    int(state.get("consecutive_block_count", 0) or 0),
                    int(item.get("consecutive_block_count", 0) or 0),
                )
                state["last_status"] = int(item.get("last_status", 0) or 0)
                state["last_url"] = safe_error_text(item.get("last_url", "") or "")
                for key in (
                    "reason",
                    "rule",
                    "module",
                    "waf_name",
                    "waf_confidence",
                    "http_waf_name",
                    "http_waf_confidence",
                    "dns_waf_name",
                    "dns_waf_confidence",
                    "dns_edge_kind",
                    "response_edge_kind",
                    "wafw00f_checked_at",
                ):
                    if item.get(key):
                        if key in {"dns_edge_kind", "response_edge_kind"}:
                            state[key] = self._merge_edge_kind(
                                state.get(key, ""), item[key]
                            )
                        else:
                            state[key] = item[key]
                if item.get("wafw00f_status"):
                    state["wafw00f_status"] = self._merge_wafw00f_status(
                        state.get("wafw00f_status", ""), item["wafw00f_status"]
                    )
                incoming_wafw00f_confidence = str(
                    item.get("wafw00f_confidence", "") or ""
                )
                if self._confidence_rank(incoming_wafw00f_confidence) > self._confidence_rank(
                    state.get("wafw00f_confidence", "")
                ):
                    state["wafw00f_confidence"] = incoming_wafw00f_confidence
                for key in ("waf_evidence", "http_waf_evidence", "dns_evidence"):
                    values = list(item.get(key, []) or [])
                    if values:
                        state[key] = values[:8]
                for key in ("wafw00f_names", "wafw00f_evidence"):
                    values = list(item.get(key, []) or [])
                    if values:
                        existing = state.setdefault(key, [])
                        for value in values:
                            if value not in existing:
                                existing.append(value)
                        state[key] = existing[:8]
                state["wafw00f_request_count"] = max(
                    int(state.get("wafw00f_request_count", 0) or 0),
                    int(item.get("wafw00f_request_count", 0) or 0),
                )
                state["wafw00f_elapsed_sec"] = max(
                    float(state.get("wafw00f_elapsed_sec", 0.0) or 0.0),
                    float(item.get("wafw00f_elapsed_sec", 0.0) or 0.0),
                )
                state["wafw00f_active_risk_blocked"] = bool(
                    state.get("wafw00f_active_risk_blocked")
                    or item.get("wafw00f_active_risk_blocked")
                )
                state.setdefault("detection_sources", set()).update(
                    item.get("detection_sources") or []
                )
                for endpoint, endpoint_item in (item.get("wafw00f_endpoints") or {}).items():
                    state.setdefault("wafw00f_endpoints", {}).setdefault(endpoint, endpoint_item)
                endpoint_items = list((state.get("wafw00f_endpoints") or {}).values())
                if endpoint_items:
                    state["wafw00f_request_count"] = sum(
                        max(0, int(endpoint.get("request_count", 0) or 0))
                        for endpoint in endpoint_items
                        if isinstance(endpoint, dict)
                    )
                    state["wafw00f_elapsed_sec"] = round(
                        sum(
                            max(0.0, float(endpoint.get("elapsed_sec", 0.0) or 0.0))
                            for endpoint in endpoint_items
                            if isinstance(endpoint, dict)
                        ),
                        6,
                    )
                state["edge_kind"] = self._merge_edge_kind(
                    state.get("edge_kind", ""), item.get("edge_kind", "")
                )
                state["blocked_classes"].update(item.get("blocked_classes") or [])
                if item.get("blocked"):
                    state["blocked"] = True
            self._event_total = max(
                int(self._event_total), int(summary.get("event_total", 0) or 0)
            )
            self._preclassified_count = max(
                int(self._preclassified_count),
                int(summary.get("preclassified_count", 0) or 0),
            )
            self._npoc_promoted_count = max(
                int(self._npoc_promoted_count),
                int(summary.get("npoc_promoted_count", 0) or 0),
            )
            self._observed_sites.update(summary.get("observed_sites", []) or [])
            self._skipped_sites.update(summary.get("skipped_sites", []) or [])
            for key in self._wafw00f_metrics:
                incoming = summary.get(key, 0)
                if key.endswith("elapsed_sec"):
                    self._wafw00f_metrics[key] = max(
                        float(self._wafw00f_metrics[key] or 0.0), float(incoming or 0.0)
                    )
                else:
                    self._wafw00f_metrics[key] = max(
                        int(self._wafw00f_metrics[key] or 0), int(incoming or 0)
                    )
            for key, value in (summary.get("active_risk_filter_stats") or {}).items():
                current = self._active_risk_filter_stats.setdefault(
                    key,
                    {"input_count": 0, "output_count": 0, "skipped_count": 0, "skip_reasons": {}},
                )
                for count_key in ("input_count", "output_count", "skipped_count"):
                    current[count_key] = max(
                        int(current.get(count_key, 0) or 0), int(value.get(count_key, 0) or 0)
                    )
                for reason, count in (value.get("skip_reasons") or {}).items():
                    current.setdefault("skip_reasons", {})[reason] = max(
                        int(current["skip_reasons"].get(reason, 0) or 0), int(count or 0)
                    )

    def summary_text(self) -> str:
        data = self.summary()
        if not data.get("enabled"):
            return "未启用"

        detected_count = int(data.get("detected_host_count", 0) or 0)
        blocked_count = int(data.get("blocked_host_count", 0) or 0)
        skipped = int(data.get("skip_request_count", 0) or 0)
        observed_sites = int(data.get("observed_site_count", 0) or 0)
        skipped_sites = int(data.get("skip_site_count", 0) or 0)
        observation_elapsed = float(data.get("observation_elapsed_sec", 0.0) or 0.0)
        timeout_count = int(data.get("timeout_count", 0) or 0)
        preclassified_count = int(data.get("preclassified_count", 0) or 0)
        npoc_promoted_count = int(data.get("npoc_promoted_count", 0) or 0)
        wafw00f_checked = int(data.get("wafw00f_checked_total", 0) or 0)
        wafw00f_detected = int(data.get("wafw00f_detected_total", 0) or 0)

        if detected_count <= 0:
            return "已启用，未识别WAF，站点:{}，请求:{}，补充检查:{}/{}，检测耗时:{:.3f}s".format(
                observed_sites,
                int(data.get("request_count", 0) or 0),
                wafw00f_detected,
                wafw00f_checked,
                observation_elapsed,
            )

        parts = [
            "已识别主机:{}".format(detected_count),
            "观测站点:{}".format(observed_sites),
            "检测耗时:{:.3f}s".format(observation_elapsed),
        ]
        if wafw00f_checked:
            parts.append("wafw00f检查:{}/{}".format(wafw00f_detected, wafw00f_checked))
        if self.smart_skip_enabled:
            parts.append("跳过主机:{}".format(blocked_count))
            parts.append("跳过站点:{}".format(skipped_sites))
            parts.append("跳过请求:{}".format(skipped))
        if preclassified_count:
            parts.append("NPoC预分类跳过:{}".format(preclassified_count))
        if npoc_promoted_count:
            parts.append("WAF证据联动NPoC:{}".format(npoc_promoted_count))
        if timeout_count:
            timeout_classes = data.get("timeout_by_class") or {}
            timeout_text = ",".join(
                "{}:{}".format(key, value)
                for key, value in sorted(timeout_classes.items())
                if int(value or 0) > 0
            )
            parts.append("分类超时:{}{}".format(
                timeout_count,
                "({})".format(timeout_text) if timeout_text else "",
            ))

        host_preview = []
        for item in data.get("detected_hosts", [])[:3]:
            host = str(item.get("host", "") or "").strip()
            waf_name = str(item.get("waf_name", "") or "").strip()
            if host:
                host_preview.append("{}({})".format(host, waf_name or "unknown"))
        if host_preview:
            parts.append("主机:{}".format(",".join(host_preview)))

        return "，".join(parts)
