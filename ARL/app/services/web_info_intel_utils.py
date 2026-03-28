"""
Web 信息增强辅助函数。

说明：
- 为页面情报提取、JS 敏感信息扫描、API 文档解析提供统一的轻量工具。
- 仅处理同目标主机或同主域范围内的候选，尽量减少跨站噪音。
"""
import hashlib
import re
from typing import Iterable, Optional, Set, Tuple
from urllib.parse import unquote, urljoin, urlparse

from app import utils
from .url_candidate_filter import (
    has_route_template_markers,
    is_js_resource_path,
    is_noise_single_segment_path,
    is_non_js_static_resource_path,
    strip_route_method_suffix,
)

DNS_POLICY_CACHE = {}

_DOMAIN_RE = re.compile(
    r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b"
)
_URL_RE = re.compile(r"https?://[^\s\"'<>`]{4,2048}", re.I)


def stable_hash(*parts) -> int:
    text = "|".join(str(part or "").strip() for part in parts)
    digest = hashlib.md5(text.encode("utf-8", errors="ignore")).hexdigest()
    return int(digest[:16], 16)


def extract_host(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""

    try:
        parsed = urlparse(text)
        host = str(parsed.hostname or "").strip().lower().rstrip(".")
        if host:
            return host
    except Exception:
        pass

    try:
        parsed = urlparse("//{}".format(text))
        return str(parsed.hostname or "").strip().lower().rstrip(".")
    except Exception:
        return ""


def safe_site(url: str) -> str:
    try:
        parsed = urlparse(str(url or "").strip())
    except Exception:
        return ""
    if parsed.scheme and parsed.netloc:
        return "{}://{}".format(parsed.scheme, parsed.netloc)
    return ""


def is_http_url(value: str) -> bool:
    text = str(value or "").strip().lower()
    return text.startswith("http://") or text.startswith("https://")


def is_js_url(value: str) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return False
    if ".js" in text or text.endswith(".mjs"):
        return True
    try:
        path = urlparse(text).path.lower()
    except Exception:
        return False
    return path.endswith(".js") or path.endswith(".mjs")


def clean_candidate(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""

    text = text.strip("\"'`;,()[]{}")
    text = text.replace("\\/", "/")
    try:
        text = unquote(text)
    except Exception:
        pass
    return text.strip()


def collect_allowed_hosts(sites: Iterable[str]) -> Set[str]:
    hosts = set()
    for site in sites or []:
        host = extract_host(site)
        if host:
            hosts.add(host)
    return hosts


def collect_allowed_flds(sites: Iterable[str]) -> Set[str]:
    flds = set()
    for site in sites or []:
        host = extract_host(site)
        if not host or not utils.is_valid_domain(host):
            continue
        fld = utils.get_fld(host)
        if fld:
            flds.add(fld)
    return flds


def normalize_in_scope_url(base_url: str, value: str, allowed_hosts: Set[str], allow_js: bool = True) -> str:
    candidate = clean_candidate(value)
    if not candidate:
        return ""

    try:
        if candidate.startswith("http://") or candidate.startswith("https://"):
            normalized = candidate
        elif candidate.startswith("//"):
            try:
                scheme = urlparse(str(base_url or "")).scheme or "https"
            except Exception:
                scheme = "https"
            normalized = "{}:{}".format(scheme, candidate)
        else:
            normalized = urljoin(str(base_url or "").strip(), candidate)

        parsed = urlparse(normalized)
    except Exception:
        return ""

    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return ""

    host = extract_host(normalized)
    if not host or (allowed_hosts and host not in allowed_hosts):
        return ""

    path_text = strip_route_method_suffix(parsed.path or "")
    if has_route_template_markers(path_text):
        return ""
    if is_noise_single_segment_path(path_text):
        return ""
    if is_non_js_static_resource_path(path_text):
        return ""
    if (not allow_js) and is_js_resource_path(path_text):
        return ""

    if parsed.fragment:
        parsed = parsed._replace(fragment="")
    if path_text != parsed.path:
        parsed = parsed._replace(path=path_text)

    return parsed.geturl()


def fetch_text(
    url: str,
    waf_guard=None,
    timeout: Tuple[int, int] = (5, 12),
    max_bytes: int = 512 * 1024,
    waf_module: str = "web_info_intel",
):
    allow_scan, policy_detail = utils.check_dns_policy_for_url(url, cache_map=DNS_POLICY_CACHE)
    if not allow_scan:
        utils.get_logger().info(
            "skip {} by dns policy url:{} reason:{} resolver_ips:{} system_ips:{}".format(
                waf_module,
                url,
                policy_detail.get("reason", ""),
                policy_detail.get("resolver_ips", []),
                policy_detail.get("system_ips", []),
            )
        )
        return "", None

    try:
        conn = utils.http_req(
            url,
            "get",
            timeout=timeout,
            waf_guard=waf_guard,
            waf_module=waf_module,
        )
    except Exception:
        return "", None

    status_code = int(getattr(conn, "status_code", 0) or 0)
    if status_code >= 400:
        return "", conn

    body = bytes(getattr(conn, "content", b"") or b"")
    if not body:
        return "", conn

    body = body[: max(1024, int(max_bytes or 1024))]
    return body.decode("utf-8", errors="ignore"), conn


def extract_scope_domains(text: str, allowed_flds: Set[str], exclude_hosts: Optional[Set[str]] = None) -> Set[str]:
    if not text or not allowed_flds:
        return set()

    exclude_hosts = set(exclude_hosts or [])
    results = set()

    candidates = set()
    for item in _DOMAIN_RE.findall(text):
        candidates.add(str(item or "").strip().lower().rstrip("."))

    for item in _URL_RE.findall(text):
        host = extract_host(item)
        if host:
            candidates.add(host)

    for candidate in candidates:
        if not candidate or candidate in exclude_hosts:
            continue
        if not utils.is_valid_domain(candidate):
            continue
        fld = utils.get_fld(candidate)
        if not fld or fld not in allowed_flds:
            continue
        try:
            if utils.check_domain_black(candidate):
                continue
        except Exception:
            pass
        results.add(candidate)

    return results
