"""
Web 信息增强辅助函数。

说明：
- 为页面情报提取、JS 敏感信息扫描、API 文档解析提供统一的轻量工具。
- 仅处理同目标主机或同主域范围内的候选，尽量减少跨站噪音。
"""
import hashlib
import re
from typing import Dict, Iterable, Optional, Set, Tuple
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
    discovery_context=None,
    traffic_class: str = "wih",
    request_profile: str = "html_get",
    mirror_html_get: bool = False,
    block_signal: Optional[Dict] = None,
):
    """统一响应缓存感知的 GET 工具。

    `request_profile` 默认 `html_get`（既有调用零变化）；第 3 批起 API 文档
    以 `api_doc` profile 获取：先查统一桶，miss 再复用 `html_get` 桶（不重复
    发网络请求），真实抓取后按需镜像登记 `html_get` 桶保持旧消费者复用面。

    `block_signal`（第 9 批 §8.2）：调用方传入空 dict 时，WAF 流量类别熔断
    导致跳过请求的路径会写 `block_signal["waf_blocked"]=True`——返回空串与
    "被熔断"不再混同（文档队列据此把 waf_blocked 与 empty_response 分开归因）。
    """
    profile = str(request_profile or "html_get")

    def _mirror(registry_context, target_profile: str, status_code, headers, content_type, body_bytes):
        """直写 registry：不发 PageFetched、不计 actual_duplicate（非第二次网络请求）。

        调用方保证 target_profile 是本次主路径未写过的另一个桶。
        """
        if registry_context is None:
            return
        try:
            registry_context.response_registry.put(
                url=url,
                method="GET",
                request_profile=target_profile,
                status_code=status_code,
                headers=headers,
                content_type=content_type,
                body=body_bytes,
                source=waf_module,
                consumer=waf_module,
            )
        except Exception:
            utils.get_logger().debug(
                "fetch_text mirror put failed url:{} profile:{}".format(url[:160], target_profile))

    inflight_owner = False
    if discovery_context is not None:
        cached_response = discovery_context.get_response(
            url,
            request_profile=profile,
            consumer=waf_module,
        )
        if cached_response is None and profile != "html_get":
            cached_response = discovery_context.get_response(
                url,
                request_profile="html_get",
                consumer=waf_module,
            )
            if cached_response is not None:
                _mirror(discovery_context, profile,
                        int(getattr(cached_response, "status_code", 0) or 0),
                        dict(getattr(cached_response, "headers", {}) or {}),
                        str(getattr(cached_response, "content_type", "") or ""),
                        bytes(getattr(cached_response, "body", b"") or b""))
        if cached_response is None:
            # 并发 miss 合并：等待先行者结果，拿不到才自己抓。
            cached_response, follower = discovery_context.await_singleflight_leader(
                url, request_profile=profile, consumer=waf_module)
            inflight_owner = not follower
        if cached_response is not None:
            status_code = int(getattr(cached_response, "status_code", 0) or 0)
            body = bytes(getattr(cached_response, "body", b"") or b"")
            if status_code >= 400 or not body:
                return "", cached_response
            request_max_bytes = max(1024, int(max_bytes or 1024))
            if bool(getattr(cached_response, "body_truncated", False)) and len(body) < request_max_bytes:
                # 登记时被正文预算截断且短于本次消费者需求：回源真实请求，避免漏提取。
                pass
            else:
                body = body[:request_max_bytes]
                return body.decode("utf-8", errors="ignore"), cached_response

    def _release_inflight():
        """先行者未走 put_response 的退出路径必须释放槽位（幂等，已释放则 no-op）。"""
        if not inflight_owner or discovery_context is None:
            return
        try:
            discovery_context.release_fetch_slot(url, request_profile=profile)
        except Exception:
            pass

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
        _release_inflight()
        return "", None

    lease = None
    if discovery_context is not None:
        lease, lease_reason = discovery_context.acquire_request(url, traffic_class)
        if lease is None and lease_reason == "blocked":
            utils.get_logger().info(
                "{} skipped by waf traffic policy url:{}".format(waf_module, url)
            )
            if block_signal is not None:
                try:
                    block_signal["waf_blocked"] = True
                except Exception:
                    pass
            _release_inflight()
            return "", None
        if lease is None:
            utils.get_logger().warning(
                "{} over capacity, continue request url:{}".format(waf_module, url)
            )

    try:
        conn = utils.http_req(
            url,
            "get",
            timeout=timeout,
            waf_guard=waf_guard,
            waf_module=waf_module,
        )
    except Exception as exc:
        if discovery_context is not None:
            discovery_context.record_metric("failed_count")
        _release_inflight()
        utils.get_logger().warning(
            "{} request failed task context error_type:{}".format(waf_module, type(exc).__name__)
        )
        return "", None
    finally:
        if lease is not None:
            lease.release()

    status_code = int(getattr(conn, "status_code", 0) or 0)
    if status_code >= 400:
        if discovery_context is not None:
            error_body = getattr(conn, "content", b"") or b""
            error_headers = getattr(conn, "headers", {}) or {}
            discovery_context.put_response(
                url=url,
                method="GET",
                request_profile=profile,
                status_code=status_code,
                headers=error_headers,
                content_type=error_headers.get("Content-Type", ""),
                body=error_body,
                source=waf_module,
                consumer=waf_module,
            )
            if mirror_html_get and profile != "html_get":
                _mirror(discovery_context, "html_get", status_code,
                        dict(error_headers), str(error_headers.get("Content-Type", "") or ""), error_body)
        return "", conn

    body = bytes(getattr(conn, "content", b"") or b"")
    if not body:
        _release_inflight()
        return "", conn

    body = body[: max(1024, int(max_bytes or 1024))]
    if discovery_context is not None:
        ok_headers = getattr(conn, "headers", {}) or {}
        discovery_context.put_response(
            url=url,
            method="GET",
            request_profile=profile,
            status_code=status_code,
            headers=ok_headers,
            content_type=ok_headers.get("Content-Type", ""),
            body=body,
            source=waf_module,
            consumer=waf_module,
        )
        if mirror_html_get and profile != "html_get":
            _mirror(discovery_context, "html_get", status_code,
                    dict(ok_headers), str(ok_headers.get("Content-Type", "") or ""), body)
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
