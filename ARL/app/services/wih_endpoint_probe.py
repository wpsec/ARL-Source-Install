"""
WIH 接口提取结果的轻量可达性探测。

请求统一走任务级响应缓存（DiscoveryContext）：命中即复用、miss 走
single-flight 合并并发抓取、成功响应回填 registry 供其它策略消费。
"""
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

import requests

from app import utils
from app.config import Config

from .api_unified_shadow import shadow_probe_failed, shadow_probe_start

logger = utils.get_logger()

_PROBE_CONSUMER = "wih_endpoint_probe"

_ACTIVE_METHODS = {"GET", "HEAD", "POST", "OPTIONS"}
_DANGEROUS_METHODS = {"DELETE", "PUT", "PATCH", "TRACE", "CONNECT"}
_SKIP_BODY_KINDS = {"multipart", "octet_stream", "binary"}
_RESPONSE_PACKET_MAX_CHARS = 4000
_SENSITIVE_REQUEST_HEADERS = {
    "authorization",
    "cookie",
    "host",
    "content-length",
    "connection",
    "proxy-authorization",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-dest",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
}


def _safe_positive_int(value):
    try:
        number = int(value)
    except Exception:
        return None
    return number if number > 0 else None


def _safe_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return default


def _has_response(item: Dict) -> bool:
    if not isinstance(item, dict):
        return False
    return _safe_positive_int(item.get("status_code") or item.get("response_status")) is not None


def _mark_probe_state(item: Dict, status: str, note: str, method: str = "") -> Dict:
    item["verification_status"] = str(status or "").strip()
    item["verification_note"] = str(note or "").strip()
    if method:
        item["verification_method"] = str(method or "").strip().upper()
    return item


def _safe_headers(item: Dict) -> Dict[str, str]:
    request_template = item.get("request_template") if isinstance(item.get("request_template"), dict) else {}
    raw_headers = request_template.get("headers") if isinstance(request_template.get("headers"), dict) else {}
    headers = {}

    for key, value in raw_headers.items():
        key_text = str(key or "").strip()
        if not key_text:
            continue
        if key_text.lower() in _SENSITIVE_REQUEST_HEADERS:
            continue
        value_text = str(value or "").strip()
        if value_text:
            headers[key_text[:80]] = value_text[:512]

    content_type = str(item.get("content_type") or "").strip()
    if content_type and not any(key.lower() == "content-type" for key in headers):
        headers["Content-Type"] = content_type[:160]

    headers.setdefault("User-Agent", "Mozilla/5.0")
    headers.setdefault("Accept", "*/*")
    headers.setdefault("X-ARL-WIH-Endpoint-Probe", "1")
    return headers


def _build_request_kwargs(item: Dict, method: str, headers: Dict) -> Dict:
    request_template = item.get("request_template") if isinstance(item.get("request_template"), dict) else {}
    body = request_template.get("body") if isinstance(request_template.get("body"), dict) else {}
    body_text = str(request_template.get("body_text") or "").strip()
    content_type = str(headers.get("Content-Type") or headers.get("content-type") or item.get("content_type") or "").strip().lower()
    body_kind = str(item.get("body_kind") or "").strip().lower()

    kwargs = {
        "headers": headers,
        "verify": False,
        "timeout": (
            3.1,
            max(3.1, float(getattr(Config, "WIH_ENDPOINT_PROBE_TIMEOUT_SEC", 8) or 8)),
        ),
        "allow_redirects": True,
    }

    if Config.PROXY_URL:
        kwargs["proxies"] = {
            "https": Config.PROXY_URL,
            "http": Config.PROXY_URL,
        }
    else:
        kwargs["proxies"] = {"http": None, "https": None}

    if method != "POST":
        return kwargs

    if body_kind == "json" or "json" in content_type:
        if body:
            kwargs["json"] = body
        elif body_text:
            kwargs["data"] = body_text
        return kwargs

    if body_kind == "form_urlencoded" or "x-www-form-urlencoded" in content_type:
        kwargs["data"] = body if body else body_text
        return kwargs

    if body_text:
        kwargs["data"] = body_text
    elif body:
        kwargs["data"] = body

    return kwargs


def _response_size(response) -> int:
    headers = getattr(response, "headers", {}) or {}
    content_length = _safe_int(headers.get("Content-Length") or headers.get("content-length"), 0)
    if content_length > 0:
        return content_length

    content = getattr(response, "content", b"") or b""
    try:
        return len(content)
    except Exception:
        return 0


def _decode_response_body(response) -> str:
    body = getattr(response, "content", b"") or b""
    if isinstance(body, str):
        return body
    encoding = str(getattr(response, "encoding", "") or "").strip()
    for candidate in [encoding, "utf-8", "gbk", "latin-1"]:
        if not candidate:
            continue
        try:
            return body.decode(candidate, errors="ignore")
        except Exception:
            continue
    return ""


def _build_response_packet(response) -> str:
    status_code = int(getattr(response, "status_code", 0) or 0)
    reason = str(getattr(response, "reason", "") or "").strip()
    headers = getattr(response, "headers", {}) or {}
    status_line = "HTTP/1.1 {}{}".format(status_code, " {}".format(reason) if reason else "")
    header_lines = []
    for key, value in list(headers.items())[:24]:
        key_text = str(key or "").strip()
        if not key_text:
            continue
        header_lines.append("{}: {}".format(key_text[:80], str(value or "").strip()[:400]))

    content_type = str(headers.get("Content-Type") or headers.get("content-type") or "").strip().lower()
    body_text = _decode_response_body(response)
    if body_text:
        body_text = body_text.replace("\r\n", "\n").replace("\r", "\n")
        if len(body_text) > _RESPONSE_PACKET_MAX_CHARS:
            body_text = "{}\n...[truncated]".format(body_text[:_RESPONSE_PACKET_MAX_CHARS])
    elif _response_size(response) > 0:
        body_text = "[binary {} bytes]".format(_response_size(response))
    elif content_type:
        body_text = "[empty body, content-type={}]".format(content_type)

    parts = [status_line]
    if header_lines:
        parts.extend(header_lines)
    if body_text:
        parts.extend(["", body_text])
    return "\n".join(parts).strip()


def _should_skip(item: Dict) -> str:
    method = str(item.get("method") or "GET").strip().upper() or "GET"
    body_kind = str(item.get("body_kind") or "").strip().lower()
    content_type = str(item.get("content_type") or "").strip().lower()

    if _has_response(item):
        return ""
    if method in _DANGEROUS_METHODS:
        return "危险 HTTP 方法 {}，未主动验证".format(method)
    if method not in _ACTIVE_METHODS:
        return "HTTP 方法 {} 不在轻量验证范围内".format(method)
    if method == "POST" and (body_kind in _SKIP_BODY_KINDS or "multipart/form-data" in content_type or "octet-stream" in content_type):
        body_label = body_kind or content_type or "POST"
        return "{} 请求体可能产生副作用，未主动验证".format(body_label)
    return ""


def _probe_request_profile(method: str, item: Dict) -> str:
    """按 method + 请求体构造 endpoint 探测的缓存 profile。

    GET 与页面抓取链路（fetchSite/pageFetch/urlfinder_extract 等）共用
    html_get，探测与抓取结果可互相复用；POST 以请求体摘要入 key，
    避免不同 body 的同 URL 记录互相污染。
    """
    method = str(method or "GET").strip().upper() or "GET"
    if method == "GET":
        return "html_get"
    if method != "POST":
        return "endpoint_{}".format(method.lower())
    request_template = item.get("request_template") if isinstance(item.get("request_template"), dict) else {}
    signature = json.dumps(
        {
            "body": request_template.get("body"),
            "body_text": request_template.get("body_text"),
            "content_type": str(item.get("content_type") or "").strip().lower(),
        },
        sort_keys=True,
        ensure_ascii=False,
        default=str,
    )
    digest = hashlib.sha256(signature.encode("utf-8")).hexdigest()[:16]
    return "endpoint_post_{}".format(digest)


class _RecordedResponse(object):
    """把 ResponseRecord 适配成 packet 构造可读的响应视图。"""

    def __init__(self, record):
        self.status_code = int(getattr(record, "status_code", 0) or 0)
        self.headers = dict(getattr(record, "headers", {}) or {})
        self.content = bytes(getattr(record, "body", b"") or b"")
        self.reason = ""
        content_type = str(getattr(record, "content_type", "") or "")
        self.encoding = (
            content_type.split("charset=", 1)[1].split(";")[0].strip()
            if "charset=" in content_type.lower() else "")


def _resolve_cached_response(discovery_context, url: str, method: str,
                             profile: str) -> Tuple[Optional[object], bool]:
    """返回 (可复用记录|None, 是否 single-flight 先行者)。"""
    cached = discovery_context.get_response(
        url, method=method, request_profile=profile,
        consumer=_PROBE_CONSUMER)
    if cached is not None:
        return cached, False
    cached, follower = discovery_context.await_singleflight_leader(
        url, method=method, request_profile=profile,
        consumer=_PROBE_CONSUMER)
    return cached, not follower


def _apply_cached_record(item: Dict, record, method: str) -> Dict:
    status_code = int(getattr(record, "status_code", 0) or 0)
    item["status_code"] = status_code if status_code > 0 else None
    item["response_status"] = item["status_code"]
    body = bytes(getattr(record, "body", b"") or b"")
    item["response_size"] = len(body)
    packet = _build_response_packet(_RecordedResponse(record))
    item["verification_response_packet"] = packet
    if not str(item.get("response_packet") or "").strip():
        item["response_packet"] = packet
    return _mark_probe_state(
        item, "probed",
        "复用任务内缓存响应的 {} 结果".format(method), method)


def _probe_one(item: Dict, waf_guard=None, dns_policy_cache=None, discovery_context=None) -> Dict:
    item = dict(item or {})
    method = str(item.get("method") or "GET").strip().upper() or "GET"
    url = str(item.get("url") or "").strip()

    if _has_response(item):
        # 文案会入库 verification_note 并在 UI 透传：说清"为什么没再探"而不是术语堆叠
        return _mark_probe_state(
            item, "observed",
            "引擎运行期已捕获该响应（状态码 {}），未重复探测".format(
                _safe_positive_int(item.get("status_code") or item.get("response_status")) or "-"),
            method)

    skip_reason = _should_skip(item)
    if skip_reason:
        return _mark_probe_state(item, "skipped", skip_reason, method)

    if not url.lower().startswith(("http://", "https://")):
        return _mark_probe_state(item, "skipped", "非 HTTP(S) 接口未主动验证", method)

    allow_scan, policy_detail = utils.check_dns_policy_for_url(url, cache_map=dns_policy_cache)
    if not allow_scan:
        return _mark_probe_state(
            item,
            "skipped",
            "DNS 策略跳过: {}".format(policy_detail.get("reason", "") or "out_of_scope"),
            method,
        )

    profile = _probe_request_profile(method, item)
    shadow_probe_start(discovery_context, url, method, profile)
    inflight_owner = False
    if discovery_context is not None:
        cached, inflight_owner = _resolve_cached_response(
            discovery_context, url, method, profile)
        if cached is not None:
            return _apply_cached_record(item, cached, method)

    lease = None
    headers = _safe_headers(item)
    try:
        if discovery_context is not None:
            lease, lease_reason = discovery_context.acquire_request(url, "wih")
            if lease is None and lease_reason == "blocked":
                return _mark_probe_state(
                    item, "skipped", "WAF 流量策略暂停 wih 类别，未主动验证", method)
            if lease is None:
                logger.debug("endpoint probe over capacity, continue url:{}".format(url[:200]))

        if waf_guard:
            should_skip, detail = waf_guard.should_skip(url, module="wih_endpoint_probe")
            if should_skip:
                return _mark_probe_state(
                    item,
                    "skipped",
                    "WAF 智能跳过: {}".format(detail.get("reason", "") or detail.get("waf_name", "") or "blocked"),
                    method,
                )

            headers, delay, _ = waf_guard.prepare_request(
                url,
                module="wih_endpoint_probe",
                method=method,
                headers=headers,
            )
            if delay > 0:
                import time

                time.sleep(delay)

        request_kwargs = _build_request_kwargs(item, method, headers)
        response = requests.request(method, url, **request_kwargs)
        if waf_guard:
            waf_guard.observe_response(url, response, module="wih_endpoint_probe")

        status_code = int(getattr(response, "status_code", 0) or 0)
        if discovery_context is not None:
            discovery_context.put_response(
                url=url,
                method=method,
                request_profile=profile,
                status_code=status_code,
                headers=getattr(response, "headers", {}) or {},
                content_type=str(
                    (getattr(response, "headers", {}) or {}).get("Content-Type", "") or ""),
                body=getattr(response, "content", b"") or b"",
                source=_PROBE_CONSUMER,
                consumer=_PROBE_CONSUMER,
            )
        item["status_code"] = status_code if status_code > 0 else None
        item["response_status"] = item["status_code"]
        item["response_size"] = _response_size(response)
        item["verification_response_packet"] = _build_response_packet(response)
        if not str(item.get("response_packet") or "").strip():
            item["response_packet"] = item["verification_response_packet"]
        return _mark_probe_state(item, "probed", "已按 {} 方法轻量验证".format(method), method)
    except Exception as exc:
        shadow_probe_failed(discovery_context)
        logger.debug("wih endpoint probe failed url:{} method:{} err:{}".format(url, method, exc))
        return _mark_probe_state(item, "error", "轻量验证失败: {}".format(exc.__class__.__name__), method)
    finally:
        if lease is not None:
            lease.release()
        if inflight_owner and discovery_context is not None:
            # 幂等释放：put_response 成功路径已释放时此处为 no-op。
            discovery_context.release_fetch_slot(
                url, method=method, request_profile=profile)


def enrich_wih_endpoints(endpoints: List[Dict], waf_guard=None, discovery_context=None) -> List[Dict]:
    """
    对 WIH 接口记录补充验证状态与可获取的响应状态。
    """
    items = [dict(item or {}) for item in list(endpoints or []) if isinstance(item, dict)]
    if not items:
        return []

    max_targets = int(getattr(Config, "WIH_ENDPOINT_PROBE_MAX_TARGETS", 120) or 120)
    concurrency = max(1, int(getattr(Config, "WIH_ENDPOINT_PROBE_CONCURRENCY", 8) or 8))
    dns_policy_cache = {}
    results = [None] * len(items)
    futures = {}
    active_count = 0

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        for index, item in enumerate(items):
            if _has_response(item) or _should_skip(item):
                results[index] = _probe_one(
                    item,
                    waf_guard=waf_guard,
                    dns_policy_cache=dns_policy_cache,
                    discovery_context=discovery_context,
                )
                continue

            if active_count >= max_targets:
                results[index] = _mark_probe_state(
                    item,
                    "skipped",
                    "超过 WIH 接口轻量验证上限，未主动验证",
                    str(item.get("method") or "GET").strip().upper() or "GET",
                )
                continue

            active_count += 1
            futures[executor.submit(_probe_one, item, waf_guard, dns_policy_cache, discovery_context)] = index

        for future in as_completed(futures):
            index = futures[future]
            try:
                results[index] = future.result()
            except Exception as exc:
                logger.warning("wih endpoint probe worker failed err:{}".format(exc))
                results[index] = _mark_probe_state(
                    items[index],
                    "error",
                    "轻量验证失败: {}".format(exc.__class__.__name__),
                    str(items[index].get("method") or "GET").strip().upper() or "GET",
                )

    return [item for item in results if isinstance(item, dict)]


def run_wih_endpoint_probe(endpoints: List[Dict], waf_guard=None, discovery_context=None) -> List[Dict]:
    """
    运行 WIH 接口轻量探测，并返回补全后的接口记录。
    """
    endpoint_list = [dict(item or {}) for item in list(endpoints or []) if isinstance(item, dict)]
    if not endpoint_list:
        logger.info("wih endpoint probe skip, no endpoints")
        return []

    logger.info("wih endpoint probe start endpoints:{}".format(len(endpoint_list)))
    results = enrich_wih_endpoints(
        endpoint_list, waf_guard=waf_guard, discovery_context=discovery_context)
    observed_count = sum(1 for item in results if _has_response(item))
    logger.info(
        "wih endpoint probe finish endpoints:{} observed:{}".format(
            len(results),
            observed_count,
        )
    )
    return results
