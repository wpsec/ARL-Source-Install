"""
WIH 接口提取结果的轻量可达性探测。
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

import requests

from app import utils
from app.config import Config


logger = utils.get_logger()

_ACTIVE_METHODS = {"GET", "HEAD", "POST", "OPTIONS"}
_DANGEROUS_METHODS = {"DELETE", "PUT", "PATCH", "TRACE", "CONNECT"}
_SKIP_BODY_KINDS = {"multipart", "octet_stream", "binary"}
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


def _probe_one(item: Dict, waf_guard=None, dns_policy_cache=None) -> Dict:
    item = dict(item or {})
    method = str(item.get("method") or "GET").strip().upper() or "GET"
    url = str(item.get("url") or "").strip()

    if _has_response(item):
        return _mark_probe_state(item, "observed", "WIH runtime 已捕获响应", method)

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

    headers = _safe_headers(item)
    try:
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
        item["status_code"] = status_code if status_code > 0 else None
        item["response_status"] = item["status_code"]
        item["response_size"] = _response_size(response)
        return _mark_probe_state(item, "probed", "已按 {} 方法轻量验证".format(method), method)
    except Exception as exc:
        logger.debug("wih endpoint probe failed url:{} method:{} err:{}".format(url, method, exc))
        return _mark_probe_state(item, "error", "轻量验证失败: {}".format(exc.__class__.__name__), method)


def enrich_wih_endpoints(endpoints: List[Dict], waf_guard=None) -> List[Dict]:
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
                results[index] = _probe_one(item, waf_guard=waf_guard, dns_policy_cache=dns_policy_cache)
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
            futures[executor.submit(_probe_one, item, waf_guard, dns_policy_cache)] = index

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


def run_wih_endpoint_probe(endpoints: List[Dict], waf_guard=None) -> List[Dict]:
    """
    运行 WIH 接口轻量探测，并返回补全后的接口记录。
    """
    endpoint_list = [dict(item or {}) for item in list(endpoints or []) if isinstance(item, dict)]
    if not endpoint_list:
        logger.info("wih endpoint probe skip, no endpoints")
        return []

    logger.info("wih endpoint probe start endpoints:{}".format(len(endpoint_list)))
    results = enrich_wih_endpoints(endpoint_list, waf_guard=waf_guard)
    observed_count = sum(1 for item in results if _has_response(item))
    logger.info(
        "wih endpoint probe finish endpoints:{} observed:{}".format(
            len(results),
            observed_count,
        )
    )
    return results
