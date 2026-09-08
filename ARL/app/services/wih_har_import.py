"""WIH HAR 导入适配器。

HAR 是用户提供的公开观测输入，不是主动验证授权。适配器只把请求的 URL、方法、
参数名、请求体类型和鉴权类型摘要转换为统一 Endpoint；Header/Cookie 值、请求体和
敏感 query 值不进入 Registry，也不会触发网络请求。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple
from urllib.parse import parse_qsl, urlsplit

from .api_candidate_registry import host_in_scope
from .api_unified_models import (
    ParameterSpec,
    UnifiedApiEndpoint,
    canonical_method,
    compute_input_signature,
    is_sensitive_key,
    sanitize_source_text,
    sanitize_url_secrets,
)
from .discovery_context import url_host


HAR_VERSION = "1.2"
DEFAULT_MAX_ENTRIES = 5000
MAX_HEADER_NAMES = 64
MAX_PARAMETERS = 64
MAX_BODY_SAMPLE_CHARS = 8192
DEFAULT_MAX_PROXY_EVENTS = 5000


@dataclass
class HarImportResult:
    endpoints: List[UnifiedApiEndpoint] = field(default_factory=list)
    imported_count: int = 0
    merged_count: int = 0
    rejected_count: int = 0
    truncated_count: int = 0
    errors: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "endpoints": [item.to_dict() for item in self.endpoints],
            "imported_count": self.imported_count,
            "merged_count": self.merged_count,
            "rejected_count": self.rejected_count,
            "truncated_count": self.truncated_count,
            "errors": list(self.errors),
        }


def import_har(
    payload: Any,
    *,
    registry: Any = None,
    allowed_hosts: Optional[Iterable[str]] = None,
    source: str = "har",
    max_entries: int = DEFAULT_MAX_ENTRIES,
) -> HarImportResult:
    """把 HAR 观测导入 Endpoint Registry，不执行请求。"""

    document = _load_payload(payload)
    if not isinstance(document, Mapping):
        return HarImportResult(errors=("invalid_har",))
    log = document.get("log")
    if not isinstance(log, Mapping) or str(log.get("version") or "") != HAR_VERSION:
        return HarImportResult(errors=("unsupported_har_version",))
    entries = log.get("entries")
    if not isinstance(entries, list):
        return HarImportResult(errors=("invalid_har_entries",))

    try:
        limit = max(0, int(max_entries))
    except (TypeError, ValueError):
        limit = DEFAULT_MAX_ENTRIES
    bounded_entries = entries[:limit]
    result = HarImportResult(truncated_count=max(0, len(entries) - len(bounded_entries)))
    seen = set()
    safe_source = sanitize_source_text(str(source or "har").strip())[:64] or "har"

    for entry in bounded_entries:
        endpoint = _endpoint_from_entry(entry, safe_source)
        if endpoint is None:
            result.rejected_count += 1
            continue
        if not host_in_scope(endpoint.url, allowed_hosts):
            result.rejected_count += 1
            continue
        identity = endpoint.idempotency_key
        if identity in seen:
            result.merged_count += 1
            continue
        seen.add(identity)

        if registry is not None:
            endpoint, outcome = _register(registry, endpoint)
            if outcome == "out_of_scope":
                result.rejected_count += 1
                continue
            if outcome == "merged":
                result.merged_count += 1
        result.endpoints.append(endpoint)
        result.imported_count += 1

    return result


def import_proxy_events(
    events: Any,
    *,
    registry: Any = None,
    allowed_hosts: Optional[Iterable[str]] = None,
    source: str = "proxy",
    max_events: int = DEFAULT_MAX_PROXY_EVENTS,
) -> HarImportResult:
    """导入标准化代理事件，不读取代理配置，也不重放请求。

    输入只约定请求侧摘要：每个事件可以直接包含 ``url``/``method``，也可以
    放在 ``request`` 对象中；headers/query/body 只用于提取名称和类型。这样
    Burp、mitmproxy 等导出适配层可以先归一化事件，再复用 HAR 的安全边界。
    """

    if isinstance(events, Mapping):
        events = events.get("events")
    if not isinstance(events, list):
        return HarImportResult(errors=("invalid_proxy_events",))

    try:
        limit = max(0, int(max_events))
    except (TypeError, ValueError):
        limit = DEFAULT_MAX_PROXY_EVENTS

    entries = []
    rejected = 0
    for event in events[:limit]:
        entry = _proxy_event_to_entry(event)
        if entry is None:
            rejected += 1
            continue
        entries.append(entry)

    result = import_har(
        {"log": {"version": HAR_VERSION, "entries": entries}},
        registry=registry,
        allowed_hosts=allowed_hosts,
        source=source,
        max_entries=len(entries),
    )
    result.rejected_count += rejected
    result.truncated_count += max(0, len(events) - limit)
    return result


def _load_payload(payload: Any) -> Any:
    if isinstance(payload, Mapping):
        return payload
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8", errors="replace")
    if isinstance(payload, str):
        try:
            return json.loads(payload)
        except (TypeError, ValueError):
            return None
    return None


def _proxy_event_to_entry(event: Any) -> Optional[Dict[str, Any]]:
    """把代理适配器的请求摘要转换成内部 HAR entry。"""

    if not isinstance(event, Mapping):
        return None
    request = event.get("request")
    request = request if isinstance(request, Mapping) else event

    raw_url = request.get("url") or request.get("uri") or event.get("url")
    method = request.get("method") or event.get("method") or "GET"
    if not str(raw_url or "").strip():
        return None

    body = request.get("postData")
    if body is None:
        body = request.get("body")
    if isinstance(body, Mapping):
        post_data = _proxy_body_mapping(body)
    elif body is not None:
        post_data = {
            "mimeType": request.get("contentType") or event.get("contentType") or "",
        }
    else:
        post_data = None

    return {
        "request": {
            "method": method,
            "url": raw_url,
            "headers": _proxy_header_items(request.get("headers") or event.get("headers")),
            "cookies": _proxy_header_items(request.get("cookies") or event.get("cookies")),
            "queryString": _proxy_query_items(
                request.get("queryString")
                or request.get("query")
                or event.get("queryString")
                or event.get("query")
            ),
            "postData": post_data,
        },
    }


def _proxy_header_items(value: Any) -> List[Dict[str, str]]:
    """只保留代理事件的字段名，丢弃所有 Header/Cookie 值。"""

    if isinstance(value, Mapping):
        return [{"name": str(name)} for name in list(value)[:MAX_HEADER_NAMES]]
    if not isinstance(value, (list, tuple)):
        return []
    items = []
    for item in value[:MAX_HEADER_NAMES]:
        if isinstance(item, Mapping):
            name = item.get("name") or item.get("key")
        elif isinstance(item, (list, tuple)) and item:
            name = item[0]
        else:
            name = item
        if name is not None:
            items.append({"name": str(name)})
    return items


def _proxy_query_items(value: Any) -> List[Dict[str, str]]:
    """只保留 query 参数名，避免代理导出值进入统一 Endpoint。"""

    if isinstance(value, Mapping):
        return [{"name": str(name)} for name in list(value)[:MAX_PARAMETERS]]
    if not isinstance(value, (list, tuple)):
        return []
    items = []
    for item in value[:MAX_PARAMETERS]:
        if isinstance(item, Mapping):
            name = item.get("name") or item.get("key")
        elif isinstance(item, (list, tuple)) and item:
            name = item[0]
        else:
            name = item
        if name is not None:
            items.append({"name": str(name)})
    return items


def _proxy_body_mapping(value: Mapping[str, Any]) -> Dict[str, Any]:
    """从代理 body 摘要中保留类型和参数名，避免复制完整正文。"""

    output: Dict[str, Any] = {}
    mime = value.get("mimeType") or value.get("contentType") or ""
    if mime:
        output["mimeType"] = str(mime)[:128]
    params = value.get("params")
    if isinstance(params, (list, tuple)):
        output["params"] = _proxy_query_items(params)
    return output


def _endpoint_from_entry(entry: Any, source: str) -> Optional[UnifiedApiEndpoint]:
    if not isinstance(entry, Mapping):
        return None
    request = entry.get("request")
    if not isinstance(request, Mapping):
        return None
    raw_url = str(request.get("url") or "").strip()
    if not _safe_http_url(raw_url):
        return None
    url = sanitize_url_secrets(raw_url)
    try:
        method = canonical_method(request.get("method") or "GET")
    except (TypeError, ValueError):
        return None

    headers = _header_names(request.get("headers"))
    cookies = _cookie_names(request.get("cookies"))
    body_type, body_sample = _body_type(request.get("postData"))
    api_type = _api_type(url, headers, body_type, body_sample)
    parameters = _parameters(url, request.get("queryString"), request.get("postData"))
    auth_hint = _auth_hint(headers, cookies)
    parameter_signature = tuple(
        (item.name, item.location, item.type_summary) for item in parameters
    )
    input_signature = compute_input_signature(
        "har", api_type, method, url.split("?", 1)[0], parameter_signature, body_type
    )
    return UnifiedApiEndpoint(
        url=url,
        observed_url=url,
        method=method,
        api_type=api_type,
        source=source,
        sources={source},
        parent_target=url_host(url),
        parameters=parameters,
        request_body_type=body_type,
        auth_hint=auth_hint,
        schema_available=False,
        confidence=75,
        status="covered",
        input_signature=input_signature,
    )


def _safe_http_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    try:
        parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme.lower() in {"http", "https"}
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
    )


def _header_names(value: Any) -> Tuple[str, ...]:
    names = []
    items = value if isinstance(value, list) else []
    for item in items[:MAX_HEADER_NAMES]:
        if not isinstance(item, Mapping):
            continue
        name = str(item.get("name") or "").strip().lower()[:128]
        if name and name not in names:
            names.append(name)
    return tuple(names)


def _cookie_names(value: Any) -> Tuple[str, ...]:
    names = []
    items = value if isinstance(value, list) else []
    for item in items[:MAX_HEADER_NAMES]:
        if not isinstance(item, Mapping):
            continue
        name = str(item.get("name") or "").strip().lower()[:128]
        if name and name not in names:
            names.append(name)
    return tuple(names)


def _body_type(value: Any) -> Tuple[str, str]:
    if not isinstance(value, Mapping):
        return "", ""
    mime = str(value.get("mimeType") or "").strip().lower()
    text = str(value.get("text") or "")[:MAX_BODY_SAMPLE_CHARS]
    if "graphql" in mime or '"query"' in text.lower():
        return "graphql", text
    if "json" in mime:
        return "json", text
    if "multipart" in mime:
        return "multipart", ""
    if "x-www-form-urlencoded" in mime:
        return "form", ""
    if "xml" in mime:
        return "xml", ""
    return mime[:64], ""


def _api_type(url: str, headers: Tuple[str, ...], body_type: str, body_sample: str) -> str:
    lowered = url.lower()
    if "/graphql" in lowered or body_type == "graphql":
        return "graphql"
    if body_type == "xml" or "soapaction" in headers or "/soap" in lowered or "/wsdl" in lowered:
        return "soap"
    return "rest"


def _parameters(url: str, query: Any, post_data: Any) -> List[ParameterSpec]:
    values = []
    try:
        pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    except ValueError:
        pairs = []
    for name, _value in pairs:
        values.append((name, "query", ""))
    if isinstance(query, list):
        for item in query[:MAX_PARAMETERS]:
            if isinstance(item, Mapping):
                values.append((item.get("name"), "query", ""))
    if isinstance(post_data, Mapping) and isinstance(post_data.get("params"), list):
        for item in post_data.get("params")[:MAX_PARAMETERS]:
            if isinstance(item, Mapping):
                type_summary = "file" if item.get("fileName") else ""
                values.append((item.get("name"), "formData", type_summary))

    result = []
    seen = set()
    for name, location, type_summary in values:
        name_text = str(name or "").strip()[:128]
        if not name_text or is_sensitive_key(name_text):
            continue
        key = (name_text, location, type_summary)
        if key in seen:
            continue
        seen.add(key)
        result.append(ParameterSpec(name_text, location, type_summary))
        if len(result) >= MAX_PARAMETERS:
            break
    return result


def _auth_hint(headers: Tuple[str, ...], cookies: Tuple[str, ...]) -> str:
    header_set = set(headers)
    if "authorization" in header_set:
        return "bearer"
    if "proxy-authorization" in header_set:
        return "basic"
    if any(name in header_set for name in ("x-api-key", "x-auth-token")):
        return "api_key"
    if cookies:
        return "cookie"
    return "none"


def _register(registry: Any, endpoint: UnifiedApiEndpoint):
    register_with_status = getattr(registry, "register_endpoint_with_status", None)
    if callable(register_with_status):
        stored, outcome = register_with_status(endpoint)
        status_names = getattr(registry, "ENDPOINT_REGISTER_OUT_OF_SCOPE", "out_of_scope")
        if outcome == status_names:
            return stored, "out_of_scope"
        if outcome == getattr(registry, "ENDPOINT_REGISTER_MERGED", "merged"):
            return stored, "merged"
        return stored, "created"
    register = getattr(registry, "register_endpoint", None)
    if not callable(register):
        return endpoint, "created"
    stored, created = register(endpoint)
    return stored, "created" if created else "merged"


__all__ = ["HarImportResult", "import_har", "import_proxy_events"]
