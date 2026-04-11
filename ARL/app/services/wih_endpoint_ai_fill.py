"""
WIH 接口 AI 填充与低副作用测试。

目标：
- 对 WIH 提取出的空参数、<value> 占位符进行类型推断与补全
- 在安全范围内对 GET/POST 等接口做一次低副作用验证
- 为后续 AI 去噪提供参数与响应摘要上下文
"""
import copy
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlsplit, urlunsplit

import requests

from app import utils
from app.config import Config
from app.services.infoHunter import InfoHunter


logger = utils.get_logger()

_ACTIVE_METHODS = {"GET", "POST", "HEAD", "OPTIONS"}
_HINT_ONLY_METHODS = {"DELETE", "PUT", "PATCH", "TRACE", "CONNECT"}
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
_MISSING_VALUE_TEXTS = {
    "",
    "-",
    "<value>",
    "<empty>",
    "null",
    "none",
    "nil",
    "undefined",
    "n/a",
    "na",
}
_ID_KEYWORDS = (
    "id", "uid", "user_id", "userid", "roleid", "tenantid", "tabid", "folderid", "said", "pid", "rid",
)
_BOOL_KEYWORDS = ("enable", "enabled", "is", "has", "flag", "check", "checked", "status")
_KEYWORD_KEYWORDS = ("kw", "keyword", "query", "search", "name", "title", "desc", "content", "text")
_AMOUNT_KEYWORDS = ("amount", "price", "money", "total", "count", "num", "size", "limit", "offset", "page")
_URL_KEYWORDS = ("url", "uri", "redirect", "callback", "returnurl", "return_url", "path")
_DATE_KEYWORDS = ("date", "time", "start", "end", "begin", "expire")


def _safe_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return default


def _safe_positive_int(value):
    number = _safe_int(value, 0)
    return number if number > 0 else None


def _safe_float(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return default


def _truncate_text(value, max_length=240):
    text = str(value or "").strip()
    if len(text) <= max_length:
        return text
    return "{}...".format(text[: max(0, max_length - 3)])


def _normalize_lower_text(value):
    return str(value or "").strip().lower()


def _has_observed_response(item: Dict) -> bool:
    return _safe_positive_int(item.get("status_code") or item.get("response_status")) is not None


def _is_missing_like(value) -> bool:
    if value is None:
        return True
    text = str(value).strip()
    if not text:
        return True
    if text.lower() in _MISSING_VALUE_TEXTS:
        return True
    if re.fullmatch(r"<[^>]+>", text):
        return True
    if re.fullmatch(r"\{\{[^}]+\}\}", text):
        return True
    if re.fullmatch(r"\$\{[^}]+\}", text):
        return True
    return False


def _deepcopy_template(value):
    if isinstance(value, dict):
        return copy.deepcopy(value)
    return {}


def _normalize_headers(raw_headers: Dict, content_type: str = "") -> Dict[str, str]:
    headers = {}
    source = raw_headers if isinstance(raw_headers, dict) else {}
    for key, value in source.items():
        key_text = str(key or "").strip()
        if not key_text:
            continue
        if key_text.lower() in _SENSITIVE_REQUEST_HEADERS:
            continue
        value_text = str(value or "").strip()
        if value_text:
            headers[key_text[:80]] = value_text[:512]
    if content_type and not any(key.lower() == "content-type" for key in headers):
        headers["Content-Type"] = content_type[:160]
    headers.setdefault("User-Agent", "Mozilla/5.0")
    headers.setdefault("Accept", "*/*")
    headers.setdefault("X-ARL-WIH-AI-Fill", "1")
    return headers


def _build_request_template_from_packet(packet: str) -> Dict:
    text = str(packet or "").replace("\r\n", "\n")
    if not text.strip():
        return {}

    lines = text.split("\n")
    request_line = str(lines[0] or "").strip()
    match = re.match(r"^([A-Z]+)\s+(\S+)\s+HTTP/\d\.\d$", request_line)
    if not match:
        return {}

    path_text = str(match.group(2) or "").strip()
    headers = {}
    body_lines = []
    header_done = False
    for line in lines[1:]:
        if not header_done:
            if line == "":
                header_done = True
                continue
            if ":" not in line:
                continue
            key_text, value_text = line.split(":", 1)
            key_text = str(key_text or "").strip()
            value_text = str(value_text or "").strip()
            if key_text:
                headers[key_text[:80]] = value_text[:512]
            continue
        body_lines.append(line)

    body_text = "\n".join(body_lines).strip()
    parsed = urlsplit(path_text)
    query = {}
    if parsed.query:
        try:
            for key_text, value_text in parse_qsl(parsed.query, keep_blank_values=True):
                if key_text:
                    query[str(key_text).strip()[:80]] = str(value_text)
        except Exception:
            pass

    content_type = _normalize_lower_text(headers.get("Content-Type") or headers.get("content-type"))
    body_kind = ""
    body = {}
    if body_text:
        if "application/json" in content_type:
            body_kind = "json"
            try:
                loaded = json.loads(body_text)
                if isinstance(loaded, dict):
                    body = loaded
            except Exception:
                body = {}
        elif "application/x-www-form-urlencoded" in content_type:
            body_kind = "form_urlencoded"
            try:
                for key_text, value_text in parse_qsl(body_text, keep_blank_values=True):
                    if key_text:
                        body[str(key_text).strip()[:80]] = str(value_text)
            except Exception:
                body = {}
        elif "multipart/form-data" in content_type:
            body_kind = "multipart"
        else:
            body_kind = "text"

    template = {
        "query": query,
        "headers": headers,
    }
    if parsed.query:
        template["query_string"] = parsed.query
    if body:
        template["body"] = body
    if body_text:
        template["body_text"] = body_text
    if body_kind:
        template["_body_kind"] = body_kind
    return template


def _merge_request_template(item: Dict) -> Dict:
    template = _deepcopy_template(item.get("request_template"))
    packet_template = _build_request_template_from_packet(item.get("request_packet"))

    if not isinstance(template.get("query"), dict):
        template["query"] = {}
    if not isinstance(template.get("body"), dict):
        template["body"] = {}
    if not isinstance(template.get("path"), dict):
        template["path"] = {}
    if not isinstance(template.get("headers"), dict):
        template["headers"] = {}

    for key in ("query", "body", "path", "headers"):
        packet_obj = packet_template.get(key) if isinstance(packet_template.get(key), dict) else {}
        for raw_key, raw_value in packet_obj.items():
            key_text = str(raw_key or "").strip()
            if not key_text:
                continue
            if key_text not in template[key]:
                template[key][key_text] = raw_value

    if not str(template.get("query_string") or "").strip() and str(packet_template.get("query_string") or "").strip():
        template["query_string"] = str(packet_template.get("query_string") or "").strip()

    if not str(template.get("body_text") or "").strip() and str(packet_template.get("body_text") or "").strip():
        template["body_text"] = str(packet_template.get("body_text") or "").strip()

    return template


def _guess_body_kind(item: Dict, template: Dict) -> str:
    body_kind = _normalize_lower_text(item.get("body_kind"))
    if body_kind:
        return body_kind
    content_type = _normalize_lower_text(
        item.get("content_type")
        or (template.get("headers") or {}).get("Content-Type")
        or (template.get("headers") or {}).get("content-type")
    )
    if "application/json" in content_type:
        return "json"
    if "application/x-www-form-urlencoded" in content_type:
        return "form_urlencoded"
    if "multipart/form-data" in content_type:
        return "multipart"
    if "octet-stream" in content_type:
        return "octet_stream"
    if str(template.get("body_text") or "").strip():
        return "text"
    return ""


def _guess_content_type(item: Dict, template: Dict) -> str:
    content_type = str(
        item.get("content_type")
        or (template.get("headers") or {}).get("Content-Type")
        or (template.get("headers") or {}).get("content-type")
        or ""
    ).strip()
    if content_type:
        return content_type
    body_kind = _guess_body_kind(item, template)
    if body_kind == "json":
        return "application/json"
    if body_kind == "form_urlencoded":
        return "application/x-www-form-urlencoded"
    return ""


def _iter_param_slots(template: Dict) -> List[Dict]:
    slots = []
    for location in ("query", "body", "path"):
        obj = template.get(location) if isinstance(template.get(location), dict) else {}
        for key, value in obj.items():
            name = str(key or "").strip()
            if not name:
                continue
            slots.append(
                {
                    "name": name[:80],
                    "location": location,
                    "value": value,
                }
            )
    return slots


def _guess_type_and_value(name: str, current_value) -> Tuple[str, str, str]:
    lower_name = _normalize_lower_text(name)
    current_text = "" if current_value is None else str(current_value).strip()
    if current_text and not _is_missing_like(current_text):
        if re.fullmatch(r"-?\d+", current_text):
            return "int", current_text, "保留原始数值参数"
        if current_text.lower() in {"true", "false"}:
            return "bool", current_text.lower(), "保留原始布尔参数"
        return "string", current_text, "保留原始请求中的稳定参数值"

    if lower_name.endswith(_ID_KEYWORDS) or any(keyword == lower_name for keyword in _ID_KEYWORDS):
        return "id", "1", "按标识符参数填充为默认主键值"
    if any(keyword in lower_name for keyword in _DATE_KEYWORDS):
        if "time" in lower_name:
            return "datetime", "2024-01-01 00:00:00", "按时间参数填充标准时间值"
        return "date", "2024-01-01", "按日期参数填充标准日期值"
    if any(keyword in lower_name for keyword in _URL_KEYWORDS):
        return "url", "/", "按地址参数填充低风险默认路径"
    if any(keyword in lower_name for keyword in _BOOL_KEYWORDS):
        return "bool", "true", "按布尔型语义填充"
    if any(keyword in lower_name for keyword in _AMOUNT_KEYWORDS):
        if "offset" in lower_name:
            return "int", "0", "按偏移量参数填充"
        if "page" in lower_name:
            return "int", "1", "按分页参数填充首页值"
        if "size" in lower_name or "limit" in lower_name:
            return "int", "10", "按分页数量参数填充默认页大小"
        return "int", "1", "按数量/金额类参数填充默认值"
    if "phone" in lower_name or "mobile" in lower_name:
        return "mobile", "13800000000", "按手机号参数填充演示号码"
    if "email" in lower_name:
        return "email", "test@example.com", "按邮箱参数填充演示邮箱"
    if "action" in lower_name:
        return "enum", "search", "按动作参数填充低风险检索值"
    if any(keyword in lower_name for keyword in _KEYWORD_KEYWORDS):
        return "keyword", "test", "按检索/关键词参数填充演示值"
    return "string", "test", "按通用字符串参数填充演示值"


def _build_heuristic_params(template: Dict) -> List[Dict]:
    result = []
    for slot in _iter_param_slots(template):
        inferred_type, inferred_value, reason = _guess_type_and_value(slot["name"], slot.get("value"))
        result.append(
            {
                "name": slot["name"],
                "location": slot["location"],
                "type": inferred_type,
                "value": inferred_value,
                "reason": reason,
                "confidence": "high" if not _is_missing_like(slot.get("value")) else "medium",
            }
        )
    return result


def _merge_ai_params(heuristic_params: List[Dict], ai_params: List[Dict]) -> List[Dict]:
    result = []
    ai_map = {}
    for item in ai_params:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        location = _normalize_lower_text(item.get("location"))
        value_text = str(item.get("value") or "").strip()
        if not name or location not in {"query", "body", "path"} or not value_text:
            continue
        ai_map[(location, name.lower())] = {
            "name": name[:80],
            "location": location,
            "type": _normalize_lower_text(item.get("type")) or "string",
            "value": value_text[:400],
            "reason": _truncate_text(item.get("reason"), 160),
            "confidence": _normalize_lower_text(item.get("confidence")) or "medium",
        }

    for item in heuristic_params:
        key = (_normalize_lower_text(item.get("location")), _normalize_lower_text(item.get("name")))
        result.append(ai_map.get(key, item))
    return result


def _apply_filled_params(template: Dict, filled_params: List[Dict]) -> Dict:
    result = _deepcopy_template(template)
    for key in ("query", "body", "path"):
        if not isinstance(result.get(key), dict):
            result[key] = {}

    for item in filled_params:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        location = _normalize_lower_text(item.get("location"))
        if not name or location not in {"query", "body", "path"}:
            continue
        result[location][name] = str(item.get("value") or "").strip()

    query_obj = result.get("query") if isinstance(result.get("query"), dict) else {}
    if query_obj:
        try:
            result["query_string"] = urlencode([(str(key), str(value)) for key, value in query_obj.items()])
        except Exception:
            pass

    body_obj = result.get("body") if isinstance(result.get("body"), dict) else {}
    content_type = _normalize_lower_text(
        (result.get("headers") or {}).get("Content-Type")
        or (result.get("headers") or {}).get("content-type")
    )
    body_kind = _guess_body_kind({}, result)
    if body_obj and (body_kind == "json" or "application/json" in content_type):
        result["body_text"] = json.dumps(body_obj, ensure_ascii=False)
    elif body_obj and (body_kind == "form_urlencoded" or "application/x-www-form-urlencoded" in content_type):
        result["body_text"] = urlencode([(str(key), str(value)) for key, value in body_obj.items()])

    return result


def _build_url_with_query(url: str, template: Dict) -> str:
    text = str(url or "").strip()
    if not text:
        return ""
    query_obj = template.get("query") if isinstance(template.get("query"), dict) else {}
    query_pairs = []
    for key, value in query_obj.items():
        key_text = str(key or "").strip()
        if not key_text:
            continue
        query_pairs.append((key_text, str(value or "")))
    if not query_pairs:
        return text
    try:
        parsed = urlsplit(text)
        merged_pairs = []
        seen = set()
        for key_text, value_text in parse_qsl(parsed.query, keep_blank_values=True):
            pair = (key_text, value_text)
            seen.add(pair)
            merged_pairs.append(pair)
        for pair in query_pairs:
            if pair in seen:
                continue
            merged_pairs.append(pair)
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(merged_pairs), parsed.fragment))
    except Exception:
        return text


def _build_request_kwargs(item: Dict, method: str, url: str, template: Dict) -> Dict:
    headers = _normalize_headers(template.get("headers"), _guess_content_type(item, template))
    content_type = _normalize_lower_text(headers.get("Content-Type") or headers.get("content-type"))
    body_kind = _guess_body_kind(item, template)
    kwargs = {
        "headers": headers,
        "verify": False,
        "timeout": (
            3.1,
            max(3.1, float(getattr(Config, "WIH_ENDPOINT_AI_FILL_TIMEOUT_SEC", 12) or 12)),
        ),
        "allow_redirects": True,
        "stream": True,
    }
    if Config.PROXY_URL:
        kwargs["proxies"] = {"http": Config.PROXY_URL, "https": Config.PROXY_URL}
    else:
        kwargs["proxies"] = {"http": None, "https": None}

    if method != "POST":
        return kwargs

    body_obj = template.get("body") if isinstance(template.get("body"), dict) else {}
    body_text = str(template.get("body_text") or "").strip()
    if body_obj and (body_kind == "json" or "application/json" in content_type):
        kwargs["json"] = body_obj
        return kwargs
    if body_obj and (body_kind == "form_urlencoded" or "application/x-www-form-urlencoded" in content_type):
        kwargs["data"] = body_obj
        return kwargs
    if body_text:
        kwargs["data"] = body_text
    elif body_obj:
        kwargs["data"] = body_obj
    return kwargs


def _read_response_bytes(response) -> Tuple[bytes, bool]:
    max_bytes = max(1024, int(getattr(Config, "WIH_ENDPOINT_AI_FILL_RESPONSE_MAX_BYTES", 65536) or 65536))
    chunks = []
    total = 0
    truncated = False
    try:
        for chunk in response.iter_content(chunk_size=4096, decode_unicode=False):
            if not chunk:
                continue
            remain = max_bytes - total
            if remain <= 0:
                truncated = True
                break
            if len(chunk) > remain:
                chunks.append(chunk[:remain])
                total += remain
                truncated = True
                break
            chunks.append(chunk)
            total += len(chunk)
    except Exception:
        pass
    return b"".join(chunks), truncated


def _decode_response_text(raw_bytes: bytes, response) -> str:
    if not raw_bytes:
        return ""
    encoding = str(getattr(response, "encoding", "") or "").strip()
    for candidate in [encoding, "utf-8", "gbk", "latin-1"]:
        if not candidate:
            continue
        try:
            return raw_bytes.decode(candidate, errors="ignore")
        except Exception:
            continue
    return ""


def _summarize_response(response, raw_bytes: bytes, truncated: bool) -> str:
    max_chars = max(200, int(getattr(Config, "WIH_ENDPOINT_AI_FILL_RESPONSE_MAX_CHARS", 1200) or 1200))
    headers = getattr(response, "headers", {}) or {}
    content_type = _normalize_lower_text(headers.get("Content-Type") or headers.get("content-type"))
    text = _decode_response_text(raw_bytes, response)

    summary_parts = []
    if "application/json" in content_type and text:
        try:
            payload = json.loads(text)
            if isinstance(payload, dict):
                keys = list(payload.keys())[:12]
                summary_parts.append("JSON键: {}".format(", ".join(keys) if keys else "-"))
                sample_pairs = []
                for key in keys[:5]:
                    value = payload.get(key)
                    if isinstance(value, (dict, list)):
                        sample_text = _truncate_text(json.dumps(value, ensure_ascii=False), 80)
                    else:
                        sample_text = _truncate_text(value, 80)
                    sample_pairs.append("{}={}".format(key, sample_text))
                if sample_pairs:
                    summary_parts.append("JSON摘要: {}".format("; ".join(sample_pairs)))
            elif isinstance(payload, list):
                summary_parts.append("JSON列表长度预览: {}".format(len(payload)))
                if payload:
                    summary_parts.append("首项摘要: {}".format(_truncate_text(payload[0], 120)))
        except Exception:
            pass

    if not summary_parts and "html" in content_type and text:
        title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
        if title_match:
            summary_parts.append("HTML标题: {}".format(_truncate_text(title_match.group(1), 120)))
        plain_text = re.sub(r"<[^>]+>", " ", text)
        plain_text = re.sub(r"\s+", " ", plain_text).strip()
        if plain_text:
            summary_parts.append("文本摘要: {}".format(_truncate_text(plain_text, 240)))

    if not summary_parts and text:
        normalized = re.sub(r"\s+", " ", text).strip()
        if normalized:
            summary_parts.append("文本摘要: {}".format(_truncate_text(normalized, 240)))

    if not summary_parts and raw_bytes:
        summary_parts.append("二进制响应预览: {} bytes".format(len(raw_bytes)))

    summary = " | ".join([part for part in summary_parts if part])
    if truncated:
        summary = "{}{}".format(summary + " | " if summary else "", "响应内容过大，已截断摘要")
    return _truncate_text(summary, max_chars)


def _build_response_packet(response, raw_bytes: bytes, truncated: bool) -> str:
    status_code = int(getattr(response, "status_code", 0) or 0)
    reason = str(getattr(response, "reason", "") or "").strip()
    status_line = "HTTP/1.1 {}{}".format(status_code, " {}".format(reason) if reason else "")
    headers = getattr(response, "headers", {}) or {}
    header_lines = []
    for key, value in list(headers.items())[:24]:
        key_text = str(key or "").strip()
        if not key_text:
            continue
        header_lines.append("{}: {}".format(key_text[:80], str(value or "").strip()[:400]))

    body_text = _decode_response_text(raw_bytes, response).replace("\r\n", "\n").replace("\r", "\n")
    if body_text:
        max_chars = max(200, int(getattr(Config, "WIH_ENDPOINT_AI_FILL_RESPONSE_MAX_CHARS", 1200) or 1200))
        if len(body_text) > max_chars:
            body_text = "{}\n...[truncated]".format(body_text[:max_chars])
        elif truncated:
            body_text = "{}\n...[truncated]".format(body_text)
    elif raw_bytes:
        body_text = "[binary {} bytes]".format(len(raw_bytes))

    parts = [status_line]
    if header_lines:
        parts.extend(header_lines)
    if body_text:
        parts.extend(["", body_text])
    return "\n".join(parts).strip()


def _response_size(response, raw_bytes: bytes) -> int:
    headers = getattr(response, "headers", {}) or {}
    content_length = _safe_int(headers.get("Content-Length") or headers.get("content-length"), 0)
    if content_length > 0:
        return content_length
    return len(raw_bytes or b"")


def _load_api_console_helpers():
    try:
        from app.routes import api_console as api_console_module
    except Exception as exc:
        logger.warning("load api_console helper failed: %s", exc)
        return None
    return api_console_module


def _load_ai_fill_runtime():
    runtime = {
        "enabled": False,
        "ai_available": False,
        "prompt_id": "",
        "prompt_name": "",
        "prompt_content": "",
        "ai_config": {},
        "active_profile": {},
        "request_delay_ms": 0,
        "api_console": None,
    }
    api_console_module = _load_api_console_helpers()
    runtime["api_console"] = api_console_module
    if api_console_module is None:
        return runtime

    try:
        config_path = api_console_module._resolve_config_path()
        config_obj = api_console_module._load_config_from_file(config_path)
        ai_config = api_console_module._extract_ai_config(config_obj)
        runtime["ai_config"] = ai_config
        runtime["enabled"] = (
            bool(ai_config.get("enable", True))
            and bool(ai_config.get("ai_wih_endpoint_fill_enable", True))
            and bool(getattr(Config, "AI_WIH_ENDPOINT_FILL_ENABLE", True))
        )
        prompt_templates = api_console_module._normalize_ai_prompt_templates(ai_config.get("prompt_templates"))
        prompt_item = None
        for item in prompt_templates:
            if str(item.get("id") or "").strip() == str(api_console_module.AI_WIH_ENDPOINT_FILL_PROMPT_ID):
                prompt_item = item
                break
        if prompt_item is None:
            for item in prompt_templates:
                if str(item.get("scene") or "").strip() == str(api_console_module.AI_WIH_ENDPOINT_FILL_SCENE):
                    prompt_item = item
                    break
        if isinstance(prompt_item, dict):
            runtime["prompt_id"] = str(prompt_item.get("id") or "").strip()
            runtime["prompt_name"] = str(prompt_item.get("name") or "").strip()
            runtime["prompt_content"] = str(prompt_item.get("content") or "").strip()

        model_profiles = api_console_module._normalize_ai_model_profiles(ai_config.get("model_profiles"), legacy_ai_conf=ai_config)
        active_model_profile_id = str(ai_config.get("active_model_profile_id") or "").strip()
        active_profile = api_console_module._pick_active_ai_model_profile(model_profiles, active_model_profile_id)
        runtime["active_profile"] = active_profile
        runtime["request_delay_ms"] = api_console_module._safe_int(ai_config.get("request_delay_ms"), 0, min_value=0)
        runtime["ai_available"] = bool(
            runtime["enabled"]
            and str(active_profile.get("base_url") or "").strip()
            and str(active_profile.get("api_key") or "").strip()
            and str(active_profile.get("model") or "").strip()
        )
    except Exception as exc:
        logger.warning("load wih endpoint ai fill runtime failed: %s", exc)
    return runtime


def _call_ai_fill(runtime: Dict, item: Dict, heuristic_params: List[Dict]) -> Dict:
    api_console_module = runtime.get("api_console")
    active_profile = runtime.get("active_profile") or {}
    provider_id = api_console_module._normalize_ai_provider_id(active_profile.get("provider") or "openai")
    model_name = api_console_module._normalize_ai_model_name(provider_id, active_profile.get("model"))
    base_url = str(active_profile.get("base_url") or "").strip()
    api_key = str(active_profile.get("api_key") or "").strip()
    profile_name = str(active_profile.get("name") or active_profile.get("id") or "").strip()
    request_proxies = api_console_module._build_ai_proxy_dict(str(active_profile.get("proxy") or "").strip())
    timeout_sec = api_console_module._safe_int(active_profile.get("timeout_sec"), 40, min_value=8)
    request_delay_ms = api_console_module._safe_int(runtime.get("request_delay_ms"), 0, min_value=0)
    if request_delay_ms > 30000:
        request_delay_ms = 30000

    request_payload = {
        "target": _truncate_text(item.get("target"), 320),
        "page_url": _truncate_text(item.get("page_url"), 900),
        "url": _truncate_text(item.get("url"), 900),
        "method": str(item.get("method") or "GET").strip().upper(),
        "content_type": _truncate_text(item.get("content_type"), 160),
        "body_kind": _truncate_text(item.get("body_kind"), 80),
        "request_packet": _truncate_text(item.get("request_packet"), 1800),
        "heuristic_params": heuristic_params[:20],
        "output_requirement": {
            "should_test": "true|false",
            "test_mode": "safe|hint_only",
            "summary": "一句话说明",
            "reason": "说明为什么这样填充/为什么只能提示",
            "filled_params": [
                {
                    "name": "参数名",
                    "location": "query|body|path",
                    "type": "string|int|bool|date|id|keyword|enum|url",
                    "value": "建议值",
                    "confidence": "high|medium|low",
                    "reason": "原因",
                }
            ],
        },
    }
    request_text = json.dumps(request_payload, ensure_ascii=False)
    system_content = "{}\n仅输出 JSON 对象，不要输出 Markdown 或额外解释。".format(
        str(runtime.get("prompt_content") or "").strip()
        or "你是 WIH 接口参数补全助手，请返回结构化 JSON。"
    )
    request_url = "{}/chat/completions".format(base_url.rstrip("/"))
    headers = {
        "Authorization": "Bearer {}".format(api_key),
        "Content-Type": "application/json",
    }
    request_body = {
        "model": model_name,
        "temperature": min(max(api_console_module._safe_float(active_profile.get("temperature"), 0.1, min_value=0.0), 0.0), 1.0),
        "max_tokens": max(500, min(api_console_module._safe_int(active_profile.get("max_tokens"), 1600, min_value=300), 2200)),
        "messages": [
            {"role": "system", "content": system_content},
            {"role": "user", "content": request_text},
        ],
    }

    def _chat_with_model(target_model):
        started_at = time.perf_counter()
        call_body = dict(request_body)
        call_body["model"] = str(target_model or "").strip()
        kwargs = {
            "headers": headers,
            "json": call_body,
            "timeout": (8, timeout_sec),
        }
        if request_proxies:
            kwargs["proxies"] = request_proxies
        if request_delay_ms > 0:
            time.sleep(float(request_delay_ms) / 1000.0)
        conn = utils.http_req(request_url, "post", **kwargs)
        status_code = int(getattr(conn, "status_code", 0) or 0)
        payload = {}
        try:
            payload = conn.json() if conn is not None else {}
        except Exception:
            payload = {}
        elapsed_ms = int((time.perf_counter() - started_at) * 1000.0)
        usage = api_console_module._normalize_ai_usage_dict(payload.get("usage") if isinstance(payload, dict) else {})

        reply_text = ""
        if status_code == 200:
            choices = payload.get("choices", []) if isinstance(payload, dict) else []
            message_obj = choices[0].get("message") if isinstance(choices, list) and choices else {}
            if isinstance(message_obj, dict):
                content_obj = message_obj.get("content")
                if isinstance(content_obj, str):
                    reply_text = content_obj.strip()
                elif isinstance(content_obj, list):
                    parts = []
                    for fragment in content_obj:
                        if isinstance(fragment, dict) and str(fragment.get("type") or "").strip() == "text":
                            text_value = str(fragment.get("text") or "").strip()
                            if text_value:
                                parts.append(text_value)
                    reply_text = "\n".join(parts).strip()

        error_message = ""
        if status_code != 200:
            if isinstance(payload, dict):
                error_obj = payload.get("error")
                if isinstance(error_obj, dict):
                    error_message = str(error_obj.get("message") or "").strip()
                if not error_message:
                    error_message = str(payload.get("message") or "").strip()
            if not error_message:
                error_message = "HTTP {}".format(status_code)
        return {
            "ok": status_code == 200,
            "status_code": status_code,
            "message": error_message,
            "reply_text": reply_text,
            "usage": usage,
            "elapsed_ms": elapsed_ms,
        }

    call_ret = _chat_with_model(model_name)
    if (not call_ret.get("ok")) and api_console_module._is_ai_model_unavailable_error(call_ret.get("message", "")):
        retry_model = api_console_module._pick_ai_retry_model(provider_id, model_name)
        if retry_model:
            retry_ret = _chat_with_model(retry_model)
            if retry_ret.get("ok"):
                model_name = retry_model
                call_ret = retry_ret
            else:
                call_ret = retry_ret

    api_console_module._write_ai_usage_log(
        scene=runtime.get("api_console").AI_WIH_ENDPOINT_FILL_SCENE,
        provider=provider_id,
        model=model_name,
        profile=profile_name,
        status="ok" if call_ret.get("ok") else "error",
        request_text=request_text,
        reply_text=str(call_ret.get("reply_text") or ""),
        error_message=str(call_ret.get("message") or ""),
        elapsed_ms=call_ret.get("elapsed_ms"),
        usage=call_ret.get("usage"),
        meta={
            "module_id": runtime.get("api_console").AI_WIH_ENDPOINT_FILL_MODULE_ID,
            "source": "wih_endpoint_ai_fill",
            "url": _truncate_text(item.get("url"), 320),
            "method": str(item.get("method") or "GET").strip().upper(),
        },
    )
    if not call_ret.get("ok"):
        return {"ok": False, "message": str(call_ret.get("message") or "ai request failed")}

    parsed = api_console_module._extract_json_object_from_text(call_ret.get("reply_text", ""))
    if not isinstance(parsed, dict):
        return {"ok": False, "message": "AI 返回格式不可解析"}
    return {"ok": True, "data": parsed}


def _should_hint_only(method: str, body_kind: str, content_type: str) -> Tuple[bool, str]:
    method_text = str(method or "GET").strip().upper() or "GET"
    body_kind_text = _normalize_lower_text(body_kind)
    content_type_text = _normalize_lower_text(content_type)
    if method_text in _HINT_ONLY_METHODS:
        return True, "危险 HTTP 方法 {}，仅给出提示不主动测试".format(method_text)
    if method_text not in _ACTIVE_METHODS:
        return True, "HTTP 方法 {} 不在自动测试范围内".format(method_text)
    if method_text == "POST" and (body_kind_text in _SKIP_BODY_KINDS or "multipart/form-data" in content_type_text or "octet-stream" in content_type_text):
        return True, "{} 请求体副作用较高，仅给出提示".format(body_kind_text or content_type_text or "POST")
    return False, ""


def _probe_with_filled_request(item: Dict, waf_guard=None, dns_policy_cache=None) -> Dict:
    result = dict(item or {})
    method = str(result.get("method") or "GET").strip().upper() or "GET"
    template = result.get("ai_fill_request_template") if isinstance(result.get("ai_fill_request_template"), dict) else {}
    url = _build_url_with_query(result.get("url"), template)
    allow_scan, policy_detail = utils.check_dns_policy_for_url(url, cache_map=dns_policy_cache)
    if not allow_scan:
        result["ai_fill_note"] = "DNS 策略跳过: {}".format(policy_detail.get("reason", "") or "out_of_scope")
        return result

    headers = _normalize_headers(template.get("headers"), _guess_content_type(result, template))
    try:
        if waf_guard:
            should_skip, detail = waf_guard.should_skip(url, module="wih_endpoint_ai_fill")
            if should_skip:
                result["ai_fill_note"] = "WAF 智能跳过: {}".format(detail.get("reason", "") or detail.get("waf_name", "") or "blocked")
                return result
            headers, delay, _ = waf_guard.prepare_request(
                url,
                module="wih_endpoint_ai_fill",
                method=method,
                headers=headers,
            )
            if delay > 0:
                time.sleep(delay)

        kwargs = _build_request_kwargs(result, method, url, template)
        kwargs["headers"] = headers
        response = requests.request(method, url, **kwargs)
        raw_bytes, truncated = _read_response_bytes(response)
        if waf_guard:
            waf_guard.observe_response(url, response, module="wih_endpoint_ai_fill")
        status_code = int(getattr(response, "status_code", 0) or 0)
        response_size = _response_size(response, raw_bytes)
        response_summary = _summarize_response(response, raw_bytes, truncated)
        result["ai_fill_tested"] = True
        result["ai_fill_test_method"] = method
        result["ai_fill_status_code"] = status_code if status_code > 0 else None
        result["ai_fill_response_size"] = response_size if response_size > 0 else None
        result["ai_fill_response_summary"] = response_summary
        result["ai_fill_response_packet"] = _build_response_packet(response, raw_bytes, truncated)
        result["ai_fill_response_content_type"] = str(
            (getattr(response, "headers", {}) or {}).get("Content-Type")
            or (getattr(response, "headers", {}) or {}).get("content-type")
            or ""
        ).strip()
        if not str(result.get("response_packet") or "").strip() and result.get("ai_fill_response_packet"):
            result["response_packet"] = result.get("ai_fill_response_packet")
        if _safe_positive_int(result.get("status_code") or result.get("response_status")) is None and status_code > 0:
            result["status_code"] = status_code
            result["response_status"] = status_code
        if _safe_positive_int(result.get("response_size")) is None and response_size > 0:
            result["response_size"] = response_size
        if not str(result.get("content_type") or "").strip() and result.get("ai_fill_response_content_type"):
            result["content_type"] = result.get("ai_fill_response_content_type")
        if status_code > 0:
            result["ai_fill_status"] = "tested"
            result["ai_fill_note"] = "已使用填充参数完成低副作用测试"
        response.close()
    except Exception as exc:
        logger.debug("wih endpoint ai fill probe failed url:%s method:%s err:%s", url, method, exc)
        result["ai_fill_tested"] = False
        result["ai_fill_note"] = "填充后测试失败: {}".format(exc.__class__.__name__)
        if not str(result.get("ai_fill_status") or "").strip():
            result["ai_fill_status"] = "error"
    return result


def _fill_one(task_id: str, item: Dict, runtime: Dict, waf_guard=None, dns_policy_cache=None) -> Dict:
    result = dict(item or {})
    result["task_id"] = str(task_id or "").strip()
    result.setdefault("ai_fill_status", "skipped")
    result.setdefault("ai_fill_source", "heuristic")
    result.setdefault("ai_fill_tested", False)
    result.setdefault("ai_fill_hint_only", False)
    result.setdefault("ai_fill_params", [])
    result.setdefault("ai_fill_response_summary", "")
    result["ai_fill_analyzed_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    result["ai_fill_prompt_id"] = str(runtime.get("prompt_id") or "")
    result["ai_fill_prompt_name"] = str(runtime.get("prompt_name") or "")

    method = str(result.get("method") or "GET").strip().upper() or "GET"
    template = _merge_request_template(result)
    body_kind = _guess_body_kind(result, template)
    content_type = _guess_content_type(result, template)
    if content_type and not str(result.get("content_type") or "").strip():
        result["content_type"] = content_type
    if body_kind and not str(result.get("body_kind") or "").strip():
        result["body_kind"] = body_kind

    heuristic_params = _build_heuristic_params(template)
    if not heuristic_params:
        result["ai_fill_status"] = "skipped"
        result["ai_fill_note"] = "请求模板未识别到可填充参数"
        return result

    hint_only, hint_note = _should_hint_only(method, body_kind, content_type)
    result["ai_fill_hint_only"] = hint_only

    merged_params = heuristic_params
    if runtime.get("enabled") and runtime.get("ai_available"):
        ai_ret = _call_ai_fill(runtime, result, heuristic_params)
        if ai_ret.get("ok"):
            ai_data = ai_ret.get("data") if isinstance(ai_ret.get("data"), dict) else {}
            merged_params = _merge_ai_params(heuristic_params, ai_data.get("filled_params") if isinstance(ai_data.get("filled_params"), list) else [])
            result["ai_fill_source"] = "ai"
            if str(ai_data.get("summary") or "").strip():
                result["ai_fill_note"] = _truncate_text(ai_data.get("summary"), 180)
            if str(ai_data.get("reason") or "").strip():
                result["ai_fill_reason"] = _truncate_text(ai_data.get("reason"), 320)
            test_mode = _normalize_lower_text(ai_data.get("test_mode"))
            should_test = bool(ai_data.get("should_test", True))
            if test_mode == "hint_only" or not should_test:
                hint_only = True
                result["ai_fill_hint_only"] = True
                if not result.get("ai_fill_note"):
                    result["ai_fill_note"] = _truncate_text(ai_data.get("reason") or ai_data.get("summary"), 180)
        else:
            result["ai_fill_source"] = "heuristic"
            result["ai_fill_note"] = "AI 填充失败，已回退启发式补全: {}".format(_truncate_text(ai_ret.get("message"), 120))
    elif not runtime.get("enabled"):
        result["ai_fill_status"] = "disabled"
        result["ai_fill_note"] = "AI 管理中已关闭 WIH 接口 AI 填充"
    elif runtime.get("enabled") and not runtime.get("ai_available"):
        result["ai_fill_note"] = "AI 模型不可用，已回退启发式补全"

    filled_template = _apply_filled_params(template, merged_params)
    filled_url = _build_url_with_query(result.get("url"), filled_template)
    result["ai_fill_params"] = merged_params[:24]
    result["ai_fill_request_template"] = filled_template
    result["ai_fill_request_packet"] = InfoHunter._build_request_packet_fallback(filled_url, method, filled_template)
    if result.get("ai_fill_status") != "disabled":
        result["ai_fill_status"] = "filled"

    if hint_only:
        result["ai_fill_status"] = "hint_only"
        result["ai_fill_note"] = hint_note or str(result.get("ai_fill_note") or "该接口仅提供填充提示，不主动测试")
        return result

    if _has_observed_response(result):
        result["ai_fill_status"] = "filled"
        if not result.get("ai_fill_note"):
            result["ai_fill_note"] = "已补齐参数建议；原始扫描阶段已捕获响应，无需再次测试"
        return result

    return _probe_with_filled_request(result, waf_guard=waf_guard, dns_policy_cache=dns_policy_cache)


def run_wih_endpoint_ai_fill(task_id: str, endpoints: List[Dict], waf_guard=None) -> List[Dict]:
    items = [dict(item or {}) for item in list(endpoints or []) if isinstance(item, dict)]
    if not items:
        return []

    runtime = _load_ai_fill_runtime()
    if not runtime.get("enabled") and not runtime.get("ai_available"):
        for item in items:
            item["task_id"] = str(task_id or "").strip()
            item["ai_fill_status"] = "disabled"
            item["ai_fill_note"] = "AI 管理中未启用 WIH 接口 AI 填充"
            item["ai_fill_source"] = "disabled"
        return items

    max_targets = max(1, int(getattr(Config, "WIH_ENDPOINT_AI_FILL_MAX_TARGETS", 60) or 60))
    concurrency = max(1, int(getattr(Config, "WIH_ENDPOINT_AI_FILL_CONCURRENCY", 4) or 4))
    dns_policy_cache = {}
    results = [None] * len(items)
    futures = {}
    active_count = 0

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        for index, item in enumerate(items):
            if active_count >= max_targets:
                item["task_id"] = str(task_id or "").strip()
                item["ai_fill_status"] = "skipped"
                item["ai_fill_note"] = "超过 WIH 接口 AI 填充上限，未继续处理"
                item["ai_fill_source"] = "skipped"
                results[index] = item
                continue
            active_count += 1
            futures[
                executor.submit(
                    _fill_one,
                    task_id,
                    item,
                    runtime,
                    waf_guard,
                    dns_policy_cache,
                )
            ] = index

        for future in as_completed(futures):
            index = futures[future]
            try:
                results[index] = future.result()
            except Exception as exc:
                item = dict(items[index] or {})
                item["task_id"] = str(task_id or "").strip()
                item["ai_fill_status"] = "error"
                item["ai_fill_note"] = "AI 填充失败: {}".format(exc.__class__.__name__)
                item["ai_fill_source"] = "error"
                results[index] = item
                logger.warning("run wih endpoint ai fill failed task_id:%s err:%s", task_id, exc)

    return [item for item in results if isinstance(item, dict)]
