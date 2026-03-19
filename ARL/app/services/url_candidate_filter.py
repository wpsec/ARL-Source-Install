"""
URL 候选过滤与归一化辅助函数。

说明：
- 统一处理 WIH / URLFinder 产出的 URL 候选，降低模板化路由、静态资源与注释污染带来的噪声。
- 仅做轻量规则判断，避免过度“智能”导致真实业务 URL 被误杀。
"""
import re
from urllib.parse import urlparse

_ROUTE_METHOD_SUFFIX_RE = re.compile(
    r"(?i)\|(get|post|put|delete|patch|options|head|connect|trace)$"
)

_NOISE_SINGLE_SEGMENT_PATHS = {
    "head",
    "body",
    "html",
    "script",
    "style",
    "meta",
    "link",
    "title",
}

_NON_JS_STATIC_SUFFIXES = (
    ".css",
    ".scss",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".ico",
    ".svg",
    ".vue",
    ".ts",
    ".woff",
    ".woff2",
    ".ttf",
    ".map",
)

_JS_SUFFIXES = (".js", ".mjs")


def strip_url_annotation(value: str) -> str:
    text = str(value or "").strip()
    if not text or " (" not in text or not text.endswith(")"):
        return text

    prefix = text.rsplit(" (", 1)[0].strip()
    parsed = urlparse(prefix)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return prefix
    return text


def strip_route_method_suffix(path_text: str) -> str:
    text = str(path_text or "").strip()
    if not text:
        return ""
    return _ROUTE_METHOD_SUFFIX_RE.sub("", text)


def has_route_template_markers(path_text: str) -> bool:
    text = str(path_text or "").strip()
    if not text:
        return False

    if any(token in text for token in ("|", "{", "}", "<", ">", "[", "]", "${")):
        return True

    for segment in text.split("/"):
        segment = str(segment or "").strip()
        if not segment:
            continue
        if segment.startswith(":"):
            return True
        if "*" in segment:
            return True

    return False


def is_noise_single_segment_path(path_text: str) -> bool:
    text = str(path_text or "").strip().strip("/")
    if not text:
        return False
    if "/" in text or "." in text:
        return False
    return text.lower() in _NOISE_SINGLE_SEGMENT_PATHS


def is_js_resource_path(path_text: str) -> bool:
    lower_path = str(path_text or "").strip().lower()
    if not lower_path:
        return False
    return any(lower_path.endswith(suffix) for suffix in _JS_SUFFIXES)


def is_non_js_static_resource_path(path_text: str) -> bool:
    lower_path = str(path_text or "").strip().lower()
    if not lower_path:
        return False
    return any(lower_path.endswith(suffix) for suffix in _NON_JS_STATIC_SUFFIXES)


def normalize_http_url_candidate(value: str, allowed_hosts=None, allow_js: bool = True) -> str:
    text = strip_url_annotation(value)
    if not text or " " in text:
        return ""

    parsed = urlparse(text)
    if parsed.scheme not in {"http", "https"}:
        return ""
    if not parsed.netloc:
        return ""

    host = str(parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        return ""
    if allowed_hosts and host not in allowed_hosts:
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
