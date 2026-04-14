"""
信息收集和处理
"""
from typing import List
from app import utils
from app.config import Config
import os
import json
import subprocess
import hashlib
import base64
import re
import time
from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl
from app.modules import WihRecord
from .url_candidate_filter import (
    has_route_template_markers,
    is_js_resource_path,
    is_non_js_static_resource_path,
    is_noise_single_segment_path,
    strip_url_annotation,
    strip_route_method_suffix,
)

logger = utils.get_logger()

_EMAIL_STATIC_SUFFIXES = {
    "png",
    "jpg",
    "jpeg",
    "gif",
    "svg",
    "webp",
    "ico",
    "bmp",
    "css",
    "js",
    "map",
    "woff",
    "woff2",
    "ttf",
    "eot",
}
_PATH_NOISE_SINGLE_SEGMENTS = {
    "svg",
    "post",
    "var",
    "return",
    "undefined",
    "template",
    "license",
    "textarea",
    "span",
    "h1",
    "h2",
    "h3",
    "dtd",
    "compiler-dom",
    "ietf",
}
_PATH_SHORT_ALLOWLIST = {
    "api",
    "app",
    "cms",
    "doc",
    "docs",
    "rpc",
    "sdk",
    "sms",
    "sso",
    "uaa",
}
_HOST_LIKE_SEGMENT_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?$")
_PATH_CODE_MARKER_RE = re.compile(
    r"(?i)(?:\.test\(|\.exec\(|parseint|parsefloat|math\.|offsetwidth|offsetheight|"
    r"function\.prototype|object\.prototype|number\.isfinite|regexp\(|substr\(|substring\(|"
    r"starting_with\(|django_value|xhtml\+xml|android/gi|iphone|msie|lark)"
)
_SECRET_PLACEHOLDER_VALUES = {
    "password",
    "passwd",
    "pwd",
    "token",
    "secret",
    "secret_key",
    "client_secret",
    "api_key",
    "access_key",
    "accesskey",
    "authorization",
    "bearer",
    "basic",
    "admin",
    "test",
    "demo",
    "sample",
    "example",
    "default",
    "changeme",
    "null",
    "undefined",
    "your_password",
    "your_secret",
    "your_token",
    "your_key",
    "secret_do_not_pass_this_or_you_will_be_fired",
}
_SECRET_METADATA_HINTS = (
    "author:",
    "github:",
    "email:",
    "homepage:",
    "discord:",
    "qq:",
    "wechat:",
    "wechar:",
    "workin:",
)
_SECRET_LITERAL_RE = re.compile(
    r"(?i)\b(?P<key>api[_-]?key|access[_-]?key|secret(?:[_-]?key)?|client[_-]?secret|authorization|token|app[_-]?key|password|passwd|pwd)\b"
    r"\s*[:=]\s*['\"](?P<value>[^\"'\r\n]{3,512})['\"]"
)
_SECRET_TEMPLATE_RE = re.compile(r"(?i)\b(token|secret|key|authorization)\b[^;\r\n]{0,80}\.concat\(")
_SECRET_PLUS_TEMPLATE_RE = re.compile(
    r"(?i)\b(token|secret|key|authorization)\b\s*[:=]\s*['\"]?(?:[^\"'\r\n]{0,32})?\+\s*[A-Za-z_$({\[]"
)
_SECRET_DEBUG_RE = re.compile(r"(?i)\b(token|secret|password|authorization)\b\s*[:=]\s*['\"]?[^\"'\s]{0,24}(?:debug|log)\s*\(")


class InfoHunter(object):
    # 从JS中收集，子域名，AK SK 等信息
    def __init__(self, sites: list, prefer_fast_mode: bool = False):
        self.sites = set(sites)
        self.endpoint_results = []
        self.prefer_fast_mode = bool(prefer_fast_mode)

        tmp_path = Config.TMP_PATH
        rand_str = utils.random_choices()

        # wih 目标文件
        self.wih_target_path = os.path.join(tmp_path, "wih_target_{}.txt".format(rand_str))

        # wih 结果文件
        self.wih_result_path = os.path.join(tmp_path, "wih_result_{}.json".format(rand_str))

        self.wih_bin_path = self._resolve_wih_binary()
        self.wih_timeout_sec = int(getattr(Config, "WIH_TIMEOUT_SEC", 2 * 60 * 60) or (2 * 60 * 60))
        self.wih_concurrency = int(getattr(Config, "WIH_CONCURRENCY", 6) or 6)
        self.wih_concurrency_per_site = int(getattr(Config, "WIH_CONCURRENCY_PER_SITE", 2) or 2)
        self.wih_max_batch_size = int(getattr(Config, "WIH_MAX_BATCH_SIZE", 12) or 12)
        self.wih_adaptive_runtime_enable = bool(getattr(Config, "WIH_ADAPTIVE_RUNTIME_ENABLE", True))
        self.wih_runtime_enable = bool(getattr(Config, "WIH_RUNTIME_ENABLE", True))
        self.wih_runtime_driver = str(getattr(Config, "WIH_RUNTIME_DRIVER", "playwright") or "playwright").strip().lower()
        self.wih_runtime_command = str(getattr(Config, "WIH_RUNTIME_COMMAND", "") or "").strip()
        self.wih_runtime_timeout_sec = int(getattr(Config, "WIH_RUNTIME_TIMEOUT_SEC", 60) or 60)
        self.wih_runtime_max_pages = int(getattr(Config, "WIH_RUNTIME_MAX_PAGES", 12) or 12)
        self.wih_runtime_max_actions = int(getattr(Config, "WIH_RUNTIME_MAX_ACTIONS", 32) or 32)
        self.wih_runtime_max_requests = int(getattr(Config, "WIH_RUNTIME_MAX_REQUESTS", 180) or 180)
        self.wih_light_timeout_sec = int(getattr(Config, "WIH_LIGHT_TIMEOUT_SEC", 15 * 60) or (15 * 60))
        self.wih_light_runtime_timeout_sec = int(getattr(Config, "WIH_LIGHT_RUNTIME_TIMEOUT_SEC", 20) or 20)
        self.wih_light_runtime_max_pages = int(getattr(Config, "WIH_LIGHT_RUNTIME_MAX_PAGES", 4) or 4)
        self.wih_light_runtime_max_actions = int(getattr(Config, "WIH_LIGHT_RUNTIME_MAX_ACTIONS", 10) or 10)
        self.wih_light_runtime_max_requests = int(getattr(Config, "WIH_LIGHT_RUNTIME_MAX_REQUESTS", 60) or 60)
        self.wih_minimal_timeout_sec = int(getattr(Config, "WIH_MINIMAL_TIMEOUT_SEC", 15 * 60) or (15 * 60))
        self.wih_minimal_runtime_enable = bool(getattr(Config, "WIH_MINIMAL_RUNTIME_ENABLE", False))
        if self.wih_timeout_sec < 60:
            self.wih_timeout_sec = 60
        if self.wih_concurrency < 1:
            self.wih_concurrency = 1
        if self.wih_concurrency_per_site < 1:
            self.wih_concurrency_per_site = 1
        if self.wih_max_batch_size < 1:
            self.wih_max_batch_size = 12
        if self.wih_runtime_timeout_sec < 1:
            self.wih_runtime_timeout_sec = 60
        if self.wih_light_timeout_sec < 60:
            self.wih_light_timeout_sec = 60
        if self.wih_light_runtime_timeout_sec < 1:
            self.wih_light_runtime_timeout_sec = 20
        if self.wih_runtime_max_pages < 1:
            self.wih_runtime_max_pages = 1
        if self.wih_light_runtime_max_pages < 1:
            self.wih_light_runtime_max_pages = 1
        if self.wih_runtime_max_actions < 0:
            self.wih_runtime_max_actions = 0
        if self.wih_light_runtime_max_actions < 0:
            self.wih_light_runtime_max_actions = 0
        if self.wih_runtime_max_requests < 1:
            self.wih_runtime_max_requests = 1
        if self.wih_light_runtime_max_requests < 1:
            self.wih_light_runtime_max_requests = 1
        if self.wih_minimal_timeout_sec < 60:
            self.wih_minimal_timeout_sec = 60
        if self.wih_runtime_driver not in {"playwright", "external", "noop"}:
            self.wih_runtime_driver = "playwright"
        self._help_text = None
        self._wih_version_text = ""
        self._wih_binary_logged = False
        self.wih_deadline_ts = None

    @staticmethod
    def _safe_int(value, default=0) -> int:
        try:
            return int(value)
        except Exception:
            return default

    @staticmethod
    def _safe_positive_int(value):
        parsed = InfoHunter._safe_int(value, default=0)
        if parsed <= 0:
            return None
        return parsed

    @staticmethod
    def _append_query_string(url: str, query_string: str) -> str:
        text = str(url or "").strip()
        query_text = str(query_string or "").strip().lstrip("?")
        if not text or not query_text:
            return text
        try:
            parsed = urlparse(text)
            existing_pairs = parse_qsl(parsed.query or "", keep_blank_values=True)
            append_pairs = parse_qsl(query_text, keep_blank_values=True)
            if not append_pairs:
                separator = "&" if parsed.query else "?"
                return "{}{}{}".format(text, separator, query_text)

            seen_pairs = set(existing_pairs)
            merged_pairs = list(existing_pairs)
            for key, value in append_pairs:
                pair = (key, value)
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                merged_pairs.append(pair)
            merged_query = urlencode(merged_pairs)
            return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "", parsed.params, merged_query, parsed.fragment))
        except Exception:
            separator = "&" if "?" in text else "?"
            return "{}{}{}".format(text, separator, query_text)

    @staticmethod
    def _request_template_query_string(request_template: dict) -> str:
        if not isinstance(request_template, dict):
            return ""
        query_string = str(request_template.get("query_string") or "").strip().lstrip("?")
        if query_string:
            return query_string

        query = request_template.get("query")
        if not isinstance(query, dict) or not query:
            return ""
        try:
            items = []
            for key, value in query.items():
                key_text = str(key or "").strip()
                if not key_text or value is None:
                    continue
                items.append((key_text, str(value)))
            return urlencode(items)
        except Exception:
            return ""

    @staticmethod
    def _build_request_packet_fallback(url: str, method: str, request_template: dict) -> str:
        text = str(url or "").strip()
        if not text:
            return ""

        parsed = urlparse(text)
        host = str(parsed.netloc or "").strip()
        path = urlunparse(("", "", parsed.path or "/", "", parsed.query or "", "")) or "/"
        method_text = str(method or "").strip().upper() or "GET"
        headers = request_template.get("headers") if isinstance(request_template, dict) else {}
        if not isinstance(headers, dict):
            headers = {}

        lines = ["{} {} HTTP/1.1".format(method_text, path)]
        if host:
            lines.append("Host: {}".format(host))

        for key, value in headers.items():
            key_text = str(key or "").strip()
            value_text = str(value or "").strip()
            if not key_text or not value_text or key_text.lower() in {"host", "content-length"}:
                continue
            lines.append("{}: {}".format(key_text, value_text))

        body_text = ""
        if isinstance(request_template, dict):
            body_text = str(request_template.get("body_text") or "").strip()
            if not body_text and isinstance(request_template.get("body"), dict) and request_template.get("body"):
                try:
                    body_text = json.dumps(request_template.get("body"), ensure_ascii=False, indent=2)
                except Exception:
                    body_text = str(request_template.get("body"))

        if body_text:
            lines.append("")
            lines.append(body_text)

        return "\n".join(lines)

    @staticmethod
    def _normalize_endpoint_record(endpoint: dict, target: str):
        if not isinstance(endpoint, dict):
            return None

        request_template = endpoint.get("request_template") if isinstance(endpoint.get("request_template"), dict) else {}
        endpoint_url = str(endpoint.get("url") or "").strip()
        query_string = InfoHunter._request_template_query_string(request_template)
        method = str(endpoint.get("method") or "GET").strip().upper() or "GET"
        if query_string:
            endpoint_url = InfoHunter._append_query_string(endpoint_url, query_string)

        if not endpoint_url:
            return None

        page_url = str(endpoint.get("page_url") or "").strip()
        trigger_context = endpoint.get("trigger_context") if isinstance(endpoint.get("trigger_context"), dict) else {}
        if not page_url:
            page_url = str(trigger_context.get("page") or "").strip()

        target_text = str(endpoint.get("site") or target or "").strip()
        request_packet = str(request_template.get("request_packet") or "").strip()
        if not request_packet:
            request_packet = InfoHunter._build_request_packet_fallback(endpoint_url, method, request_template)

        hash_text = "{}|{}|{}|{}|{}|{}".format(
            target_text,
            page_url,
            method,
            endpoint_url,
            request_packet,
            str(endpoint.get("endpoint_id") or "").strip(),
        )
        hash_digest = hashlib.md5(hash_text.encode("utf-8", errors="ignore")).hexdigest()
        endpoint_hash = hash_digest[:16]
        response_status = endpoint.get("response_status", endpoint.get("status_code"))
        response_size = endpoint.get("response_size", endpoint.get("content_length"))
        status_code = InfoHunter._safe_positive_int(response_status)
        response_size_int = InfoHunter._safe_int(response_size)
        normalized_response_size = response_size_int if response_size_int > 0 or status_code is not None else None

        return {
            "endpoint_id": str(endpoint.get("endpoint_id") or "").strip(),
            "target": target_text,
            "site": target_text,
            "page_url": page_url,
            "url": endpoint_url,
            "path": str(endpoint.get("path") or "").strip(),
            "method": method,
            "protocol": str(endpoint.get("protocol") or "").strip(),
            "source_types": endpoint.get("source_types") if isinstance(endpoint.get("source_types"), list) else [],
            "content_type": str(endpoint.get("content_type") or "").strip(),
            "body_kind": str(endpoint.get("body_kind") or "").strip(),
            "status_code": status_code,
            "response_status": status_code,
            "response_size": normalized_response_size,
            "request_packet": request_packet,
            "request_template": request_template,
            "confidence": endpoint.get("confidence", 0),
            "fnv_hash": endpoint_hash,
        }

    @staticmethod
    def _should_keep_plain_content(record_type: str, content: str) -> bool:
        record_type = str(record_type or "").strip().lower()
        content = str(content or "").strip().lower()
        if record_type in {"domain_url", "ip_url", "path_url", "page_url", "urlfinder_url", "urlfinder_js"}:
            return True
        return content.startswith("http://") or content.startswith("https://")

    @staticmethod
    def _is_js_source(source: str, site: str) -> bool:
        source_text = str(source or "").strip()
        site_text = str(site or "").strip()
        if not source_text:
            return False
        parsed = urlparse(source_text)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            if is_js_resource_path(parsed.path or ""):
                return True
        return bool(site_text and source_text != site_text and source_text.endswith((".js", ".mjs")))

    @staticmethod
    def _is_http_url(value: str) -> bool:
        text = str(value or "").strip().lower()
        return text.startswith("http://") or text.startswith("https://")

    @staticmethod
    def _canonicalize_http_url(value: str, origin_only: bool = False) -> str:
        text = strip_url_annotation(str(value or "").strip())
        if not text:
            return ""

        try:
            parsed = urlparse(text)
        except Exception:
            return ""

        scheme = str(parsed.scheme or "").strip().lower()
        host = str(parsed.hostname or "").strip().lower().rstrip(".")
        if scheme not in {"http", "https"} or not host:
            return ""

        try:
            port = int(parsed.port) if parsed.port else None
        except Exception:
            port = None

        if (scheme == "http" and port in {None, 80}) or (scheme == "https" and port in {None, 443}):
            netloc = host
        elif port:
            netloc = "{}:{}".format(host, port)
        else:
            netloc = host

        if origin_only:
            path = ""
            query = ""
        else:
            path = strip_route_method_suffix(parsed.path or "")
            if path == "/":
                path = ""
            query = str(parsed.query or "").strip()

        return urlunparse((scheme, netloc, path, "", query, ""))

    @staticmethod
    def _should_keep_email_content(content: str) -> bool:
        text = str(content or "").strip()
        if "@" not in text:
            return False

        domain = text.rsplit("@", 1)[-1].strip().lower().rstrip(".")
        if "." not in domain:
            return False

        suffix = domain.rsplit(".", 1)[-1]
        if suffix in _EMAIL_STATIC_SUFFIXES:
            return False

        if re.search(r"(?i)@(1x|2x|3x|4x|5x)(?:-[a-f0-9]{4,})?\.[a-z0-9]{2,10}$", text):
            return False

        return True

    @staticmethod
    def _is_host_like_path_segment(segment: str) -> bool:
        text = str(segment or "").strip().lower().rstrip(".")
        if not text:
            return False
        if text.startswith("localhost"):
            return True
        if _HOST_LIKE_SEGMENT_RE.match(text):
            return True
        if ":" in text:
            host_part = text.split(":", 1)[0].strip()
            if host_part and utils.is_valid_domain(host_part):
                return True
        return utils.is_valid_domain(text)

    @staticmethod
    def _should_keep_path_content(content: str, source: str, site: str) -> bool:
        path_text = strip_route_method_suffix(str(content or "").strip())
        if not path_text or not path_text.startswith("/"):
            return False
        if len(path_text) > 180:
            return False
        if any(token in path_text for token in ("\r", "\n", "\t", "\\", " ")):
            return False
        if has_route_template_markers(path_text):
            return False
        if is_js_resource_path(path_text) or is_non_js_static_resource_path(path_text):
            return False
        if _PATH_CODE_MARKER_RE.search(path_text):
            return False

        raw_text = path_text.strip("/")
        if not raw_text:
            return False

        first_segment = raw_text.split("/", 1)[0].strip()
        if InfoHunter._is_host_like_path_segment(first_segment):
            return False

        is_js_source = InfoHunter._is_js_source(source, site)
        if is_js_source and any(token in path_text for token in ("(", ")", ",", "=", "$")):
            return False

        if "/" not in raw_text:
            lowered = raw_text.lower()
            if is_noise_single_segment_path(path_text):
                return False
            if lowered.isdigit():
                return False
            if lowered in _PATH_NOISE_SINGLE_SEGMENTS:
                return False
            if is_js_source and len(lowered) <= 3 and lowered not in _PATH_SHORT_ALLOWLIST:
                return False

        return True

    @staticmethod
    def _is_secret_like_record_type(record_type: str) -> bool:
        record_type_text = str(record_type or "").strip().lower()
        if not record_type_text:
            return False
        if record_type_text in {"password", "passwd", "authorization", "credential", "basic_token", "auth_token"}:
            return True
        return record_type_text.endswith("_key") or record_type_text.endswith("_token")

    @staticmethod
    def _normalize_secret_token_text(value: str) -> str:
        return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")

    @staticmethod
    def _canonicalize_domain_text(value: str) -> str:
        return str(value or "").strip().lower().rstrip(".")

    @staticmethod
    def _looks_like_secret_placeholder_value(key_text: str, value_text: str) -> bool:
        key_norm = InfoHunter._normalize_secret_token_text(key_text)
        value_norm = InfoHunter._normalize_secret_token_text(value_text)
        if not value_norm:
            return False

        if value_norm in _SECRET_PLACEHOLDER_VALUES:
            return True

        if key_norm and value_norm == key_norm:
            return True

        if key_norm and value_norm.startswith("{}_".format(key_norm)):
            suffix = value_norm[len(key_norm):].strip("_")
            if suffix in _SECRET_PLACEHOLDER_VALUES:
                return True

        return False

    @staticmethod
    def _decode_base64_secret_literal(value: str) -> str:
        value_text = str(value or "").strip()
        if not value_text.lower().startswith("base64:"):
            return ""

        payload = value_text.split(":", 1)[1].strip()
        if len(payload) < 16 or (not re.fullmatch(r"[A-Za-z0-9+/=]+", payload)):
            return ""

        padding = (-len(payload)) % 4
        if padding:
            payload = "{}{}".format(payload, "=" * padding)

        try:
            return base64.b64decode(payload, validate=False).decode("utf-8", errors="ignore").strip()
        except Exception:
            return ""

    @staticmethod
    def _looks_like_secret_literal_noise(secret_name: str, secret_value: str) -> bool:
        key_text = InfoHunter._normalize_secret_token_text(secret_name)
        value_text = str(secret_value or "").strip()
        value_norm = InfoHunter._normalize_secret_token_text(value_text)
        if not value_text:
            return False

        if InfoHunter._looks_like_secret_placeholder_value(key_text, value_norm):
            return True

        decoded_text = InfoHunter._decode_base64_secret_literal(value_text)
        if decoded_text:
            decoded_lower = decoded_text.lower()
            marker_hits = sum(1 for token in _SECRET_METADATA_HINTS if token in decoded_lower)
            if marker_hits >= 3:
                return True

        return False

    @staticmethod
    def _looks_like_placeholder_basic_token(content: str) -> bool:
        match = re.search(r"(?i)\bbasic\s+(?P<token>[A-Za-z0-9+/]{8,}={0,2})\b", str(content or "").strip())
        if not match:
            return False

        payload = str(match.group("token") or "").strip()
        if not payload:
            return False

        padding = (-len(payload)) % 4
        if padding:
            payload = "{}{}".format(payload, "=" * padding)

        try:
            decoded = base64.b64decode(payload, validate=False).decode("utf-8", errors="ignore").strip()
        except Exception:
            return False

        if ":" not in decoded:
            return False

        username, password = decoded.split(":", 1)
        username_norm = InfoHunter._normalize_secret_token_text(username)
        password_norm = InfoHunter._normalize_secret_token_text(password)
        if not username_norm or not password_norm:
            return False

        if (
            password_norm in _SECRET_PLACEHOLDER_VALUES
            or password_norm == username_norm
            or password_norm in username_norm
            or username_norm in password_norm
        ):
            return True

        if password_norm.startswith(username_norm):
            suffix = password_norm[len(username_norm):].strip("_")
            if suffix in {"secret", "token", "password", "key", "client_secret", "access_key"}:
                return True

        return False

    @staticmethod
    def _looks_like_js_secret_noise(content: str) -> bool:
        content_text = str(content or "").strip()
        content_lower = content_text.lower()
        if not content_lower:
            return False

        literal_match = _SECRET_LITERAL_RE.search(content_text)
        if literal_match and InfoHunter._looks_like_secret_literal_noise(
            literal_match.group("key"),
            literal_match.group("value"),
        ):
            return True

        if _SECRET_TEMPLATE_RE.search(content_text) or _SECRET_PLUS_TEMPLATE_RE.search(content_text):
            return True

        if any(token in content_lower for token in ("localstorage[", "sessionstorage[", "location.host", "webcustomize.title")) and \
                any(token in content_lower for token in ("token", "secret", "key", "authorization")):
            return True

        if any(token in content_lower for token in ("console.debug(", "console.log(", "logger.debug(", "logger.info(", "debug(", "trace(", "syno.debug(")) and \
                any(token in content_lower for token in ("token", "secret", "password", "authorization")):
            return True

        if _SECRET_DEBUG_RE.search(content_text):
            return True

        return False

    @staticmethod
    def _should_keep_secret_content(record_type: str, content: str, source: str = "", site: str = "") -> bool:
        record_type_text = str(record_type or "").strip().lower()
        content_text = str(content or "").strip()
        if not content_text:
            return False

        if record_type_text in {"basic_token", "auth_token", "authorization", "token"} and \
                InfoHunter._looks_like_placeholder_basic_token(content_text):
            return False

        if InfoHunter._is_js_source(source, site) and InfoHunter._looks_like_js_secret_noise(content_text):
            return False

        return True

    @staticmethod
    def _canonicalize_record_fields(record_type: str, content: str, source: str = "", site: str = ""):
        record_type_text = str(record_type or "").strip().lower()
        content_text = str(content or "").strip()
        source_text = str(source or "").strip()
        site_text = str(site or "").strip()

        if InfoHunter._is_http_url(content_text):
            content_text = InfoHunter._canonicalize_http_url(content_text) or content_text
        elif record_type_text == "domain":
            content_text = InfoHunter._canonicalize_domain_text(content_text)

        if InfoHunter._is_http_url(source_text):
            source_text = InfoHunter._canonicalize_http_url(source_text) or source_text

        if InfoHunter._is_http_url(site_text):
            site_text = InfoHunter._canonicalize_http_url(site_text, origin_only=True) or site_text
        elif record_type_text == "domain":
            site_text = InfoHunter._canonicalize_domain_text(site_text)

        return record_type_text, content_text, source_text, site_text

    @staticmethod
    def normalize_wih_record(record) -> WihRecord:
        if not record:
            return None

        record_type = str(getattr(record, "recordType", "") or getattr(record, "record_type", "") or "").strip()
        content = str(getattr(record, "content", "") or "").strip()
        source = str(getattr(record, "source", "") or "").strip()
        site = str(getattr(record, "site", "") or "").strip()
        if not record_type or not content:
            return None

        record_type, content, source, site = InfoHunter._canonicalize_record_fields(
            record_type,
            content,
            source=source,
            site=site,
        )
        if not record_type or not content:
            return None

        hash_text = "{}|{}|{}|{}".format(record_type, content, source, site)
        hash_digest = hashlib.md5(hash_text.encode("utf-8", errors="ignore")).hexdigest()
        fnv_hash = int(hash_digest[:16], 16)
        return WihRecord(
            record_type=record_type,
            content=content,
            source=source,
            site=site,
            fnv_hash=fnv_hash,
        )

    @staticmethod
    def _normalize_record_content(record_type: str, content: str, source: str = "", site: str = "") -> str:
        normalized_type = str(record_type or "").strip().lower()
        text = str(content or "").strip()
        if not normalized_type or not text:
            return ""

        if normalized_type == "email":
            return text if InfoHunter._should_keep_email_content(text) else ""

        if normalized_type == "path":
            normalized_path = strip_route_method_suffix(text)
            return normalized_path if InfoHunter._should_keep_path_content(normalized_path, source, site) else ""

        if InfoHunter._is_secret_like_record_type(normalized_type):
            return text if InfoHunter._should_keep_secret_content(normalized_type, text, source=source, site=site) else ""

        return text

    @staticmethod
    def _resolve_wih_binary() -> str:
        # 默认固定走镜像内编译产物，避免共享 tools 目录残留旧版二进制时被优先命中。
        configured_binary = str(getattr(Config, "WIH_BIN_PATH", "") or "").strip()
        candidates = []
        if configured_binary:
            candidates.append(configured_binary)
        candidates.extend([
            "/usr/bin/wih",
            "/usr/local/bin/wih",
            "wih",
            "wihscan",
            "/code/tools/wih/wih",
            "/code/tools/wih/wihscan",
            "/code/tools/wih/bin/wih",
            "/code/tools/wih/bin/wihscan",
        ])
        for candidate in candidates:
            binary_path = utils.resolve_executable(candidate)
            if binary_path:
                return binary_path
        return "wih"

    def _get_target_file(self, sites=None):
        site_list = list(sites or self.sites or [])
        with open(self.wih_target_path, "w") as f:
            for site in site_list:
                site = str(site or "").strip()
                if site:
                    f.write(site + "\n")

    def _clear_result_file(self):
        try:
            if os.path.exists(self.wih_result_path):
                os.unlink(self.wih_result_path)
            for extra_path in self._structured_result_paths():
                if os.path.exists(extra_path):
                    os.unlink(extra_path)
        except Exception as e:
            logger.warning(e)

    def _delete_file(self):
        try:
            if os.path.exists(self.wih_target_path):
                os.unlink(self.wih_target_path)
            self._clear_result_file()
        except Exception as e:
            logger.warning(e)

    def _structured_result_paths(self) -> list:
        base_path = os.path.splitext(self.wih_result_path)[0]
        if not base_path:
            return []
        return [
            "{}_endpoint.json".format(base_path),
            "{}_parameter.json".format(base_path),
            "{}_endpoint.csv".format(base_path),
            "{}_parameter.csv".format(base_path),
        ]

    def _initial_batch_size(self) -> int:
        site_count = len(list(self.sites or []))
        if site_count <= 0:
            return 1
        suggested_batch_size = max(8, int(self.wih_concurrency) * 2)
        return min(site_count, int(self.wih_max_batch_size), suggested_batch_size)

    @staticmethod
    def _split_site_batches(sites: list, batch_size: int) -> list:
        site_list = [str(site or "").strip() for site in list(sites or []) if str(site or "").strip()]
        if not site_list:
            return []
        size = max(1, int(batch_size or 1))
        return [site_list[idx: idx + size] for idx in range(0, len(site_list), size)]

    def _read_current_result_text(self) -> str:
        if not os.path.exists(self.wih_result_path):
            return ""
        with open(self.wih_result_path, "r", encoding="utf-8", errors="ignore") as f:
            return str(f.read() or "").strip()

    @staticmethod
    def _parse_wih_payload_items(raw_text: str) -> tuple:
        payload_items = []
        invalid_items = 0
        text = str(raw_text or "").strip()
        if not text:
            return payload_items, invalid_items

        if text.startswith("["):
            try:
                payload = json.loads(text)
                if isinstance(payload, list):
                    payload_items = payload
                elif isinstance(payload, dict):
                    payload_items = [payload]
            except Exception as e:
                logger.debug("parse wih json array failed err:{}".format(e))
                invalid_items += 1
            return payload_items, invalid_items

        for line in text.splitlines():
            line = str(line or "").strip()
            if not line:
                continue
            try:
                payload_items.append(json.loads(line))
            except Exception as e:
                invalid_items += 1
                logger.debug("skip invalid wih json line err:{} line:{}".format(e, line[:200]))

        return payload_items, invalid_items

    @staticmethod
    def _extract_result_sites(payload_items: list) -> list:
        site_list = []
        site_seen = set()
        for item in list(payload_items or []):
            if not isinstance(item, dict):
                continue
            site = str(item.get("target") or item.get("url") or item.get("site") or "").strip()
            if not site or site in site_seen:
                continue
            site_seen.add(site)
            site_list.append(site)
        return site_list

    def _salvage_partial_batch_results(self, aggregate_result_texts: list, batch_sites: list, depth: int, command_name: str) -> list:
        raw_text = self._read_current_result_text()
        if not raw_text:
            return []

        payload_items, invalid_items = self._parse_wih_payload_items(raw_text)
        completed_sites = self._extract_result_sites(payload_items)
        if not completed_sites:
            logger.info(
                "wih {} partial result empty depth:{} batch_sites:{} invalid_items:{}".format(
                    command_name,
                    depth,
                    len(list(batch_sites or [])),
                    invalid_items,
                )
            )
            return []

        aggregate_result_texts.append(raw_text)
        logger.info(
            "salvage wih {} partial result depth:{} batch_sites:{} completed_sites:{} invalid_items:{}".format(
                command_name,
                depth,
                len(list(batch_sites or [])),
                len(completed_sites),
                invalid_items,
            )
        )
        return completed_sites

    def _write_aggregate_result_texts(self, result_texts: list):
        merged_lines = []
        for item in list(result_texts or []):
            raw_text = str(item or "").strip()
            if not raw_text:
                continue
            if raw_text.startswith("["):
                try:
                    payload = json.loads(raw_text)
                except Exception:
                    payload = None
                if isinstance(payload, list):
                    for row in payload:
                        if isinstance(row, dict):
                            merged_lines.append(json.dumps(row, ensure_ascii=False))
                    continue
            merged_lines.append(raw_text)
        merged_text = "\n".join(merged_lines)
        if not merged_text:
            self._clear_result_file()
            return
        with open(self.wih_result_path, "w", encoding="utf-8") as f:
            f.write(merged_text)

    def _build_runtime_profile(self, profile_name: str = "full") -> dict:
        normalized_name = str(profile_name or "full").strip().lower()
        runtime_enable = bool(self.wih_runtime_enable)

        profile = {
            "name": "full",
            "timeout_sec": self.wih_timeout_sec,
            "runtime_enable": runtime_enable,
            "runtime_driver": self.wih_runtime_driver if runtime_enable else "noop",
            "runtime_command": self.wih_runtime_command if runtime_enable else "",
            "runtime_timeout_sec": self.wih_runtime_timeout_sec,
            "runtime_max_pages": self.wih_runtime_max_pages,
            "runtime_max_actions": self.wih_runtime_max_actions,
            "runtime_max_requests": self.wih_runtime_max_requests,
            "minimal": False,
        }

        if normalized_name == "light":
            profile.update({
                "name": "light",
                "timeout_sec": min(self.wih_timeout_sec, self.wih_light_timeout_sec),
                "runtime_enable": runtime_enable,
                "runtime_driver": self.wih_runtime_driver if runtime_enable else "noop",
                "runtime_command": self.wih_runtime_command if runtime_enable else "",
                "runtime_timeout_sec": self.wih_light_runtime_timeout_sec,
                "runtime_max_pages": self.wih_light_runtime_max_pages,
                "runtime_max_actions": self.wih_light_runtime_max_actions,
                "runtime_max_requests": self.wih_light_runtime_max_requests,
            })
        elif normalized_name == "minimal":
            minimal_runtime_enable = bool(self.wih_runtime_enable and self.wih_minimal_runtime_enable)
            profile.update({
                "name": "minimal",
                "timeout_sec": min(self.wih_timeout_sec, self.wih_minimal_timeout_sec),
                "runtime_enable": minimal_runtime_enable,
                "runtime_driver": self.wih_runtime_driver if minimal_runtime_enable else "noop",
                "runtime_command": self.wih_runtime_command if minimal_runtime_enable else "",
                "runtime_timeout_sec": min(self.wih_runtime_timeout_sec, self.wih_light_runtime_timeout_sec),
                "runtime_max_pages": min(self.wih_runtime_max_pages, self.wih_light_runtime_max_pages),
                "runtime_max_actions": min(self.wih_runtime_max_actions, self.wih_light_runtime_max_actions),
                "runtime_max_requests": min(self.wih_runtime_max_requests, self.wih_light_runtime_max_requests),
                "minimal": True,
            })

        return profile

    def _select_primary_profile_name(self, batch_sites: list, depth: int = 0) -> str:
        if not self.prefer_fast_mode:
            return "full"
        if not self.wih_adaptive_runtime_enable:
            return "full"
        if depth > 1:
            return "full"
        if len(list(batch_sites or [])) <= 0:
            return "full"
        return "light"

    def _summarize_payload(self, raw_text: str) -> dict:
        payload_items, invalid_items = self._parse_wih_payload_items(raw_text)
        record_count = 0
        endpoint_count = 0
        signal_record_count = 0
        completed_sites = self._extract_result_sites(payload_items)
        signal_types = {
            "endpoint",
            "path",
            "page_url",
            "urlfinder_url",
            "urlfinder_js",
            "api_doc_url",
        }
        for item in list(payload_items or []):
            if not isinstance(item, dict):
                continue
            endpoints = item.get("endpoints")
            if isinstance(endpoints, list):
                endpoint_count += len(endpoints)
                signal_record_count += len(endpoints)

            records = item.get("records")
            if not isinstance(records, list):
                records = item.get("result")
            if not isinstance(records, list):
                records = item.get("results")
            if isinstance(records, list):
                record_count += len(records)
                for record in records:
                    if not isinstance(record, dict):
                        continue
                    record_type = str(
                        record.get("id") or record.get("type") or record.get("name") or ""
                    ).strip().lower()
                    if record_type in signal_types:
                        signal_record_count += 1

        return {
            "payload_items": payload_items,
            "invalid_items": invalid_items,
            "completed_sites": completed_sites,
            "record_count": record_count,
            "endpoint_count": endpoint_count,
            "signal_record_count": signal_record_count,
        }

    def _should_escalate_light_result(self, raw_text: str, batch_sites: list) -> bool:
        summary = self._summarize_payload(raw_text)
        site_count = max(1, len(list(batch_sites or [])))
        completed_sites = summary.get("completed_sites", []) or []
        record_count = int(summary.get("record_count", 0) or 0)
        endpoint_count = int(summary.get("endpoint_count", 0) or 0)
        signal_record_count = int(summary.get("signal_record_count", 0) or 0)

        if len(completed_sites) < site_count:
            return True
        if endpoint_count > 0:
            return False

        # 轻量 runtime 只在结果足够“厚”或信号足够明确时直接接受，避免周期任务为了提速把稀疏站点过早放行。
        min_record_threshold = max(8, site_count * 5)
        min_signal_threshold = max(3, site_count * 2)
        if signal_record_count >= min_signal_threshold:
            return False
        return record_count < min_record_threshold

    def _run_wih_command(self, command: list, batch_sites: list, command_name: str, timeout_sec: int = None):
        if timeout_sec is None:
            effective_timeout = max(60, int(self.wih_timeout_sec))
        else:
            effective_timeout = max(1, int(timeout_sec))
        try:
            completed = utils.exec_system(
                command,
                timeout=effective_timeout,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except subprocess.TimeoutExpired as e:
            logger.warning(
                "wih {} timeout:{}s batch_sites:{} cmd:{}".format(
                    command_name,
                    effective_timeout,
                    len(list(batch_sites or [])),
                    " ".join(command),
                )
            )
            return {
                "ok": False,
                "timed_out": True,
                "completed": None,
                "stderr": "",
                "stdout": "",
                "error": str(e),
            }
        except Exception as e:
            logger.warning(
                "wih {} exception batch_sites:{} err:{} cmd:{}".format(
                    command_name,
                    len(list(batch_sites or [])),
                    e,
                    " ".join(command),
                )
            )
            return {
                "ok": False,
                "timed_out": False,
                "completed": None,
                "stderr": "",
                "stdout": "",
                "error": str(e),
            }

        stderr_text = completed.stderr.decode("utf-8", errors="ignore").strip() if completed.stderr else ""
        stdout_text = completed.stdout.decode("utf-8", errors="ignore").strip() if completed.stdout else ""
        if completed.returncode == 0:
            return {
                "ok": True,
                "timed_out": False,
                "completed": completed,
                "stderr": stderr_text,
                "stdout": stdout_text,
                "error": "",
            }

        logger.warning(
            "wih {} failed rc={} batch_sites={} stderr={} stdout={}".format(
                command_name,
                completed.returncode,
                len(list(batch_sites or [])),
                stderr_text[:500],
                stdout_text[:500],
            )
        )
        return {
            "ok": False,
            "timed_out": False,
            "completed": completed,
            "stderr": stderr_text,
            "stdout": stdout_text,
            "error": "",
        }

    def _remaining_wih_deadline_sec(self):
        deadline_ts = getattr(self, "wih_deadline_ts", None)
        if deadline_ts is None:
            return None
        try:
            deadline_float = float(deadline_ts)
        except Exception:
            return None
        return max(0.0, deadline_float - time.time())

    def _is_wih_deadline_exhausted(self):
        remaining_sec = self._remaining_wih_deadline_sec()
        if remaining_sec is None:
            return False
        return remaining_sec <= 0

    def _execute_profile_once(self, batch_sites: list, aggregate_result_texts: list, depth: int, profile_name: str, stage_name: str) -> dict:
        current_sites = [str(site or "").strip() for site in list(batch_sites or []) if str(site or "").strip()]
        if not current_sites:
            return {
                "ok": False,
                "timed_out": False,
                "partial_saved": False,
                "remaining_sites": [],
                "raw_text": "",
                "profile": self._build_runtime_profile(profile_name),
                "deadline_exhausted": False,
            }

        profile = self._build_runtime_profile(profile_name)
        profile_timeout_sec = int(profile["timeout_sec"] or self.wih_timeout_sec)
        remaining_deadline_sec = self._remaining_wih_deadline_sec()
        if remaining_deadline_sec is not None:
            if remaining_deadline_sec <= 0:
                logger.warning(
                    "skip wih batch stage:{} depth:{} sites:{} reason:deadline_exhausted".format(
                        stage_name,
                        depth,
                        len(current_sites),
                    )
                )
                return {
                    "ok": False,
                    "timed_out": False,
                    "partial_saved": False,
                    "remaining_sites": list(current_sites),
                    "raw_text": "",
                    "profile": profile,
                    "deadline_exhausted": True,
                }
            profile_timeout_sec = min(profile_timeout_sec, max(1, int(remaining_deadline_sec)))

        self._clear_result_file()
        self._get_target_file(current_sites)

        command = self._build_command(runtime_profile=profile)
        logger.info(
            "run wih batch stage:{} depth:{} sites:{} timeout:{}s concurrency:{} per_site:{} runtime:{} cmd:{}".format(
                stage_name,
                depth,
                len(current_sites),
                profile_timeout_sec,
                self.wih_concurrency,
                self.wih_concurrency_per_site,
                profile["runtime_enable"],
                " ".join(command),
            )
        )
        result = self._run_wih_command(
            command,
            current_sites,
            stage_name,
            timeout_sec=profile_timeout_sec,
        )
        if result.get("ok"):
            raw_text = self._read_current_result_text()
            return {
                "ok": True,
                "timed_out": False,
                "partial_saved": False,
                "remaining_sites": [],
                "raw_text": raw_text,
                "profile": profile,
                "deadline_exhausted": False,
            }

        partial_saved = False
        remaining_sites = list(current_sites)
        if result.get("timed_out"):
            completed_sites = self._salvage_partial_batch_results(
                aggregate_result_texts,
                current_sites,
                depth,
                stage_name,
            )
            if completed_sites:
                partial_saved = True
                completed_site_set = set(completed_sites)
                remaining_sites = [site for site in current_sites if site not in completed_site_set]
                logger.info(
                    "wih {} timeout salvage depth:{} remaining_sites:{} completed_sites:{}".format(
                        stage_name,
                        depth,
                        len(remaining_sites),
                        len(completed_sites),
                    )
                )

        return {
            "ok": False,
            "timed_out": bool(result.get("timed_out")),
            "partial_saved": partial_saved,
            "remaining_sites": remaining_sites,
            "raw_text": "",
            "profile": profile,
            "deadline_exhausted": False,
        }

    def _exec_wih_batch(self, batch_sites: list, aggregate_result_texts: list, depth: int = 0) -> bool:
        current_sites = [str(site or "").strip() for site in list(batch_sites or []) if str(site or "").strip()]
        if not current_sites:
            return False

        partial_saved = False
        primary_sites = list(current_sites)
        primary_profile_name = self._select_primary_profile_name(primary_sites, depth=depth)
        primary_stage_name = "primary" if primary_profile_name == "full" else "primary_{}".format(primary_profile_name)
        primary = self._execute_profile_once(primary_sites, aggregate_result_texts, depth, primary_profile_name, primary_stage_name)
        if primary.get("ok"):
            if primary_profile_name == "light" and self._should_escalate_light_result(primary.get("raw_text", ""), primary_sites):
                logger.info(
                    "wih light result thin, escalate to full depth:{} sites:{}".format(
                        depth,
                        len(primary_sites),
                    )
                )
                light_raw_text = str(primary.get("raw_text", "") or "").strip()
                primary = self._execute_profile_once(primary_sites, aggregate_result_texts, depth, "full", "primary_escalated")
                if (not primary.get("ok")) and light_raw_text:
                    aggregate_result_texts.append(light_raw_text)
                    partial_saved = True
            else:
                if primary.get("raw_text"):
                    aggregate_result_texts.append(primary["raw_text"])
                return True

        partial_saved = bool(partial_saved or primary.get("partial_saved"))
        current_sites = [str(site or "").strip() for site in list(primary.get("remaining_sites", []) or []) if str(site or "").strip()]
        if primary.get("ok"):
            if primary.get("raw_text"):
                aggregate_result_texts.append(primary["raw_text"])
            return True
        if primary.get("deadline_exhausted"):
            return partial_saved
        if not current_sites:
            return partial_saved
        if primary.get("timed_out"):
            if self._is_wih_deadline_exhausted():
                logger.warning(
                    "skip wih timeout split depth:{} sites:{} reason:deadline_exhausted".format(
                        depth,
                        len(current_sites),
                    )
                )
                return partial_saved
            if len(current_sites) > 1:
                mid = max(1, len(current_sites) // 2)
                left_ok = self._exec_wih_batch(current_sites[:mid], aggregate_result_texts, depth=depth + 1)
                right_ok = self._exec_wih_batch(current_sites[mid:], aggregate_result_texts, depth=depth + 1)
                return bool(partial_saved or left_ok or right_ok)

        fallback = self._execute_profile_once(current_sites, aggregate_result_texts, depth, "minimal", "minimal")
        partial_saved = bool(primary.get("partial_saved")) or bool(fallback.get("partial_saved"))
        if fallback.get("ok"):
            if fallback.get("raw_text"):
                aggregate_result_texts.append(fallback["raw_text"])
            return True

        current_sites = [str(site or "").strip() for site in list(fallback.get("remaining_sites", []) or []) if str(site or "").strip()]
        if fallback.get("deadline_exhausted"):
            return partial_saved
        if not current_sites:
            return partial_saved

        if fallback.get("timed_out"):
            if self._is_wih_deadline_exhausted():
                logger.warning(
                    "skip wih minimal timeout split depth:{} sites:{} reason:deadline_exhausted".format(
                        depth,
                        len(current_sites),
                    )
                )
                return partial_saved
            if len(current_sites) > 1:
                mid = max(1, len(current_sites) // 2)
                left_ok = self._exec_wih_batch(current_sites[:mid], aggregate_result_texts, depth=depth + 1)
                right_ok = self._exec_wih_batch(current_sites[mid:], aggregate_result_texts, depth=depth + 1)
                return bool(partial_saved or left_ok or right_ok)

        logger.warning(
            "skip wih batch after failure depth:{} sites:{} sample:{}".format(
                depth,
                len(current_sites),
                ",".join(current_sites[:3]),
            )
        )
        return partial_saved

    def _load_help_text(self) -> str:
        if self._help_text is not None:
            return self._help_text

        try:
            output = utils.check_output([self.wih_bin_path, "-h"], timeout=2 * 60, stderr=subprocess.STDOUT)
            self._help_text = str(output or b"", "utf-8", errors="ignore")
        except Exception:
            self._help_text = ""

        return self._help_text

    def _load_wih_version_text(self) -> str:
        if self._wih_version_text:
            return self._wih_version_text

        command = [self.wih_bin_path, "--version"]
        try:
            completed = utils.exec_system(
                command,
                timeout=2 * 60,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except Exception as e:
            logger.debug("load wih version failed err:{}".format(e))
            return ""

        if completed.returncode != 0:
            return ""

        output_text = completed.stdout.decode("utf-8", errors="ignore").strip() if completed.stdout else ""
        if output_text:
            self._wih_version_text = output_text.splitlines()[0].strip()
        return self._wih_version_text

    def _log_wih_binary_once(self):
        if self._wih_binary_logged:
            return
        self._wih_binary_logged = True
        version_text = self._load_wih_version_text() or "unknown"
        logger.info(
            "using wih binary path:{} version_text:{} timeout:{}s concurrency:{} per_site:{} max_batch:{} runtime:{} driver:{}".format(
                self.wih_bin_path,
                version_text,
                self.wih_timeout_sec,
                self.wih_concurrency,
                self.wih_concurrency_per_site,
                self.wih_max_batch_size,
                self.wih_runtime_enable,
                self.wih_runtime_driver,
            )
        )

    def _supports_flag(self, flag_text: str) -> bool:
        return flag_text in self._load_help_text()

    @staticmethod
    def _resolve_rule_path() -> str:
        configured_path = str(getattr(Config, "WIH_RULE_PATH", "") or "").strip()
        if configured_path and os.path.isfile(configured_path):
            return configured_path

        if configured_path:
            logger.warning("wih rule path not found: {}, fallback to built-in/default".format(configured_path))

        local_candidates = [
            os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "tools", "wih", "config", "rules.yml")),
            "/code/tools/wih/config/rules.yml",
        ]
        for candidate in local_candidates:
            if os.path.isfile(candidate):
                return candidate

        return ""

    def _build_command(self, minimal=False, runtime_profile: dict = None) -> list:
        profile = runtime_profile or self._build_runtime_profile("minimal" if minimal else "full")
        command = [
            self.wih_bin_path,
            "-J",
            "-o",
            self.wih_result_path,
            "-t",
            self.wih_target_path,
        ]

        self._append_wih_control_flags(command)
        if self._supports_flag("--runtime-enable"):
            command.append("--runtime-enable={}".format("true" if profile["runtime_enable"] else "false"))

        if self._supports_flag("--runtime-driver"):
            runtime_driver = profile["runtime_driver"] if profile["runtime_enable"] else "noop"
            command.extend(["--runtime-driver", runtime_driver])

        if profile["runtime_enable"]:
            if self._supports_flag("--runtime-command") and profile["runtime_command"]:
                command.extend(["--runtime-command", profile["runtime_command"]])
            if self._supports_flag("--runtime-timeout"):
                command.extend(["--runtime-timeout", str(profile["runtime_timeout_sec"])])
            if self._supports_flag("--runtime-max-pages"):
                command.extend(["--runtime-max-pages", str(profile["runtime_max_pages"])])
            if self._supports_flag("--runtime-max-actions"):
                command.extend(["--runtime-max-actions", str(profile["runtime_max_actions"])])
            if self._supports_flag("--runtime-max-requests"):
                command.extend(["--runtime-max-requests", str(profile["runtime_max_requests"])])

        if minimal or profile.get("minimal", False):
            return command

        rule_path = self._resolve_rule_path()
        if rule_path:
            command.extend(["-r", rule_path])

        # 兼容不同 WIH 版本参数差异：仅在帮助信息里检测到时才追加。
        if self._supports_flag("--concurrency"):
            command.extend(["--concurrency", str(self.wih_concurrency)])
        elif self._supports_flag("-c"):
            command.extend(["-c", str(self.wih_concurrency)])

        if self._supports_flag("--log-level"):
            command.extend(["--log-level", "zero"])
        elif self._supports_flag("-v"):
            command.extend(["-v", "zero"])

        if self._supports_flag("--concurrency-per-site"):
            command.extend(["--concurrency-per-site", str(self.wih_concurrency_per_site)])

        proxy_url = str(getattr(Config, "PROXY_URL", "") or "").strip()
        if proxy_url:
            if self._supports_flag("--proxy"):
                command.extend(["--proxy", proxy_url])
            elif self._supports_flag("-x"):
                command.extend(["-x", proxy_url])

        return command

    def _append_wih_control_flags(self, command: list):
        if self._supports_flag("--disable-ak-sk-output"):
            command.append("--disable-ak-sk-output")
        if self._supports_flag("--disable-structured-output"):
            command.append("--disable-structured-output")

    def exec_wih(self):
        site_list = [str(site or "").strip() for site in sorted(list(self.sites or [])) if str(site or "").strip()]
        if not site_list:
            return False

        batch_size = self._initial_batch_size()
        batches = self._split_site_batches(site_list, batch_size)
        aggregate_result_texts = []
        success_batches = 0

        logger.info(
            "run wih batched total_sites:{} batch_size:{} batches:{} timeout:{}s".format(
                len(site_list),
                batch_size,
                len(batches),
                self.wih_timeout_sec,
            )
        )

        for batch_sites in batches:
            if self._exec_wih_batch(batch_sites, aggregate_result_texts, depth=0):
                success_batches += 1

        self._write_aggregate_result_texts(aggregate_result_texts)
        logger.info(
            "wih batch summary success_batches:{} total_batches:{} result_chunks:{}".format(
                success_batches,
                len(batches),
                len(aggregate_result_texts),
            )
        )
        return success_batches > 0

    def check_have_wih(self) -> bool:
        try:
            output_text = self._load_wih_version_text()
            normalized = output_text.lower()
            if output_text and (
                "version" in normalized or normalized.startswith("v") or normalized[0].isdigit()
            ):
                self._log_wih_binary_once()
                return True
            # 某些旧版二进制 --version 无输出，回退校验 -h。
            help_text = self._load_help_text()
            if help_text and ("webinfohunter" in help_text.lower() or "wih" in help_text.lower()):
                self._log_wih_binary_once()
                return True
        except Exception as e:
            logger.debug("{}".format(str(e)))

        return False

    def dump_result(self) -> list:
        results = []
        self.endpoint_results = []
        total_items = 0
        invalid_items = 0
        filtered_items = 0
        endpoint_hash_set = set()

        # 检查结果文件是否存在
        if not os.path.exists(self.wih_result_path):
            logger.warning("wih result file not found: {}".format(self.wih_result_path))
            return results

        with open(self.wih_result_path, "r", encoding="utf-8", errors="ignore") as f:
            raw_text = str(f.read() or "").strip()

        payload_items, invalid_items = self._parse_wih_payload_items(raw_text)
        record_hash_set = set()

        for data in payload_items:
            total_items += 1
            if not isinstance(data, dict):
                invalid_items += 1
                continue

            site = str(data.get("target") or data.get("url") or data.get("site") or "").strip()
            if not site:
                invalid_items += 1
                continue

            endpoints = data.get("endpoints")
            if isinstance(endpoints, list):
                for endpoint in endpoints:
                    endpoint_record = self._normalize_endpoint_record(endpoint, site)
                    if not endpoint_record:
                        filtered_items += 1
                        continue
                    endpoint_hash = endpoint_record.get("fnv_hash")
                    if endpoint_hash in endpoint_hash_set:
                        filtered_items += 1
                        continue
                    endpoint_hash_set.add(endpoint_hash)
                    self.endpoint_results.append(endpoint_record)

            records = data.get("records")
            if not isinstance(records, list):
                records = data.get("result")
            if not isinstance(records, list):
                records = data.get("results")
            if not isinstance(records, list):
                continue

            for item in records:
                if not isinstance(item, dict):
                    continue

                record_type = str(item.get("id") or item.get("type") or item.get("name") or "").strip()
                raw_content = str(item.get("content") or item.get("value") or item.get("match") or "").strip()
                source = str(item.get("source") or item.get("from") or site or "").strip()
                content = self._normalize_record_content(record_type, raw_content, source=source, site=site)
                if not record_type or not content:
                    filtered_items += 1
                    continue

                tag_text = str(item.get("tag") or item.get("rule") or "").strip()
                hash_needs_refresh = content != raw_content
                if tag_text and str(record_type or "").strip().lower() != "path" and \
                        (not self._should_keep_plain_content(record_type, content)):
                    content = "{} ({})".format(content, tag_text)
                    hash_needs_refresh = True

                hash_value = item.get("hash", item.get("fnv_hash"))
                try:
                    if hash_needs_refresh:
                        raise ValueError("refresh normalized hash")
                    hash_value = int(hash_value)
                except Exception:
                    hash_text = "{}|{}|{}|{}".format(record_type, content, source, site)
                    hash_digest = hashlib.md5(hash_text.encode("utf-8", errors="ignore")).hexdigest()
                    hash_value = int(hash_digest[:16], 16)

                record_dict = {
                    "record_type": record_type,
                    "content": content,
                    "source": source,
                    "site": site,
                    "fnv_hash": hash_value,
                }
                record = InfoHunter.normalize_wih_record(WihRecord(**record_dict))
                if not record:
                    filtered_items += 1
                    continue
                if record.fnv_hash in record_hash_set:
                    filtered_items += 1
                    continue
                record_hash_set.add(record.fnv_hash)
                results.append(record)

        logger.info(
            "wih parsed result file:{} payload_items:{} invalid_items:{} filtered_items:{} records:{} endpoints:{} bin:{} version_text:{}".format(
                self.wih_result_path,
                total_items,
                invalid_items,
                filtered_items,
                len(results),
                len(self.endpoint_results),
                self.wih_bin_path,
                self._load_wih_version_text() or "unknown",
            )
        )
        return results

    def run(self):
        if not self.check_have_wih():
            logger.warning("not found webInfoHunter binary")
            return []

        try:
            if not self.exec_wih():
                return []
            return self.dump_result()
        finally:
            self._delete_file()


def run_wih(sites: List[str], include_endpoints: bool = False, prefer_fast_mode: bool = False):
    logger.info("run webInfoHunter, sites: {} prefer_fast_mode:{}".format(len(sites), bool(prefer_fast_mode)))
    hunter = InfoHunter(sites, prefer_fast_mode=prefer_fast_mode)
    results = hunter.run()

    logger.info("webInfoHunter result: {}".format(len(results)))

    if include_endpoints:
        return results, list(hunter.endpoint_results or [])

    return results
