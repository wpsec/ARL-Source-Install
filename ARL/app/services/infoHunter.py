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
from urllib.parse import urlparse, urlunparse
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
    def __init__(self, sites: list):
        self.sites = set(sites)

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
        self.wih_runtime_enable = bool(getattr(Config, "WIH_RUNTIME_ENABLE", True))
        self.wih_runtime_driver = str(getattr(Config, "WIH_RUNTIME_DRIVER", "playwright") or "playwright").strip().lower()
        self.wih_runtime_command = str(getattr(Config, "WIH_RUNTIME_COMMAND", "") or "").strip()
        self.wih_runtime_timeout_sec = int(getattr(Config, "WIH_RUNTIME_TIMEOUT_SEC", 20) or 20)
        self.wih_runtime_max_pages = int(getattr(Config, "WIH_RUNTIME_MAX_PAGES", 8) or 8)
        self.wih_runtime_max_actions = int(getattr(Config, "WIH_RUNTIME_MAX_ACTIONS", 20) or 20)
        self.wih_runtime_max_requests = int(getattr(Config, "WIH_RUNTIME_MAX_REQUESTS", 120) or 120)
        if self.wih_timeout_sec < 60:
            self.wih_timeout_sec = 60
        if self.wih_concurrency < 1:
            self.wih_concurrency = 1
        if self.wih_concurrency_per_site < 1:
            self.wih_concurrency_per_site = 1
        if self.wih_runtime_timeout_sec < 1:
            self.wih_runtime_timeout_sec = 20
        if self.wih_runtime_max_pages < 1:
            self.wih_runtime_max_pages = 1
        if self.wih_runtime_max_actions < 0:
            self.wih_runtime_max_actions = 0
        if self.wih_runtime_max_requests < 1:
            self.wih_runtime_max_requests = 1
        if self.wih_runtime_driver not in {"playwright", "external", "noop"}:
            self.wih_runtime_driver = "playwright"
        self._help_text = None

    @staticmethod
    def _should_keep_plain_content(record_type: str, content: str) -> bool:
        record_type = str(record_type or "").strip().lower()
        content = str(content or "").strip().lower()
        if record_type in {"domain_url", "ip_url", "path_url", "urlfinder_url", "urlfinder_js"}:
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
        # 优先使用本地/挂载目录下的“成品二进制”，其次回退到镜像内编译产物。
        candidates = [
            "/code/tools/wih/wih",
            "/code/tools/wih/wihscan",
            "/code/tools/wih/bin/wih",
            "/code/tools/wih/bin/wihscan",
            "wihscan",
            "wih",
        ]
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
        if site_count <= 12:
            return site_count
        return min(48, max(8, int(self.wih_concurrency) * 6))

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

    def _run_wih_command(self, command: list, batch_sites: list, command_name: str):
        try:
            completed = utils.exec_system(
                command,
                timeout=self.wih_timeout_sec,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except subprocess.TimeoutExpired as e:
            logger.warning(
                "wih {} timeout:{}s batch_sites:{} cmd:{}".format(
                    command_name,
                    self.wih_timeout_sec,
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

    def _exec_wih_batch(self, batch_sites: list, aggregate_result_texts: list, depth: int = 0) -> bool:
        current_sites = [str(site or "").strip() for site in list(batch_sites or []) if str(site or "").strip()]
        if not current_sites:
            return False

        self._clear_result_file()
        self._get_target_file(current_sites)

        command = self._build_command(minimal=False)
        logger.info(
            "run wih batch depth:{} sites:{} timeout:{}s concurrency:{} per_site:{} cmd:{}".format(
                depth,
                len(current_sites),
                self.wih_timeout_sec,
                self.wih_concurrency,
                self.wih_concurrency_per_site,
                " ".join(command),
            )
        )
        primary = self._run_wih_command(command, current_sites, "primary")
        if primary.get("ok"):
            raw_text = self._read_current_result_text()
            if raw_text:
                aggregate_result_texts.append(raw_text)
            return True

        if primary.get("timed_out") and len(current_sites) > 1:
            mid = max(1, len(current_sites) // 2)
            left_ok = self._exec_wih_batch(current_sites[:mid], aggregate_result_texts, depth=depth + 1)
            right_ok = self._exec_wih_batch(current_sites[mid:], aggregate_result_texts, depth=depth + 1)
            return bool(left_ok or right_ok)

        fallback_command = self._build_command(minimal=True)
        logger.info(
            "retry wih batch minimal depth:{} sites:{} cmd:{}".format(
                depth,
                len(current_sites),
                " ".join(fallback_command),
            )
        )
        fallback = self._run_wih_command(fallback_command, current_sites, "minimal")
        if fallback.get("ok"):
            raw_text = self._read_current_result_text()
            if raw_text:
                aggregate_result_texts.append(raw_text)
            return True

        if fallback.get("timed_out") and len(current_sites) > 1:
            mid = max(1, len(current_sites) // 2)
            left_ok = self._exec_wih_batch(current_sites[:mid], aggregate_result_texts, depth=depth + 1)
            right_ok = self._exec_wih_batch(current_sites[mid:], aggregate_result_texts, depth=depth + 1)
            return bool(left_ok or right_ok)

        logger.warning(
            "skip wih batch after failure depth:{} sites:{} sample:{}".format(
                depth,
                len(current_sites),
                ",".join(current_sites[:3]),
            )
        )
        return False

    def _load_help_text(self) -> str:
        if self._help_text is not None:
            return self._help_text

        try:
            output = utils.check_output([self.wih_bin_path, "-h"], timeout=2 * 60, stderr=subprocess.STDOUT)
            self._help_text = str(output or b"", "utf-8", errors="ignore")
        except Exception:
            self._help_text = ""

        return self._help_text

    def _supports_flag(self, flag_text: str) -> bool:
        return flag_text in self._load_help_text()

    @staticmethod
    def _resolve_rule_path() -> str:
        configured_path = str(getattr(Config, "WIH_RULE_PATH", "") or "").strip()
        if configured_path and os.path.isfile(configured_path):
            return configured_path

        if configured_path:
            logger.warning("wih rule path not found: {}, fallback to built-in/default".format(configured_path))

        return ""

    def _build_command(self, minimal=False) -> list:
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
            command.append("--runtime-enable={}".format("true" if self.wih_runtime_enable else "false"))

        if self._supports_flag("--runtime-driver"):
            runtime_driver = self.wih_runtime_driver if self.wih_runtime_enable else "noop"
            command.extend(["--runtime-driver", runtime_driver])

        if self.wih_runtime_enable:
            if self._supports_flag("--runtime-command") and self.wih_runtime_command:
                command.extend(["--runtime-command", self.wih_runtime_command])
            if self._supports_flag("--runtime-timeout"):
                command.extend(["--runtime-timeout", str(self.wih_runtime_timeout_sec)])
            if self._supports_flag("--runtime-max-pages"):
                command.extend(["--runtime-max-pages", str(self.wih_runtime_max_pages)])
            if self._supports_flag("--runtime-max-actions"):
                command.extend(["--runtime-max-actions", str(self.wih_runtime_max_actions)])
            if self._supports_flag("--runtime-max-requests"):
                command.extend(["--runtime-max-requests", str(self.wih_runtime_max_requests)])

        if minimal:
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
        command = [self.wih_bin_path, "--version"]
        try:
            completed = utils.exec_system(
                command,
                timeout=2 * 60,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if completed.returncode != 0:
                return False

            output_text = completed.stdout.decode("utf-8", errors="ignore").strip() if completed.stdout else ""
            normalized = output_text.lower()
            if output_text and (
                "version" in normalized or normalized.startswith("v") or normalized[0].isdigit()
            ):
                return True
            # 某些旧版二进制 --version 无输出，回退校验 -h。
            help_text = self._load_help_text()
            if help_text and ("webinfohunter" in help_text.lower() or "wih" in help_text.lower()):
                return True
        except Exception as e:
            logger.debug("{}".format(str(e)))

        return False

    def dump_result(self) -> list:
        results = []
        total_items = 0
        invalid_items = 0
        filtered_items = 0

        # 检查结果文件是否存在
        if not os.path.exists(self.wih_result_path):
            logger.warning("wih result file not found: {}".format(self.wih_result_path))
            return results

        with open(self.wih_result_path, "r", encoding="utf-8", errors="ignore") as f:
            raw_text = str(f.read() or "").strip()

        payload_items = []
        record_hash_set = set()
        if not raw_text:
            payload_items = []
        elif raw_text.startswith("["):
            try:
                payload = json.loads(raw_text)
                if isinstance(payload, list):
                    payload_items = payload
                elif isinstance(payload, dict):
                    payload_items = [payload]
            except Exception as e:
                logger.debug("parse wih json array failed err:{}".format(e))
                payload_items = []
        else:
            for line in raw_text.splitlines():
                line = str(line or "").strip()
                if not line:
                    continue
                try:
                    payload_items.append(json.loads(line))
                except Exception as e:
                    invalid_items += 1
                    logger.debug("skip invalid wih json line err:{} line:{}".format(e, line[:200]))

        for data in payload_items:
            total_items += 1
            if not isinstance(data, dict):
                invalid_items += 1
                continue

            site = str(data.get("target") or data.get("url") or data.get("site") or "").strip()
            if not site:
                invalid_items += 1
                continue

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
            "wih parsed result file:{} payload_items:{} invalid_items:{} filtered_items:{} records:{} bin:{}".format(
                self.wih_result_path, total_items, invalid_items, filtered_items, len(results), self.wih_bin_path
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


def run_wih(sites: List[str]) -> List[WihRecord]:
    logger.info("run webInfoHunter, sites: {}".format(len(sites)))
    hunter = InfoHunter(sites)
    results = hunter.run()

    logger.info("webInfoHunter result: {}".format(len(results)))

    return results
