"""
URL/JS 提取增强服务（自研实现，借鉴 URLFinder 思路）

能力说明：
- 从站点页面与 JS 文本中提取更多 JS 链接与接口 URL
- 统一处理绝对/协议相对/相对路径并归一化
- 仅保留当前任务目标站点 host 来源，避免第三方噪音
- 结果输出为 WihRecord，复用现有 WIH 入库链路
"""
import re
import time
from collections import deque
from typing import Deque, List, Set, Tuple
from urllib.parse import unquote, urljoin, urlparse

from app import utils
from app.config import Config
from app.modules import WihRecord
from .url_candidate_filter import (
    has_route_template_markers,
    is_noise_single_segment_path,
    strip_route_method_suffix,
)
from .discovery_context import register_intel_candidate

logger = utils.get_logger()
DNS_POLICY_CACHE = {}

try:
    from .rust_accel import (
        extract_urlfinder_candidates as rust_extract_urlfinder_candidates,
    )
except Exception as exc:
    logger.warning(
        "rust acceleration adapter unavailable stage:extract reason_type:{}".format(type(exc).__name__)
    )

    class _UnavailableRustBatchResult(list):
        def __init__(self, batch_size=0):
            super().__init__()
            self.used_native = False
            self.metrics = {
                "stage": "extract",
                "backend": "python",
                "used_native": False,
                "fallback_count": 1,
                "fallback_reason": "adapter_import_error",
                "batch_size": int(batch_size or 0),
            }

    def rust_extract_urlfinder_candidates(*args, **kwargs):
        if not bool(getattr(Config, "RUST_ACCEL_FALLBACK_ENABLE", True)):
            raise RuntimeError("Rust acceleration adapter unavailable at extract")
        pages = kwargs.get("pages") if "pages" in kwargs else (args[0] if args else [])
        return _UnavailableRustBatchResult(len(list(pages or [])))


class UrlfinderExtractResult(list):
    """保持旧 list 返回类型，同时携带批量后端和降级统计。"""

    def __init__(self, values=None, metrics=None):
        super().__init__(values or [])
        self.metrics = dict(metrics or {})


class UrlfinderExtractService:
    """
    站点 URL/JS 提取增强器
    """
    RUST_BATCH_SIZE = 16

    JS_PATTERNS = [
        # 绝对 JS URL
        re.compile(r"https?://[^\s\"'<>`]{3,2048}\.js(?:\?[^\s\"'<>`]*)?", re.I),
        # 常见 src/href JS 引用
        re.compile(r"(?:src|href)\s*=\s*[\"']\s*([^\"']+?\.js(?:\?[^\"']*)?)\s*[\"']", re.I),
        # 引号中的相对/协议相对 JS 引用
        re.compile(r"[\"'`]\s*((?:\/\/|\/|\./|\.\./)?[^\s\"'<>`]{2,2048}\.js(?:\?[^\s\"'<>`]*)?)\s*[\"'`]", re.I),
    ]

    URL_PATTERNS = [
        # 绝对 URL
        re.compile(r"https?://[^\s\"'<>`]{4,2048}", re.I),
        # 引号中的根路径/相对路径 URL
        re.compile(r"[\"'`]\s*((?:\/|\./|\.\./)[^\s\"'<>`]{2,2048})\s*[\"'`]", re.I),
        # 常见 api/auth/rest 前缀路径
        re.compile(r"[\"'`]\s*((?:api|auth|oauth|rest|v[0-9]+)[^\s\"'<>`]{1,2048})\s*[\"'`]", re.I),
    ]

    JS_BLACK_KEYWORDS = (
        "www.w3.org",
        "example.com",
        "javascript:",
        "data:",
    )
    URL_BLACK_KEYWORDS = (
        "www.w3.org",
        "example.com",
        "javascript:",
        "data:",
        "location.href",
        "application/x-www-form-urlencoded",
        "*#__pure__*",
    )
    STATIC_SUFFIXES = (
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

    def __init__(
        self,
        sites: List[str],
        wih_records: List[WihRecord],
        waf_guard=None,
        discovery_context=None,
    ):
        self.sites = list(sites or [])
        self.wih_records = list(wih_records or [])
        self.waf_guard = waf_guard
        self.discovery_context = discovery_context

        self.max_seed_pages = 80
        self.max_js_files = 120
        self.max_js_depth = 2
        self.max_url_records = 1500
        self.max_page_bytes = 512 * 1024
        self.fetch_timeout = (5, 12)

        # 兼容将来在 config 中开放控制参数
        self.max_seed_pages = int(getattr(Config, "URLFINDER_SEED_PAGES_MAX", self.max_seed_pages) or self.max_seed_pages)
        self.max_js_files = int(getattr(Config, "URLFINDER_JS_MAX_FILES", self.max_js_files) or self.max_js_files)
        self.max_js_depth = int(getattr(Config, "URLFINDER_JS_MAX_DEPTH", self.max_js_depth) or self.max_js_depth)
        self.max_url_records = int(getattr(Config, "URLFINDER_URL_MAX_RECORDS", self.max_url_records) or self.max_url_records)
        self.max_page_bytes = int(getattr(Config, "URLFINDER_MAX_PAGE_BYTES", self.max_page_bytes) or self.max_page_bytes)

        if self.max_seed_pages < 1:
            self.max_seed_pages = 1
        if self.max_js_files < 1:
            self.max_js_files = 1
        if self.max_js_depth < 1:
            self.max_js_depth = 1
        if self.max_url_records < 1:
            self.max_url_records = 1
        if self.max_page_bytes < 1024:
            self.max_page_bytes = 1024

        self.allowed_hosts = self._collect_allowed_hosts()
        self.records: List[WihRecord] = []
        self.record_hash_set: Set[int] = set()
        self.js_seen: Set[str] = set()
        self.page_seen: Set[str] = set()
        self.rust_metrics = {
            "batch_count": 0,
            "native_batch_count": 0,
            "fallback_count": 0,
            "fallback_reasons": {},
        }
        self.network_wait_sec = 0.0
        self.network_request_count = 0

    @staticmethod
    def _extract_host(value: str) -> str:
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

    def _collect_allowed_hosts(self) -> Set[str]:
        hosts: Set[str] = set()
        for site in self.sites:
            host = self._extract_host(site)
            if host:
                hosts.add(host)
        return hosts

    @staticmethod
    def _is_http_url(value: str) -> bool:
        text = str(value or "").strip().lower()
        return text.startswith("http://") or text.startswith("https://")

    @staticmethod
    def _clean_candidate(value: str) -> str:
        text = str(value or "").strip()
        if not text:
            return ""

        text = text.strip("\"'`;,()[]{}")
        text = text.replace("\\/", "/")
        text = text.replace("%3A", ":").replace("%2F", "/")
        try:
            text = unquote(text)
        except Exception:
            pass
        return text.strip()

    @staticmethod
    def _safe_site(url: str) -> str:
        try:
            parsed = urlparse(str(url or ""))
        except Exception:
            return ""
        if parsed.scheme and parsed.netloc:
            return "{}://{}".format(parsed.scheme, parsed.netloc)
        return ""

    @staticmethod
    def _is_js_url(url: str) -> bool:
        text = str(url or "").strip().lower()
        if not text:
            return False
        if ".js" in text:
            return True
        try:
            path = urlparse(text).path.lower()
        except Exception:
            return False
        return path.endswith(".js")

    def _normalize_url(self, base_url: str, value: str) -> str:
        candidate = self._clean_candidate(value)
        if not candidate:
            return ""

        try:
            if candidate.startswith("http://") or candidate.startswith("https://"):
                normalized = candidate
            elif candidate.startswith("//"):
                try:
                    scheme = urlparse(base_url).scheme or "https"
                except Exception:
                    scheme = "https"
                normalized = "{}:{}".format(scheme, candidate)
            else:
                normalized = urljoin(base_url, candidate)

            parsed = urlparse(normalized)
        except Exception:
            logger.debug("urlfinder skip malformed candidate base:%s raw:%s", base_url, candidate[:160])
            return ""

        if parsed.scheme not in ("http", "https"):
            return ""
        if not parsed.netloc:
            return ""

        host = self._extract_host(normalized)
        if not host or host not in self.allowed_hosts:
            return ""

        path_text = strip_route_method_suffix(parsed.path or "")
        if has_route_template_markers(path_text):
            return ""
        if is_noise_single_segment_path(path_text):
            return ""

        if parsed.fragment:
            parsed = parsed._replace(fragment="")
        if path_text != parsed.path:
            parsed = parsed._replace(path=path_text)
        return parsed.geturl()

    def _url_blocked(self, url: str, for_js: bool) -> bool:
        lower_url = str(url or "").lower()
        if not lower_url:
            return True

        if for_js:
            for keyword in self.JS_BLACK_KEYWORDS:
                if keyword in lower_url:
                    return True
            return False

        for keyword in self.URL_BLACK_KEYWORDS:
            if keyword in lower_url:
                return True

        try:
            path = urlparse(lower_url).path or ""
        except Exception:
            return True
        for suffix in self.STATIC_SUFFIXES:
            if path.endswith(suffix):
                return True
        return False

    @staticmethod
    def _extract_by_patterns(text: str, patterns: List[re.Pattern]) -> List[str]:
        results: List[str] = []
        if not text:
            return results

        for pattern in patterns:
            for match in pattern.finditer(text):
                if not match:
                    continue
                token = match.group(1) if match.lastindex else match.group(0)
                token = str(token or "").strip()
                if token:
                    results.append(token)
        return results

    @staticmethod
    def _stable_hash(text: str) -> int:
        # WihRecord.__hash__ 需要整数；将 md5 十六进制稳定映射为 64bit 整数。
        digest = utils.gen_md5(str(text or ""))
        return int(digest[:16], 16)

    def _append_record(self, record_type: str, content: str, source: str, site: str):
        # 候选图先于记录去重登记：不同来源命中同一候选时要合并 sources。
        register_intel_candidate(self.discovery_context, record_type, content, source, site)

        hash_text = "{}|{}|{}|{}".format(record_type, content, source, site)
        fnv_hash = self._stable_hash(hash_text)
        if fnv_hash in self.record_hash_set:
            return

        self.record_hash_set.add(fnv_hash)
        self.records.append(
            WihRecord(
                record_type=record_type,
                content=content,
                source=source,
                site=site,
                fnv_hash=fnv_hash,
            )
        )

    def _fetch_text(self, url: str) -> str:
        inflight_owner = False
        if self.discovery_context is not None:
            cached_response = self.discovery_context.get_response(
                url,
                request_profile="html_get",
                consumer="urlfinder_extract",
            )
            if cached_response is None:
                # 并发 miss 合并：等待先行者结果，拿不到才自己抓。
                cached_response, follower = self.discovery_context.await_singleflight_leader(
                    url, request_profile="html_get", consumer="urlfinder_extract")
                inflight_owner = not follower
            if cached_response is not None:
                status_code = int(getattr(cached_response, "status_code", 0) or 0)
                if status_code >= 400:
                    return ""
                body = bytes(getattr(cached_response, "body", b"") or b"")
                return body[: self.max_page_bytes].decode("utf-8", errors="ignore")

        network_started_at = time.monotonic()
        lease = None
        try:
            allow_scan, policy_detail = utils.check_dns_policy_for_url(url, cache_map=DNS_POLICY_CACHE)
            if not allow_scan:
                logger.info(
                    "skip urlfinder extract by dns policy url:{} reason:{} resolver_ips:{} system_ips:{}".format(
                        url,
                        policy_detail.get("reason", ""),
                        policy_detail.get("resolver_ips", []),
                        policy_detail.get("system_ips", []),
                    )
                )
                return ""

            if self.discovery_context is not None:
                lease, lease_reason = self.discovery_context.acquire_request(url, "wih")
                if lease is None and lease_reason == "blocked":
                    logger.info("urlfinder skipped by waf traffic policy url:%s", url)
                    return ""
                if lease is None:
                    logger.warning("urlfinder over capacity, continue request url:%s", url)

            self.network_request_count += 1

            try:
                conn = utils.http_req(
                    url,
                    "get",
                    timeout=self.fetch_timeout,
                    waf_guard=self.waf_guard,
                    waf_module="urlfinder_extract",
                )
            except Exception as e:
                logger.debug("urlfinder fetch failed {} {}".format(url, e))
                return ""

            status_code = int(getattr(conn, "status_code", 0) or 0)
            if status_code >= 400:
                if self.discovery_context is not None:
                    self.discovery_context.put_response(
                        url=url,
                        method="GET",
                        request_profile="html_get",
                        status_code=status_code,
                        headers=getattr(conn, "headers", {}) or {},
                        content_type=(getattr(conn, "headers", {}) or {}).get("Content-Type", ""),
                        body=getattr(conn, "content", b"") or b"",
                        source="urlfinder_extract",
                        consumer="urlfinder_extract",
                    )
                return ""

            body = bytes(getattr(conn, "content", b"") or b"")
            if not body:
                return ""
            body = body[: self.max_page_bytes]
            if self.discovery_context is not None:
                self.discovery_context.put_response(
                    url=url,
                    method="GET",
                    request_profile="html_get",
                    status_code=status_code,
                    headers=getattr(conn, "headers", {}) or {},
                    content_type=(getattr(conn, "headers", {}) or {}).get("Content-Type", ""),
                    body=body,
                    source="urlfinder_extract",
                    consumer="urlfinder_extract",
                )
            return body.decode("utf-8", errors="ignore")
        finally:
            if lease is not None:
                lease.release()
            if inflight_owner and self.discovery_context is not None:
                # 幂等释放：put_response 成功路径已释放时此处为 no-op。
                self.discovery_context.release_fetch_slot(url, request_profile="html_get")
            self.network_wait_sec += max(0.0, time.monotonic() - network_started_at)

    def _collect_seed_pages(self) -> List[str]:
        pages: Set[str] = set()

        for site in self.sites:
            site_text = str(site or "").strip()
            if self._is_http_url(site_text):
                normalized = self._normalize_url(site_text, site_text)
                if normalized:
                    pages.add(normalized)

        for record in self.wih_records:
            for raw in (
                str(getattr(record, "site", "") or "").strip(),
                str(getattr(record, "source", "") or "").strip(),
            ):
                if not self._is_http_url(raw):
                    continue
                normalized = self._normalize_url(raw, raw)
                if not normalized:
                    continue
                if self._is_js_url(normalized):
                    continue
                pages.add(normalized)

        page_list = sorted(pages)
        if len(page_list) > self.max_seed_pages:
            page_list = page_list[: self.max_seed_pages]
        return page_list

    def _extract_with_rust(
        self,
        pages: List[dict],
        js_queue: Deque[Tuple[str, int, str]],
    ) -> bool:
        batch_result = rust_extract_urlfinder_candidates(
            pages=pages,
            allowed_hosts=self.allowed_hosts,
            allow_js=True,
            max_url_records=self.max_url_records,
            max_js_files=self.max_js_files,
            max_js_depth=self.max_js_depth,
        )
        batch_metrics = getattr(batch_result, "metrics", {})
        self.rust_metrics["batch_count"] += 1
        fallback_count = int(batch_metrics.get("fallback_count", 0) or 0)
        self.rust_metrics["fallback_count"] += fallback_count
        if fallback_count:
            reason = str(batch_metrics.get("fallback_reason", "unknown") or "unknown")
            reasons = self.rust_metrics.setdefault("fallback_reasons", {})
            reasons[reason] = int(reasons.get(reason, 0) or 0) + fallback_count

        if not bool(getattr(batch_result, "used_native", False)):
            return False
        self.rust_metrics["native_batch_count"] += 1

        for item in batch_result:
            record_type = str(item.get("record_type", "") or "").strip()
            content = str(item.get("content", "") or "").strip()
            source = str(item.get("source", "") or "").strip()
            site = str(item.get("site", "") or "").strip()
            if not content:
                continue

            if record_type == "urlfinder_js":
                if content in self.js_seen or len(self.js_seen) >= self.max_js_files:
                    continue
                self.js_seen.add(content)
                next_depth = max(1, int(item.get("next_depth", 1) or 1))
                js_queue.append((content, next_depth, source))
                self._append_record(record_type, content, source, site)
                continue

            if record_type == "urlfinder_url":
                if len(self.records) >= self.max_url_records:
                    break
                self._append_record(record_type, content, source, site)
        return True

    def _extract_page_data(self, page_url: str, text: str, js_queue: Deque[Tuple[str, int, str]]):
        if not text:
            return

        if self._extract_with_rust(
            [{"base_url": page_url, "text": text, "source_url": page_url, "depth": 0, "is_js": False}],
            js_queue,
        ):
            return

        self._extract_page_data_python(page_url, text, js_queue)

    def _extract_page_data_python(self, page_url: str, text: str, js_queue: Deque[Tuple[str, int, str]]):
        if not text:
            return

        # 页面中提取 JS
        for raw in self._extract_by_patterns(text, self.JS_PATTERNS):
            normalized = self._normalize_url(page_url, raw)
            if not normalized:
                continue
            if not self._is_js_url(normalized):
                continue
            if self._url_blocked(normalized, for_js=True):
                continue
            if normalized in self.js_seen:
                continue
            if len(self.js_seen) >= self.max_js_files:
                break
            self.js_seen.add(normalized)
            js_queue.append((normalized, 1, page_url))
            self._append_record("urlfinder_js", normalized, page_url, self._safe_site(normalized))

        # 页面中提取 URL
        for raw in self._extract_by_patterns(text, self.URL_PATTERNS):
            if len(self.records) >= self.max_url_records:
                break
            normalized = self._normalize_url(page_url, raw)
            if not normalized:
                continue
            if self._is_js_url(normalized):
                continue
            if self._url_blocked(normalized, for_js=False):
                continue
            self._append_record("urlfinder_url", normalized, page_url, self._safe_site(normalized))

    def _extract_js_data(self, js_url: str, depth: int, source_url: str, text: str, js_queue: Deque[Tuple[str, int, str]]):
        if not text:
            return

        if self._extract_with_rust(
            [{"base_url": js_url, "text": text, "source_url": source_url, "depth": depth, "is_js": True}],
            js_queue,
        ):
            return

        self._extract_js_data_python(js_url, depth, source_url, text, js_queue)

    def _extract_js_data_python(
        self,
        js_url: str,
        depth: int,
        source_url: str,
        text: str,
        js_queue: Deque[Tuple[str, int, str]],
    ):
        if not text:
            return

        # JS 中提取 URL
        for raw in self._extract_by_patterns(text, self.URL_PATTERNS):
            if len(self.records) >= self.max_url_records:
                break
            normalized = self._normalize_url(js_url, raw)
            if not normalized:
                continue
            if self._is_js_url(normalized):
                continue
            if self._url_blocked(normalized, for_js=False):
                continue
            self._append_record("urlfinder_url", normalized, js_url, self._safe_site(normalized))

        # JS 中提取更多 JS（递归）
        if depth >= self.max_js_depth:
            return

        for raw in self._extract_by_patterns(text, self.JS_PATTERNS):
            normalized = self._normalize_url(js_url, raw)
            if not normalized:
                continue
            if not self._is_js_url(normalized):
                continue
            if self._url_blocked(normalized, for_js=True):
                continue
            if normalized in self.js_seen:
                continue
            if len(self.js_seen) >= self.max_js_files:
                break
            self.js_seen.add(normalized)
            js_queue.append((normalized, depth + 1, js_url))
            self._append_record("urlfinder_js", normalized, source_url or js_url, self._safe_site(normalized))

    def run(self) -> List[WihRecord]:
        if not self.allowed_hosts:
            logger.info("urlfinder extract skip, no allowed hosts from current target sites")
            return []

        seed_pages = self._collect_seed_pages()
        if not seed_pages:
            logger.info("urlfinder extract skip, no seed pages")
            return []

        js_queue: Deque[Tuple[str, int, str]] = deque()

        # 扫描种子页面，提取首批 JS/URL
        page_batch = []
        for page_url in seed_pages:
            if page_url in self.page_seen:
                continue
            self.page_seen.add(page_url)
            text = self._fetch_text(page_url)
            if not text:
                continue
            page_batch.append(
                {
                    "base_url": page_url,
                    "text": text,
                    "source_url": page_url,
                    "depth": 0,
                    "is_js": False,
                }
            )
            if len(page_batch) >= self.RUST_BATCH_SIZE:
                if not self._extract_with_rust(page_batch, js_queue):
                    for page in page_batch:
                        self._extract_page_data_python(page["base_url"], page["text"], js_queue)
                page_batch = []

        if page_batch:
            if not self._extract_with_rust(page_batch, js_queue):
                for page in page_batch:
                    self._extract_page_data_python(page["base_url"], page["text"], js_queue)

        # 递归扫描 JS（深度受控）
        while js_queue:
            js_batch = []
            while js_queue and len(js_batch) < self.RUST_BATCH_SIZE:
                js_url, depth, source_url = js_queue.popleft()
                text = self._fetch_text(js_url)
                if not text:
                    continue
                js_batch.append(
                    {
                        "base_url": js_url,
                        "text": text,
                        "source_url": source_url,
                        "depth": depth,
                        "is_js": True,
                    }
                )
            if not js_batch:
                continue
            if not self._extract_with_rust(js_batch, js_queue):
                for page in js_batch:
                    self._extract_js_data_python(
                        page["base_url"],
                        page["depth"],
                        page["source_url"],
                        page["text"],
                        js_queue,
                    )

        logger.info(
            "urlfinder extract done, hosts:{} pages:{} js:{} records:{}".format(
                len(self.allowed_hosts),
                len(seed_pages),
                len(self.js_seen),
                len(self.records),
            )
        )
        return self.records


def run_urlfinder_extract(
    sites: List[str],
    wih_records: List[WihRecord],
    waf_guard=None,
    discovery_context=None,
) -> List[WihRecord]:
    extractor = UrlfinderExtractService(
        sites=sites,
        wih_records=wih_records,
        waf_guard=waf_guard,
        discovery_context=discovery_context,
    )
    started_at = time.monotonic()
    records = extractor.run()
    rust_metrics = dict(extractor.rust_metrics)
    extract_calls = int(rust_metrics.get("batch_count", 0) or 0)
    fallback_count = int(rust_metrics.get("fallback_count", 0) or 0)
    native_batch_count = int(rust_metrics.get("native_batch_count", 0) or 0)
    if native_batch_count > 0 and fallback_count > 0:
        backend = "mixed"
    elif native_batch_count > 0:
        backend = "rust"
    else:
        backend = "python"
    metrics = {
        "backend": backend,
        "fallback_count": fallback_count,
        "fallback_reason": str(
            next(iter((rust_metrics.get("fallback_reasons") or {}).keys()), "")
        ) if fallback_count else "",
        "fallback_reasons": dict(rust_metrics.get("fallback_reasons") or {}),
        "batch_count": extract_calls,
        "native_batch_count": native_batch_count,
        "page_count": len(extractor._collect_seed_pages()),
        "js_count": len(extractor.js_seen),
        "output_count": len(records or []),
        "network_wait_sec": round(max(0.0, extractor.network_wait_sec), 6),
        "network_request_count": int(extractor.network_request_count),
        "elapsed": max(0.0, time.monotonic() - started_at),
    }
    return UrlfinderExtractResult(records, metrics=metrics)
