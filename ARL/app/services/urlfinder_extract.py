"""
URL/JS 提取增强服务（自研实现，借鉴 URLFinder 思路）

能力说明：
- 从站点页面与 JS 文本中提取更多 JS 链接与接口 URL
- 统一处理绝对/协议相对/相对路径并归一化
- 仅保留当前任务目标站点 host 来源，避免第三方噪音
- 结果输出为 WihRecord，复用现有 WIH 入库链路
"""
import re
from collections import deque
from typing import Deque, List, Set, Tuple
from urllib.parse import unquote, urljoin, urlparse

from app import utils
from app.config import Config
from app.modules import WihRecord

logger = utils.get_logger()
DNS_POLICY_CACHE = {}


class UrlfinderExtractService:
    """
    站点 URL/JS 提取增强器
    """

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

    def __init__(self, sites: List[str], wih_records: List[WihRecord], waf_guard=None):
        self.sites = list(sites or [])
        self.wih_records = list(wih_records or [])
        self.waf_guard = waf_guard

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

    @staticmethod
    def _extract_host(value: str) -> str:
        text = str(value or "").strip()
        if not text:
            return ""

        parsed = urlparse(text)
        host = str(parsed.hostname or "").strip().lower().rstrip(".")
        if host:
            return host

        parsed = urlparse("//{}".format(text))
        return str(parsed.hostname or "").strip().lower().rstrip(".")

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
        parsed = urlparse(str(url or ""))
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
        path = urlparse(text).path.lower()
        return path.endswith(".js")

    def _normalize_url(self, base_url: str, value: str) -> str:
        candidate = self._clean_candidate(value)
        if not candidate:
            return ""

        if candidate.startswith("http://") or candidate.startswith("https://"):
            normalized = candidate
        elif candidate.startswith("//"):
            scheme = urlparse(base_url).scheme or "https"
            normalized = "{}:{}".format(scheme, candidate)
        else:
            normalized = urljoin(base_url, candidate)

        parsed = urlparse(normalized)
        if parsed.scheme not in ("http", "https"):
            return ""
        if not parsed.netloc:
            return ""

        host = self._extract_host(normalized)
        if not host or host not in self.allowed_hosts:
            return ""

        if parsed.fragment:
            parsed = parsed._replace(fragment="")
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

        path = urlparse(lower_url).path or ""
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
            return ""

        body = bytes(getattr(conn, "content", b"") or b"")
        if not body:
            return ""
        body = body[: self.max_page_bytes]
        return body.decode("utf-8", errors="ignore")

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

    def _extract_page_data(self, page_url: str, text: str, js_queue: Deque[Tuple[str, int, str]]):
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
        for page_url in seed_pages:
            if page_url in self.page_seen:
                continue
            self.page_seen.add(page_url)
            text = self._fetch_text(page_url)
            self._extract_page_data(page_url, text, js_queue)

        # 递归扫描 JS（深度受控）
        while js_queue:
            js_url, depth, source_url = js_queue.popleft()
            text = self._fetch_text(js_url)
            self._extract_js_data(js_url, depth, source_url, text, js_queue)

        logger.info(
            "urlfinder extract done, hosts:{} pages:{} js:{} records:{}".format(
                len(self.allowed_hosts),
                len(seed_pages),
                len(self.js_seen),
                len(self.records),
            )
        )
        return self.records


def run_urlfinder_extract(sites: List[str], wih_records: List[WihRecord], waf_guard=None) -> List[WihRecord]:
    extractor = UrlfinderExtractService(sites=sites, wih_records=wih_records, waf_guard=waf_guard)
    return extractor.run()
