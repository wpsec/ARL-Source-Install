"""
JS 情报扫描服务。

能力说明：
- 基于站点内 JS 资源提取 API 端点与 API 文档入口
- 作为 WIH 的补充层，重点处理相对路径、模块风格路径与文档种子发现
- 故意不重复承担 WIH 已覆盖的 secrets / 子域名识别职责
"""
import re
from typing import List, Set

from app import utils
from app.config import Config
from app.modules import WihRecord
from .web_info_intel_utils import (
    collect_allowed_hosts,
    extract_host,
    fetch_text,
    is_http_url,
    is_js_url,
    normalize_in_scope_url,
    safe_site,
    stable_hash,
)

logger = utils.get_logger()


class JsIntelScanner:
    """
    JS 端点增强器。

    说明：
    - 当前项目中的 secrets / domain 主能力仍由 WIH 提供。
    - 该增强器只补充 WIH 相对偏弱的 JS 端点字符串和 API 文档入口发现。
    """

    _ENDPOINT_PATTERNS = [
        re.compile(r"https?://[^\s\"'<>`]{4,2048}", re.I),
        re.compile(r"[\"'`]\s*((?:\/\/|\/|\./|\.\./)[^\s\"'<>`]{2,2048})\s*[\"'`]"),
        re.compile(
            r"[\"'`]\s*((?:(?:api|auth|oauth|rest|graphql|rpc|v[0-9]+|service|services|module|modules)"
            r"[^\s\"'<>`]{2,2048}))\s*[\"'`]",
            re.I,
        ),
        re.compile(
            r"(?i)(?:fetch|axios(?:\.[a-z]+)?|baseurl|endpoint|request|url)\s*[:=,(]\s*[\"'`]"
            r"(https?://[^\s\"'<>`]{4,2048}|(?:\/\/|\/|\./|\.\./)[^\s\"'<>`]{2,2048}|"
            r"(?:(?:api|auth|oauth|rest|graphql|rpc|v[0-9]+)[^\s\"'<>`]{2,2048}))\s*[\"'`]"
        ),
    ]

    def __init__(self, sites: List[str], wih_records: List[WihRecord], waf_guard=None):
        self.sites = list(sites or [])
        self.wih_records = list(wih_records or [])
        self.waf_guard = waf_guard

        self.enable = bool(getattr(Config, "JS_INTEL_ENABLE", True))
        self.max_files = int(getattr(Config, "JS_INTEL_MAX_FILES", 80) or 80)
        self.max_file_bytes = int(getattr(Config, "JS_INTEL_MAX_FILE_BYTES", 512 * 1024) or (512 * 1024))
        self.timeout = (5, 12)

        if self.max_files < 1:
            self.max_files = 1
        if self.max_file_bytes < 1024:
            self.max_file_bytes = 1024

        self.allowed_hosts = collect_allowed_hosts(self.sites)
        self.records: List[WihRecord] = []
        self.record_hash_set: Set[int] = set()

    def _append_record(self, record_type: str, content: str, source: str, site: str):
        record_type = str(record_type or "").strip()
        content = str(content or "").strip()
        source = str(source or "").strip()
        site = str(site or "").strip()
        if not record_type or not content or not site:
            return

        fnv_hash = stable_hash(record_type, content, site)
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

    def _collect_js_urls(self) -> List[str]:
        js_urls = set()
        for record in self.wih_records:
            for raw in (
                str(getattr(record, "source", "") or "").strip(),
                str(getattr(record, "content", "") or "").strip(),
            ):
                if not is_http_url(raw) or not is_js_url(raw):
                    continue
                host = extract_host(raw)
                if host and host in self.allowed_hosts:
                    js_urls.add(raw)

        js_url_list = sorted(js_urls)
        if len(js_url_list) > self.max_files:
            js_url_list = js_url_list[: self.max_files]
        return js_url_list

    @staticmethod
    def _is_api_doc_candidate(url: str) -> bool:
        lowered = str(url or "").lower()
        if not lowered:
            return False
        return any(token in lowered for token in ("swagger", "openapi", "api-docs", "postman"))

    def _extract_endpoint_records(self, js_url: str, text: str):
        for pattern in self._ENDPOINT_PATTERNS:
            for match in pattern.finditer(text):
                token = match.group(1) if match.lastindex else match.group(0)
                normalized = normalize_in_scope_url(js_url, token, self.allowed_hosts, allow_js=False)
                if not normalized:
                    continue
                if self._is_api_doc_candidate(normalized):
                    self._append_record("api_doc_url", normalized, js_url, safe_site(normalized))
                self._append_record("urlfinder_url", normalized, js_url, safe_site(normalized))

    def run(self) -> List[WihRecord]:
        if not self.enable:
            logger.info("js intel scan skip, disabled")
            return []

        if not self.allowed_hosts:
            logger.info("js intel scan skip, no allowed hosts from current target sites")
            return []

        js_urls = self._collect_js_urls()
        if not js_urls:
            logger.info("js intel scan skip, no js urls found from current wih records")
            return []

        for js_url in js_urls:
            text, _ = fetch_text(
                js_url,
                waf_guard=self.waf_guard,
                timeout=self.timeout,
                max_bytes=self.max_file_bytes,
                waf_module="js_intel_scan",
            )
            if not text:
                continue

            self._extract_endpoint_records(js_url, text)

        logger.info(
            "js intel scan done, hosts:{} js:{} records:{}".format(
                len(self.allowed_hosts),
                len(js_urls),
                len(self.records),
            )
        )
        return self.records


def run_js_intel_scan(sites: List[str], wih_records: List[WihRecord], waf_guard=None) -> List[WihRecord]:
    scanner = JsIntelScanner(sites=sites, wih_records=wih_records, waf_guard=waf_guard)
    return scanner.run()
