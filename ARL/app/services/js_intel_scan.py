"""
JS 情报扫描服务。

能力说明：
- 基于站点内 JS 资源提取 API 端点与 API 文档入口
- 作为 WIH 的补充层，重点处理相对路径、模块风格路径与文档种子发现
- 故意不重复承担 WIH 已覆盖的 secrets / 子域名识别职责
"""
import re
import time
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
from .discovery_context import register_intel_candidate

logger = utils.get_logger()

try:
    # 直接绑定可接受：三面口径一致性由 test_rust_accel.TestApiDocKeywordAlignment
    # （源码钉）+ golden corpus --run-native（编译钉）双重门禁防漂移。
    from .rust_accel import extract_js_endpoint_candidates as rust_extract_js_endpoint_candidates
except Exception as exc:
    logger.warning(
        "rust acceleration adapter unavailable stage:js_endpoint reason_type:{}".format(
            type(exc).__name__
        )
    )

    class _UnavailableRustBatchResult(list):
        def __init__(self, batch_size=0):
            super().__init__()
            self.used_native = False
            self.metrics = {
                "stage": "js_endpoint",
                "backend": "python",
                "used_native": False,
                "fallback_count": 1,
                "fallback_reason": "adapter_import_error",
                "batch_size": int(batch_size or 0),
            }

    def rust_extract_js_endpoint_candidates(*args, **kwargs):
        if not bool(getattr(Config, "RUST_ACCEL_FALLBACK_ENABLE", True)):
            raise RuntimeError("Rust acceleration adapter unavailable at js_endpoint")
        pages = kwargs.get("pages") if "pages" in kwargs else (args[0] if args else [])
        return _UnavailableRustBatchResult(len(list(pages or [])))


class JsIntelResult(list):
    """保持旧 list 返回类型，同时携带 JS 批处理指标。"""

    def __init__(self, values=None, metrics=None):
        super().__init__(values or [])
        self.metrics = dict(metrics or {})


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

    def __init__(self, sites: List[str], wih_records: List[WihRecord], waf_guard=None, discovery_context=None):
        self.sites = list(sites or [])
        self.wih_records = list(wih_records or [])
        self.waf_guard = waf_guard
        self.discovery_context = discovery_context

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
        self.js_batch_size = 16
        self.rust_metrics = {
            "batch_count": 0,
            "native_batch_count": 0,
            "fallback_count": 0,
            "fallback_reasons": {},
        }
        self.network_wait_sec = 0.0
        self.network_request_count = 0

    def _append_record(self, record_type: str, content: str, source: str, site: str):
        record_type = str(record_type or "").strip()
        content = str(content or "").strip()
        source = str(source or "").strip()
        site = str(site or "").strip()
        if not record_type or not content or not site:
            return

        # 候选图先于记录去重登记：不同来源命中同一候选时要合并 sources。
        register_intel_candidate(self.discovery_context, record_type, content, source, site)

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
        # 与 Rust 原生面 lib.rs::is_api_doc_candidate 及统一面 `_TYPE_HINT_KEYWORDS`
        # 关键词集合同口径（第 10 批对齐，计划 6 §9.3）；两侧漂移会被
        # rust_accel_golden_corpus 门禁拦截。legacy 请求面 `_DOC_KEYWORDS` 不变。
        lowered = str(url or "").lower()
        if not lowered:
            return False
        return any(
            token in lowered
            for token in (
                "swagger", "openapi", "api-docs", "postman",
                "wsdl", "graphql", "graphiql",
            )
        )

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

    def _record_rust_batch(self, batch_result):
        self.rust_metrics["batch_count"] += 1
        metrics = getattr(batch_result, "metrics", {}) or {}
        fallback_count = int(metrics.get("fallback_count", 0) or 0)
        self.rust_metrics["fallback_count"] += fallback_count
        if fallback_count:
            reason = str(metrics.get("fallback_reason", "unknown") or "unknown")
            reasons = self.rust_metrics.setdefault("fallback_reasons", {})
            reasons[reason] = int(reasons.get(reason, 0) or 0) + fallback_count
        if bool(getattr(batch_result, "used_native", False)):
            self.rust_metrics["native_batch_count"] += 1

    def _process_js_batch(self, pages):
        if not pages:
            return
        max_records = max(
            1,
            sum(max(1, len(str(item.get("text", "") or ""))) for item in pages),
        )
        batch_result = rust_extract_js_endpoint_candidates(
            pages=pages,
            allowed_hosts=self.allowed_hosts,
            max_records=max_records,
        )
        if batch_result is not None:
            self._record_rust_batch(batch_result)
        if bool(getattr(batch_result, "used_native", False)):
            for item in list(batch_result or []):
                self._append_record(
                    str(item.get("record_type", "") or ""),
                    str(item.get("content", "") or ""),
                    str(item.get("source", "") or ""),
                    str(item.get("site", "") or ""),
                )
            return

        for item in pages:
            self._extract_endpoint_records(item["base_url"], item["text"])

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

        pages = []
        for js_url in js_urls:
            network_started_at = time.monotonic()
            self.network_request_count += 1
            try:
                text, _ = fetch_text(
                    js_url,
                    waf_guard=self.waf_guard,
                    timeout=self.timeout,
                    max_bytes=self.max_file_bytes,
                    waf_module="js_intel_scan",
                    discovery_context=self.discovery_context,
                    traffic_class="wih",
                )
            finally:
                self.network_wait_sec += max(0.0, time.monotonic() - network_started_at)
            if not text:
                continue
            pages.append(
                {
                    "base_url": js_url,
                    "text": text,
                    "source_url": js_url,
                    "depth": 0,
                    "is_js": True,
                }
            )
            if len(pages) >= self.js_batch_size:
                self._process_js_batch(pages)
                pages = []
        self._process_js_batch(pages)

        logger.info(
            "js intel scan done, hosts:{} js:{} records:{}".format(
                len(self.allowed_hosts),
                len(js_urls),
                len(self.records),
            )
        )
        return self.records


def run_js_intel_scan(
    sites: List[str],
    wih_records: List[WihRecord],
    waf_guard=None,
    discovery_context=None,
) -> List[WihRecord]:
    scanner = JsIntelScanner(
        sites=sites,
        wih_records=wih_records,
        waf_guard=waf_guard,
        discovery_context=discovery_context,
    )
    records = scanner.run()
    native_batch_count = int(scanner.rust_metrics.get("native_batch_count", 0) or 0)
    fallback_count = int(scanner.rust_metrics.get("fallback_count", 0) or 0)
    if native_batch_count > 0 and fallback_count > 0:
        backend = "mixed"
    elif native_batch_count > 0:
        backend = "rust"
    else:
        backend = "python"
    metrics = {
        "backend": backend,
        "batch_count": int(scanner.rust_metrics.get("batch_count", 0) or 0),
        "native_batch_count": native_batch_count,
        "fallback_count": fallback_count,
        "fallback_reasons": dict(scanner.rust_metrics.get("fallback_reasons") or {}),
        "output_count": len(records or []),
        "network_wait_sec": round(max(0.0, scanner.network_wait_sec), 6),
        "network_request_count": int(scanner.network_request_count),
    }
    return JsIntelResult(records, metrics=metrics)
