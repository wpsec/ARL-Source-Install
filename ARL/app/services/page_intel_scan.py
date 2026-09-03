"""
页面情报提取服务。

能力说明：
- 受控深度抓取当前目标站点页面
- 提取链接、表单、脚本入口
- 自动补充同主域子域名线索
- 结果统一转换为 WihRecord，复用现有入库链路
"""
from collections import deque
import time
from typing import Deque, List, Set, Tuple
from urllib.parse import urlparse

from pyquery import PyQuery as pq

from app import utils
from app.config import Config
from app.modules import WihRecord
from .web_info_intel_utils import (
    collect_allowed_flds,
    collect_allowed_hosts,
    extract_scope_domains,
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
    from .rust_accel import extract_html_candidates as rust_extract_html_candidates
except Exception as exc:
    logger.warning(
        "rust acceleration adapter unavailable stage:html reason_type:{}".format(type(exc).__name__)
    )

    class _UnavailableRustBatchResult(list):
        def __init__(self, batch_size=0):
            super().__init__()
            self.used_native = False
            self.metrics = {
                "stage": "html",
                "backend": "python",
                "used_native": False,
                "fallback_count": 1,
                "fallback_reason": "adapter_import_error",
                "batch_size": int(batch_size or 0),
            }

    def rust_extract_html_candidates(*args, **kwargs):
        if not bool(getattr(Config, "RUST_ACCEL_FALLBACK_ENABLE", True)):
            raise RuntimeError("Rust acceleration adapter unavailable at html")
        pages = kwargs.get("pages") if "pages" in kwargs else (args[0] if args else [])
        return _UnavailableRustBatchResult(len(list(pages or [])))


class PageIntelResult(list):
    """保持旧 list 返回类型，同时携带 HTML 批处理指标。"""

    def __init__(self, values=None, metrics=None):
        super().__init__(values or [])
        self.metrics = dict(metrics or {})


class PageIntelScanner:
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

        self.enable = bool(getattr(Config, "PAGE_INTEL_ENABLE", True))
        self.max_pages = int(getattr(Config, "PAGE_INTEL_MAX_PAGES", 30) or 30)
        self.max_depth = int(getattr(Config, "PAGE_INTEL_MAX_DEPTH", 2) or 2)
        self.max_page_bytes = int(getattr(Config, "PAGE_INTEL_MAX_PAGE_BYTES", 384 * 1024) or (384 * 1024))
        self.timeout = (5, 12)

        if self.max_pages < 1:
            self.max_pages = 1
        if self.max_depth < 1:
            self.max_depth = 1
        if self.max_page_bytes < 1024:
            self.max_page_bytes = 1024

        self.allowed_hosts = collect_allowed_hosts(self.sites)
        self.allowed_flds = collect_allowed_flds(self.sites)
        self.records: List[WihRecord] = []
        self.record_hash_set: Set[int] = set()
        self.visited_pages: Set[str] = set()
        self.queued_pages: Set[str] = set()
        self.rust_metrics = {
            "batch_count": 0,
            "native_batch_count": 0,
            "fallback_count": 0,
            "fallback_reasons": {},
        }
        self.network_wait_sec = 0.0
        self.network_request_count = 0
        self.html_batch_size = 16

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

    def _collect_seed_pages(self) -> List[str]:
        pages: Set[str] = set()

        for site in self.sites:
            site_text = str(site or "").strip()
            if not is_http_url(site_text):
                continue
            normalized = normalize_in_scope_url(site_text, site_text, self.allowed_hosts, allow_js=False)
            if normalized:
                pages.add(normalized)

        for record in self.wih_records:
            for raw in (
                str(getattr(record, "site", "") or "").strip(),
                str(getattr(record, "source", "") or "").strip(),
                str(getattr(record, "content", "") or "").strip(),
            ):
                if not is_http_url(raw) or is_js_url(raw):
                    continue
                normalized = normalize_in_scope_url(raw, raw, self.allowed_hosts, allow_js=False)
                if normalized:
                    pages.add(normalized)

        page_list = sorted(pages)
        if len(page_list) > self.max_pages:
            page_list = page_list[: self.max_pages]
        return page_list

    def _queue_page(self, queue: Deque[Tuple[str, int]], page_url: str, depth: int):
        if not page_url or page_url in self.visited_pages or page_url in self.queued_pages:
            return
        if len(self.visited_pages) + len(self.queued_pages) >= self.max_pages:
            return
        self.queued_pages.add(page_url)
        queue.append((page_url, depth))

    def _extract_links(self, dom: pq, page_url: str, queue: Deque[Tuple[str, int]], next_depth: int):
        for item in dom("a[href]").items():
            raw = item.attr("href")
            normalized = normalize_in_scope_url(page_url, raw, self.allowed_hosts, allow_js=False)
            if not normalized:
                continue
            self._append_record("page_link", normalized, page_url, safe_site(normalized))
            self._append_record("urlfinder_url", normalized, page_url, safe_site(normalized))
            self._queue_page(queue, normalized, next_depth)

        for item in dom("iframe[src]").items():
            raw = item.attr("src")
            normalized = normalize_in_scope_url(page_url, raw, self.allowed_hosts, allow_js=False)
            if not normalized:
                continue
            self._append_record("page_link", normalized, page_url, safe_site(normalized))
            self._append_record("urlfinder_url", normalized, page_url, safe_site(normalized))
            self._queue_page(queue, normalized, next_depth)

    def _extract_forms(self, dom: pq, page_url: str):
        for item in dom("form").items():
            raw_action = item.attr("action") or page_url
            normalized = normalize_in_scope_url(page_url, raw_action, self.allowed_hosts, allow_js=False)
            if not normalized:
                continue

            method = str(item.attr("method") or "GET").strip().upper()
            field_names = []
            for input_item in item("input[name],textarea[name],select[name]").items():
                name = str(input_item.attr("name") or "").strip()
                if name:
                    field_names.append(name)

            form_summary = "{} {}".format(method or "GET", normalized)
            if field_names:
                form_summary = "{} [{}]".format(form_summary, ",".join(sorted(set(field_names))[:12]))

            self._append_record("page_form", form_summary, page_url, safe_site(page_url))
            self._append_record("urlfinder_url", normalized, page_url, safe_site(normalized))

    def _extract_scripts(self, dom: pq, page_url: str):
        for item in dom("script[src]").items():
            raw = item.attr("src")
            normalized = normalize_in_scope_url(page_url, raw, self.allowed_hosts, allow_js=True)
            if not normalized or not is_js_url(normalized):
                continue
            self._append_record("urlfinder_js", normalized, page_url, safe_site(normalized))

    def _extract_domains(self, html_text: str, page_url: str):
        page_host = utils.normalize_domain(urlparse(page_url).hostname or "")
        exclude_hosts = set(self.allowed_hosts)
        if page_host:
            exclude_hosts.add(page_host)

        for domain in extract_scope_domains(html_text, self.allowed_flds, exclude_hosts=exclude_hosts):
            self._append_record("domain", domain, page_url, safe_site(page_url))

    def _process_page(self, page_url: str, depth: int, queue: Deque[Tuple[str, int]]):
        html_text, conn = fetch_text(
            page_url,
            waf_guard=self.waf_guard,
            timeout=self.timeout,
            max_bytes=self.max_page_bytes,
            waf_module="page_intel_scan",
            discovery_context=self.discovery_context,
            traffic_class="wih",
        )
        if not html_text or conn is None:
            return

        content_type = str((getattr(conn, "headers", {}) or {}).get("Content-Type", "") or "").lower()
        if "html" not in content_type and "<html" not in html_text.lower():
            return

        try:
            dom = pq(html_text)
        except Exception as e:
            logger.debug("page intel parse failed url:{} err:{}".format(page_url, e))
            return

        next_depth = depth + 1
        self._extract_links(dom, page_url, queue, next_depth)
        self._extract_forms(dom, page_url)
        self._extract_scripts(dom, page_url)
        self._extract_domains(html_text, page_url)

    def _fetch_page_for_batch(self, page_url: str):
        network_started_at = time.monotonic()
        self.network_request_count += 1
        try:
            html_text, conn = fetch_text(
                page_url,
                waf_guard=self.waf_guard,
                timeout=self.timeout,
                max_bytes=self.max_page_bytes,
                waf_module="page_intel_scan",
                discovery_context=self.discovery_context,
                traffic_class="wih",
            )
        finally:
            self.network_wait_sec += max(0.0, time.monotonic() - network_started_at)
        if not html_text or conn is None:
            return None

        content_type = str((getattr(conn, "headers", {}) or {}).get("Content-Type", "") or "").lower()
        if "html" not in content_type and "<html" not in html_text.lower():
            return None
        return html_text

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

    def _apply_native_html_records(self, batch_result, queue: Deque[Tuple[str, int]]):
        for item in list(batch_result or []):
            record_type = str(item.get("record_type", "") or "").strip()
            content = str(item.get("content", "") or "").strip()
            source = str(item.get("source", "") or "").strip()
            site = str(item.get("site", "") or "").strip()
            if not record_type or not content or not source or not site:
                continue
            if record_type == "domain":
                try:
                    if not utils.is_valid_domain(content):
                        continue
                    try:
                        if utils.check_domain_black(content):
                            continue
                    except Exception as exc:
                        logger.warning(
                            "page intel domain blacklist check failed domain:{} reason_type:{}".format(
                                content,
                                type(exc).__name__,
                            )
                        )
                except Exception as exc:
                    logger.warning(
                        "page intel domain validation failed domain:{} reason_type:{}".format(
                            content,
                            type(exc).__name__,
                        )
                    )
                    continue
            self._append_record(record_type, content, source, site)
            if record_type == "page_link":
                self._queue_page(
                    queue,
                    content,
                    max(0, int(item.get("next_depth", 0) or 0)),
                )

    def _process_html_batch(self, pages, queue: Deque[Tuple[str, int]]):
        if not pages:
            return
        batch_result = rust_extract_html_candidates(
            pages=[
                {
                    "base_url": item["page_url"],
                    "text": item["html_text"],
                    "source_url": item["page_url"],
                    "depth": item["depth"],
                    "is_js": False,
                }
                for item in pages
            ],
            allowed_hosts=self.allowed_hosts,
            allowed_flds=self.allowed_flds,
            exclude_hosts=self.allowed_hosts,
        )
        if batch_result is not None:
            self._record_rust_batch(batch_result)
        if bool(getattr(batch_result, "used_native", False)):
            self._apply_native_html_records(batch_result, queue)
            return

        for item in pages:
            try:
                dom = pq(item["html_text"])
            except Exception as exc:
                logger.debug(
                    "page intel parse failed url:{} err:{}".format(
                        item["page_url"],
                        exc,
                    )
                )
                continue
            next_depth = item["depth"] + 1
            self._extract_links(dom, item["page_url"], queue, next_depth)
            self._extract_forms(dom, item["page_url"])
            self._extract_scripts(dom, item["page_url"])
            self._extract_domains(item["html_text"], item["page_url"])

    def run(self) -> List[WihRecord]:
        if not self.enable:
            logger.info("page intel scan skip, disabled")
            return []

        if not self.allowed_hosts:
            logger.info("page intel scan skip, no allowed hosts from current target sites")
            return []

        seed_pages = self._collect_seed_pages()
        if not seed_pages:
            logger.info("page intel scan skip, no seed pages")
            return []

        queue: Deque[Tuple[str, int]] = deque()
        for page_url in seed_pages:
            self._queue_page(queue, page_url, 0)

        while queue:
            pages = []
            while queue and len(pages) < self.html_batch_size:
                page_url, depth = queue.popleft()
                self.queued_pages.discard(page_url)
                if page_url in self.visited_pages:
                    continue
                if len(self.visited_pages) >= self.max_pages:
                    break

                self.visited_pages.add(page_url)
                if depth > self.max_depth:
                    continue
                html_text = self._fetch_page_for_batch(page_url)
                if html_text:
                    pages.append(
                        {
                            "page_url": page_url,
                            "depth": depth,
                            "html_text": html_text,
                        }
                    )
            self._process_html_batch(pages, queue)

        logger.info(
            "page intel scan done, hosts:{} pages:{} records:{}".format(
                len(self.allowed_hosts),
                len(self.visited_pages),
                len(self.records),
            )
        )
        return self.records


def run_page_intel_scan(
    sites: List[str],
    wih_records: List[WihRecord],
    waf_guard=None,
    discovery_context=None,
) -> List[WihRecord]:
    scanner = PageIntelScanner(
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
    return PageIntelResult(records, metrics=metrics)
