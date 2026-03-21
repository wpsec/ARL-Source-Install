"""
API 文档解析服务。

能力说明：
- 发现并解析 Swagger / OpenAPI / Postman 文档
- 提取路径、方法、基础服务地址与同主域子域名
- 将高价值端点回流到现有 URL 探测与风险扫描链路
"""
import json
import re
from collections import deque
from typing import Deque, Dict, Iterable, List, Set
from urllib.parse import urljoin, urlparse

import yaml

from app import utils
from app.config import Config
from app.modules import WihRecord
from .web_info_intel_utils import (
    collect_allowed_flds,
    collect_allowed_hosts,
    extract_host,
    extract_scope_domains,
    fetch_text,
    is_http_url,
    normalize_in_scope_url,
    safe_site,
    stable_hash,
)

logger = utils.get_logger()


class ApiDocScanner:
    _HTTP_METHODS = {"get", "post", "put", "delete", "patch", "options", "head"}
    _DOC_KEYWORDS = ("swagger", "openapi", "api-docs", "postman")
    _DOC_PATHS = (
        "/swagger",
        "/swagger-ui",
        "/swagger-ui.html",
        "/swagger-ui/index.html",
        "/swagger.json",
        "/swagger.yaml",
        "/swagger.yml",
        "/swagger/v1/swagger.json",
        "/v2/api-docs",
        "/v3/api-docs",
        "/api-docs",
        "/openapi.json",
        "/openapi.yaml",
        "/openapi.yml",
        "/postman.json",
        "/postman/collection.json",
    )
    _HTML_DOC_PATTERNS = [
        re.compile(r"(?i)\burl\s*:\s*[\"']([^\"']+)[\"']"),
        re.compile(r"(?i)\burls\s*:\s*\[[^\]]*?\burl\s*:\s*[\"']([^\"']+)[\"']"),
        re.compile(r"https?://[^\s\"'<>`]{4,2048}", re.I),
    ]

    def __init__(self, sites: List[str], wih_records: List[WihRecord], waf_guard=None):
        self.sites = list(sites or [])
        self.wih_records = list(wih_records or [])
        self.waf_guard = waf_guard

        self.enable = bool(getattr(Config, "API_DOC_ENABLE", True))
        self.max_docs = int(getattr(Config, "API_DOC_MAX_CANDIDATES", 20) or 20)
        self.max_body_bytes = int(getattr(Config, "API_DOC_MAX_BODY_BYTES", 768 * 1024) or (768 * 1024))
        self.timeout = (5, 12)

        if self.max_docs < 1:
            self.max_docs = 1
        if self.max_body_bytes < 1024:
            self.max_body_bytes = 1024

        self.allowed_hosts = collect_allowed_hosts(self.sites)
        self.allowed_flds = collect_allowed_flds(self.sites)
        self.records: List[WihRecord] = []
        self.record_hash_set: Set[int] = set()
        self.visited_docs: Set[str] = set()
        self.queued_docs: Set[str] = set()

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

    @classmethod
    def _looks_like_doc_url(cls, value: str) -> bool:
        lowered = str(value or "").strip().lower()
        return bool(lowered and any(keyword in lowered for keyword in cls._DOC_KEYWORDS))

    def _collect_seed_candidates(self) -> List[str]:
        candidates: Set[str] = set()

        for site in self.sites:
            site_text = str(site or "").strip()
            if not is_http_url(site_text):
                continue
            base_site = safe_site(site_text) or site_text
            for path in self._DOC_PATHS:
                normalized = normalize_in_scope_url(base_site, path, self.allowed_hosts, allow_js=False)
                if normalized:
                    candidates.add(normalized)

        for record in self.wih_records:
            for raw in (
                str(getattr(record, "content", "") or "").strip(),
                str(getattr(record, "source", "") or "").strip(),
            ):
                if not is_http_url(raw):
                    continue
                if not self._looks_like_doc_url(raw):
                    continue
                normalized = normalize_in_scope_url(raw, raw, self.allowed_hosts, allow_js=False)
                if normalized:
                    candidates.add(normalized)

        candidate_list = sorted(candidates)
        if len(candidate_list) > self.max_docs:
            candidate_list = candidate_list[: self.max_docs]
        return candidate_list

    def _queue_doc(self, queue: Deque[str], doc_url: str):
        if not doc_url or doc_url in self.visited_docs or doc_url in self.queued_docs:
            return
        if len(self.visited_docs) + len(self.queued_docs) >= self.max_docs:
            return
        self.queued_docs.add(doc_url)
        queue.append(doc_url)

    def _extract_html_doc_refs(self, doc_url: str, html_text: str, queue: Deque[str]):
        for pattern in self._HTML_DOC_PATTERNS:
            for match in pattern.finditer(html_text):
                token = match.group(1) if match.lastindex else match.group(0)
                if not self._looks_like_doc_url(token):
                    continue
                normalized = normalize_in_scope_url(doc_url, token, self.allowed_hosts, allow_js=False)
                if normalized:
                    self._queue_doc(queue, normalized)

    def _load_doc_object(self, raw_text: str):
        text = str(raw_text or "").strip()
        if not text:
            return None

        try:
            return json.loads(text)
        except Exception:
            pass

        try:
            return yaml.safe_load(text)
        except Exception:
            return None

    def _emit_domain_records(self, source_url: str, values: Iterable[str]):
        for item in values or []:
            host = extract_host(item)
            if not host:
                continue
            if host in self.allowed_hosts:
                continue
            if not utils.is_valid_domain(host):
                continue
            fld = utils.get_fld(host)
            if not fld or fld not in self.allowed_flds:
                continue
            self._append_record("domain", host, source_url, safe_site(source_url))

    def _emit_endpoint(self, source_url: str, method: str, raw_url: str):
        method_text = str(method or "GET").strip().upper()
        if not method_text:
            method_text = "GET"

        if is_http_url(raw_url):
            host = extract_host(raw_url)
            if host and host not in self.allowed_hosts:
                self._emit_domain_records(source_url, [raw_url])
                return
            normalized = normalize_in_scope_url(raw_url, raw_url, self.allowed_hosts, allow_js=False)
        else:
            normalized = ""
            for site in self.sites:
                normalized = normalize_in_scope_url(site, raw_url, self.allowed_hosts, allow_js=False)
                if normalized:
                    break

        if not normalized:
            return

        self._append_record("api_doc_endpoint", "{} {}".format(method_text, normalized), source_url, safe_site(normalized))
        self._append_record("urlfinder_url", normalized, source_url, safe_site(normalized))

    def _parse_swagger_like(self, source_url: str, doc_obj: Dict):
        self._append_record("api_doc_url", source_url, source_url, safe_site(source_url))

        base_urls = []
        servers = doc_obj.get("servers", [])
        if isinstance(servers, list):
            for item in servers:
                if not isinstance(item, dict):
                    continue
                url = str(item.get("url", "") or "").strip()
                if url:
                    base_urls.append(url)

        host = str(doc_obj.get("host", "") or "").strip()
        base_path = str(doc_obj.get("basePath", "") or "").strip()
        schemes = doc_obj.get("schemes") if isinstance(doc_obj.get("schemes"), list) else []
        if host:
            if not schemes:
                schemes = ["https"]
            for scheme in schemes:
                base_urls.append("{}://{}{}".format(str(scheme or "https").strip(), host, base_path))

        if not base_urls:
            base_urls = [safe_site(source_url)]

        self._emit_domain_records(source_url, base_urls)

        paths = doc_obj.get("paths")
        if not isinstance(paths, dict):
            return

        for path, methods in paths.items():
            if not isinstance(path, str):
                continue

            if isinstance(methods, dict):
                found_methods = [name.upper() for name in methods.keys() if str(name).lower() in self._HTTP_METHODS]
                if not found_methods:
                    found_methods = ["GET"]
            else:
                found_methods = ["GET"]

            if path.startswith("http://") or path.startswith("https://"):
                for method in found_methods:
                    self._emit_endpoint(source_url, method, path)
                continue

            for base_url in base_urls:
                target_url = urljoin(str(base_url or "").rstrip("/") + "/", str(path or "").lstrip("/"))
                for method in found_methods:
                    self._emit_endpoint(source_url, method, target_url)

    def _postman_url_to_text(self, url_data):
        if isinstance(url_data, str):
            return str(url_data or "").strip()

        if not isinstance(url_data, dict):
            return ""

        raw = str(url_data.get("raw", "") or "").strip()
        if raw:
            return raw

        protocol = str(url_data.get("protocol", "") or "").strip()
        host = url_data.get("host") or []
        path = url_data.get("path") or []
        if isinstance(host, list):
            host = ".".join(str(item or "").strip() for item in host if str(item or "").strip())
        else:
            host = str(host or "").strip()
        if isinstance(path, list):
            path = "/".join(str(item or "").strip() for item in path if str(item or "").strip())
        else:
            path = str(path or "").strip().lstrip("/")

        if protocol and host:
            if path:
                return "{}://{}/{}".format(protocol, host, path)
            return "{}://{}".format(protocol, host)
        if path:
            return "/{}".format(path.lstrip("/"))
        return ""

    def _walk_postman_items(self, source_url: str, items):
        if not isinstance(items, list):
            return

        for item in items:
            if not isinstance(item, dict):
                continue

            request = item.get("request")
            if isinstance(request, dict):
                method = str(request.get("method", "GET") or "GET").strip().upper()
                url_text = self._postman_url_to_text(request.get("url"))
                if url_text and "{{" not in url_text and "}}" not in url_text:
                    self._emit_endpoint(source_url, method, url_text)

            child_items = item.get("item")
            if isinstance(child_items, list):
                self._walk_postman_items(source_url, child_items)

    def _parse_postman(self, source_url: str, doc_obj: Dict):
        self._append_record("api_doc_url", source_url, source_url, safe_site(source_url))
        self._walk_postman_items(source_url, doc_obj.get("item"))

    def _parse_doc(self, doc_url: str, raw_text: str, queue: Deque[str]):
        lower_text = raw_text.lower()
        if "<html" in lower_text:
            self._extract_html_doc_refs(doc_url, raw_text, queue)
            return

        doc_obj = self._load_doc_object(raw_text)
        if not isinstance(doc_obj, dict):
            return

        if any(key in doc_obj for key in ("openapi", "swagger")) and isinstance(doc_obj.get("paths"), dict):
            self._parse_swagger_like(doc_url, doc_obj)
            return

        if isinstance(doc_obj.get("paths"), dict) and (doc_obj.get("info") or doc_obj.get("components")):
            self._parse_swagger_like(doc_url, doc_obj)
            return

        if isinstance(doc_obj.get("item"), list) and doc_obj.get("info"):
            self._parse_postman(doc_url, doc_obj)
            return

        if self.allowed_flds:
            self._emit_domain_records(doc_url, extract_scope_domains(raw_text, self.allowed_flds))

    def run(self) -> List[WihRecord]:
        if not self.enable:
            logger.info("api doc scan skip, disabled")
            return []

        if not self.allowed_hosts:
            logger.info("api doc scan skip, no allowed hosts from current target sites")
            return []

        seed_candidates = self._collect_seed_candidates()
        if not seed_candidates:
            logger.info("api doc scan skip, no api doc candidates")
            return []

        queue: Deque[str] = deque()
        for item in seed_candidates:
            self._queue_doc(queue, item)

        while queue:
            doc_url = queue.popleft()
            self.queued_docs.discard(doc_url)
            if doc_url in self.visited_docs:
                continue

            self.visited_docs.add(doc_url)
            raw_text, _ = fetch_text(
                doc_url,
                waf_guard=self.waf_guard,
                timeout=self.timeout,
                max_bytes=self.max_body_bytes,
                waf_module="api_doc_scan",
            )
            if not raw_text:
                continue

            self._parse_doc(doc_url, raw_text, queue)

        logger.info(
            "api doc scan done, hosts:{} docs:{} records:{}".format(
                len(self.allowed_hosts),
                len(self.visited_docs),
                len(self.records),
            )
        )
        return self.records


def run_api_doc_scan(sites: List[str], wih_records: List[WihRecord], waf_guard=None) -> List[WihRecord]:
    scanner = ApiDocScanner(sites=sites, wih_records=wih_records, waf_guard=waf_guard)
    return scanner.run()
