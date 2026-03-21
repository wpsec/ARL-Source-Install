"""
Web 专项渗透测试执行器。

设计目标：
- 将“渗透测试”与 nuclei / afrog 的模板化 PoC 扫描解耦
- 复用 ARL 已发现的页面、表单、URL、API 文档线索，构建主动测试面
- 以保守的差分测试为主，减少高攻击性与高误报 payload
- 增加 DOM XSS 静态分析与只读型验证，不引入 DNSLog 依赖
"""
import base64
import hashlib
import json
import re
import time
from urllib.parse import parse_qsl, urlencode, unquote, urlparse, urlunparse
from typing import Dict, List, Optional, Tuple

from app import utils

logger = utils.get_logger()


class PenetrationScanService(object):
    """
    Web 专项渗透测试服务。

    当前实现说明：
    - 仅测试 GET / POST 两类常见入口，默认跳过 PUT / PATCH / DELETE 等高风险方法
    - 仅针对带参数 URL、页面表单、API 文档端点做主动测试
    - 核心依赖“基线 + 少量 payload + 响应差分/特征”判定，不复用 PoC 模板
    """

    SUPPORTED_WIH_RECORD_TYPES = {
        "api_doc_endpoint",
        "api_doc_url",
        "domain_url",
        "page_form",
        "path_url",
        "urlfinder_js",
        "urlfinder_url",
    }
    STATIC_SUFFIX_BLACKLIST = {
        ".7z", ".apk", ".avif", ".bmp", ".css", ".csv", ".eot", ".gif", ".gz", ".ico",
        ".jpeg", ".jpg", ".js", ".map", ".mp3", ".mp4", ".otf", ".pdf", ".png", ".rar",
        ".svg", ".tar", ".tgz", ".ttf", ".txt", ".wav", ".webm", ".webp", ".woff",
        ".woff2", ".zip",
    }
    SQL_ERROR_KEYWORDS = (
        "sql syntax",
        "mysql",
        "postgresql",
        "sqlite",
        "syntax error",
        "unterminated",
        "ora-",
        "odbc",
        "jdbc",
        "sqlserver",
        "database error",
    )
    DEAD_PAGE_KEYWORDS = (
        "404 not found",
        "page not found",
        "resource not found",
        "the requested url was not found",
        "object not found",
    )
    FILE_DISCLOSURE_KEYWORDS = (
        "root:x:",
        "[fonts]",
        "daemon:",
        "www-data",
        "/bin/bash",
    )
    SSRF_METADATA_KEYWORDS = (
        "instance-id",
        "ami-id",
        "availability-zone",
        "hostname",
        "region-id",
        "\"uuid\"",
    )
    PARAM_HINTS = {
        "lfi": {"dir", "download", "file", "filename", "include", "inc", "lang", "page", "path", "template", "view"},
        "rce": {"cmd", "command", "daemon", "exec", "execute", "ping", "process", "shell"},
        "ssrf": {"api", "callback", "continue", "dest", "domain", "feed", "fetch", "host", "image", "link",
                 "load", "next", "open", "proxy", "redirect", "resource", "return", "returnurl", "return_url",
                 "site", "src", "target", "uri", "url"},
        "ssti": {"content", "email", "message", "name", "query", "q", "redirect", "search", "template", "title", "view"},
        "xxe": {"body", "data", "payload", "request", "soap", "xml"},
    }
    DOM_XSS_SOURCES = (
        "location.href",
        "location.search",
        "location.hash",
        "location.pathname",
        "document.url",
        "document.documenturi",
        "document.baseuri",
        "document.referrer",
        "window.name",
        "localstorage.getitem",
        "sessionstorage.getitem",
    )
    DOM_XSS_SANITIZE_PATTERNS = (
        r"dompurify",
        r"sanitize",
        r"escapehtml",
        r"htmlspecialchars",
        r"encodeuricomponent",
        r"textcontent",
        r"innertext",
        r"\.replace\s*\(\s*/[<>'\"]",
        r"createTextNode",
    )
    DOM_XSS_RULES = (
        (r"\.innerHTML\s*=\s*([^;]+)", "innerHTML", "high"),
        (r"\.outerHTML\s*=\s*([^;]+)", "outerHTML", "high"),
        (r"document\.write(?:ln)?\s*\(\s*([^)]+)\s*\)", "document.write", "high"),
        (r"eval\s*\(\s*([^)]+)\s*\)", "eval", "critical"),
        (r"setTimeout\s*\(\s*([^,]+)", "setTimeout", "medium"),
        (r"setInterval\s*\(\s*([^,]+)", "setInterval", "medium"),
        (r"\.html\s*\(\s*([^)]+)\s*\)", "jquery.html", "high"),
        (r"\.(?:append|prepend|after|before)\s*\(\s*([^)]+)\s*\)", "jquery.dom", "medium"),
        (r"dangerouslySetInnerHTML\s*:\s*\{\s*__html\s*:\s*([^}]+)\}", "dangerouslySetInnerHTML", "high"),
        (r"v-html\s*=\s*[\"']([^\"']+)[\"']", "v-html", "high"),
    )
    MAX_TARGETS = 80
    MAX_TEST_PARAMS_PER_TARGET = 4
    MAX_JS_TARGETS = 12
    REQUEST_TIMEOUT = (5, 12)

    def __init__(self, task_id: str, sites: list, page_url_set=None, waf_guard=None):
        self.task_id = str(task_id or "").strip()
        self.sites = list(sites or [])
        self.page_url_set = set(page_url_set or [])
        self.waf_guard = waf_guard
        self.allowed_hosts = self._collect_allowed_hosts()
        self.allowed_flds = self._collect_allowed_flds()
        self.dns_policy_cache = {}
        self.baseline_cache = {}
        self.finding_hash_set = set()
        self.wih_records_cache = None

    @staticmethod
    def _normalize_host(value: str) -> str:
        text = str(value or "").strip().lower()
        if not text:
            return ""

        parsed = urlparse(text if "://" in text else "//{}".format(text))
        return str(parsed.hostname or "").strip().lower().rstrip(".")

    def _collect_allowed_hosts(self):
        hosts = set()
        for site in self.sites:
            host = self._normalize_host(site)
            if host:
                hosts.add(host)
        return hosts

    def _collect_allowed_flds(self):
        flds = set()
        for host in self.allowed_hosts:
            parsed = utils.domain_parsed(host)
            fld = str(parsed.get("fld", "") if parsed else "").strip().lower()
            if fld:
                flds.add(fld)
        return flds

    def _host_in_scope(self, host: str) -> bool:
        host = self._normalize_host(host)
        if not host:
            return False

        if host in self.allowed_hosts:
            return True

        for item in self.allowed_hosts:
            if host.endswith("." + item):
                return True

        parsed = utils.domain_parsed(host)
        fld = str(parsed.get("fld", "") if parsed else "").strip().lower()
        if fld and fld in self.allowed_flds:
            return True

        return False

    @staticmethod
    def _is_http_url(value: str) -> bool:
        text = str(value or "").strip().lower()
        return text.startswith("http://") or text.startswith("https://")

    @staticmethod
    def _is_js_url(value: str) -> bool:
        text = str(value or "").strip().lower()
        if not text:
            return False
        if ".js" in text:
            return True

        try:
            return urlparse(text).path.lower().endswith(".js")
        except Exception:
            return False

    def _is_static_resource(self, path_text: str) -> bool:
        path_text = str(path_text or "").strip().lower()
        if not path_text:
            return False

        for suffix in self.STATIC_SUFFIX_BLACKLIST:
            if path_text.endswith(suffix):
                return True
        return False

    def _normalize_target_url(self, url: str) -> str:
        raw = str(url or "").strip()
        if not self._is_http_url(raw):
            return ""

        parsed = urlparse(raw)
        host = self._normalize_host(parsed.netloc)
        if not self._host_in_scope(host):
            return ""

        if self._is_static_resource(parsed.path):
            return ""

        if not parsed.scheme or not host:
            return ""

        netloc = host
        if parsed.port:
            netloc = "{}:{}".format(host, parsed.port)

        clean = parsed._replace(
            scheme=parsed.scheme.lower(),
            netloc=netloc,
            fragment="",
        )
        return clean.geturl()

    def _normalize_js_url(self, url: str) -> str:
        raw = str(url or "").strip()
        if not self._is_http_url(raw):
            return ""

        parsed = urlparse(raw)
        host = self._normalize_host(parsed.netloc)
        if not host or not self._host_in_scope(host):
            return ""

        if not self._is_js_url(raw):
            return ""

        netloc = host
        if parsed.port:
            netloc = "{}:{}".format(host, parsed.port)

        clean = parsed._replace(
            scheme=parsed.scheme.lower(),
            netloc=netloc,
            fragment="",
        )
        return clean.geturl()

    def _normalize_param_names(self, items) -> List[str]:
        params = []
        seen = set()
        for item in items or []:
            name = str(item or "").strip()
            if not name or name in seen:
                continue
            seen.add(name)
            params.append(name)
        return params[: self.MAX_TEST_PARAMS_PER_TARGET]

    @staticmethod
    def _stable_hash(*parts) -> str:
        text = "|".join(str(part or "").strip() for part in parts)
        return hashlib.md5(text.encode("utf-8", errors="ignore")).hexdigest()

    @staticmethod
    def _safe_json(value) -> str:
        try:
            return json.dumps(value, ensure_ascii=False, sort_keys=True)
        except Exception:
            return str(value)

    def _load_db_urls(self):
        if not self.task_id:
            return []

        try:
            return list(utils.conn_db("url").distinct("url", {"task_id": self.task_id}) or [])
        except Exception as e:
            logger.warning("load penetration url assets failed task_id:{} err:{}".format(self.task_id, e))
            return []

    def _load_wih_records(self):
        if self.wih_records_cache is not None:
            return list(self.wih_records_cache)

        if not self.task_id:
            return []

        try:
            cursor = utils.conn_db("wih").find(
                {
                    "task_id": self.task_id,
                    "record_type": {"$in": sorted(self.SUPPORTED_WIH_RECORD_TYPES)},
                },
                {
                    "record_type": 1,
                    "content": 1,
                    "source": 1,
                    "site": 1,
                },
            )
            self.wih_records_cache = list(cursor or [])
            return list(self.wih_records_cache)
        except Exception as e:
            logger.warning("load penetration wih records failed task_id:{} err:{}".format(self.task_id, e))
            return []

    @staticmethod
    def _parse_query_param_names(url: str) -> List[str]:
        parsed = urlparse(str(url or "").strip())
        params = []
        seen = set()
        for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
            key = str(key or "").strip()
            if not key or key in seen:
                continue
            seen.add(key)
            params.append(key)
        return params

    @staticmethod
    def _parse_query_original_values(url: str) -> Dict[str, str]:
        parsed = urlparse(str(url or "").strip())
        values = {}
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            key = str(key or "").strip()
            if not key or key in values:
                continue
            values[key] = str(value or "")
        return values

    @staticmethod
    def _parse_form_record(text: str) -> Optional[Dict]:
        """
        解析 `page_form` 记录摘要：
        `POST https://example.com/login [username,password]`
        """
        raw = str(text or "").strip()
        if not raw:
            return None

        match = re.match(r"^\s*([A-Za-z]+)\s+(\S+?)(?:\s+\[([^\]]*)\])?\s*$", raw)
        if not match:
            return None

        method = str(match.group(1) or "GET").strip().upper()
        action = str(match.group(2) or "").strip()
        field_text = str(match.group(3) or "").strip()
        fields = []
        if field_text:
            for item in field_text.split(","):
                name = str(item or "").strip()
                if name:
                    fields.append(name)

        return {
            "method": method,
            "url": action,
            "params": fields,
        }

    @staticmethod
    def _parse_api_doc_endpoint(text: str) -> Optional[Dict]:
        raw = str(text or "").strip()
        if not raw:
            return None

        match = re.match(r"^\s*([A-Za-z]+)\s+(\S+)\s*$", raw)
        if not match:
            return None

        return {
            "method": str(match.group(1) or "GET").strip().upper(),
            "url": str(match.group(2) or "").strip(),
        }

    def _build_normal_values(self, param_names: List[str], original_values: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        original_values = original_values if isinstance(original_values, dict) else {}
        values = {}
        for name in param_names:
            text = str(name or "").strip().lower()
            if name in original_values:
                values[name] = str(original_values[name] or "")
                continue
            if text in {"id", "uid", "user_id", "page", "size", "limit"}:
                values[name] = "1"
            else:
                values[name] = "arl_test_123"
        return values

    @staticmethod
    def _merge_url_params(url: str, params: Dict[str, str]) -> str:
        parsed = urlparse(str(url or "").strip())
        current = dict(parse_qsl(parsed.query, keep_blank_values=True))
        for key, value in (params or {}).items():
            current[str(key)] = str(value)
        query = urlencode(current, doseq=True)
        return urlunparse(parsed._replace(query=query))

    def _request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, str]] = None,
        data=None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Tuple[int, int] = None,
    ):
        timeout = timeout or self.REQUEST_TIMEOUT
        method_name = str(method or "GET").strip().lower() or "get"
        if method_name == "get":
            final_url = self._merge_url_params(url, params or {})
            return utils.http_req(
                final_url,
                method="get",
                timeout=timeout,
                waf_guard=self.waf_guard,
                waf_module="penetration_test",
                headers=headers or {},
            )

        return utils.http_req(
            url,
            method="post",
            timeout=timeout,
            waf_guard=self.waf_guard,
            waf_module="penetration_test",
            headers=headers or {},
            data=data if data is not None else (params or {}),
        )

    def _build_baseline(self, target: Dict) -> Dict:
        param_names = self._normalize_param_names(target.get("params", []))
        cache_key = self._stable_hash(target.get("method"), target.get("url"), ",".join(param_names))
        cached = self.baseline_cache.get(cache_key)
        if cached:
            return cached

        default_values = self._build_normal_values(param_names, target.get("original_values"))
        started_at = time.time()
        try:
            resp = self._request(target.get("method"), target.get("url"), params=default_values)
            elapsed = time.time() - started_at
            body = str(getattr(resp, "text", "") or "")
            baseline = {
                "ok": True,
                "status_code": int(getattr(resp, "status_code", 0) or 0),
                "content_length": len(body),
                "content_hash": self._stable_hash(body[:4096]),
                "response_time": elapsed,
                "error_keywords": [item for item in self.SQL_ERROR_KEYWORDS if item in body.lower()],
                "original_params": default_values,
                "body": body[:4096],
            }
        except Exception as e:
            baseline = {
                "ok": False,
                "status_code": 0,
                "content_length": 0,
                "content_hash": "",
                "response_time": 0.0,
                "error_keywords": [],
                "original_params": default_values,
                "body": "",
                "error": str(e),
            }

        self.baseline_cache[cache_key] = baseline
        return baseline

    def _is_dead_code_page(self, body: str) -> bool:
        text = str(body or "").strip().lower()
        if not text:
            return False
        return any(keyword in text for keyword in self.DEAD_PAGE_KEYWORDS)

    def _is_significant_difference(self, body: str, status_code: int, baseline: Dict, vuln_type: str, elapsed: float = 0.0):
        """
        基于状态码、响应长度、SQL 错误和响应时间做保守差分判断。
        """
        text = str(body or "")
        if self._is_dead_code_page(text):
            return False, "命中错误页特征"

        baseline_status = int(baseline.get("status_code", 0) or 0)
        if status_code != baseline_status:
            if status_code in {500, 502, 503}:
                return True, "状态码变为服务端错误"
            if status_code >= 400:
                return False, "状态码变为客户端错误"

        baseline_length = int(baseline.get("content_length", 0) or 0)
        current_length = len(text)
        if baseline_length > 0:
            length_ratio = abs(current_length - baseline_length) / float(baseline_length)
            if length_ratio > 0.5:
                return True, "响应长度差异显著"

        baseline_time = float(baseline.get("response_time", 0.0) or 0.0)
        if elapsed > 0 and baseline_time > 0:
            if elapsed >= max(baseline_time * 3.0, baseline_time + 4.0):
                return True, "响应时间显著变慢"

        if vuln_type == "sqli":
            current_errors = [item for item in self.SQL_ERROR_KEYWORDS if item in text.lower()]
            baseline_errors = set(baseline.get("error_keywords", []))
            new_errors = [item for item in current_errors if item not in baseline_errors]
            if new_errors:
                return True, "出现新的 SQL 错误特征"

        baseline_hash = str(baseline.get("content_hash", "") or "")
        current_hash = self._stable_hash(text[:4096])
        if baseline_hash and current_hash != baseline_hash and baseline_length > 0:
            length_change_pct = abs(current_length - baseline_length) / float(baseline_length)
            if length_change_pct > 0.3:
                return True, "响应内容结构变化明显"

        return False, ""

    @staticmethod
    def _is_response_similar_to_baseline(body: str, status_code: int, baseline: Dict) -> bool:
        baseline_status = int(baseline.get("status_code", 0) or 0)
        if baseline_status != int(status_code or 0):
            return False

        baseline_length = int(baseline.get("content_length", 0) or 0)
        current_length = len(str(body or ""))
        if baseline_length > 0:
            diff_ratio = abs(current_length - baseline_length) / float(baseline_length)
            if diff_ratio > 0.15:
                return False

        baseline_hash = str(baseline.get("content_hash", "") or "")
        if baseline_hash:
            current_hash = PenetrationScanService._stable_hash(str(body or "")[:4096])
            if current_hash == baseline_hash:
                return True

        return baseline_length == 0 or abs(current_length - baseline_length) <= 64

    @staticmethod
    def _decode_js_content(content: str) -> str:
        text = str(content or "")
        decoded = text

        for _ in range(2):
            original = decoded

            def _replace_urlencoded(match):
                try:
                    return '"{}"'.format(unquote(match.group(2)))
                except Exception:
                    return match.group(0)

            decoded = re.sub(
                r"decodeURIComponent\s*\(\s*([\"'])(.*?)\1\s*\)",
                _replace_urlencoded,
                decoded,
                flags=re.I | re.S,
            )

            def _replace_base64(match):
                value = str(match.group(2) or "")
                try:
                    return '"{}"'.format(
                        base64.b64decode(value).decode("utf-8", errors="ignore")
                    )
                except Exception:
                    return match.group(0)

            decoded = re.sub(
                r"atob\s*\(\s*([\"'])([A-Za-z0-9+/=]{12,})\1\s*\)",
                _replace_base64,
                decoded,
                flags=re.I,
            )

            def _replace_charcode(match):
                try:
                    items = [
                        int(part.strip())
                        for part in str(match.group(1) or "").split(",")
                        if str(part).strip().isdigit()
                    ]
                    if not items:
                        return match.group(0)
                    return '"{}"'.format("".join(chr(item) for item in items))
                except Exception:
                    return match.group(0)

            decoded = re.sub(
                r"String\.fromCharCode\s*\(([^)]+)\)",
                _replace_charcode,
                decoded,
                flags=re.I,
            )

            decoded = re.sub(
                r"\\x([0-9a-fA-F]{2})",
                lambda match: chr(int(match.group(1), 16)),
                decoded,
            )
            decoded = re.sub(
                r"\\u([0-9a-fA-F]{4})",
                lambda match: chr(int(match.group(1), 16)),
                decoded,
            )

            if decoded == original:
                break

        return decoded

    def _has_dom_sanitization(self, snippet: str) -> bool:
        lowered = str(snippet or "")
        return any(re.search(pattern, lowered, flags=re.I) for pattern in self.DOM_XSS_SANITIZE_PATTERNS)

    def _extract_js_urls(self, records: List[Dict]) -> List[str]:
        urls = []
        url_set = set()

        def _append(candidate: str):
            normalized = self._normalize_js_url(candidate)
            if not normalized or normalized in url_set:
                return
            url_set.add(normalized)
            urls.append(normalized)

        for record in records or []:
            record_type = str(record.get("record_type", "") or "").strip()
            content = str(record.get("content", "") or "").strip()
            source = str(record.get("source", "") or "").strip()
            if record_type == "urlfinder_js":
                _append(content)
            _append(source)
            _append(content)

        urls.sort()
        return urls[: self.MAX_JS_TARGETS]

    def _scan_dom_xss_js(self, js_url: str, findings: List[Dict]):
        allow_scan, policy_detail = utils.check_dns_policy_for_url(js_url, cache_map=self.dns_policy_cache)
        if not allow_scan:
            logger.info(
                "skip dom xss js by dns policy url:{} reason:{} resolver_ips:{} system_ips:{}".format(
                    js_url,
                    policy_detail.get("reason", ""),
                    policy_detail.get("resolver_ips", []),
                    policy_detail.get("system_ips", []),
                )
            )
            return

        try:
            resp = utils.http_req(
                js_url,
                method="get",
                timeout=self.REQUEST_TIMEOUT,
                waf_guard=self.waf_guard,
                waf_module="penetration_test",
            )
        except Exception:
            return

        status_code = int(getattr(resp, "status_code", 0) or 0)
        if status_code >= 400:
            return

        body = bytes(getattr(resp, "content", b"") or b"")[: 512 * 1024]
        if not body:
            return

        try:
            js_content = body.decode("utf-8", errors="ignore")
        except Exception:
            return

        decoded = self._decode_js_content(js_content)
        merged_content = "{}\n{}".format(js_content, decoded) if decoded != js_content else js_content

        for pattern, sink_name, severity in self.DOM_XSS_RULES:
            for match in re.finditer(pattern, merged_content, flags=re.I):
                expr = str(match.group(1) or "").strip()
                if not expr:
                    continue

                snippet_start = max(0, match.start() - 120)
                snippet_end = min(len(merged_content), match.end() + 120)
                snippet = merged_content[snippet_start:snippet_end]
                snippet_lower = snippet.lower()
                expr_lower = expr.lower()

                if self._has_dom_sanitization(expr_lower) or self._has_dom_sanitization(snippet_lower):
                    continue

                matched_source = ""
                for source_name in self.DOM_XSS_SOURCES:
                    if source_name in expr_lower or source_name in snippet_lower:
                        matched_source = source_name
                        break
                if not matched_source:
                    continue

                self._append_finding(
                    findings,
                    vuln_type="dom_xss",
                    vuln_name="DOM XSS",
                    severity=severity,
                    target={
                        "method": "GET",
                        "url": js_url,
                        "source": "urlfinder_js",
                    },
                    param_name=matched_source,
                    payload=sink_name,
                    detail="JS 中发现 {} 接收 {} 且附近无明显过滤".format(sink_name, matched_source),
                    evidence=snippet.strip()[:300],
                    request_text="",
                    response_text="",
                )

    def _test_dom_xss(self, findings: List[Dict], records: List[Dict]):
        for js_url in self._extract_js_urls(records):
            self._scan_dom_xss_js(js_url, findings)

    def _param_matches_hint(self, param_name: str, hint_name: str) -> bool:
        name = str(param_name or "").strip().lower()
        if not name:
            return False
        return name in self.PARAM_HINTS.get(hint_name, set())

    @staticmethod
    def _summarize_response(resp, body: str) -> str:
        headers = dict(getattr(resp, "headers", {}) or {})
        preview = str(body or "")[:300]
        return "status={} headers={} body={}".format(
            int(getattr(resp, "status_code", 0) or 0),
            json.dumps(headers, ensure_ascii=False)[:300],
            preview,
        )

    def _append_finding(
        self,
        findings: List[Dict],
        vuln_type: str,
        vuln_name: str,
        severity: str,
        target: Dict,
        param_name: str,
        payload: str,
        detail: str,
        evidence: str = "",
        request_text: str = "",
        response_text: str = "",
    ):
        finding_hash = self._stable_hash(
            vuln_type,
            target.get("method"),
            target.get("url"),
            param_name,
            detail,
        )
        if finding_hash in self.finding_hash_set:
            return

        self.finding_hash_set.add(finding_hash)
        findings.append(
            {
                "type": vuln_type,
                "name": vuln_name,
                "severity": severity,
                "url": target.get("url", ""),
                "method": target.get("method", "GET"),
                "param": param_name,
                "payload": payload,
                "detail": detail,
                "source": target.get("source", ""),
                "evidence": evidence,
                "request": request_text,
                "response": response_text,
            }
        )

    def _test_sqli(self, target: Dict, findings: List[Dict]):
        param_names = self._normalize_param_names(target.get("params", []))
        if not param_names:
            return

        baseline = self._build_baseline(target)
        for param_name in param_names:
            normal_params = baseline.get("original_params", {}).copy()

            # 先做错误型/差分检测。
            for payload in ["'", "1' AND '1'='1"]:
                test_params = normal_params.copy()
                test_params[param_name] = payload
                started_at = time.time()
                try:
                    resp = self._request(target.get("method"), target.get("url"), params=test_params)
                except Exception:
                    continue
                elapsed = time.time() - started_at
                body = str(getattr(resp, "text", "") or "")
                is_vuln, reason = self._is_significant_difference(
                    body,
                    int(getattr(resp, "status_code", 0) or 0),
                    baseline,
                    "sqli",
                    elapsed=elapsed,
                )
                if not is_vuln:
                    continue
                self._append_finding(
                    findings,
                    vuln_type="sqli",
                    vuln_name="SQL注入",
                    severity="critical",
                    target=target,
                    param_name=param_name,
                    payload=payload,
                    detail="SQL 注入差分命中: {}".format(reason),
                    evidence=reason,
                    request_text=self._safe_json({"method": target.get("method"), "params": test_params}),
                    response_text=self._summarize_response(resp, body),
                )
                break

            if any(item.get("param") == param_name and item.get("url") == target.get("url") for item in findings):
                continue

            true_params = normal_params.copy()
            false_params = normal_params.copy()
            true_payload = "1' AND '1'='1"
            false_payload = "1' AND '1'='2"
            true_params[param_name] = true_payload
            false_params[param_name] = false_payload
            try:
                true_resp = self._request(target.get("method"), target.get("url"), params=true_params)
                false_resp = self._request(target.get("method"), target.get("url"), params=false_params)
            except Exception:
                true_resp = None
                false_resp = None

            if true_resp is not None and false_resp is not None:
                true_body = str(getattr(true_resp, "text", "") or "")
                false_body = str(getattr(false_resp, "text", "") or "")
                true_status = int(getattr(true_resp, "status_code", 0) or 0)
                false_status = int(getattr(false_resp, "status_code", 0) or 0)
                false_is_diff, false_reason = self._is_significant_difference(
                    false_body,
                    false_status,
                    baseline,
                    "sqli",
                )
                if self._is_response_similar_to_baseline(true_body, true_status, baseline) and false_is_diff:
                    self._append_finding(
                        findings,
                        vuln_type="sqli",
                        vuln_name="SQL注入",
                        severity="critical",
                        target=target,
                        param_name=param_name,
                        payload="{} | {}".format(true_payload, false_payload),
                        detail="SQL 布尔差分命中: {}".format(false_reason),
                        evidence="true_like_baseline=true false_diff=true",
                        request_text=self._safe_json(
                            {
                                "method": target.get("method"),
                                "true_params": true_params,
                                "false_params": false_params,
                            }
                        ),
                        response_text="true={} false={}".format(
                            self._summarize_response(true_resp, true_body),
                            self._summarize_response(false_resp, false_body),
                        ),
                    )
                    continue

            # 再做时间型检测，满足用户强调的基线差分能力。
            if any(item.get("param") == param_name and item.get("url") == target.get("url") for item in findings):
                continue
            time_params = normal_params.copy()
            time_payload = "1' AND SLEEP(5)--"
            time_params[param_name] = time_payload
            started_at = time.time()
            try:
                resp = self._request(target.get("method"), target.get("url"), params=time_params, timeout=(5, 8))
                elapsed = time.time() - started_at
                body = str(getattr(resp, "text", "") or "")
            except Exception as e:
                elapsed = time.time() - started_at
                body = str(e)
                resp = None

            baseline_time = float(baseline.get("response_time", 0.0) or 0.0)
            if elapsed >= max(baseline_time * 3.0, baseline_time + 4.0):
                self._append_finding(
                    findings,
                    vuln_type="sqli",
                    vuln_name="SQL注入",
                    severity="critical",
                    target=target,
                    param_name=param_name,
                    payload=time_payload,
                    detail="SQL 时间盲注差分命中",
                    evidence="baseline={:.2f}s test={:.2f}s".format(baseline_time, elapsed),
                    request_text=self._safe_json({"method": target.get("method"), "params": time_params}),
                    response_text=self._summarize_response(resp, body) if resp is not None else body[:300],
                )

    def _test_xss(self, target: Dict, findings: List[Dict]):
        param_names = self._normalize_param_names(target.get("params", []))
        if not param_names:
            return

        baseline = self._build_baseline(target)
        baseline_body = str(baseline.get("body", "") or "")
        payload = "<svg/onload=alert(1337)>ARL_XSS_MARK"
        for param_name in param_names:
            test_params = baseline.get("original_params", {}).copy()
            test_params[param_name] = payload
            try:
                resp = self._request(target.get("method"), target.get("url"), params=test_params)
            except Exception:
                continue

            body = str(getattr(resp, "text", "") or "")
            if payload in body and payload not in baseline_body:
                self._append_finding(
                    findings,
                    vuln_type="xss",
                    vuln_name="XSS",
                    severity="high",
                    target=target,
                    param_name=param_name,
                    payload=payload,
                    detail="响应中出现未转义的 XSS 载荷回显",
                    evidence="payload reflected",
                    request_text=self._safe_json({"method": target.get("method"), "params": test_params}),
                    response_text=self._summarize_response(resp, body),
                )

    def _test_lfi(self, target: Dict, findings: List[Dict]):
        param_names = self._normalize_param_names(target.get("params", []))
        if not param_names:
            return

        baseline = self._build_baseline(target)
        payloads = ["../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini"]
        for param_name in param_names:
            if not self._param_matches_hint(param_name, "lfi"):
                continue
            for payload in payloads:
                test_params = baseline.get("original_params", {}).copy()
                test_params[param_name] = payload
                try:
                    resp = self._request(target.get("method"), target.get("url"), params=test_params)
                except Exception:
                    continue
                body = str(getattr(resp, "text", "") or "")
                if any(keyword in body.lower() for keyword in [item.lower() for item in self.FILE_DISCLOSURE_KEYWORDS]):
                    self._append_finding(
                        findings,
                        vuln_type="lfi",
                        vuln_name="本地文件包含",
                        severity="high",
                        target=target,
                        param_name=param_name,
                        payload=payload,
                        detail="文件读取特征命中",
                        evidence="匹配到系统文件内容片段",
                        request_text=self._safe_json({"method": target.get("method"), "params": test_params}),
                        response_text=self._summarize_response(resp, body),
                    )
                    break

    def _test_rce(self, target: Dict, findings: List[Dict]):
        param_names = self._normalize_param_names(target.get("params", []))
        if not param_names:
            return

        baseline = self._build_baseline(target)
        delay_payload = ";sleep 5;"
        echo_payload = ";echo ARL_RCE_MARK;"
        baseline_time = float(baseline.get("response_time", 0.0) or 0.0)

        for param_name in param_names:
            if not self._param_matches_hint(param_name, "rce"):
                continue

            delay_params = baseline.get("original_params", {}).copy()
            delay_params[param_name] = delay_payload
            started_at = time.time()
            try:
                resp = self._request(target.get("method"), target.get("url"), params=delay_params, timeout=(5, 8))
                elapsed = time.time() - started_at
                body = str(getattr(resp, "text", "") or "")
            except Exception as e:
                elapsed = time.time() - started_at
                body = str(e)
                resp = None

            if elapsed >= max(baseline_time * 3.0, baseline_time + 4.0):
                self._append_finding(
                    findings,
                    vuln_type="rce",
                    vuln_name="远程代码执行",
                    severity="critical",
                    target=target,
                    param_name=param_name,
                    payload=delay_payload,
                    detail="命令执行延时特征命中",
                    evidence="baseline={:.2f}s test={:.2f}s".format(baseline_time, elapsed),
                    request_text=self._safe_json({"method": target.get("method"), "params": delay_params}),
                    response_text=self._summarize_response(resp, body) if resp is not None else body[:300],
                )
                continue

            echo_params = baseline.get("original_params", {}).copy()
            echo_params[param_name] = echo_payload
            try:
                resp = self._request(target.get("method"), target.get("url"), params=echo_params)
            except Exception:
                continue
            body = str(getattr(resp, "text", "") or "")
            if "ARL_RCE_MARK" in body:
                self._append_finding(
                    findings,
                    vuln_type="rce",
                    vuln_name="远程代码执行",
                    severity="critical",
                    target=target,
                    param_name=param_name,
                    payload=echo_payload,
                    detail="命令输出回显命中",
                    evidence="ARL_RCE_MARK",
                    request_text=self._safe_json({"method": target.get("method"), "params": echo_params}),
                    response_text=self._summarize_response(resp, body),
                )

    def _test_ssti(self, target: Dict, findings: List[Dict]):
        param_names = self._normalize_param_names(target.get("params", []))
        if not param_names:
            return

        baseline = self._build_baseline(target)
        baseline_body = str(baseline.get("body", "") or "")
        payloads = ["{{7*191}}", "${7*191}"]
        for param_name in param_names:
            if not self._param_matches_hint(param_name, "ssti"):
                continue
            for payload in payloads:
                test_params = baseline.get("original_params", {}).copy()
                test_params[param_name] = payload
                try:
                    resp = self._request(target.get("method"), target.get("url"), params=test_params)
                except Exception:
                    continue
                body = str(getattr(resp, "text", "") or "")
                if "1337" in body and "1337" not in baseline_body and payload not in body:
                    self._append_finding(
                        findings,
                        vuln_type="ssti",
                        vuln_name="服务器端模板注入",
                        severity="high",
                        target=target,
                        param_name=param_name,
                        payload=payload,
                        detail="模板表达式被服务端求值",
                        evidence="检测到数学表达式结果 1337",
                        request_text=self._safe_json({"method": target.get("method"), "params": test_params}),
                        response_text=self._summarize_response(resp, body),
                    )
                    break

    def _test_ssrf(self, target: Dict, findings: List[Dict]):
        param_names = self._normalize_param_names(target.get("params", []))
        if not param_names:
            return

        baseline = self._build_baseline(target)
        payload = "http://169.254.169.254/latest/meta-data/"
        for param_name in param_names:
            if not self._param_matches_hint(param_name, "ssrf"):
                continue

            test_params = baseline.get("original_params", {}).copy()
            test_params[param_name] = payload
            try:
                resp = self._request(target.get("method"), target.get("url"), params=test_params)
            except Exception:
                continue
            body = str(getattr(resp, "text", "") or "")
            lowered = body.lower()
            if any(keyword in lowered for keyword in self.SSRF_METADATA_KEYWORDS):
                self._append_finding(
                    findings,
                    vuln_type="ssrf",
                    vuln_name="服务端请求伪造",
                    severity="critical",
                    target=target,
                    param_name=param_name,
                    payload=payload,
                    detail="云元数据内容命中",
                    evidence="metadata keywords matched",
                    request_text=self._safe_json({"method": target.get("method"), "params": test_params}),
                    response_text=self._summarize_response(resp, body),
                )

    def _test_xxe(self, target: Dict, findings: List[Dict]):
        method = str(target.get("method") or "GET").strip().upper()
        if method != "POST":
            return

        url_text = str(target.get("url") or "").strip().lower()
        param_names = self._normalize_param_names(target.get("params", []))
        if not (any(key in url_text for key in ("xml", "soap", "wsdl")) or any(self._param_matches_hint(name, "xxe") for name in param_names)):
            return

        payload = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            '<root>&xxe;</root>'
        )
        headers = {"Content-Type": "application/xml"}
        try:
            resp = self._request("POST", target.get("url"), data=payload, headers=headers)
        except Exception:
            return
        body = str(getattr(resp, "text", "") or "")
        if any(keyword.lower() in body.lower() for keyword in self.FILE_DISCLOSURE_KEYWORDS):
            self._append_finding(
                findings,
                vuln_type="xxe",
                vuln_name="XML 实体注入",
                severity="high",
                target=target,
                param_name="xml",
                payload=payload,
                detail="XML 实体解析后出现本地文件内容特征",
                evidence="匹配到系统文件内容片段",
                request_text=self._safe_json({"method": "POST", "body": payload[:200]}),
                response_text=self._summarize_response(resp, body),
            )

    def _collect_seed_targets(self) -> List[Dict]:
        """
        构建主动测试入口：
        - 带查询参数的页面/URL
        - 页面表单
        - API 文档端点（目前仅使用带查询参数的 URL）
        """
        targets = []
        target_hash_set = set()
        wih_records = self._load_wih_records()

        def _append_target(item: Dict):
            if not isinstance(item, dict):
                return
            method = str(item.get("method") or "GET").strip().upper()
            if method not in {"GET", "POST"}:
                return

            url_text = self._normalize_target_url(item.get("url"))
            if not url_text:
                return

            allow_scan, policy_detail = utils.check_dns_policy_for_url(url_text, cache_map=self.dns_policy_cache)
            if not allow_scan:
                logger.info(
                    "skip penetration target by dns policy url:{} reason:{} resolver_ips:{} system_ips:{}".format(
                        url_text,
                        policy_detail.get("reason", ""),
                        policy_detail.get("resolver_ips", []),
                        policy_detail.get("system_ips", []),
                    )
                )
                return

            params = self._normalize_param_names(item.get("params", []))
            if not params:
                return

            target_key = self._stable_hash(method, url_text, ",".join(params), item.get("source"))
            if target_key in target_hash_set:
                return

            target_hash_set.add(target_key)
            targets.append(
                {
                    "method": method,
                    "url": url_text,
                    "params": params,
                    "source": str(item.get("source") or "").strip(),
                    "original_values": item.get("original_values") if isinstance(item.get("original_values"), dict) else {},
                }
            )

        for url_text in list(self.page_url_set) + self._load_db_urls():
            normalized = self._normalize_target_url(url_text)
            if not normalized:
                continue
            query_params = self._parse_query_param_names(normalized)
            if not query_params:
                continue
            _append_target(
                {
                    "method": "GET",
                    "url": normalized,
                    "params": query_params,
                    "source": "query_url",
                    "original_values": self._parse_query_original_values(normalized),
                }
            )

        for record in wih_records:
            record_type = str(record.get("record_type", "") or "").strip()
            content = str(record.get("content", "") or "").strip()
            if record_type == "page_form":
                parsed = self._parse_form_record(content)
                if parsed:
                    parsed["source"] = "page_form"
                    _append_target(parsed)
                continue

            if record_type == "api_doc_endpoint":
                parsed = self._parse_api_doc_endpoint(content)
                if parsed:
                    query_params = self._parse_query_param_names(parsed["url"])
                    if query_params:
                        parsed["params"] = query_params
                        parsed["original_values"] = self._parse_query_original_values(parsed["url"])
                        parsed["source"] = "api_doc_endpoint"
                        _append_target(parsed)
                continue

            if record_type in {"urlfinder_url", "path_url", "domain_url"} and self._is_http_url(content):
                normalized = self._normalize_target_url(content)
                if not normalized:
                    continue
                query_params = self._parse_query_param_names(normalized)
                if not query_params:
                    continue
                _append_target(
                    {
                        "method": "GET",
                        "url": normalized,
                        "params": query_params,
                        "source": record_type,
                        "original_values": self._parse_query_original_values(normalized),
                    }
                )

        targets.sort(
            key=lambda item: (
                0 if item.get("source") == "page_form" else 1 if item.get("source") == "query_url" else 2,
                -len(item.get("params", [])),
                item.get("url", ""),
            )
        )
        return targets[: self.MAX_TARGETS]

    def run(self):
        if not self.allowed_hosts:
            logger.info("penetration scan skip, no in-scope hosts")
            return {"targets": [], "findings": []}

        wih_records = self._load_wih_records()
        targets = self._collect_seed_targets()
        if not targets:
            logger.info("penetration scan skip active targets, fallback to js static analysis only")

        findings = []
        for target in targets:
            self._test_sqli(target, findings)
            self._test_xss(target, findings)
            self._test_lfi(target, findings)
            self._test_rce(target, findings)
            self._test_ssti(target, findings)
            self._test_ssrf(target, findings)
            self._test_xxe(target, findings)
        self._test_dom_xss(findings, wih_records)

        logger.info(
            "penetration scan done task_id:{} targets:{} findings:{}".format(
                self.task_id,
                len(targets),
                len(findings),
            )
        )
        return {
            "targets": targets,
            "findings": findings,
        }


def run_penetration_scan(task_id: str, sites: list, page_url_set=None, waf_guard=None):
    service = PenetrationScanService(
        task_id=task_id,
        sites=sites,
        page_url_set=page_url_set,
        waf_guard=waf_guard,
    )
    return service.run()
