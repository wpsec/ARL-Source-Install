"""
Web 专项渗透测试执行器

设计目标：
- 复用现有 nuclei / afrog 扫描器，不重复建设第三套漏洞执行引擎
- 基于站点、URL 资产与 WIH/API 文档线索，挑选更适合漏洞测试的 URL 目标
- 统一覆盖 SQLi / XSS / LFI / RCE / XXE / SSTI / SSRF / 云存储暴露 / 接管类能力
"""
from urllib.parse import urlparse

from app import utils
from app.services.nuclei_scan import nuclei_scan
from app.services.afrog_scan import run_afrog_scan

logger = utils.get_logger()


class PenetrationScanService(object):
    """
    Web 专项漏洞测试服务。
    """

    SUPPORTED_WIH_RECORD_TYPES = {
        "api_doc_url",
        "domain_url",
        "path_url",
        "urlfinder_url",
    }
    STATIC_SUFFIX_BLACKLIST = {
        ".7z", ".apk", ".avif", ".bmp", ".css", ".csv", ".eot", ".gif", ".gz", ".ico",
        ".jpeg", ".jpg", ".js", ".map", ".mp3", ".mp4", ".otf", ".pdf", ".png", ".rar",
        ".svg", ".tar", ".tgz", ".ttf", ".txt", ".wav", ".webm", ".webp", ".woff",
        ".woff2", ".zip",
    }
    PATH_HINTS = {
        "actuator", "admin", "api", "auth", "bucket", "callback", "convert", "debug",
        "download", "export", "fetch", "file", "graphql", "import", "include", "json",
        "login", "metadata", "openapi", "preview", "proxy", "query", "redirect", "render",
        "report", "rpc", "search", "soap", "sql", "ssti", "ssrf", "storage", "swagger",
        "template", "upload", "url", "wsdl", "xml", "xxe",
    }
    QUERY_HINTS = {
        "callback", "continue", "dest", "dir", "domain", "download", "feed", "file",
        "host", "image", "include", "import", "load", "next", "open", "page", "path",
        "preview", "proxy", "query", "redirect", "reference", "resource", "return",
        "returnto", "returnurl", "return_url", "search", "site", "src", "target",
        "template", "to", "u", "uri", "url", "view", "xml",
    }
    PENETRATION_NUCLEI_TAGS = [
        "sqli",
        "time-based-sqli",
        "xss",
        "dom",
        "ssti",
        "ssrf",
        "xxe",
        "lfi",
        "rce",
        "bucket",
        "s3",
        "oss",
        "firebase",
        "azure-storage",
        "google-cloud-storage",
        "takeover",
        "exposure",
        "misconfig",
        "listing",
        "unauth",
    ]
    AFROG_SEARCH_KEYWORDS = "sql,xss,lfi,rce,xxe,ssti,ssrf,bucket,oss,s3,takeover,cloud"
    AFROG_SEVERITY = "medium,high,critical"
    MAX_COLLECTED_TARGETS = 120
    MAX_NUCLEI_TARGETS = 72
    MAX_AFROG_TARGETS = 24

    def __init__(self, task_id: str, sites: list, page_url_set=None, waf_guard=None):
        self.task_id = str(task_id or "").strip()
        self.sites = list(sites or [])
        self.page_url_set = set(page_url_set or [])
        self.waf_guard = waf_guard
        self.allowed_hosts = self._collect_allowed_hosts()
        self.allowed_flds = self._collect_allowed_flds()
        self.dns_policy_cache = {}

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

    def _is_static_resource(self, path_text: str) -> bool:
        path_text = str(path_text or "").strip().lower()
        if not path_text:
            return False

        for suffix in self.STATIC_SUFFIX_BLACKLIST:
            if path_text.endswith(suffix):
                return True
        return False

    def _normalize_target(self, url: str) -> str:
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

    def _score_target(self, target: str) -> tuple:
        parsed = urlparse(target)
        path = str(parsed.path or "/").strip().lower()
        query = str(parsed.query or "").strip().lower()
        score = 0

        if target in self.sites:
            score += 80

        if not path or path == "/":
            score += 20

        if query:
            score += 45
            for key in query.split("&"):
                key_name = key.split("=", 1)[0].strip().lower()
                if key_name in self.QUERY_HINTS:
                    score += 10

        for hint in self.PATH_HINTS:
            if hint in path:
                score += 8

        if any(flag in path for flag in ("swagger", "openapi", "graphql", "soap", "wsdl")):
            score += 20

        return (-score, len(target), target)

    def _load_db_urls(self):
        if not self.task_id:
            return []

        try:
            return list(utils.conn_db("url").distinct("url", {"task_id": self.task_id}) or [])
        except Exception as e:
            logger.warning("load penetration url assets failed task_id:{} err:{}".format(self.task_id, e))
            return []

    def _load_wih_urls(self):
        if not self.task_id:
            return []

        try:
            return list(
                utils.conn_db("wih").distinct(
                    "content",
                    {
                        "task_id": self.task_id,
                        "record_type": {"$in": sorted(self.SUPPORTED_WIH_RECORD_TYPES)},
                    },
                ) or []
            )
        except Exception as e:
            logger.warning("load penetration wih urls failed task_id:{} err:{}".format(self.task_id, e))
            return []

    def collect_targets(self):
        candidates = set()
        for item in self.sites:
            normalized = self._normalize_target(item)
            if normalized:
                candidates.add(normalized)

        for item in self.page_url_set:
            normalized = self._normalize_target(item)
            if normalized:
                candidates.add(normalized)

        for item in self._load_db_urls():
            normalized = self._normalize_target(item)
            if normalized:
                candidates.add(normalized)

        for item in self._load_wih_urls():
            normalized = self._normalize_target(item)
            if normalized:
                candidates.add(normalized)

        targets = sorted(candidates, key=self._score_target)
        if len(targets) > self.MAX_COLLECTED_TARGETS:
            targets = targets[: self.MAX_COLLECTED_TARGETS]

        return targets

    def _filter_dns_policy_targets(self, targets):
        keep_targets = []
        for target in targets:
            allow_scan, policy_detail = utils.check_dns_policy_for_url(target, cache_map=self.dns_policy_cache)
            if allow_scan:
                keep_targets.append(target)
                continue

            logger.info(
                "skip penetration target by dns policy url:{} reason:{} resolver_ips:{} system_ips:{}".format(
                    target,
                    policy_detail.get("reason", ""),
                    policy_detail.get("resolver_ips", []),
                    policy_detail.get("system_ips", []),
                )
            )

        return keep_targets

    def _filter_waf_targets(self, targets, stage_name="penetration"):
        target_list = list(targets or [])
        if not self.waf_guard:
            return target_list

        keep_targets, skipped = self.waf_guard.filter_targets(target_list)
        if skipped > 0:
            logger.info(
                "penetration waf smart skip stage:{} keep:{} skipped:{}".format(
                    stage_name,
                    len(keep_targets),
                    skipped,
                )
            )
        return keep_targets

    def _select_afrog_targets(self, targets):
        preferred = []
        fallback = []

        for target in targets:
            parsed = urlparse(target)
            path = str(parsed.path or "").strip().lower()
            query = str(parsed.query or "").strip().lower()
            if query or any(hint in path for hint in self.PATH_HINTS):
                preferred.append(target)
            else:
                fallback.append(target)

        selected = preferred[: self.MAX_AFROG_TARGETS]
        if len(selected) < self.MAX_AFROG_TARGETS:
            selected.extend(fallback[: self.MAX_AFROG_TARGETS - len(selected)])

        return selected

    def run(self):
        all_targets = self.collect_targets()
        if not all_targets:
            logger.info("penetration scan skip, no candidate targets")
            return {
                "targets": [],
                "nuclei_targets": [],
                "afrog_targets": [],
                "nuclei_results": [],
                "afrog_results": [],
            }

        nuclei_targets = all_targets[: self.MAX_NUCLEI_TARGETS]
        afrog_targets = self._select_afrog_targets(all_targets)

        nuclei_targets = self._filter_dns_policy_targets(nuclei_targets)
        afrog_targets = self._filter_dns_policy_targets(afrog_targets)
        nuclei_targets = self._filter_waf_targets(nuclei_targets, stage_name="penetration_nuclei")
        afrog_targets = self._filter_waf_targets(afrog_targets, stage_name="penetration_afrog")

        nuclei_results = []
        afrog_results = []

        if nuclei_targets:
            logger.info(
                "start penetration nuclei task_id:{} targets:{} tags:{}".format(
                    self.task_id,
                    len(nuclei_targets),
                    ",".join(self.PENETRATION_NUCLEI_TAGS),
                )
            )
            nuclei_results = nuclei_scan(
                nuclei_targets,
                scan_profile={
                    "name": "penetration",
                    "force_tags": self.PENETRATION_NUCLEI_TAGS,
                },
            )

        if afrog_targets:
            logger.info(
                "start penetration afrog task_id:{} targets:{} keywords:{} severity:{}".format(
                    self.task_id,
                    len(afrog_targets),
                    self.AFROG_SEARCH_KEYWORDS,
                    self.AFROG_SEVERITY,
                )
            )
            afrog_results = run_afrog_scan(
                afrog_targets,
                search_keywords=self.AFROG_SEARCH_KEYWORDS,
                severity=self.AFROG_SEVERITY,
            )

        logger.info(
            "penetration scan done task_id:{} collected:{} nuclei_targets:{} afrog_targets:{} nuclei_results:{} afrog_results:{}".format(
                self.task_id,
                len(all_targets),
                len(nuclei_targets),
                len(afrog_targets),
                len(nuclei_results),
                len(afrog_results),
            )
        )

        return {
            "targets": all_targets,
            "nuclei_targets": nuclei_targets,
            "afrog_targets": afrog_targets,
            "nuclei_results": nuclei_results,
            "afrog_results": afrog_results,
        }


def run_penetration_scan(task_id: str, sites: list, page_url_set=None, waf_guard=None):
    service = PenetrationScanService(
        task_id=task_id,
        sites=sites,
        page_url_set=page_url_set,
        waf_guard=waf_guard,
    )
    return service.run()
