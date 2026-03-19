"""
URLFinder 提取 URL 可达性探测并入库

能力说明：
- 从 WIH 的 `urlfinder_url/path_url` 记录中筛选当前任务同目标 URL
- 探测 URL 可达性并提取页面基础信息
- 将可访问 URL 写入 url 资产表，来源标记为 wih_url_probe
"""
from typing import List, Optional, Set
from urllib.parse import urlparse

from app import utils
from app.config import Config
from app.modules import CollectSource, WihRecord
from app.services.pageFetch import page_fetch
from app.services.url_candidate_filter import normalize_http_url_candidate

logger = utils.get_logger()


class UrlfinderUrlProbeService:
    """
    URLFinder/WIH 路径 URL 可达性探测服务。

    说明：
    - `urlfinder_url`：URLFinder 从 HTML/JS 提取出的候选 URL
    - `path_url`：WIH 对 path 规则拼接探测命中的候选 URL
    两类记录都会进入可达性探测，命中后统一写入 URL 信息表。
    """

    _SUPPORTED_RECORD_TYPES = {"urlfinder_url", "path_url"}

    def __init__(
        self,
        task_id: str,
        sites: List[str],
        wih_records: List[WihRecord],
        page_url_set: Optional[Set[str]] = None,
        waf_guard=None,
    ):
        self.task_id = str(task_id or "").strip()
        self.sites = list(sites or [])
        self.wih_records = list(wih_records or [])
        self.page_url_set = page_url_set if isinstance(page_url_set, set) else None
        self.waf_guard = waf_guard

        self.enable = bool(getattr(Config, "URLFINDER_URL_PROBE_ENABLE", True))
        self.max_targets = int(getattr(Config, "URLFINDER_URL_PROBE_MAX_TARGETS", 300) or 300)
        self.concurrency = int(getattr(Config, "URLFINDER_URL_PROBE_CONCURRENCY", 6) or 6)
        self.dns_policy_cache = {}

        if self.max_targets < 1:
            self.max_targets = 1
        if self.concurrency < 1:
            self.concurrency = 1

        self.allowed_hosts = self._collect_allowed_hosts()
        self.record_type_counter = {}

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
        hosts = set()
        for site in self.sites:
            host = self._extract_host(site)
            if host:
                hosts.add(host)
        return hosts

    @staticmethod
    def _is_http_url(value: str) -> bool:
        text = str(value or "").strip().lower()
        return text.startswith("http://") or text.startswith("https://")

    def _normalize_url(self, value: str) -> str:
        text = str(value or "").strip()
        if not self._is_http_url(text):
            return ""

        return normalize_http_url_candidate(
            text,
            allowed_hosts=self.allowed_hosts,
            allow_js=False,
        )

    def _collect_candidates(self) -> List[str]:
        urls = set()
        for record in self.wih_records:
            record_type = str(getattr(record, "recordType", "") or "").strip().lower()
            if record_type not in self._SUPPORTED_RECORD_TYPES:
                continue
            self.record_type_counter[record_type] = self.record_type_counter.get(record_type, 0) + 1
            normalized = self._normalize_url(getattr(record, "content", ""))
            if normalized:
                urls.add(normalized)
        return sorted(urls)

    @staticmethod
    def _build_url_item(url: str, task_id: str, source: str):
        item = {
            "site": url,
            "task_id": task_id,
            "source": source,
        }
        domain_parsed = utils.domain_parsed(url)
        if domain_parsed:
            item["fld"] = domain_parsed["fld"]
        return item

    def _filter_existing(self, targets: List[str]) -> List[str]:
        if not targets:
            return []

        existing_urls = set()
        if self.page_url_set:
            existing_urls |= set(self.page_url_set)

        db_existing = utils.conn_db("url").distinct(
            "url",
            {
                "task_id": self.task_id,
                "url": {"$in": targets},
            },
        )
        existing_urls |= set(db_existing or [])

        return [url for url in targets if url not in existing_urls]

    def _filter_dns_policy(self, targets: List[str]) -> List[str]:
        keep_targets = []
        for url in targets:
            allow_scan, policy_detail = utils.check_dns_policy_for_url(url, cache_map=self.dns_policy_cache)
            if allow_scan:
                keep_targets.append(url)
                continue

            logger.info(
                "skip urlfinder url probe by dns policy url:{} reason:{} resolver_ips:{} system_ips:{}".format(
                    url,
                    policy_detail.get("reason", ""),
                    policy_detail.get("resolver_ips", []),
                    policy_detail.get("system_ips", []),
                )
            )
        return keep_targets

    def _insert_url_pages(self, page_map: dict) -> int:
        inserted = 0
        for url, page_data in (page_map or {}).items():
            if not isinstance(page_data, dict):
                continue

            item = self._build_url_item(url, self.task_id, source=CollectSource.WIH_URL_PROBE)
            item.update(page_data)
            utils.conn_db("url").insert_one(item)
            inserted += 1

            if self.page_url_set is not None:
                self.page_url_set.add(url)

        return inserted

    def run(self) -> int:
        if not self.enable:
            logger.info("urlfinder url probe skip, disabled")
            return 0

        if not self.task_id:
            logger.info("urlfinder url probe skip, task_id is empty")
            return 0

        candidates = self._collect_candidates()
        if not candidates:
            logger.info("urlfinder url probe skip, no urlfinder_url/path_url records")
            return 0

        pending_targets = self._filter_existing(candidates)
        if not pending_targets:
            logger.info("urlfinder url probe skip, all candidates already collected")
            return 0

        if len(pending_targets) > self.max_targets:
            pending_targets = pending_targets[: self.max_targets]

        probe_targets = self._filter_dns_policy(pending_targets)
        if not probe_targets:
            logger.info("urlfinder url probe skip, no targets after dns policy filtering")
            return 0

        page_map = page_fetch(
            probe_targets,
            concurrency=self.concurrency,
            waf_guard=self.waf_guard,
            waf_module="urlfinder_url_probe",
        )
        inserted_count = self._insert_url_pages(page_map)

        logger.info(
            "urlfinder url probe done, record_types:{} candidates:{} pending:{} dns_keep:{} inserted:{}".format(
                self.record_type_counter,
                len(candidates),
                len(pending_targets),
                len(probe_targets),
                inserted_count,
            )
        )
        return inserted_count


def run_urlfinder_url_probe(
    task_id: str,
    sites: List[str],
    wih_records: List[WihRecord],
    page_url_set: Optional[Set[str]] = None,
    waf_guard=None,
) -> int:
    service = UrlfinderUrlProbeService(
        task_id=task_id,
        sites=sites,
        wih_records=wih_records,
        page_url_set=page_url_set,
        waf_guard=waf_guard,
    )
    return service.run()
