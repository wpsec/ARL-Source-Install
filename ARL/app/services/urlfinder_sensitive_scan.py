"""
URLFinder 二次敏感信息扫描服务

能力说明：
- 对 URLFinder 提取出的 URL/JS/HTML 目标执行二次敏感信息扫描（复用 WIH）
- 严格限制仅扫描当前任务目标 host，避免跨站误扫
- 对扫描结果再次进行 host 过滤，确保只保留同目标记录
"""
from typing import List, Set
from urllib.parse import urlparse

from app import utils
from app.config import Config
from app.modules import WihRecord
from .infoHunter import run_wih

logger = utils.get_logger()


class UrlfinderSensitiveScanner:
    def __init__(self, sites: List[str], wih_records: List[WihRecord]):
        self.sites = list(sites or [])
        self.wih_records = list(wih_records or [])

        self.max_targets = int(getattr(Config, "URLFINDER_SENSITIVE_MAX_TARGETS", 300) or 300)
        self.include_js = bool(getattr(Config, "URLFINDER_SENSITIVE_INCLUDE_JS", True))

        if self.max_targets < 1:
            self.max_targets = 1

        self.allowed_hosts = self._collect_allowed_hosts()

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
    def _is_js_url(value: str) -> bool:
        text = str(value or "").strip().lower()
        if not text:
            return False
        if ".js" in text:
            return True
        path = urlparse(text).path.lower()
        return path.endswith(".js")

    def _normalize_target_url(self, raw_url: str) -> str:
        text = str(raw_url or "").strip()
        if not self._is_http_url(text):
            return ""

        parsed = urlparse(text)
        if parsed.scheme not in ("http", "https"):
            return ""
        if not parsed.netloc:
            return ""

        host = self._extract_host(text)
        if not host or host not in self.allowed_hosts:
            return ""

        if parsed.fragment:
            parsed = parsed._replace(fragment="")
        return parsed.geturl()

    def _collect_targets(self) -> List[str]:
        targets: Set[str] = set()

        for record in self.wih_records:
            record_type = str(getattr(record, "recordType", "") or "").strip().lower()
            if not record_type.startswith("urlfinder_"):
                continue

            for candidate in (
                str(getattr(record, "content", "") or "").strip(),
                str(getattr(record, "source", "") or "").strip(),
            ):
                normalized = self._normalize_target_url(candidate)
                if not normalized:
                    continue

                if (not self.include_js) and self._is_js_url(normalized):
                    continue

                targets.add(normalized)

        target_list = sorted(targets)
        if len(target_list) > self.max_targets:
            target_list = target_list[: self.max_targets]

        return target_list

    def _record_in_scope(self, record: WihRecord) -> bool:
        source = str(getattr(record, "source", "") or "").strip()
        site = str(getattr(record, "site", "") or "").strip()

        source_host = self._extract_host(source) if source else ""
        site_host = self._extract_host(site) if site else ""

        if source_host and source_host not in self.allowed_hosts:
            return False
        if site_host and site_host not in self.allowed_hosts:
            return False

        return True

    def run(self) -> List[WihRecord]:
        if not bool(getattr(Config, "URLFINDER_SENSITIVE_ENABLE", True)):
            logger.info("urlfinder sensitive scan skip, disabled")
            return []

        if not self.allowed_hosts:
            logger.info("urlfinder sensitive scan skip, no allowed hosts from current target sites")
            return []

        targets = self._collect_targets()
        if not targets:
            logger.info("urlfinder sensitive scan skip, no in-scope targets from urlfinder records")
            return []

        logger.info(
            "urlfinder sensitive scan start, hosts:{} targets:{} include_js:{}".format(
                len(self.allowed_hosts),
                len(targets),
                self.include_js,
            )
        )

        try:
            records = list(run_wih(targets) or [])
        except Exception as e:
            logger.warning("urlfinder sensitive scan failed {}".format(e))
            return []

        filtered: List[WihRecord] = []
        skipped = 0
        for record in records:
            if self._record_in_scope(record):
                filtered.append(record)
            else:
                skipped += 1

        if skipped > 0:
            logger.info(
                "urlfinder sensitive scan host filter applied, raw:{} kept:{} skipped:{}".format(
                    len(records),
                    len(filtered),
                    skipped,
                )
            )

        return filtered


def run_urlfinder_sensitive_scan(sites: List[str], wih_records: List[WihRecord]) -> List[WihRecord]:
    scanner = UrlfinderSensitiveScanner(sites=sites, wih_records=wih_records)
    return scanner.run()
