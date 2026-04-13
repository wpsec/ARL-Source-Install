"""
URLFinder 二次敏感信息扫描服务

能力说明：
- 对 URLFinder 提取出的 URL/JS/HTML 目标执行二次敏感信息扫描（复用 WIH）
- 严格限制仅扫描当前任务目标 host，避免跨站误扫
- 对扫描结果再次进行 host 过滤，确保只保留同目标记录

设计补充：
- 二次敏感扫描默认走“轻量 WIH”模式，避免在主 WIH 阶段里再次拉起大预算 runtime
- 通过分批、小超时与总预算控制，把该增强链路限制在可预期的时间窗口内
"""
import time
from typing import List, Set
from urllib.parse import urlparse

from app import utils
from app.config import Config
from app.modules import WihRecord
from .infoHunter import InfoHunter
from .url_candidate_filter import normalize_http_url_candidate

logger = utils.get_logger()


class UrlfinderSensitiveScanner:
    SECONDARY_WIH_BATCH_SIZE = 24
    _SENSITIVE_PATH_KEYWORDS = (
        "api",
        "ajax",
        "admin",
        "auth",
        "login",
        "logout",
        "upload",
        "download",
        "export",
        "import",
        "graphql",
        "search",
        "query",
        "config",
        "report",
        "token",
        "user",
        "account",
        "order",
        "payment",
        "invoice",
    )
    _CRITICAL_PATH_KEYWORDS = (
        "admin",
        "export",
        "upload",
        "download",
        "report",
        "graphql",
        "config",
        "token",
    )

    def __init__(self, sites: List[str], wih_records: List[WihRecord], waf_guard=None):
        self.sites = list(sites or [])
        self.wih_records = list(wih_records or [])
        self.waf_guard = waf_guard

        self.max_targets = int(getattr(Config, "URLFINDER_SENSITIVE_MAX_TARGETS", 300) or 300)
        self.include_js = bool(getattr(Config, "URLFINDER_SENSITIVE_INCLUDE_JS", True))
        self.secondary_wih_timeout_sec = int(
            getattr(Config, "URLFINDER_SENSITIVE_WIH_TIMEOUT_SEC", 10 * 60) or (10 * 60)
        )
        self.stage_timeout_sec = int(
            getattr(Config, "URLFINDER_SENSITIVE_STAGE_TIMEOUT_SEC", 30 * 60) or (30 * 60)
        )
        self.no_gain_batch_limit = int(
            getattr(Config, "URLFINDER_SENSITIVE_NO_GAIN_BATCH_LIMIT", 2) or 2
        )

        if self.max_targets < 1:
            self.max_targets = 1
        if self.secondary_wih_timeout_sec < 60:
            self.secondary_wih_timeout_sec = 60
        if self.stage_timeout_sec < 0:
            self.stage_timeout_sec = 0
        if self.no_gain_batch_limit < 0:
            self.no_gain_batch_limit = 0

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
        normalized = normalize_http_url_candidate(
            raw_url,
            allowed_hosts=self.allowed_hosts,
            allow_js=self.include_js,
        )
        if not normalized:
            return ""

        host = self._extract_host(normalized)
        if not host or host not in self.allowed_hosts:
            return ""
        if self.waf_guard and self.waf_guard.is_blocked_host(host):
            return ""
        return normalized

    def _score_candidate(self, normalized_url: str, record_type: str = "", source: str = "") -> int:
        parsed = urlparse(str(normalized_url or "").strip())
        path_text = str(parsed.path or "").strip().lower()
        query_text = str(parsed.query or "").strip().lower()
        record_type_text = str(record_type or "").strip().lower()
        source_host = self._extract_host(source)
        target_host = self._extract_host(normalized_url)

        score = 10
        if self._is_js_url(normalized_url):
            score += 4
        else:
            score += 6
        if query_text:
            score += 4
        if source_host and target_host and source_host == target_host:
            score += 2
        if "urlfinder_js" in record_type_text:
            score += 2
        if "urlfinder_url" in record_type_text:
            score += 3

        for keyword in self._SENSITIVE_PATH_KEYWORDS:
            if keyword in path_text:
                score += 3
        for keyword in self._CRITICAL_PATH_KEYWORDS:
            if keyword in path_text:
                score += 2
        if path_text.count("/") >= 3:
            score += 2
        if any(token in query_text for token in ("id=", "token=", "kw=", "keyword=", "page=", "size=")):
            score += 3
        return score

    def _collect_targets(self) -> List[str]:
        target_scores = {}

        for record in self.wih_records:
            record_type = str(getattr(record, "recordType", "") or "").strip().lower()
            if not record_type.startswith("urlfinder_"):
                continue
            source_text = str(getattr(record, "source", "") or "").strip()

            for candidate in (
                str(getattr(record, "content", "") or "").strip(),
                source_text,
            ):
                normalized = self._normalize_target_url(candidate)
                if not normalized:
                    continue

                if (not self.include_js) and self._is_js_url(normalized):
                    continue

                score = self._score_candidate(normalized, record_type=record_type, source=source_text)
                previous = target_scores.get(normalized)
                if previous is None or score > previous:
                    target_scores[normalized] = score

        target_list = [
            item[0]
            for item in sorted(target_scores.items(), key=lambda item: (-int(item[1] or 0), item[0]))
        ]
        if len(target_list) > self.max_targets:
            target_list = target_list[: self.max_targets]

        return target_list

    @staticmethod
    def _record_fingerprint(record: WihRecord) -> str:
        return "|".join([
            str(getattr(record, "recordType", "") or "").strip().lower(),
            str(getattr(record, "content", "") or "").strip(),
            str(getattr(record, "source", "") or "").strip(),
            str(getattr(record, "site", "") or "").strip(),
        ])

    @classmethod
    def _split_targets(cls, targets: List[str]) -> List[List[str]]:
        size = max(1, int(cls.SECONDARY_WIH_BATCH_SIZE))
        target_list = [str(item or "").strip() for item in list(targets or []) if str(item or "").strip()]
        return [target_list[idx: idx + size] for idx in range(0, len(target_list), size)]

    def _build_secondary_hunter(self, batch_targets: List[str], timeout_sec: int) -> InfoHunter:
        hunter = InfoHunter(batch_targets)
        hunter.wih_timeout_sec = max(60, int(timeout_sec or self.secondary_wih_timeout_sec))
        # 二次敏感扫描的目标主要是 URL/HTML/JS，关闭 runtime 能明显降低耗时与资源占用。
        hunter.wih_runtime_enable = False
        hunter.wih_runtime_driver = "noop"
        hunter.wih_runtime_command = ""
        return hunter

    def _run_secondary_wih(self, targets: List[str]) -> List[WihRecord]:
        batches = self._split_targets(targets)
        if not batches:
            return []

        start_at = time.time()
        merged_records: List[WihRecord] = []
        seen_fingerprints: Set[str] = set()
        no_gain_batches = 0

        for index, batch_targets in enumerate(batches, start=1):
            elapsed = max(0.0, time.time() - start_at)
            if self.stage_timeout_sec > 0:
                remaining = int(self.stage_timeout_sec - elapsed)
                if remaining < 60:
                    logger.warning(
                        "urlfinder sensitive scan stage timeout reached elapsed:{:.2f}s timeout:{}s finished_batch:{}/{}".format(
                            elapsed,
                            self.stage_timeout_sec,
                            index - 1,
                            len(batches),
                        )
                    )
                    break
                batch_timeout = min(self.secondary_wih_timeout_sec, remaining)
            else:
                batch_timeout = self.secondary_wih_timeout_sec

            logger.info(
                "urlfinder sensitive scan batch:{}/{} targets:{} timeout:{}s runtime:off".format(
                    index,
                    len(batches),
                    len(batch_targets),
                    batch_timeout,
                )
            )

            try:
                hunter = self._build_secondary_hunter(batch_targets, batch_timeout)
                batch_records = list(hunter.run() or [])
            except Exception as e:
                logger.warning(
                    "urlfinder sensitive scan batch failed batch:{}/{} targets:{} err:{}".format(
                        index,
                        len(batches),
                        len(batch_targets),
                        e,
                    )
                )
                continue

            batch_new_records = 0
            for record in batch_records:
                fingerprint = self._record_fingerprint(record)
                if fingerprint in seen_fingerprints:
                    continue
                seen_fingerprints.add(fingerprint)
                merged_records.append(record)
                batch_new_records += 1

            if batch_new_records <= 0:
                no_gain_batches += 1
            else:
                no_gain_batches = 0

            logger.info(
                "urlfinder sensitive scan batch done batch:{}/{} records:{} new_records:{} cumulative:{} no_gain_batches:{} elapsed:{:.2f}s".format(
                    index,
                    len(batches),
                    len(batch_records),
                    batch_new_records,
                    len(merged_records),
                    no_gain_batches,
                    max(0.0, time.time() - start_at),
                )
            )

            if self.no_gain_batch_limit > 0 and no_gain_batches >= self.no_gain_batch_limit:
                logger.info(
                    "urlfinder sensitive scan early stop batch:{}/{} no_gain_batches:{} limit:{} cumulative:{}".format(
                        index,
                        len(batches),
                        no_gain_batches,
                        self.no_gain_batch_limit,
                        len(merged_records),
                    )
                )
                break

        return merged_records

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
            "urlfinder sensitive scan start, hosts:{} targets:{} include_js:{} batch_size:{} batch_timeout:{}s stage_timeout:{}s".format(
                len(self.allowed_hosts),
                len(targets),
                self.include_js,
                self.SECONDARY_WIH_BATCH_SIZE,
                self.secondary_wih_timeout_sec,
                self.stage_timeout_sec,
            )
        )

        records = self._run_secondary_wih(targets)
        if not records:
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


def run_urlfinder_sensitive_scan(sites: List[str], wih_records: List[WihRecord], waf_guard=None) -> List[WihRecord]:
    scanner = UrlfinderSensitiveScanner(sites=sites, wih_records=wih_records, waf_guard=waf_guard)
    return scanner.run()
