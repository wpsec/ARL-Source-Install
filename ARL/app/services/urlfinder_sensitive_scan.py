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


class UrlfinderSensitiveResult(list):
    """保持 list 兼容性，同时携带二次扫描的批次统计。"""

    def __init__(self, values=None, metrics=None):
        super().__init__(values or [])
        self.metrics = dict(metrics or {})

try:
    from .rust_accel import (
        rank_sensitive_targets as rust_rank_sensitive_targets,
    )
except Exception as exc:
    logger.warning(
        "rust acceleration adapter unavailable stage:rank reason_type:{}".format(type(exc).__name__)
    )

    class _UnavailableRustBatchResult(list):
        def __init__(self, batch_size=0):
            super().__init__()
            self.used_native = False
            self.metrics = {
                "stage": "rank",
                "backend": "python",
                "used_native": False,
                "fallback_count": 1,
                "fallback_reason": "adapter_import_error",
                "batch_size": int(batch_size or 0),
            }

    def rust_rank_sensitive_targets(*args, **kwargs):
        if not bool(getattr(Config, "RUST_ACCEL_FALLBACK_ENABLE", True)):
            raise RuntimeError("Rust acceleration adapter unavailable at rank")
        records = kwargs.get("records") if "records" in kwargs else (args[0] if args else [])
        return _UnavailableRustBatchResult(len(list(records or [])))


class UrlfinderSensitiveScanner:
    SECONDARY_WIH_BATCH_SIZE = 24
    LOW_VALUE_SCORE_THRESHOLD = 20
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
        self.last_target_metrics = {}
        self.last_run_metrics = {}
        self.rust_metrics = {
            "call_count": 0,
            "native_call_count": 0,
            "fallback_count": 0,
            "fallback_reasons": {},
        }

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
        native_records = []
        for record in self.wih_records:
            native_records.append(
                {
                    "record_type": str(getattr(record, "recordType", "") or ""),
                    "content": str(getattr(record, "content", "") or ""),
                    "source": str(getattr(record, "source", "") or ""),
                    "site": str(getattr(record, "site", "") or ""),
                }
            )

        blocked_hosts = []
        if self.waf_guard:
            blocked_hosts = [
                host for host in sorted(self.allowed_hosts) if self.waf_guard.is_blocked_host(host)
            ]
        native_result = rust_rank_sensitive_targets(
            records=native_records,
            sites=self.sites,
            blocked_hosts=blocked_hosts,
            include_js=self.include_js,
            max_targets=self.max_targets,
        )
        self.rust_metrics["call_count"] += 1
        batch_metrics = getattr(native_result, "metrics", {})
        fallback_count = int(batch_metrics.get("fallback_count", 0) or 0)
        self.rust_metrics["fallback_count"] += fallback_count
        if fallback_count:
            reason = str(batch_metrics.get("fallback_reason", "unknown") or "unknown")
            reasons = self.rust_metrics.setdefault("fallback_reasons", {})
            reasons[reason] = int(reasons.get(reason, 0) or 0) + fallback_count

        if bool(getattr(native_result, "used_native", False)):
            self.rust_metrics["native_call_count"] += 1
            native_targets = list(native_result or [])
            low_value_target_count = sum(
                1 for _, score in native_targets
                if int(score or 0) < self.LOW_VALUE_SCORE_THRESHOLD
            )
            self.last_target_metrics = {
                "candidate_count": len(native_records),
                "target_count": len(native_targets),
                "low_value_target_count": low_value_target_count,
                "backend": "rust",
            }
            return [str(item[0]) for item in native_targets]

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

        low_value_target_count = sum(
            1 for score in target_scores.values()
            if int(score or 0) < self.LOW_VALUE_SCORE_THRESHOLD
        )
        target_list = [
            item[0]
            for item in sorted(target_scores.items(), key=lambda item: (-int(item[1] or 0), item[0]))
        ]
        if len(target_list) > self.max_targets:
            target_list = target_list[: self.max_targets]

        self.last_target_metrics = {
            "candidate_count": len(native_records),
            "target_count": len(target_list),
            "low_value_target_count": low_value_target_count,
            "backend": "python",
        }

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
        hunter.wih_deadline_ts = time.time() + max(1, int(timeout_sec or self.secondary_wih_timeout_sec))
        # 二次敏感扫描的目标主要是 URL/HTML/JS，关闭 runtime 能明显降低耗时与资源占用。
        hunter.wih_runtime_enable = False
        hunter.wih_runtime_driver = "noop"
        hunter.wih_runtime_command = ""
        return hunter

    def _run_secondary_wih(self, targets: List[str]) -> List[WihRecord]:
        batches = self._split_targets(targets)
        if not batches:
            self.last_run_metrics = {
                "status": "skipped",
                "end_reason": "no_targets",
                "input_count": 0,
                "output_count": 0,
                "candidate_metrics": dict(self.last_target_metrics),
            }
            return []

        start_at = time.time()
        metric_started = time.monotonic()
        merged_records: List[WihRecord] = []
        seen_fingerprints: Set[str] = set()
        no_gain_batches = 0
        processed_batches = 0
        duplicate_record_count = 0
        slow_batch_count = 0
        slow_candidate_count = 0
        batch_error_count = 0
        stop_reason = ""

        for index, batch_targets in enumerate(batches, start=1):
            elapsed = max(0.0, time.time() - start_at)
            if self.stage_timeout_sec > 0:
                remaining = int(self.stage_timeout_sec - elapsed)
                if remaining < 60:
                    stop_reason = "timeout"
                    logger.warning(
                        "urlfinder sensitive scan stage timeout reached elapsed:{:.2f}s timeout:{}s finished_batch:{}/{} reason:timeout".format(
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

            batch_started = time.monotonic()
            try:
                hunter = self._build_secondary_hunter(batch_targets, batch_timeout)
                batch_records = list(hunter.run() or [])
            except Exception as e:
                batch_error_count += 1
                logger.warning(
                    "urlfinder sensitive scan batch failed batch:{}/{} targets:{} err:{}".format(
                        index,
                        len(batches),
                        len(batch_targets),
                        e,
                    )
                )
                continue

            batch_elapsed = max(0.0, time.monotonic() - batch_started)
            if batch_timeout > 0 and batch_elapsed >= float(batch_timeout) * 0.8:
                slow_batch_count += 1
                slow_candidate_count += len(batch_targets)
            processed_batches += 1

            batch_new_records = 0
            for record in batch_records:
                fingerprint = self._record_fingerprint(record)
                if fingerprint in seen_fingerprints:
                    continue
                seen_fingerprints.add(fingerprint)
                merged_records.append(record)
                batch_new_records += 1

            duplicate_record_count += max(0, len(batch_records) - batch_new_records)

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
                stop_reason = "no_gain"
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

        if not stop_reason:
            if batch_error_count > 0:
                stop_reason = "batch_error"
            elif processed_batches < len(batches):
                stop_reason = "partial"
            else:
                stop_reason = "completed"

        if stop_reason == "completed":
            status = "success"
        elif merged_records or processed_batches > 0:
            status = "partial"
        else:
            status = "timeout" if stop_reason == "timeout" else "error"
        self.last_run_metrics = {
            "status": status,
            "end_reason": stop_reason,
            # 二次敏感扫描经 InfoHunter 拉起 Go WIH 子进程，任务内缓存不可见。
            "external_network": "wih_go",
            "input_count": len(targets),
            "output_count": len(merged_records),
            "batch_count": len(batches),
            "processed_batch_count": processed_batches,
            "no_gain_batches": no_gain_batches,
            "duplicate_record_count": duplicate_record_count,
            "slow_batch_count": slow_batch_count,
            "slow_candidate_count": slow_candidate_count,
            "low_value_candidate_count": int(
                self.last_target_metrics.get("low_value_target_count", 0) or 0
            ),
            "batch_error_count": batch_error_count,
            "candidate_metrics": dict(self.last_target_metrics),
            "elapsed": max(0.0, time.monotonic() - metric_started),
        }
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
            self.last_run_metrics = {
                "status": "skipped",
                "end_reason": "disabled",
                "input_count": 0,
                "output_count": 0,
                "budget_sec": self.stage_timeout_sec or None,
            }
            logger.info("urlfinder sensitive scan skip, disabled")
            return []

        if not self.allowed_hosts:
            self.last_run_metrics = {
                "status": "skipped",
                "end_reason": "no_allowed_hosts",
                "input_count": 0,
                "output_count": 0,
                "budget_sec": self.stage_timeout_sec or None,
            }
            logger.info("urlfinder sensitive scan skip, no allowed hosts from current target sites")
            return []

        targets = self._collect_targets()
        if not targets:
            self.last_run_metrics = {
                "status": "skipped",
                "end_reason": "no_targets",
                "input_count": 0,
                "output_count": 0,
                "budget_sec": self.stage_timeout_sec or None,
                "candidate_metrics": dict(self.last_target_metrics),
            }
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

        self.last_run_metrics["output_count"] = len(filtered)
        self.last_run_metrics["filtered_out_count"] = skipped
        return filtered


def run_urlfinder_sensitive_scan(sites: List[str], wih_records: List[WihRecord], waf_guard=None) -> List[WihRecord]:
    scanner = UrlfinderSensitiveScanner(sites=sites, wih_records=wih_records, waf_guard=waf_guard)
    results = scanner.run()
    rust_metrics = dict(scanner.rust_metrics)
    rank_calls = int(rust_metrics.get("call_count", 0) or 0)
    fallback_count = int(rust_metrics.get("fallback_count", 0) or 0)
    native_batch_count = int(rust_metrics.get("native_call_count", 0) or 0)
    if native_batch_count > 0 and fallback_count > 0:
        backend = "mixed"
    elif native_batch_count > 0:
        backend = "rust"
    else:
        backend = "python"
    scanner.last_run_metrics.update(
        {
            "backend": backend,
            "fallback_count": fallback_count,
            "fallback_reason": str(
                next(iter((rust_metrics.get("fallback_reasons") or {}).keys()), "")
            ) if fallback_count else "",
            "fallback_reasons": dict(rust_metrics.get("fallback_reasons") or {}),
            "batch_count": rank_calls,
            "native_batch_count": native_batch_count,
        }
    )
    candidate_metrics = scanner.last_run_metrics.get("candidate_metrics")
    if isinstance(candidate_metrics, dict):
        candidate_metrics["backend"] = backend
        candidate_metrics["fallback_count"] = fallback_count
    return UrlfinderSensitiveResult(results, metrics=scanner.last_run_metrics)
