"""wafw00f 补充识别适配器。

适配器只负责一次受控的指纹探测和结果归一化；WAF 是否跳过主动风险阶段仍由
WAFSmartSkipGuard 决定，避免外部库状态泄漏到任务编排层。
"""

import hashlib
import logging
import socket
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError, as_completed
from urllib.parse import urlsplit, urlunsplit

import requests

from app import utils
from app.config import Config


logger = utils.get_logger()


class WAFW00FAdapter(object):
    """对 wafw00f Python API 做 fail-open、可限时的任务级封装。"""

    GENERIC_TOKENS = ("generic", "unknown", "unidentified")

    def __init__(self, detector_factory=None, config=None, clock=None):
        self.detector_factory = detector_factory
        self.config = config or Config
        self.clock = clock or time.monotonic
        self.task_id = ""

    @staticmethod
    def normalize_target(target):
        """移除认证、查询和片段，只保留同源 HTTP 目标的路径。"""
        text = str(target or "").strip()
        if not text:
            return ""
        parsed = urlsplit(text)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return ""
        try:
            port = parsed.port
        except ValueError:
            return ""
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname.rstrip(".").lower()
        if not hostname:
            return ""
        if ":" in hostname and not hostname.startswith("["):
            hostname = "[{}]".format(hostname)
        default_port = 443 if scheme == "https" else 80
        effective_port = int(port or default_port)
        netloc = "{}:{}".format(hostname, effective_port)
        path = parsed.path or "/"
        return urlunsplit((scheme, netloc, path, "", ""))

    @classmethod
    def endpoint_key(cls, target):
        normalized = cls.normalize_target(target)
        if not normalized:
            return ""
        parsed = urlsplit(normalized)
        return "{}://{}".format(parsed.scheme, parsed.netloc)

    @staticmethod
    def _host_label(target):
        try:
            host = urlsplit(target).hostname or ""
        except Exception:
            host = ""
        digest = hashlib.sha256(host.encode("utf-8", "ignore")).hexdigest()
        return digest[:12]

    @staticmethod
    def _is_generic(names):
        values = [str(item or "").strip().lower() for item in names or []]
        return bool(values) and any(
            any(token in value for token in WAFW00FAdapter.GENERIC_TOKENS)
            for value in values
        )

    def _build_detector(self, target):
        if callable(self.detector_factory):
            return self.detector_factory(target)

        # wafw00f 的导入必须保持惰性，smart_skip_waf 关闭时不会要求安装它。
        library_logger = logging.getLogger("wafw00f")
        library_logger.setLevel(logging.CRITICAL)
        library_logger.propagate = False
        from wafw00f.main import WAFW00F

        proxy = str(getattr(self.config, "PROXY_URL", "") or "").strip()
        proxies = {"http": proxy, "https": proxy} if proxy else {}
        return WAFW00F(
            target=target,
            followredirect=False,
            extraheaders={},
            proxies=proxies,
            timeout=max(1, int(getattr(self.config, "WAFW00F_TIMEOUT_SEC", 7) or 7)),
        )

    def probe(self, target):
        """探测单个目标，返回不包含 URL 和响应正文的安全结果。"""
        started = self.clock()
        result = {
            "status": "error",
            "names": [],
            "confidence": "",
            "evidence": [],
            "request_count": 0,
            "elapsed_sec": 0.0,
            "exception_type": "",
        }
        detector = None
        try:
            detector = self._build_detector(target)
            detected, _trigger_url = detector.identwaf(findall=False)
            if detected is False or detected is None:
                names = []
            else:
                names = detected if isinstance(detected, (list, tuple, set)) else [detected]
                names = [
                    str(item or "").replace("\r", " ").replace("\n", " ").strip()[:120]
                    for item in names
                    if str(item or "").strip()
                ]
            if names and not self._is_generic(names):
                result.update(
                    status="detected",
                    names=names[:8],
                    confidence="high",
                    evidence=["wafw00f:{}".format(item) for item in names[:8]],
                )
            elif names:
                result.update(
                    status="generic",
                    names=names[:8],
                    confidence="low",
                    evidence=["wafw00f:{}".format(item) for item in names[:8]],
                )
            else:
                result["status"] = "not_detected"
        except Exception as exc:
            result["status"] = "timeout" if self._is_timeout(exc) else "error"
            result["exception_type"] = type(exc).__name__
        finally:
            try:
                result["request_count"] = max(
                    0, int(getattr(detector, "requestnumber", 0) or 0)
                )
            except (TypeError, ValueError):
                result["request_count"] = 0
            result["elapsed_sec"] = round(max(0.0, self.clock() - started), 6)
            self._log_result(target, result)
        return result

    @staticmethod
    def _is_timeout(error):
        if isinstance(error, (requests.exceptions.Timeout, socket.timeout, TimeoutError)):
            return True
        return "timeout" in type(error).__name__.lower() or "timed out" in str(error).lower()

    def _log_result(self, target, result):
        vendors = ",".join(
            str(item).replace("\r", " ").replace("\n", " ").strip()
            for item in (result.get("names") or [])
        ) or "-"
        logger.info(
            "task_id:%s wafw00f host_id:%s status:%s vendors:%s requests:%s elapsed:%.3f exception_type:%s",
            self.task_id or "-",
            self._host_label(target),
            result.get("status", "error"),
            vendors,
            result.get("request_count", 0),
            float(result.get("elapsed_sec", 0.0) or 0.0),
            result.get("exception_type", "") or "-",
        )

    def run(self, targets, guard, task_id=""):
        """批量探测并把结果写入守卫；所有外部异常均转换为阶段指标。"""
        started = self.clock()
        self.task_id = str(task_id or "")
        metrics = {
            "status": "success",
            "end_reason": "completed",
            "input_count": 0,
            "output_count": 0,
            "checked_count": 0,
            "detected_count": 0,
            "not_detected_count": 0,
            "generic_count": 0,
            "timeout_count": 0,
            "error_count": 0,
            "skipped_by_passive_count": 0,
            "target_cap_skipped_count": 0,
            "request_count": 0,
            "elapsed_sec": 0.0,
        }
        if not getattr(guard, "enabled", False) or not getattr(guard, "smart_skip_enabled", False):
            metrics["end_reason"] = "smart_skip_disabled"
            return metrics

        unique = {}
        for target in targets or []:
            normalized = self.normalize_target(target)
            key = self.endpoint_key(normalized)
            if not key or key in unique:
                continue
            unique[key] = normalized
        metrics["input_count"] = len(unique)

        candidates = []
        for target in unique.values():
            if not guard.can_probe_wafw00f(target):
                metrics["skipped_by_passive_count"] += 1
                continue
            candidates.append(target)

        max_targets = max(1, int(getattr(self.config, "WAFW00F_MAX_TARGETS", 200) or 200))
        if len(candidates) > max_targets:
            metrics["target_cap_skipped_count"] = len(candidates) - max_targets
            candidates = candidates[:max_targets]

        if not candidates:
            metrics["elapsed_sec"] = round(max(0.0, self.clock() - started), 6)
            self._attach_metric_names(metrics)
            guard.record_wafw00f_metrics(metrics)
            return metrics

        concurrency = max(1, int(getattr(self.config, "WAFW00F_CONCURRENCY", 2) or 2))
        stage_timeout = max(
            1.0, float(getattr(self.config, "WAFW00F_STAGE_TIMEOUT_SEC", 900) or 900)
        )
        deadline = self.clock() + stage_timeout
        executor = ThreadPoolExecutor(max_workers=concurrency)
        future_map = {executor.submit(self.probe, target): target for target in candidates}
        processed_futures = set()
        try:
            for future in as_completed(future_map, timeout=stage_timeout):
                target = future_map[future]
                if self.clock() > deadline:
                    break
                try:
                    result = future.result()
                except Exception as exc:
                    result = {
                        "status": "timeout" if self._is_timeout(exc) else "error",
                        "names": [],
                        "confidence": "",
                        "evidence": [],
                        "request_count": 0,
                        "elapsed_sec": 0.0,
                        "exception_type": type(exc).__name__,
                    }
                guard.record_wafw00f_result(target, result)
                self._count_result(metrics, result)
                processed_futures.add(future)
        except FuturesTimeoutError:
            metrics["status"] = "partial"
            metrics["end_reason"] = "stage_budget_exhausted"
        finally:
            for future, target in future_map.items():
                if future in processed_futures:
                    continue
                if future.done():
                    try:
                        result = future.result()
                    except Exception as exc:
                        result = {
                            "status": "timeout" if self._is_timeout(exc) else "error",
                            "names": [],
                            "evidence": [],
                            "request_count": 0,
                            "elapsed_sec": 0.0,
                            "exception_type": type(exc).__name__,
                        }
                    guard.record_wafw00f_result(target, result)
                    self._count_result(metrics, result)
                    continue
                if not future.done():
                    future.cancel()
                    guard.record_wafw00f_result(
                        target,
                        {
                            "status": "timeout",
                            "names": [],
                            "confidence": "",
                            "evidence": [],
                            "request_count": 0,
                            "elapsed_sec": 0.0,
                            "exception_type": "StageTimeout",
                        },
                    )
                    self._count_result(metrics, {"status": "timeout", "request_count": 0})
            executor.shutdown(wait=False, cancel_futures=True)

        metrics["output_count"] = metrics["checked_count"]
        metrics["elapsed_sec"] = round(max(0.0, self.clock() - started), 6)
        if metrics["timeout_count"] or metrics["error_count"]:
            metrics["status"] = "partial"
        if task_id:
            logger.info(
                "task_id:%s wafw00f batch checked:%s detected:%s timeout:%s error:%s elapsed:%.3f",
                task_id,
                metrics["checked_count"],
                metrics["detected_count"],
                metrics["timeout_count"],
                metrics["error_count"],
                metrics["elapsed_sec"],
            )
        self._attach_metric_names(metrics)
        guard.record_wafw00f_metrics(metrics)
        return metrics

    @staticmethod
    def _attach_metric_names(metrics):
        mapping = {
            "checked_count": "wafw00f_checked_total",
            "detected_count": "wafw00f_detected_total",
            "not_detected_count": "wafw00f_not_detected_total",
            "timeout_count": "wafw00f_timeout_total",
            "error_count": "wafw00f_error_total",
            "skipped_by_passive_count": "wafw00f_skipped_by_passive_total",
            "target_cap_skipped_count": "wafw00f_target_cap_skipped_total",
            "request_count": "wafw00f_request_total",
            "elapsed_sec": "wafw00f_elapsed_sec",
        }
        for source_key, target_key in mapping.items():
            metrics[target_key] = metrics.get(source_key, 0)

    @staticmethod
    def _count_result(metrics, result):
        status = str(result.get("status", "error") or "error")
        metrics["checked_count"] += 1
        metrics["request_count"] += max(0, int(result.get("request_count", 0) or 0))
        if status == "detected":
            metrics["detected_count"] += 1
        elif status == "not_detected":
            metrics["not_detected_count"] += 1
        elif status == "generic":
            metrics["generic_count"] += 1
        elif status == "timeout":
            metrics["timeout_count"] += 1
        else:
            metrics["error_count"] += 1
