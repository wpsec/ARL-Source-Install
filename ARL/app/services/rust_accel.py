"""Rust CPU 加速层的 Python 适配器。

适配器只负责边界转换、开关和按批次降级；业务状态、网络策略和记录对象仍由 Python 管理。
"""
import threading
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

from app import utils
from app.config import Config

logger = utils.get_logger()

try:
    import arl_accel as _NATIVE_MODULE
    _IMPORT_ERROR = None
except Exception as exc:
    _NATIVE_MODULE = None
    _IMPORT_ERROR = exc


class RustAccelerationError(RuntimeError):
    """Rust 加速不可用且未允许降级时抛出。"""


class RustBatchResult(list):
    """兼容 list 返回值，同时携带本次批处理的独立指标。"""

    def __init__(self, values=None, metrics=None, used_native=False):
        super().__init__(values or [])
        self.metrics = dict(metrics or {})
        self.used_native = bool(used_native)


_STATS = {
    "extract_calls": 0,
    "extract_fallbacks": 0,
    "html_calls": 0,
    "html_fallbacks": 0,
    "js_endpoint_calls": 0,
    "js_endpoint_fallbacks": 0,
    "rank_calls": 0,
    "rank_fallbacks": 0,
    "last_fallback_reason": "",
    "last_extract_fallback_reason": "",
    "last_rank_fallback_reason": "",
}
_FALLBACK_WARNED = set()
_STATS_LOCK = threading.Lock()


def is_native_available() -> bool:
    return _NATIVE_MODULE is not None


def get_stats() -> Dict[str, Any]:
    with _STATS_LOCK:
        return dict(_STATS)


def _increment_stat(name: str, amount: int = 1):
    with _STATS_LOCK:
        _STATS[name] = int(_STATS.get(name, 0) or 0) + int(amount or 0)


def _fallback(stage: str, batch_size: int, reason: Optional[BaseException] = None):
    fallback_key = "{}:{}".format(stage, type(reason).__name__ if reason else "ImportError")
    reason_type = (
        type(reason).__name__
        if reason
        else (type(_IMPORT_ERROR).__name__ if _IMPORT_ERROR else "ImportError")
    )
    count_key = "{}_fallbacks".format(stage)
    _increment_stat(count_key)
    with _STATS_LOCK:
        _STATS["last_fallback_reason"] = reason_type
        _STATS["last_{}_fallback_reason".format(stage)] = reason_type

    message = "rust acceleration fallback stage:{} batch_size:{} reason_type:{}".format(
        stage,
        batch_size,
        reason_type,
    )
    if fallback_key not in _FALLBACK_WARNED:
        _FALLBACK_WARNED.add(fallback_key)
        logger.warning(message)
    else:
        logger.debug(message)

    if bool(getattr(Config, "RUST_ACCEL_FALLBACK_ENABLE", True)):
        return RustBatchResult(
            metrics={
                "stage": stage,
                "backend": "python",
                "used_native": False,
                "fallback_count": 1,
                "fallback_reason": reason_type,
                "batch_size": int(batch_size or 0),
            }
        )
    raise RustAccelerationError("Rust acceleration failed at {}".format(stage))


def _enabled() -> bool:
    return bool(getattr(Config, "RUST_ACCEL_ENABLE", True))


def _disabled_result(stage: str, batch_size: int):
    return RustBatchResult(
        metrics={
            "stage": stage,
            "backend": "python",
            "used_native": False,
            "fallback_count": 0,
            "fallback_reason": "disabled",
            "batch_size": int(batch_size or 0),
        }
    )


def _page_tuple(page: Any) -> Tuple[str, str, str, int, bool]:
    if isinstance(page, dict):
        return (
            str(page.get("base_url", "") or ""),
            str(page.get("text", "") or ""),
            str(page.get("source_url", "") or ""),
            max(0, int(page.get("depth", 0) or 0)),
            bool(page.get("is_js", False)),
        )
    if isinstance(page, (tuple, list)) and len(page) == 5:
        return (
            str(page[0] or ""),
            str(page[1] or ""),
            str(page[2] or ""),
            max(0, int(page[3] or 0)),
            bool(page[4]),
        )
    raise ValueError("invalid Rust page input")


def _record_tuple(record: Any) -> Tuple[str, str, str, str]:
    if isinstance(record, dict):
        return (
            str(record.get("record_type", "") or ""),
            str(record.get("content", "") or ""),
            str(record.get("source", "") or ""),
            str(record.get("site", "") or ""),
        )
    if isinstance(record, (tuple, list)) and len(record) == 4:
        return tuple(str(item or "") for item in record)
    raise ValueError("invalid Rust record input")


def _map_extracted_records(result: Any) -> List[Dict[str, Any]]:
    if not isinstance(result, list):
        raise ValueError("invalid Rust extraction result")

    allowed_types = {
        "urlfinder_url",
        "urlfinder_js",
        "page_link",
        "page_form",
        "domain",
        "api_doc_url",
    }
    records: List[Dict[str, Any]] = []
    for item in result:
        if not isinstance(item, (tuple, list)) or len(item) != 5:
            raise ValueError("invalid Rust extraction record")
        record_type = str(item[0] or "").strip()
        if record_type not in allowed_types:
            raise ValueError("invalid Rust extraction record type")
        content = str(item[1] or "").strip()
        source = str(item[2] or "").strip()
        site = str(item[3] or "").strip()
        if not content or not source or not site:
            raise ValueError("invalid Rust extraction record fields")
        records.append(
            {
                "record_type": record_type,
                "content": content,
                "source": source,
                "site": site,
                "next_depth": max(0, int(item[4] or 0)),
            }
        )
    return records


def _native_extraction_result(stage: str, batch_size: int, started_at: float, result: Any):
    records = _map_extracted_records(result)
    return RustBatchResult(
        records,
        metrics={
            "stage": stage,
            "backend": "rust",
            "used_native": True,
            "fallback_count": 0,
            "fallback_reason": "",
            "batch_size": batch_size,
            "output_count": len(records),
            "elapsed": max(0.0, time.monotonic() - started_at),
        },
        used_native=True,
    )


def extract_urlfinder_candidates(
    pages: Iterable[Any],
    allowed_hosts: Iterable[str],
    allow_js: bool,
    max_url_records: int,
    max_js_files: int,
    max_js_depth: int,
) -> RustBatchResult:
    """批量提取 URL/JS 候选，失败时返回带原因的当前批次回退标记。"""
    page_list = list(pages or [])
    _increment_stat("extract_calls")
    if not _enabled():
        return _disabled_result("extract", len(page_list))
    if _NATIVE_MODULE is None:
        return _fallback("extract", len(page_list))

    started_at = time.monotonic()
    try:
        native_pages = [_page_tuple(page) for page in page_list]
        result = _NATIVE_MODULE.extract_urlfinder_candidates(
            native_pages,
            [str(host or "").strip().lower() for host in list(allowed_hosts or []) if str(host or "").strip()],
            bool(allow_js),
            max(1, int(max_url_records or 1)),
            max(1, int(max_js_files or 1)),
            max(1, int(max_js_depth or 1)),
        )
        wrapped = _native_extraction_result("extract", len(page_list), started_at, result)
        logger.debug(
            "rust acceleration complete stage:extract batch_size:{} records:{} elapsed:{:.3f}s".format(
                len(page_list),
                len(wrapped),
                max(0.0, time.monotonic() - started_at),
            )
        )
        return wrapped
    except Exception as exc:
        return _fallback("extract", len(page_list), exc)


def extract_html_candidates(
    pages: Iterable[Any],
    allowed_hosts: Iterable[str],
    allowed_flds: Iterable[str],
    exclude_hosts: Iterable[str],
) -> RustBatchResult:
    """批量解析 HTML 结构，失败时返回当前批次的 Python fallback 标记。"""
    page_list = list(pages or [])
    _increment_stat("html_calls")
    if not _enabled():
        return _disabled_result("html", len(page_list))
    if _NATIVE_MODULE is None:
        return _fallback("html", len(page_list))

    started_at = time.monotonic()
    try:
        native_pages = [_page_tuple(page) for page in page_list]
        result = _NATIVE_MODULE.extract_html_candidates(
            native_pages,
            [str(host or "").strip().lower() for host in list(allowed_hosts or []) if str(host or "").strip()],
            [str(fld or "").strip().lower() for fld in list(allowed_flds or []) if str(fld or "").strip()],
            [str(host or "").strip().lower() for host in list(exclude_hosts or []) if str(host or "").strip()],
        )
        return _native_extraction_result("html", len(page_list), started_at, result)
    except Exception as exc:
        return _fallback("html", len(page_list), exc)


def extract_js_endpoint_candidates(
    pages: Iterable[Any],
    allowed_hosts: Iterable[str],
    max_records: int,
) -> RustBatchResult:
    """批量提取 JS 端点与 API 文档入口。"""
    page_list = list(pages or [])
    _increment_stat("js_endpoint_calls")
    if not _enabled():
        return _disabled_result("js_endpoint", len(page_list))
    if _NATIVE_MODULE is None:
        return _fallback("js_endpoint", len(page_list))

    started_at = time.monotonic()
    try:
        native_pages = [_page_tuple(page) for page in page_list]
        result = _NATIVE_MODULE.extract_js_endpoint_candidates(
            native_pages,
            [str(host or "").strip().lower() for host in list(allowed_hosts or []) if str(host or "").strip()],
            max(1, int(max_records or 1)),
        )
        return _native_extraction_result("js_endpoint", len(page_list), started_at, result)
    except Exception as exc:
        return _fallback("js_endpoint", len(page_list), exc)


def rank_sensitive_targets(
    records: Iterable[Any],
    sites: Iterable[str],
    blocked_hosts: Iterable[str],
    include_js: bool,
    max_targets: int,
) -> RustBatchResult:
    """批量归一化并排序敏感扫描目标，失败时返回带原因的回退标记。"""
    record_list = list(records or [])
    _increment_stat("rank_calls")
    if not _enabled():
        return _disabled_result("rank", len(record_list))
    if _NATIVE_MODULE is None:
        return _fallback("rank", len(record_list))

    started_at = time.monotonic()
    try:
        native_records = [_record_tuple(record) for record in record_list]
        result = _NATIVE_MODULE.rank_sensitive_targets(
            native_records,
            [str(site or "") for site in list(sites or [])],
            [str(host or "").strip().lower() for host in list(blocked_hosts or []) if str(host or "").strip()],
            bool(include_js),
            max(1, int(max_targets or 1)),
        )
        if not isinstance(result, list):
            raise ValueError("invalid Rust ranking result")

        targets: List[Tuple[str, int]] = []
        for item in result:
            if not isinstance(item, (tuple, list)) or len(item) != 2:
                raise ValueError("invalid Rust ranking target")
            target = str(item[0] or "").strip()
            if not target:
                raise ValueError("invalid Rust ranking target url")
            targets.append((target, int(item[1] or 0)))
        logger.debug(
            "rust acceleration complete stage:rank batch_size:{} targets:{} elapsed:{:.3f}s".format(
                len(record_list),
                len(targets),
                max(0.0, time.monotonic() - started_at),
            )
        )
        return RustBatchResult(
            targets,
            metrics={
                "stage": "rank",
                "backend": "rust",
                "used_native": True,
                "fallback_count": 0,
                "fallback_reason": "",
                "batch_size": len(record_list),
                "output_count": len(targets),
                "elapsed": max(0.0, time.monotonic() - started_at),
            },
            used_native=True,
        )
    except Exception as exc:
        return _fallback("rank", len(record_list), exc)
