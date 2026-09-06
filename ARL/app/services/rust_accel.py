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
    # 第 10 批统一 API 面批量入口（引擎动态键的静态声明，便于观测口径盘点）。
    "unified_normalize_calls": 0,
    "unified_normalize_fallbacks": 0,
    "unified_hint_calls": 0,
    "unified_hint_fallbacks": 0,
    "unified_method_calls": 0,
    "unified_method_fallbacks": 0,
    "unified_dedupe_calls": 0,
    "unified_dedupe_fallbacks": 0,
    "unified_shadow_mismatches": 0,
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


# ---------------------------------------------------------------------------
# 第 10 批：统一 API 面纯数据批量入口（计划 6 §9.3 第三阶段）。
#
# 模式开关 RUST_ACCEL_API_UNIFIED_MODE（getattr 软读，Config 未定义默认 shadow）：
#   off    全部走 Python 基线（零开销）；
#   shadow 双跑 Rust+Python，逐条比对计 mismatch（输出恒取 Python，基线为准）；
#   rust   安全子集取 Rust 结果、子集外取 Python，不做双跑；native 失败当前批回退。
# "rust" 只有在 shadow 观测 mismatch 恒为 0、golden --run-native 全绿且 CPU 基准
# 过闸后才按发布流程启用（第 11 批验收面）。
# 输入非安全子集条目恒走 Python：CPython 版本间 urlsplit 边缘行为（控制字符剥离、
# WHATWG lstrip、bracketed IPv6 校验、Unicode case mapping）不在 Rust 复刻范围。
# ---------------------------------------------------------------------------

_UNIFIED_MODES = ("off", "shadow", "rust")
_UNIFIED_SAFE_URL_RE = None
_UNIFIED_ASCII_SAFE_RE = None


def _unified_patterns():
    global _UNIFIED_SAFE_URL_RE, _UNIFIED_ASCII_SAFE_RE
    if _UNIFIED_SAFE_URL_RE is None:
        import re

        # 小写 http(s) + 纯 ASCII netloc（无方括号，控制字符禁入 path/query）。
        _UNIFIED_SAFE_URL_RE = re.compile(
            r"^https?://[A-Za-z0-9.\-_~%!$&'()*+,;=:@]+"
            r"(?:[/?#][^\x00-\x1f\x7f]*)?\Z"
        )
        # method/hint 基线只做 strip+lower/upper；限定纯可打印 ASCII 即与
        # CPython 行为逐字节一致（非 ASCII case mapping 差异交回 Python）。
        _UNIFIED_ASCII_SAFE_RE = re.compile(r"^[\x20-\x7e]*\Z")
    return _UNIFIED_SAFE_URL_RE, _UNIFIED_ASCII_SAFE_RE


def unified_url_is_safe(text: str) -> bool:
    safe_re, _ = _unified_patterns()
    return bool(safe_re.match(str(text or "")))


def _unified_mode() -> str:
    if _NATIVE_MODULE is None or not _enabled():
        return "off"
    mode = str(getattr(Config, "RUST_ACCEL_API_UNIFIED_MODE", "shadow") or "shadow").strip().lower()
    if mode not in _UNIFIED_MODES:
        return "shadow"
    return mode


def _unified_metrics(stage, mode, batch_size, safe_count, mismatch, elapsed, used_native):
    return {
        "stage": stage,
        "backend": "rust" if used_native else "python",
        "mode": mode,
        "used_native": bool(used_native),
        "fallback_count": 1 if used_native is False and mode != "off" and safe_count else 0,
        "fallback_reason": "",
        "batch_size": int(batch_size or 0),
        "safe_count": int(safe_count or 0),
        "mismatch_count": int(mismatch or 0),
        "output_count": int(batch_size or 0),
        "elapsed": max(0.0, float(elapsed or 0.0)),
    }


def _require_equal_length(result, expected):
    if not isinstance(result, list) or len(result) != expected:
        raise ValueError("invalid Rust unified output length")
    return result


def _unified_batch(stage, items, safe_flags, python_batch_fn, native_fn, stats_prefix,
                   aggregate=False):
    """安全子集批量执行引擎：三模式统一调度，输出与 Python 基线对齐。

    - items/safe_flags 等长；python_batch_fn(items)->等长列表；
    - 逐元素函数（normalize/hint/method）：native_fn 接收安全子集并返回等长
      列表（同长校验在各自 wrapper 内），子集外条目恒取基线；
    - 聚合函数（dedupe）：输出为分组结果（长度不等于输入数），安全子集判定
      按"部分不安全即整批走基线"处理，shadow 比对用整批相等判定；
    - shadow 恒输出 Python 基线；rust 输出 native；
    - native 异常：shadow 计 fallback 静默降级、rust 按 RUST_ACCEL_FALLBACK_ENABLE。
    """

    started_at = time.monotonic()
    _increment_stat("{}_calls".format(stats_prefix))
    mode = _unified_mode()
    count = len(items)
    safe_flags = [bool(flag) for flag in safe_flags]
    if aggregate and count and not all(safe_flags):
        safe_flags = [False] * count  # 聚合语义下部分安全即整批走基线
    safe_count = sum(safe_flags)

    if mode == "off" or not safe_count:
        values = list(python_batch_fn(items))
        return RustBatchResult(
            values,
            metrics=_unified_metrics(
                stage, mode, count, safe_count, 0, time.monotonic() - started_at, False,
            ),
        )

    native_indices = [i for i, flag in enumerate(safe_flags) if flag]
    try:
        native_values = [items[i] for i in native_indices]
        native_result = native_fn(native_values)
        if not isinstance(native_result, list):
            raise ValueError("invalid Rust {} output".format(stage))
        rust_by_index = dict(zip(native_indices, native_result))
    except Exception as exc:
        _increment_stat("{}_fallbacks".format(stats_prefix))
        with _STATS_LOCK:
            _STATS["last_{}_fallback_reason".format(stats_prefix)] = type(exc).__name__
        if mode == "rust" and not bool(getattr(Config, "RUST_ACCEL_FALLBACK_ENABLE", True)):
            raise RustAccelerationError(
                "Rust acceleration failed at {}".format(stage)
            ) from exc
        logger.debug(
            "rust acceleration fallback stage:%s batch_size:%s reason_type:%s",
            stage, count, type(exc).__name__,
        )
        values = list(python_batch_fn(items))
        return RustBatchResult(
            values,
            metrics=_unified_metrics(
                stage, mode, count, safe_count, 0, time.monotonic() - started_at, False,
            ),
        )

    if mode == "shadow":
        baseline = list(python_batch_fn(items))
        if aggregate:
            mismatch = 0 if list(native_result) == baseline else 1
        else:
            mismatch = sum(
                1 for index in native_indices if baseline[index] != rust_by_index[index]
            )
        if mismatch:
            _increment_stat("unified_shadow_mismatches", mismatch)
            logger.warning(
                "rust unified shadow mismatch stage:%s count:%s batch_size:%s",
                stage, mismatch, count,
            )
        return RustBatchResult(
            baseline,
            metrics=_unified_metrics(
                stage, mode, count, safe_count, mismatch,
                time.monotonic() - started_at, True,
            ),
        )

    # mode == "rust"：聚合函数直接取整批 native；逐元素函数安全子集取
    # native、子集外按基线补齐。
    if aggregate or all(safe_flags):
        values = list(native_result)
    else:
        baseline = list(python_batch_fn(items))
        values = [
            rust_by_index[index] if index in rust_by_index else baseline[index]
            for index in range(count)
        ]
    return RustBatchResult(
        values,
        metrics=_unified_metrics(
            stage, mode, count, safe_count, 0, time.monotonic() - started_at, True,
        ),
        used_native=True,
    )


def unified_normalize_urls(values):
    """批量 URL 规范化（基线 = discovery_context.normalize_url，逐条等价）。"""

    from app.services.discovery_context import normalize_url as _py_normalize

    items = [str(value or "").strip() for value in (values or [])]
    return _unified_batch(
        "api_unified_normalize", items,
        [bool(item) and unified_url_is_safe(item) for item in items],
        lambda batch: [_py_normalize(item) for item in batch],
        lambda safe_items: [
            str(item)
            for item in _require_equal_length(
                _NATIVE_MODULE.unified_normalize_urls(safe_items), len(safe_items)
            )
        ],
        "unified_normalize",
    )


def unified_document_type_hints(values):
    """批量文档类型分类（基线 = api_candidate_registry.document_type_hint）。"""

    from app.services.api_candidate_registry import document_type_hint as _py_hint

    items = [str(value or "") for value in (values or [])]
    _, ascii_re = _unified_patterns()
    return _unified_batch(
        "api_unified_hint", items,
        [bool(ascii_re.match(item)) for item in items],
        lambda batch: [_py_hint(item) for item in batch],
        lambda safe_items: [
            str(item)
            for item in _require_equal_length(
                _NATIVE_MODULE.unified_document_type_hints(safe_items), len(safe_items)
            )
        ],
        "unified_hint",
    )


def unified_canonical_methods(values):
    """批量 method 规范化（基线 = api_unified_models.canonical_method）。

    第 10 批代码入口 + golden 覆盖；Endpoint 对象构造在 UnifiedApiEndpoint
    契约面内完成，生产接线待 CPU 门禁证据后评估（§9.3 扩大范围约束）。
    """

    from app.services.api_unified_models import canonical_method as _py_method

    items = [str(value or "") for value in (values or [])]
    _, ascii_re = _unified_patterns()
    return _unified_batch(
        "api_unified_method", items,
        [bool(ascii_re.match(item)) for item in items],
        lambda batch: [_py_method(item) for item in batch],
        lambda safe_items: [
            str(item)
            for item in _require_equal_length(
                _NATIVE_MODULE.unified_canonical_methods(safe_items), len(safe_items)
            )
        ],
        "unified_method",
    )


def unified_dedupe_endpoints(records):
    """批量 Endpoint 记录去重合并（基线 = api_unified_models.merge_endpoint_records）。

    records: [(url, method, api_type, path_template, source), ...]
    返回 [(first_index, sorted_unique_sources), ...] 按首现顺序。第 10 批代码
    入口 + golden；生产接线待 CPU 门禁证据。字段全集 UTF-8 字节序与 CPython
    codepoint 排序一致，无需子集预检（整批 native 失败仍回退）。
    """

    from app.services.api_unified_models import merge_endpoint_records as _py_merge

    tuples = []
    for record in records or []:
        if isinstance(record, (tuple, list)) and len(record) == 5:
            tuples.append(tuple(str(item or "") for item in record))
        else:
            raise ValueError("invalid unified endpoint record")
    return _unified_batch(
        "api_unified_dedupe", tuples,
        [True] * len(tuples),
        _py_merge,
        lambda safe_items: [
            (int(item[0]), [str(source) for source in item[1]])
            for item in _NATIVE_MODULE.unified_dedupe_endpoints(list(safe_items))
        ],
        "unified_dedupe",
        aggregate=True,
    )
