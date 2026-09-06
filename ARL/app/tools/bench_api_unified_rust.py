#!/usr/bin/env python3
"""第 10 批统一 API 面 Rust/Python CPU 基准（计划 6 §十二性能闸）。

门禁：Rust 热点 CPU 降低 ≥30%（时间比 ≤0.70）或吞吐 ≥1.5x 才允许扩大范围；
端到端耗时不恶化 ≤5% 属第 11 批容器/任务级验收，不在本脚本范围。

基线函数为生产实现的逐字副本（discovery_context.normalize_url、
api_candidate_registry.document_type_hint、api_unified_models.canonical_method /
merge_endpoint_records，及预检正则与关键词/方法常量表）——基准必须在装有
release .so 的容器内运行（无 app 重依赖），故以副本替代导入；一致性由
ARL/test/test_api_unified_rust_batch.py::TestBenchBaselinePins 在宿主逐函数
AST 源文本钉住，漂移会导致该测试失败、基准数据作废需重跑。

用法：
- 任意环境（无 arl_accel 时只跑 Python 半边）：
    python3 app/tools/bench_api_unified_rust.py
- 容器（装有 release .so）同命令，输出两侧对比与门禁判定 JSON。
"""
import json
import platform
import random
import re
import statistics
import sys
import time
from typing import Dict, List, Tuple
from urllib.parse import urlsplit, urlunsplit

BATCH_NORMALIZE = 20000
BATCH_HINT = 20000
BATCH_METHOD = 20000
BATCH_DEDUPE = 40000
REPEAT = 5

# ---------------- Python 基线（生产逐字副本） ----------------


def py_normalize_url(value):
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        parsed = urlsplit(text)
    except ValueError:
        return text
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return text
    host = parsed.hostname.lower().rstrip(".")
    netloc = host
    try:
        port = parsed.port
    except ValueError:
        return text
    if port:
        default_port = (parsed.scheme.lower() == "http" and port == 80) or (
            parsed.scheme.lower() == "https" and port == 443
        )
        if not default_port:
            netloc = "{}:{}".format(host, port)
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, ""))


_HINT_KEYWORDS = (
    ("postman", "postman"),
    ("openapi", "openapi"),
    ("swagger", "swagger"),
    ("api-docs", "swagger"),
    ("wsdl", "wsdl"),
    ("graphql", "graphql"),
    ("graphiql", "graphql"),
)


def py_document_type_hint(url):
    lowered = str(url or "").strip().lower()
    for keyword, hint in _HINT_KEYWORDS:
        if keyword in lowered:
            return hint
    return "unknown"


HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD")


def py_canonical_method(method):
    text = str(method or "GET").strip().upper()
    return text if text in HTTP_METHODS else "GET"


def py_merge_endpoint_records(records):
    order: List[Tuple[str, str, str, str]] = []
    groups: Dict[Tuple[str, str, str, str], Tuple[int, set]] = {}
    for index, record in enumerate(records or []):
        url, method, api_type, path_template, source = record
        key = (str(url or ""), str(method or ""), str(api_type or ""), str(path_template or ""))
        entry = groups.get(key)
        if entry is None:
            entry = (index, set())
            groups[key] = entry
            order.append(key)
        text = str(source or "").strip()
        if text:
            entry[1].add(text)
    return [(groups[key][0], sorted(groups[key][1])) for key in order]


# ---------------- 输入合成（确定性种子，跨环境可复现） ----------------


def build_inputs():
    rng = random.Random(20260906)
    hosts = ["api.example.test", "www.shop.test", "admin.corp.test", "gw.internal.test"]
    paths = ["/v1/users", "/api/orders", "/search", "/v3/api-docs", "/graphql",
             "/admin/export", "/login", "/static/app.js", "/a/b/c", "/health"]
    queries = ["", "?page=1", "?q=abc&lang=zh", "?id=%3D1"]
    normalize_inputs = []
    for i in range(BATCH_NORMALIZE):
        scheme = "https" if i % 4 else "http"
        port = ""
        if i % 97 == 0:
            port = ":8443"
        elif i % 211 == 0:
            port = ":443"
        normalize_inputs.append(
            "{}://{}{}{}{}".format(
                scheme, rng.choice(hosts), port, rng.choice(paths), rng.choice(queries))
        )
    hint_inputs = [url + ("#f" if i % 33 == 0 else "") for i, url in enumerate(normalize_inputs[:BATCH_HINT])]
    methods = ["get", "post", "GET ", " put", "delete", "patch", "options", "head",
               "trace", "weird", "", "POST"]
    method_inputs = [methods[i % len(methods)] + ("|x" if i % 41 == 0 else "")
                     for i in range(BATCH_METHOD)]
    dedupe_inputs = []
    for i in range(BATCH_DEDUPE):
        base = normalize_inputs[i % len(normalize_inputs)]
        dedupe_inputs.append([
            base, methods[i % len(methods)].strip().upper()[:4] or "GET",
            ("rest", "graphql", "soap")[i % 3], "/v1" if i % 17 == 0 else "",
            ("js", "doc", "browser", "page", "")[i % 5],
        ])
    return {
        "normalize": normalize_inputs,
        "hint": hint_inputs,
        "method": method_inputs,
        "dedupe": [tuple(record) for record in dedupe_inputs],
    }


def _time_batch(fn, arg):
    samples = []
    for _ in range(REPEAT):
        started = time.perf_counter()
        fn(arg)
        samples.append(time.perf_counter() - started)
    samples.sort()
    return {
        "repeats": REPEAT,
        "best_sec": round(samples[0], 6),
        "median_sec": round(statistics.median(samples), 6),
        "p95_sec": round(samples[min(len(samples) - 1, int(len(samples) * 0.95))], 6),
    }


def main():
    inputs = build_inputs()
    try:
        import arl_accel
        native_available = True
    except Exception:
        arl_accel = None
        native_available = False

    python_side = {
        "normalize": _time_batch(lambda batch: [py_normalize_url(x) for x in batch], inputs["normalize"]),
        "hint": _time_batch(lambda batch: [py_document_type_hint(x) for x in batch], inputs["hint"]),
        "method": _time_batch(lambda batch: [py_canonical_method(x) for x in batch], inputs["method"]),
        "dedupe": _time_batch(py_merge_endpoint_records, inputs["dedupe"]),
    }
    report = {
        "schema_version": 1,
        "platform": "{} {} python{}".format(platform.system(), platform.machine(), platform.python_version()),
        "native_available": native_available,
        "batch_sizes": {
            "normalize": BATCH_NORMALIZE, "hint": BATCH_HINT,
            "method": BATCH_METHOD, "dedupe": BATCH_DEDUPE,
        },
        "python": python_side,
    }
    if native_available:
        # 基准直测 native 纯函数（不含 adapter 预检——预检成本单列）。
        rust_side = {
            "normalize": _time_batch(arl_accel.unified_normalize_urls, inputs["normalize"]),
            "hint": _time_batch(arl_accel.unified_document_type_hints, inputs["hint"]),
            "method": _time_batch(arl_accel.unified_canonical_methods, inputs["method"]),
            "dedupe": _time_batch(arl_accel.unified_dedupe_endpoints, inputs["dedupe"]),
        }
        gates = {}
        for key in rust_side:
            py_median = python_side[key]["median_sec"]
            rs_median = rust_side[key]["median_sec"]
            ratio = rs_median / py_median if py_median else None
            cpu_gate = ratio is not None and ratio <= 0.70
            throughput_gate = ratio is not None and ratio <= 2 / 3
            gates[key] = {
                "rust_vs_python_median": round(ratio, 4) if ratio is not None else None,
                "cpu_reduction_gate_30pct": cpu_gate,
                "throughput_gate_1_5x": throughput_gate,
                "gate_passed": bool(cpu_gate or throughput_gate),
            }
        report["rust"] = rust_side
        report["gates"] = gates
        # adapter 预检开销（生产接线真实成本：regex 判定 + 子集重组）。
        safe_re = re.compile(
            r"^https?://[A-Za-z0-9.\-_~%!$&'()*+,;=:@]+(?:[/?#][^\x00-\x1f\x7f]*)?\Z")
        report["preflight_median_sec"] = _time_batch(
            lambda batch: [bool(safe_re.match(x)) for x in batch], inputs["normalize"],
        )["median_sec"]
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
