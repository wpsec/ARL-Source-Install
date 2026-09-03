#!/usr/bin/env python3
"""比较 Rust 与 Python 的 WIH 热点 golden corpus 输出。

语义比较以规范化记录集合为准；排序差异单独报告，避免把不影响入库的排序变化误判为结果丢失。
"""
import argparse
from collections import Counter
import json
import sys
from pathlib import Path


EXTRACT_FIELDS = ("record_type", "content", "source", "site")


def _unwrap_output(value, kind):
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        keys = ("records", "results") if kind in ("extract", "html", "js_endpoint") else ("targets", "results")
        for key in keys:
            nested = value.get(key)
            if isinstance(nested, list):
                return nested
    raise ValueError("{} 输出必须是列表".format(kind))


def _canonical_extract_item(item):
    if isinstance(item, dict):
        values = [item.get(field, "") for field in EXTRACT_FIELDS]
    elif isinstance(item, (tuple, list)) and len(item) >= 4:
        values = item[:4]
    else:
        raise ValueError("extract 输出记录格式无效")
    return tuple(str(value or "") for value in values)


def _canonical_rank_item(item):
    if isinstance(item, dict):
        target = item.get("target", item.get("url", item.get("content", "")))
        score = item.get("score")
    elif isinstance(item, (tuple, list)) and len(item) >= 2:
        target, score = item[:2]
    else:
        raise ValueError("rank 输出目标格式无效")
    if not str(target or "").strip():
        raise ValueError("rank 输出目标 URL 为空")
    try:
        score = int(score)
    except (TypeError, ValueError) as exc:
        raise ValueError("rank 输出分数无效") from exc
    return str(target).strip(), score


def _canonicalize(kind, value):
    raw_items = _unwrap_output(value, kind)
    if kind in ("extract", "html", "js_endpoint"):
        return [_canonical_extract_item(item) for item in raw_items]
    if kind == "rank":
        return [_canonical_rank_item(item) for item in raw_items]
    raise ValueError("不支持的 corpus 类型: {}".format(kind))


def _duplicates(items):
    return [list(item) for item, count in Counter(items).items() if count > 1]


def _case_id(case, index):
    return str(case.get("id", "case-{}".format(index)) or "case-{}".format(index))


def compare_corpus(payload, strict_order=False):
    if not isinstance(payload, dict):
        raise ValueError("corpus 必须是 JSON 对象")
    if payload.get("schema_version") != 1:
        raise ValueError("corpus schema_version 必须为 1")

    cases = payload.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("corpus cases 必须是非空列表")

    results = []
    errors = []
    for index, case in enumerate(cases, start=1):
        if not isinstance(case, dict):
            errors.append("case-{} 必须是对象".format(index))
            continue
        case_id = _case_id(case, index)
        kind = str(case.get("kind", "") or "").strip().lower()
        try:
            python_output = _canonicalize(kind, case.get("python"))
            rust_output = _canonicalize(kind, case.get("rust"))
        except ValueError as exc:
            errors.append("{}: {}".format(case_id, exc))
            continue

        python_set = set(python_output)
        rust_set = set(rust_output)
        missing = sorted(python_set - rust_set)
        unexpected = sorted(rust_set - python_set)
        python_duplicates = _duplicates(python_output)
        rust_duplicates = _duplicates(rust_output)
        order_equal = python_output == rust_output
        semantic_equal = not (
            missing or unexpected or python_duplicates or rust_duplicates
        )
        results.append(
            {
                "id": case_id,
                "kind": kind,
                "ok": semantic_equal and (not strict_order or order_equal),
                "python_count": len(python_output),
                "rust_count": len(rust_output),
                "missing_from_rust": [list(item) for item in missing],
                "unexpected_in_rust": [list(item) for item in unexpected],
                "python_duplicates": python_duplicates,
                "rust_duplicates": rust_duplicates,
                "order_equal": order_equal,
            }
        )

    return {
        "schema_version": 1,
        "ok": not errors and all(item["ok"] for item in results),
        "strict_order": bool(strict_order),
        "case_count": len(cases),
        "errors": errors,
        "cases": results,
    }


def load_corpus(path):
    with Path(path).open("r", encoding="utf-8") as stream:
        return json.load(stream)


def _native_case_output(case, native_module):
    kind = str(case.get("kind", "") or "").strip().lower()
    inputs = case.get("input")
    if not isinstance(inputs, dict):
        raise ValueError("{} 缺少 input 对象".format(_case_id(case, 0)))

    if kind in ("extract", "html", "js_endpoint"):
        pages = inputs.get("pages")
        if not isinstance(pages, list):
            raise ValueError("extract input.pages 必须是列表")
        native_pages = []
        for page in pages:
            if not isinstance(page, dict):
                raise ValueError("extract input.pages 包含无效页面")
            native_pages.append(
                (
                    str(page.get("base_url", "") or ""),
                    str(page.get("text", "") or ""),
                    str(page.get("source_url", "") or ""),
                    max(0, int(page.get("depth", 0) or 0)),
                    bool(page.get("is_js", False)),
                )
            )
        if kind == "extract":
            return native_module.extract_urlfinder_candidates(
                native_pages,
                [str(host or "") for host in inputs.get("allowed_hosts", [])],
                bool(inputs.get("allow_js", True)),
                max(1, int(inputs.get("max_url_records", 1) or 1)),
                max(1, int(inputs.get("max_js_files", 1) or 1)),
                max(1, int(inputs.get("max_js_depth", 1) or 1)),
            )
        if kind == "html":
            return native_module.extract_html_candidates(
                native_pages,
                [str(host or "") for host in inputs.get("allowed_hosts", [])],
                [str(fld or "") for fld in inputs.get("allowed_flds", [])],
                [str(host or "") for host in inputs.get("exclude_hosts", [])],
            )
        return native_module.extract_js_endpoint_candidates(
            native_pages,
            [str(host or "") for host in inputs.get("allowed_hosts", [])],
            max(1, int(inputs.get("max_records", 1) or 1)),
        )

    if kind == "rank":
        records = inputs.get("records")
        if not isinstance(records, list):
            raise ValueError("rank input.records 必须是列表")
        native_records = []
        for record in records:
            if not isinstance(record, (list, tuple)) or len(record) < 4:
                raise ValueError("rank input.records 包含无效记录")
            native_records.append(tuple(str(value or "") for value in record[:4]))
        return native_module.rank_sensitive_targets(
            native_records,
            [str(site or "") for site in inputs.get("sites", [])],
            [str(host or "") for host in inputs.get("blocked_hosts", [])],
            bool(inputs.get("include_js", True)),
            max(1, int(inputs.get("max_targets", 1) or 1)),
        )

    raise ValueError("不支持的 corpus 类型: {}".format(kind))


def compare_native_corpus(payload, strict_order=False, native_module=None):
    if native_module is None:
        try:
            import arl_accel as native_module
        except Exception as exc:
            raise ValueError("无法导入 arl_accel，请先安装 native wheel: {}".format(exc)) from exc

    if not isinstance(payload, dict) or not isinstance(payload.get("cases"), list):
        raise ValueError("corpus cases 必须是列表")

    executable_cases = []
    for case in payload["cases"]:
        if not isinstance(case, dict):
            raise ValueError("corpus case 必须是对象")
        executable_case = dict(case)
        executable_case["rust"] = _native_case_output(case, native_module)
        executable_cases.append(executable_case)

    report = compare_corpus(
        {"schema_version": payload.get("schema_version"), "cases": executable_cases},
        strict_order=strict_order,
    )
    report["execution_mode"] = "native_vs_python_golden"
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description="比较 Rust/Python WIH golden corpus")
    parser.add_argument("--input", required=True, help="Rust/Python 配对输出 corpus JSON")
    parser.add_argument("--output", help="输出比较报告 JSON；省略时写入标准输出")
    parser.add_argument(
        "--strict-order",
        action="store_true",
        help="将排序差异也视为失败；默认只校验规范化集合和去重",
    )
    parser.add_argument(
        "--run-native",
        action="store_true",
        help="直接调用已安装的 arl_accel，并与 corpus 中的 Python golden 输出比较",
    )
    args = parser.parse_args(argv)

    try:
        corpus = load_corpus(args.input)
        if args.run_native:
            report = compare_native_corpus(corpus, strict_order=args.strict_order)
        else:
            report = compare_corpus(corpus, strict_order=args.strict_order)
        output = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
        if args.output:
            with Path(args.output).open("w", encoding="utf-8") as stream:
                stream.write(output)
        else:
            sys.stdout.write(output)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("比较 Rust/Python corpus 失败: {}".format(exc), file=sys.stderr)
        return 2
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
