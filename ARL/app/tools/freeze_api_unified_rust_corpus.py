#!/usr/bin/env python3
"""第 10 批统一 API 面 Rust/Python golden corpus 冻结工具（计划 6 §9.3/§十二）。

corpus 语义：`python` 字段 = 生产 Python 基线（discovery_context.normalize_url /
api_candidate_registry.document_type_hint / api_unified_models.canonical_method /
merge_endpoint_records）实测输出；`rust` 字段 = 编译后的 arl_accel 对同一输入
实测输出。输入表全部落在 adapter 安全子集内（子集外的条目 Rust 永不接收，
由 adapter 预检测试钉住，见 test_api_unified_rust_batch）。

用法：
- 宿主生成/更新 python 侧：
    python3 app/tools/freeze_api_unified_rust_corpus.py --fill-python
- 容器内（装好 arl_accel .so）回填 rust 侧：
    python3 app/tools/freeze_api_unified_rust_corpus.py --fill-rust
- 校验两侧严格一致（不需要 native）：
    python3 app/tools/freeze_api_unified_rust_corpus.py --check
"""
import argparse
import json
import pathlib
import sys

ARL_ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = ARL_ROOT / "test" / "data" / "api_unified_rust_corpus.json"

NORMALIZE_INPUTS = [
    "https://example.test/Path?x=1#frag",
    "http://example.test:80/a",
    "https://example.test:443",
    "https://example.test",
    "https://example.test?a=b",
    "http://example.test:8080/a?b=2#z",
    "https://user:pw@example.test/x",
    "https://a@b@example.test/x",
    "https://a.b:080/x",
    "https://a.b:0/x",
    "https://a.b:/x",
    "https://a.b:99999/x",
    "https://a.b:abc/x",
    "https://example.test./x",
    "https://example.test../x",
    "https://a.b/a%2Fb?c=%3Cd#e",
    "https://a.b/a?b=1#?c",
    "https://a.b//double//slash",
    "https://a.b/中文路径?q=中文",
    "https://a.b/x?a=b c",
    "https://a.b/x?#empty-query",
    "https://a.b/;p=1",
    "https://a.b/%7Euser",
    "https://a.b:8080",
    "HTTP%41://a.b",  # 非法形态：子集内但以 ASCII 直传（urlsplit 不识别→原样）
]

HINT_INPUTS = [
    "https://a.b/v3/api-docs",
    "https://a.b/SWAGGER.json",
    "https://a.b/openapi.yaml",
    "https://a.b/collection.postman.json",
    "https://a.b/service?singleWsdl",
    "https://a.b/graphql",
    "https://a.b/GraphiQL",
    "https://a.b/openapi.postman.json",  # 顺序即优先级：postman 在前
    "https://a.b/api/users",
    "https://a.b/swagger-wsdl-x",        # 双命中取先序
    "",
    "not a url at all SWAGGER",
]

METHOD_INPUTS = [
    "get", " GET ", "POST", "post", "put", "DELETE", "patch", "options",
    "head", "HEAD", "connect", "trace", "weird", "", "   ", "ＧＥＴ",
    "get|post", "GET;",
]

DEDUPE_INPUTS = [
    ["https://a.b/u", "GET", "rest", "", "js"],
    ["https://a.b/u", "POST", "rest", "", "doc"],
    ["https://a.b/u", "GET", "rest", "", "browser"],
    ["https://a.b/u", "GET", "rest", "", "js"],          # 重复来源
    ["https://a.b/u", "GET", "graphql", "", "   "],      # 空白来源剔除
    ["https://a.b/u", "GET", "rest", "/v1", "page"],
    ["https://a.b/u", "GET", "rest", "", "中文"],
    ["https://a.b/u", "GET", "rest", "", "abc"],
]


def _load_modules():
    sys.path.insert(0, str(ARL_ROOT))
    from test._api_unified_bootstrap import load_unified_modules  # noqa: WPS433

    captured = load_unified_modules()
    return captured


def _python_outputs(modules):
    discovery = modules["app.services.discovery_context"]
    registry = modules["app.services.api_candidate_registry"]
    models = modules["app.services.api_unified_models"]
    return {
        "unified_normalize": [discovery.normalize_url(item) for item in NORMALIZE_INPUTS],
        "unified_hint": [registry.document_type_hint(item) for item in HINT_INPUTS],
        "unified_method": [models.canonical_method(item) for item in METHOD_INPUTS],
        "unified_dedupe": [
            [index, sources]
            for index, sources in models.merge_endpoint_records(
                [tuple(record) for record in DEDUPE_INPUTS]
            )
        ],
    }


def _rust_outputs(payload):
    try:
        import arl_accel  # noqa: WPS433
    except Exception as exc:  # pragma: no cover - 容器内路径
        raise SystemExit("需要已安装的 arl_accel：{}".format(exc))
    results = {
        "unified_normalize": [str(x) for x in arl_accel.unified_normalize_urls(NORMALIZE_INPUTS)],
        "unified_hint": [str(x) for x in arl_accel.unified_document_type_hints(HINT_INPUTS)],
        "unified_method": [str(x) for x in arl_accel.unified_canonical_methods(METHOD_INPUTS)],
        "unified_dedupe": [
            [int(item[0]), [str(source) for source in item[1]]]
            for item in arl_accel.unified_dedupe_endpoints(
                [tuple(record) for record in DEDUPE_INPUTS]
            )
        ],
    }
    return results


def _build_cases(values_by_kind):
    inputs_by_kind = {
        "unified_normalize": NORMALIZE_INPUTS,
        "unified_hint": HINT_INPUTS,
        "unified_method": METHOD_INPUTS,
        "unified_dedupe": DEDUPE_INPUTS,
    }
    return [
        {
            "id": "api-unified-{}".format(kind),
            "kind": kind,
            "input": {"values": inputs_by_kind[kind]},
            "python": values_by_kind[kind],
        }
        for kind in ("unified_normalize", "unified_hint", "unified_method", "unified_dedupe")
    ]


def main(argv=None):
    parser = argparse.ArgumentParser(description="冻结统一 API 面 Rust/Python golden corpus")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--fill-python", action="store_true")
    parser.add_argument("--fill-rust", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    output = pathlib.Path(args.output)

    if args.fill_python:
        cases = _build_cases(_python_outputs(_load_modules()))
        payload = {"schema_version": 1, "cases": cases}
        # rust 字段保留已有文件内容（若有），初始为空待容器回填。
        if output.exists():
            try:
                existing = {c["kind"]: c for c in json.loads(output.read_text(encoding="utf-8"))["cases"]}
                for case in payload["cases"]:
                    old = existing.get(case["kind"])
                    if old and old.get("rust"):
                        case["rust"] = old["rust"]
            except (ValueError, KeyError):
                pass
        for case in payload["cases"]:
            case.setdefault("rust", [])
        output.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print("python golden 写入 {}".format(output))
        return 0

    if args.fill_rust:
        if not output.exists():
            raise SystemExit("corpus 不存在，先 --fill-python")
        payload = json.loads(output.read_text(encoding="utf-8"))
        results = _rust_outputs(payload)
        for case in payload["cases"]:
            case["rust"] = results[case["kind"]]
        output.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print("rust 输出回填 {}".format(output))
        return 0

    if args.check:
        payload = json.loads(output.read_text(encoding="utf-8"))
        failures = []
        for case in payload["cases"]:
            if not case.get("rust"):
                failures.append("{}: rust 输出未回填".format(case["id"]))
                continue
            if case["python"] != case["rust"]:
                for index, (left, right) in enumerate(zip(case["python"], case["rust"])):
                    if left != right:
                        failures.append("{}[{}]: python={!r} rust={!r}".format(
                            case["id"], index, left, right))
        if failures:
            for line in failures:
                print(line, file=sys.stderr)
            return 1
        print("unified corpus Rust/Python 严格一致（{} cases）".format(len(payload["cases"])))
        return 0

    parser.error("需要 --fill-python / --fill-rust / --check 之一")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
