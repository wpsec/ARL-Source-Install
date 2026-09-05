#!/usr/bin/env python3
"""计划 6 第 1 批：统一 API golden corpus 基线生成器。

用现行 ApiDocScanner（网络无关：直接喂 fixture 文本）对 OpenAPI/Swagger/Postman
样本生成记录基线，写入 ARL/test/fixtures/api_unified/expected/。
该基线是后续统一 Parser 的“结果集合不得低于现状”验收锚点；
corpus 变更后重跑本脚本刷新，禁止手改产物。

用法：python3 scripts/api-unified-golden.py [--check]
  --check  只比对不落盘，漂移即退出码 1（测试与 CI 用）。
"""
import argparse
import json
import pathlib
import sys
import types
from collections import deque

ROOT = pathlib.Path(__file__).resolve().parents[1]
ARL = ROOT / "ARL"
FIXTURES = ARL / "test" / "fixtures" / "api_unified"
EXPECTED = FIXTURES / "expected"

# app.services 的包级 import 会拉起 NPoC 等重依赖；这里以 __path__ 桩方式
# 只加载纯 stdlib 的 discovery_context 与 api_doc_scan 两个模块。
def _bootstrap() -> None:
    sys.path.insert(0, str(ARL))
    app_pkg = types.ModuleType("app")
    app_pkg.__path__ = [str(ARL / "app")]
    svc_pkg = types.ModuleType("app.services")
    svc_pkg.__path__ = [str(ARL / "app" / "services")]
    sys.modules.setdefault("app", app_pkg)
    sys.modules.setdefault("app.services", svc_pkg)


_bootstrap()

import yaml  # noqa: E402  (api_doc_scan 依赖)
from app.services import api_doc_scan  # noqa: E402

Scanner = api_doc_scan.ApiDocScanner

DOC_URLS = {
    "openapi3_petstore.json": "https://api.example.com/v3/api-docs",
    "openapi3_petstore.yaml": "https://api.example.com/openapi3_petstore.yaml",
    "swagger2_petstore.json": "https://api.example.com/v2/api-docs",
    "postman_collection.json": "https://api.example.com/postman.json",
}

SITES = ["https://api.example.com"]


def _make_scanner() -> "Scanner":
    scanner = Scanner(sites=SITES, wih_records=[], waf_guard=None, discovery_context=None)
    scanner.allowed_hosts = {"api.example.com"}
    scanner.allowed_flds = {"example.com"}
    return scanner


def _records_of(scanner: "Scanner") -> list:
    out = []
    for record in scanner.records:
        out.append(
            {
                "record_type": record.recordType,
                "content": record.content,
                "source": record.source,
                "site": record.site,
                "fnv_hash": str(record.fnv_hash),
            }
        )
    out.sort(key=lambda item: (item["record_type"], item["content"], item["source"]))
    return out


def build_baseline() -> dict:
    fixtures = {}
    for name, doc_url in DOC_URLS.items():
        text = (FIXTURES / name).read_text(encoding="utf-8")
        scanner = _make_scanner()
        scanner._parse_doc(doc_url, text, deque())
        fixtures[name] = {"doc_url": doc_url, "records": _records_of(scanner)}
    return {
        "generator": "scripts/api-unified-golden.py",
        "note": "现行 ApiDocScanner 的 golden 基线；统一 Parser 输出集合不得低于本基线（计划6 §十二）。",
        "fixtures": fixtures,
    }


def validate_corpus() -> list:
    """corpus 自身合法性与预期失败面检查，返回问题列表。"""

    problems = []
    for name in DOC_URLS:
        path = FIXTURES / name
        if not path.exists():
            problems.append("missing fixture: {}".format(name))

    # YAML 镜像与 JSON 结构等价（servers/paths 口径一致性验证的输入前提）。
    json_doc = json.loads((FIXTURES / "openapi3_petstore.json").read_text(encoding="utf-8"))
    yaml_doc = yaml.safe_load((FIXTURES / "openapi3_petstore.yaml").read_text(encoding="utf-8"))
    if json_doc != yaml_doc:
        problems.append("openapi3 yaml mirror differs from json")

    # 同一文档内容以 JSON 文本或 YAML 文本喂入，解析记录必须一致（装载路径无关性）。
    text = (FIXTURES / "openapi3_petstore.json").read_text(encoding="utf-8")
    scanner = _make_scanner()
    scanner._parse_doc(DOC_URLS["openapi3_petstore.json"], text, deque())
    scanner2 = _make_scanner()
    scanner2._parse_doc(DOC_URLS["openapi3_petstore.json"], yaml.dump(json_doc), deque())
    if _records_of(scanner) != _records_of(scanner2):
        problems.append("json/yaml load paths produce different records")

    # 非法 JSON：现行解析必须静默不产记录（不得伪装成功产出 endpoint）。
    scanner3 = _make_scanner()
    scanner3._parse_doc(
        "https://api.example.com/invalid.json",
        (FIXTURES / "invalid_json.json").read_text(encoding="utf-8"),
        deque(),
    )
    if any(r.recordType == "api_doc_endpoint" for r in scanner3.records):
        problems.append("invalid json produced endpoints")

    import xml.etree.ElementTree as ET

    ET.fromstring((FIXTURES / "wsdl_service.wsdl").read_text(encoding="utf-8"))
    ET.fromstring((FIXTURES / "types.xsd").read_text(encoding="utf-8"))
    # XXE 样本必须让标准解析器在实体处失败（或产出含外部内容的结果——后者即缺陷）。
    try:
        root = ET.fromstring((FIXTURES / "wsdl_xxe.xml").read_text(encoding="utf-8"))
        leaked = "xxe-probe" in ET.tostring(root, encoding="unicode")
        problems.append("wsdl_xxe parsed without failure; check entity handling" if not leaked else "wsdl_xxe unexpectedly expanded")
    except ET.ParseError:
        pass  # 预期：实体未定义即解析失败，统一 Parser 须映射为 failed/degraded。
    return problems


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="比对已落盘基线，不写入")
    args = parser.parse_args()

    problems = validate_corpus()
    for item in problems:
        print("corpus problem: {}".format(item), file=sys.stderr)

    baseline = build_baseline()
    target = EXPECTED / "current_parser_baseline.json"
    payload = json.dumps(baseline, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.check:
        current = target.read_text(encoding="utf-8") if target.exists() else ""
        if current != payload:
            print("baseline drift: rerun scripts/api-unified-golden.py", file=sys.stderr)
            return 1
    else:
        EXPECTED.mkdir(parents=True, exist_ok=True)
        target.write_text(payload, encoding="utf-8")
        print("written:", target)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
