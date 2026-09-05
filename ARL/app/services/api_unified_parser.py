"""统一 OpenAPI/Swagger 解析器（计划 6 第 4 批）。

对 `api_unified_models.ParseResult` 契约的 openapi3/swagger2 实现，补齐
06-附录A §五缺口面中第 4 批范围：

- G1：`{petId}` 花括号模板端点不再丢弃——模板 URL 以原样大括号形态进入资产面；
  模板不可直接请求，桥接层据此抑制 `urlfinder_url` 记录（附录A §4.8 契约）；
- G3：参数四位置（path/query/header/cookie；swagger2 formData）、path 级参数
  与 operation 参数合并、requestBody/responses schema 摘要、
  securitySchemes/securityDefinitions→auth_hint；
- G4：非法/异常文档产生显式 `failed` diagnostics（error_type 可见），
  不再伪装成"无 API"；
- G7：端点携带 parent_document/base_url/api_version 追溯字段，越界 server
  产 `out_of_scope_domain` 证据候选（Review P0-01：不可信文档 host 不得进入
  in-scope domain 资产面），范围内多 server 全展开。

安全边界（§11.3）：外部 `$ref` 不获取（标 unresolved 并计数）、Schema 摘要
深度有界（内部 3 层、属性 50 个）、引用总预算 `ParseOptions.max_ref_count`、
循环引用显式标记，解析全程零网络零存储。输出过 `ParseResult.to_dict()`
泄露守卫。非 openapi/swagger 形态（postman/graphql/wsdl/html）返回
`skipped`，由队列回退 legacy 解析（第 5-7 批逐格式接管）。
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple  # noqa: F401
from urllib.parse import unquote, urljoin, urlsplit

from .api_unified_models import (
    ApiDocumentCandidate,
    ParseDiagnostics,
    ParseOptions,
    ParseResult,
    ParameterSpec,
    SecurityRequirementSummary,
    UnifiedApiEndpoint,
    canonical_method,
    compute_input_signature,
    graphql_query_hash,
    is_sensitive_key,
)

try:  # 与 legacy 解析链同源；yaml 缺失时 JSON-only。
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

_HTTP_METHOD_KEYS = ("get", "post", "put", "delete", "patch", "options", "head")
_TEMPLATE_RE = re.compile(r"\{[^{}]+\}")
# `:id` 冒号路径变量与花括号模板同口径：是资产形态、不是可直接请求的 URL。
_COLON_VAR_RE = re.compile(r"(^|/):[^/?#{}]+(?=[/?#]|$)")
_SCHEMA_SUMMARY_MAX_DEPTH = 3
_SCHEMA_SUMMARY_MAX_PROPERTIES = 50
# openapi/swagger 痕迹：断裂文档只有命中痕迹才按 G4 显式 failed，
# 无痕迹的载入失败（GraphQL SDL 等任意文本）skip 交解析器链后继。
_OPENAPI_TRACE_RE = re.compile(r"(?:openapi|swagger)", re.IGNORECASE)
_PARAM_LOCATIONS = ("path", "query", "header", "cookie", "formData", "body")

# Review P0-01：不可信文档（server/base/soap:address）里的越界 host 只是发现
# 证据，不是可消费的 in-scope domain 资产。解析器对越界候选统一冻结为该
# record_type；桥接层（api_candidate_registry）只计数、绝不落 domain 记录。
OUT_OF_SCOPE_DOMAIN_RECORD_TYPE = "out_of_scope_domain"


def url_has_template(url: Any) -> bool:
    text = str(url or "")
    return bool(_TEMPLATE_RE.search(text)) or "{{" in text or bool(_COLON_VAR_RE.search(text))


def _host_of(url: Any) -> str:
    try:
        return str(urlsplit(str(url or "")).hostname or "").strip().lower().rstrip(".")
    except ValueError:
        return ""


_XML_MARKUP_RE = re.compile(r"^<[A-Za-z_]")


def _looks_like_xml(text: Any) -> bool:
    """XML/HTML 标记形态判定：`<?xml` 声明或以 `<标签名` 起始。

    JSON（`{`/`[`）与 YAML（`openapi:`/`#`）均不以 `<` 起始，故本判定不会
    误伤 openapi/postman 正常形态。
    """

    head = str(text or "").lstrip()[:64]
    if head.startswith("<?xml"):
        return True
    return bool(_XML_MARKUP_RE.match(head))


class _RefBudget:
    """本地 $ref 解析预算与 unresolved/cycle 计数（G4/G7 诊断来源）。"""

    def __init__(self, max_count: int):
        self.remaining = max(1, int(max_count or 1))
        self.unresolved = 0
        self.cycles = 0
        self.exhausted = False

    def consume(self, document: Dict[str, Any], ref: Any, active: Set[str]):
        """返回 (target|None, kind)；kind∈resolved|cycle|external|missing|budget。"""
        text = str(ref or "")
        if not text.startswith("#/"):
            self.unresolved += 1
            return None, "external"
        if text in active:
            self.cycles += 1
            return None, "cycle"
        if self.remaining <= 0:
            self.exhausted = True
            self.unresolved += 1
            return None, "budget"
        node: Any = document
        try:
            for part in text[1:].strip("/").split("/"):
                node = node[unquote(part).replace("~1", "/").replace("~0", "~")]
        except (KeyError, IndexError, TypeError):
            self.remaining -= 1
            self.unresolved += 1
            return None, "missing"
        self.remaining -= 1
        return node, "resolved"


def _resolve_or_none(document, ref, budget: _RefBudget, active: Set[str]):
    target, kind = budget.consume(document, ref, active)
    return target, kind


def _dereference(document, node, budget: _RefBudget, active: Set[str]):
    """dict 若为 $ref 壳则解一层；失败返回 (None, kind)。"""
    if isinstance(node, dict) and isinstance(node.get("$ref"), str):
        return _resolve_or_none(document, node["$ref"], budget, active)
    return node, "inline"


class UnifiedOpenApiParser:
    """openapi3/swagger2 统一解析。构造注入任务与范围上下文（零网络）。"""

    parser_name = "openapi_unified"
    parser_version = "v1"

    def __init__(self, task_id: str, doc_url: str, allowed_hosts=None, allowed_flds=None):
        self.task_id = str(task_id or "")
        self.doc_url = str(doc_url or "")
        self.allowed_hosts = {str(h or "").strip().lower() for h in (allowed_hosts or set()) if str(h or "").strip()}
        self.allowed_flds = {str(f or "").strip().lower() for f in (allowed_flds or set()) if str(f or "").strip()}

    # -- 载入与识别 --------------------------------------------------------

    def parse(self, document_artifact: Any, parse_options: Optional[ParseOptions] = None) -> ParseResult:
        options = parse_options or ParseOptions()
        diag = ParseDiagnostics(parser=self.parser_name)
        doc = document_artifact
        if not isinstance(doc, dict):
            text = document_artifact.decode("utf-8", "ignore") if isinstance(document_artifact, bytes) \
                else str(document_artifact or "")
            if _looks_like_xml(text):
                # XML/WSDL 形态交 wsdl_unified 接管：本解析器契约为"非
                # openapi/swagger 形态一律 skipped"，不得把 XML 误判成 failed
                # 而截断解析器链（第 7 批链式分发前置修复）。
                diag.status = "skipped"
                diag.error_type = "not_openapi_document"
                return ParseResult(parser=self.parser_name, diagnostics=diag)
            if len(text.encode("utf-8", "ignore")) > options.max_document_bytes:
                diag.status = "failed"
                diag.error_type = "document_too_large"
                return ParseResult(parser=self.parser_name, diagnostics=diag)
            doc, error_type = self._load(text)
            if doc is None:
                # G4 显式失败只覆盖带 openapi/swagger 痕迹的断裂文档（invalid_json
                # 伪装"无 API"是本契约的核心场景）。任意文本的 YAML 载入失败不是
                # 坏 openapi 的证据——GraphQL SDL 等文本形态必须 skipped，否则解析器
                # 链在链首被截断，graphql/wsdl 永远无法经真实队列进入（与第 7 批
                # "XML→skip"同一链式分发前置修复）。RecursionError 是成本边界信号，
                # 不受痕迹门控，维持显式 failed。
                if error_type == "load_error" and not _OPENAPI_TRACE_RE.search(text):
                    diag.status = "skipped"
                    diag.error_type = "not_openapi_document"
                else:
                    diag.status = "failed"
                    diag.error_type = error_type
                return ParseResult(parser=self.parser_name, diagnostics=diag)
        if not isinstance(doc, dict):
            # 载入成功但非标量以外形态（YAML scalar / JSON 数组）：同样不构成
            # openapi 痕迹，failed 会截断链；交回链式分发按各格式自身判定。
            diag.status = "skipped"
            diag.error_type = "not_openapi_document"
            return ParseResult(parser=self.parser_name, diagnostics=diag)

        version = self._detect_version(doc)
        if version is None:
            diag.status = "skipped"
            diag.error_type = "not_openapi_document"
            return ParseResult(parser=self.parser_name, diagnostics=diag)
        return self._parse_document(doc, version, options, diag)

    @staticmethod
    def _load(text: str):
        try:
            return json.loads(text), ""
        except RecursionError:
            # deep_nesting 类输入：显式失败而不是伪装"无 API"（G4）。
            return None, "RecursionError"
        except Exception:
            pass
        if yaml is not None:
            try:
                loaded = yaml.safe_load(text)
                return loaded, ""
            except Exception:
                return None, "load_error"
        return None, "load_error"

    @staticmethod
    def _detect_version(doc: Dict[str, Any]) -> Optional[str]:
        if str(doc.get("openapi", "") or "").startswith("3"):
            return "v3"
        if str(doc.get("swagger", "") or "") == "2.0":
            return "v2"
        if isinstance(doc.get("paths"), dict) and (doc.get("info") or doc.get("components")):
            return "v3"
        if isinstance(doc.get("paths"), dict) and (doc.get("host") or doc.get("basePath")):
            return "v2"
        return None

    # -- 主解析 ------------------------------------------------------------

    def _parse_document(self, doc, version, options: ParseOptions, diag: ParseDiagnostics) -> ParseResult:
        budget = _RefBudget(options.max_ref_count)
        schemes = self._security_schemes(doc, version)
        base_entries = self._base_entries(doc, version)
        paths = doc.get("paths")
        if not isinstance(paths, dict) or not paths:
            diag.status = "skipped"
            diag.error_type = "empty_paths"
            return ParseResult(parser=self.parser_name, diagnostics=diag)

        diag.input_count = len(paths)
        domains: Set[str] = set()
        endpoints: List[UnifiedApiEndpoint] = []
        seen_endpoint_keys: Set[str] = set()
        deduplicated = 0

        for path_text, path_item in paths.items():
            if not isinstance(path_text, str):
                continue
            path_level_params: List[Any] = []
            operations: List[Tuple[str, Dict[str, Any]]] = []
            if isinstance(path_item, dict):
                raw_params = path_item.get("parameters")
                if isinstance(raw_params, list):
                    path_level_params = raw_params
                for key in _HTTP_METHOD_KEYS:
                    value = path_item.get(key)
                    if isinstance(value, dict):
                        operations.append((key.upper(), value))
                if not operations:
                    # §二 冻结行为：path item 无任何 method 键兜底 GET（不留结果缺口）。
                    operations = [("GET", {})]
            else:
                operations = [("GET", {})]

            for method, operation in operations:
                for base_url, base_host in base_entries:
                    endpoint, domain_out = self._resolve_operation(
                        doc, version, path_text, method, operation,
                        path_level_params, schemes, base_url, base_host, budget,
                    )
                    if domain_out:
                        domains.add(domain_out)
                    if endpoint is None:
                        continue
                    content = "{} {}".format(endpoint.method, endpoint.url)
                    if content in seen_endpoint_keys:
                        deduplicated += 1
                        continue
                    seen_endpoint_keys.add(content)
                    endpoints.append(endpoint)

        diag.output_count = len(endpoints)
        diag.deduplicated_count = deduplicated
        diag.unresolved_ref_count = budget.unresolved
        diag.rejected_count = budget.cycles
        diag.status = "degraded" if (budget.unresolved or budget.exhausted) else "ok"

        document_type_hint = "openapi" if version == "v3" else "swagger"
        document_candidate = ApiDocumentCandidate(
            task_id=self.task_id,
            url=self.doc_url,
            type_hint=document_type_hint,
            source=self.doc_url,
            parser_version=self.parser_version,
            input_signature=compute_input_signature(_stable_dump(doc)),
            status="fetched",
        )
        return ParseResult(
            parser=self.parser_name,
            endpoints=endpoints,
            documents=[document_candidate],
            candidates=[
                # P0-01：越界 host 只作证据出口，防止不可信文档把范围外
                # host 注入任务 domain 资产面。
                {"record_type": OUT_OF_SCOPE_DOMAIN_RECORD_TYPE,
                 "content": host, "source": self.doc_url}
                for host in sorted(domains)
            ],
            diagnostics=diag,
        )

    # -- servers / 鉴权方案 -------------------------------------------------

    def _base_entries(self, doc, version) -> List[Tuple[str, str]]:
        """[(base_url, host)]；无 server 回退文档站点（legacy §二 语义）。"""
        from .web_info_intel_utils import safe_site

        entries: List[Tuple[str, str]] = []
        if version == "v3":
            for server in doc.get("servers") or []:
                if not isinstance(server, dict):
                    continue
                url_text = str(server.get("url", "") or "").strip().rstrip("/")
                if not url_text:
                    continue
                if url_text.startswith("//") or url_text.startswith("/"):
                    scheme = str(urlsplit(self.doc_url).scheme or "https").lower() or "https"
                    url_text = "{}:{}".format(scheme, url_text)
                entries.append((url_text, _host_of(url_text)))
        else:
            host = str(doc.get("host", "") or "").strip()
            base_path = str(doc.get("basePath", "") or "").strip()
            schemes = doc.get("schemes") if isinstance(doc.get("schemes"), list) else []
            if host:
                if not schemes:
                    schemes = ["https"]
                for scheme in schemes:
                    entries.append((
                        "{}://{}{}".format(str(scheme or "https").strip(), host, base_path).rstrip("/"),
                        _host_of("https://" + host),
                    ))
        if not entries:
            site = str(safe_site(self.doc_url) or self.doc_url).rstrip("/")
            entries = [(site, _host_of(site))]
        deduped: List[Tuple[str, str]] = []
        seen: Set[Tuple[str, str]] = set()
        for entry in entries:
            if entry in seen:
                continue
            seen.add(entry)
            deduped.append(entry)
        return deduped

    def _security_schemes(self, doc, version) -> Dict[str, Dict[str, Any]]:
        if version == "v3":
            raw = (doc.get("components") or {}).get("securitySchemes") if isinstance(doc.get("components"), dict) else None
        else:
            raw = doc.get("securityDefinitions")
        out: Dict[str, Dict[str, Any]] = {}
        if isinstance(raw, dict):
            for name, spec in raw.items():
                if isinstance(spec, dict):
                    out[str(name)] = spec
        return out

    def _auth_for_operation(self, doc, operation, schemes) -> Tuple[str, List[SecurityRequirementSummary]]:
        raw_reqs = operation.get("security")
        if raw_reqs is None:
            raw_reqs = doc.get("security")
        if raw_reqs == []:
            return "none", []
        requirements: List[SecurityRequirementSummary] = []
        auth_hint = "unknown"
        if isinstance(raw_reqs, list):
            for requirement in raw_reqs:
                if not isinstance(requirement, dict):
                    continue
                for name in requirement.keys():
                    spec = schemes.get(str(name)) or {}
                    summary = SecurityRequirementSummary(name=str(name), type=_scheme_type_key(spec))
                    requirements.append(summary)
                    if auth_hint == "unknown":
                        auth_hint = summary.type
        return auth_hint, requirements

    # -- 单 operation -------------------------------------------------------

    def _resolve_operation(self, doc, version, path_text, method, operation,
                           path_level_params, schemes, base_url, base_host, budget):
        from .web_info_intel_utils import normalize_in_scope_url

        raw_url = urljoin(str(base_url or "").rstrip("/") + "/", str(path_text or "").lstrip("/"))
        host = _host_of(raw_url) or base_host
        if not host or host not in self.allowed_hosts:
            # 越界 server/path：越界证据候选替代端点（§二 冻结行为 + P0-01）。
            return None, (host or "")

        if url_has_template(raw_url):
            # G1：模板 URL 原样保留（资产语义），不再走会丢弃花括号的过滤器。
            normalized = raw_url
        else:
            normalized = normalize_in_scope_url(raw_url, raw_url, self.allowed_hosts, allow_js=False)
        if not normalized:
            return None, ""

        parameters = self._merge_parameters(doc, version, path_level_params, operation, budget)
        request_body_type, request_body_schema = self._request_body(doc, version, operation, budget)
        response_schema, response_resolved = self._response_summary(doc, version, operation, budget)
        auth_hint, security_reqs = self._auth_for_operation(doc, operation, schemes)
        info = doc.get("info") if isinstance(doc.get("info"), dict) else {}
        endpoint = UnifiedApiEndpoint(
            url=normalized,
            method=canonical_method(method),
            api_type="rest",
            path_template=str(path_text or "")[:256],
            source=self.doc_url,
            parent_document=self.doc_url,
            base_url=str(base_url or "")[:512],
            api_version=str(info.get("version") or "")[:64],
            operation_id=str(operation.get("operationId") or "")[:128],
            tags=[str(t)[:64] for t in (operation.get("tags") or []) if str(t).strip()][:10],
            parameters=parameters,
            request_body_type=request_body_type,
            request_body_schema=request_body_schema,
            response_schema=response_schema,
            auth_hint=auth_hint,
            security_requirements=security_reqs,
            schema_available=bool(request_body_schema) or bool(response_schema and response_resolved),
            confidence=80,
            input_signature=compute_input_signature(
                self.doc_url, base_url, path_text, method, request_body_type, auth_hint),
        )
        return endpoint, ""

    def _merge_parameters(self, doc, version, path_level_params, operation, budget) -> List[ParameterSpec]:
        parameters: List[ParameterSpec] = []
        seen: Set[Tuple[str, str]] = set()
        for raw_param in list(path_level_params) + list(operation.get("parameters") or []):
            param = raw_param
            if isinstance(param, dict) and isinstance(param.get("$ref"), str):
                param, _kind = _resolve_or_none(doc, param["$ref"], budget, set())
            if not isinstance(param, dict):
                continue
            location = str(param.get("in", "query") or "query").strip()
            if location not in _PARAM_LOCATIONS:
                continue
            if version == "v2" and location == "body":
                # swagger2 body 参数走 _request_body 摘要，不混入参数列表。
                continue
            key = (str(param.get("name") or "unnamed"), location)
            if key in seen:
                continue
            seen.add(key)
            schema = param.get("schema") if isinstance(param.get("schema"), dict) else {}
            type_summary = str(schema.get("type") or param.get("type") or "").strip()[:128]
            parameters.append(ParameterSpec(
                name=str(param.get("name") or "unnamed"),
                location=location,
                type_summary=type_summary,
                required=bool(param.get("required", False)),
            ))
        return parameters

    def _request_body(self, doc, version, operation, budget):
        if version == "v3":
            body, _ = _dereference(doc, operation.get("requestBody"), budget, set())
            if isinstance(body, dict):
                content = body.get("content") if isinstance(body.get("content"), dict) else {}
                for ctype, media in content.items():
                    schema = media.get("schema") if isinstance(media, dict) else None
                    summary, _resolved = self._summarize_schema(doc, schema, budget, set(), _SCHEMA_SUMMARY_MAX_DEPTH)
                    return str(ctype)[:64], summary
            return "", {}
        consumes = [str(c) for c in (operation.get("consumes") or []) if str(c).strip()]
        for param in operation.get("parameters") or []:
            if isinstance(param, dict) and str(param.get("in")) == "body":
                summary, _ = self._summarize_schema(doc, param.get("schema"), budget, set(), _SCHEMA_SUMMARY_MAX_DEPTH)
                return (consumes[0] if consumes else "application/json")[:64], summary
        if any(isinstance(p, dict) and str(p.get("in")) == "formData" for p in operation.get("parameters") or []):
            return (consumes[0] if consumes else "application/x-www-form-urlencoded")[:64], {}
        return "", {}

    def _response_summary(self, doc, version, operation, budget):
        responses = operation.get("responses")
        if not isinstance(responses, dict):
            return {}, False
        summary: Dict[str, Any] = {}
        resolved_any = False
        for code, response in responses.items():
            node, _ = _dereference(doc, response, budget, set())
            if not isinstance(node, dict):
                continue
            schema = None
            if version == "v3":
                content = node.get("content") if isinstance(node.get("content"), dict) else {}
                for media in content.values():
                    if isinstance(media, dict) and isinstance(media.get("schema"), dict):
                        schema = media["schema"]
                        break
            else:
                schema = node.get("schema") if isinstance(node.get("schema"), dict) else None
            if schema is None:
                summary[str(code)[:16]] = {"type": "none"}
                continue
            brief, resolved = self._summarize_schema(doc, schema, budget, set(), _SCHEMA_SUMMARY_MAX_DEPTH)
            summary[str(code)[:16]] = brief
            resolved_any = resolved_any or resolved
        return summary, resolved_any

    def _summarize_schema(self, doc, schema, budget: _RefBudget, active: Set[str], depth: int):
        """有界摘要：类型/属性名/引用标记；循环与未解析显式标注，不复制大文档。"""
        if not isinstance(schema, dict):
            return {"type": "unknown"}, False
        if isinstance(schema.get("$ref"), str):
            ref = str(schema["$ref"])
            target, kind = budget.consume(doc, ref, active)
            if kind == "cycle":
                return {"cycle_ref": ref}, True
            if target is None:
                return {"unresolved_ref": ref}, False
            brief, resolved = self._summarize_schema(
                doc, target, budget, active | {ref}, depth)
            if resolved:
                return brief, True
            return {"ref": ref}, False
        if depth <= 0:
            return {"type": str(schema.get("type") or "object"), "truncated": True}, False
        node_type = str(schema.get("type") or "").strip()
        brief: Dict[str, Any] = {"type": node_type or "unknown"}
        resolved_any = bool(node_type)
        items = schema.get("items")
        if node_type == "array" or isinstance(items, dict):
            item_brief, resolved = self._summarize_schema(doc, items or {}, budget, active, depth - 1)
            brief["items"] = item_brief
            resolved_any = resolved_any or resolved
        properties = schema.get("properties")
        if isinstance(properties, dict):
            names: Dict[str, Any] = {}
            for name, sub in list(properties.items())[:_SCHEMA_SUMMARY_MAX_PROPERTIES]:
                sub_brief, resolved = self._summarize_schema(doc, sub, budget, active, depth - 1)
                names[str(name)[:64]] = (
                    sub_brief.get("type", "unknown")
                    if set(sub_brief.keys()) <= {"type"}
                    else sub_brief
                )
                resolved_any = resolved_any or resolved
            if names:
                brief["properties"] = names
            if len(properties) > _SCHEMA_SUMMARY_MAX_PROPERTIES:
                brief["truncated"] = True
        enum = schema.get("enum")
        if isinstance(enum, list):
            brief["enum_count"] = len(enum)
        return brief, resolved_any


_VAR_RE = re.compile(r"\{\{\s*([^\s{}]+?)\s*\}\}")
_POSTMAN_MAX_DEPTH = 10
_POSTMAN_MAX_ITEMS = 500


class UnifiedPostmanParser:
    """Postman Collection v2 统一解析（第 5 批，G2 闭环）。

    变量解析策略（expectations 冻结）：可解析变量 → 候选 URL + 置信度降级；
    解析不了的保留 `{var}` 模板、低置信度，不猜测具体值。查询参数与环境/头部
    变量只记录名称与位置（`ParameterSpec` 无取值通道）；raw body 仅在可解析为
    JSON 时输出键名摘要，敏感键名整体剔除——凭据值在本结构下无落点。
    """

    parser_name = "postman_unified"
    parser_version = "v1"

    def __init__(self, task_id: str, doc_url: str, allowed_hosts=None, allowed_flds=None):
        self.task_id = str(task_id or "")
        self.doc_url = str(doc_url or "")
        self.allowed_hosts = {str(h or "").strip().lower() for h in (allowed_hosts or set()) if str(h or "").strip()}
        self.allowed_flds = {str(f or "").strip().lower() for f in (allowed_flds or set()) if str(f or "").strip()}

    def parse(self, document_artifact: Any, parse_options: Optional[ParseOptions] = None) -> ParseResult:
        diag = ParseDiagnostics(parser=self.parser_name)
        doc = document_artifact
        if not isinstance(doc, dict):
            text = document_artifact.decode("utf-8", "ignore") if isinstance(document_artifact, bytes) \
                else str(document_artifact or "")
            options = parse_options or ParseOptions()
            if len(text.encode("utf-8", "ignore")) > options.max_document_bytes:
                diag.status = "failed"
                diag.error_type = "document_too_large"
                return ParseResult(parser=self.parser_name, diagnostics=diag)
            doc, error_type = UnifiedOpenApiParser._load(text)
            if doc is None:
                # Collection v2.x 是 JSON-only 格式：载入失败即"非 postman 形态"，
                # 必须 skipped 交链（与 openapi 链首修复同一契约）；把 GraphQL SDL
                # 等任意文本标 failed 会在链上截断后继解析器。真实 postman JSON
                # 必能载入，其结构异常由 legacy 路径与本解析器 item 校验兜底。
                diag.status = "skipped"
                diag.error_type = "not_postman_document"
                return ParseResult(parser=self.parser_name, diagnostics=diag)
        if not isinstance(doc, dict) or not isinstance(doc.get("item"), list):
            diag.status = "skipped"
            diag.error_type = "not_postman_document"
            return ParseResult(parser=self.parser_name, diagnostics=diag)

        variables: Dict[str, str] = {}
        for var in doc.get("variable") or []:
            if isinstance(var, dict) and str(var.get("key") or "").strip():
                variables[str(var["key"])] = str(var.get("value") or "")

        requests: List[Tuple[str, Dict[str, Any]]] = []
        self._walk(doc.get("item") or [], requests, [], 0)
        diag.input_count = len(requests)

        from .web_info_intel_utils import normalize_in_scope_url, safe_site

        endpoints: List[UnifiedApiEndpoint] = []
        seen: Set[str] = set()
        domains: Set[str] = set()
        unresolved_templates = 0
        rejected = 0
        for folder_name, request in requests:
            try:
                endpoint, domain_host, unresolved, bad = self._build_endpoint(
                    doc, request, variables, folder_name, normalize_in_scope_url, safe_site)
            except Exception:
                rejected += 1
                continue
            if bad:
                rejected += 1
            if unresolved:
                unresolved_templates += 1
            if domain_host:
                domains.add(domain_host)
            if endpoint is None:
                continue
            content = "{} {}".format(endpoint.method, endpoint.url)
            if content in seen:
                continue
            seen.add(content)
            endpoints.append(endpoint)

        diag.output_count = len(endpoints)
        diag.rejected_count = rejected
        diag.unresolved_ref_count = unresolved_templates
        diag.status = "degraded" if (unresolved_templates or rejected) else "ok"
        document_candidate = ApiDocumentCandidate(
            task_id=self.task_id,
            url=self.doc_url,
            type_hint="postman",
            source=self.doc_url,
            parser_version=self.parser_version,
            input_signature=compute_input_signature(_stable_dump(doc)),
            status="fetched",
        )
        return ParseResult(
            parser=self.parser_name,
            endpoints=endpoints,
            documents=[document_candidate],
            candidates=[
                {"record_type": OUT_OF_SCOPE_DOMAIN_RECORD_TYPE,
                 "content": host, "source": self.doc_url}
                for host in sorted(domains)
            ],
            diagnostics=diag,
        )

    def _walk(self, items, out: List, name_chain: List[str], depth: int) -> None:
        if depth > _POSTMAN_MAX_DEPTH or len(out) >= _POSTMAN_MAX_ITEMS:
            return
        for item in items:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "")[:64]
            child = item.get("item")
            if isinstance(child, list):
                self._walk(child, out, name_chain + [name] if name else name_chain, depth + 1)
                continue
            request = item.get("request")
            if isinstance(request, dict):
                out.append(("/".join([n for n in name_chain if n]) or name, request))

    def _substitute(self, text: str, variables: Dict[str, str]) -> Tuple[str, bool]:
        unresolved = False

        def _repl(match):
            nonlocal unresolved
            key = match.group(1)
            if key in variables:
                if is_sensitive_key(key):
                    # Review P0-02：敏感键名是唯一安全依据，命中即永不产出真实值——
                    # URL 的 raw 文本、protocol/host/path 拼装、query 段、path 变量段
                    # 都经由本替换函数，统一保留 {{key}} 模板并标 unresolved，
                    # 走既有"不可解析变量→模板保留、置信度 30、桥接抑制 urlfinder"
                    # 链路，而不是静默替换成原值。models 的 sanitize_url_secrets 只
                    # 兜敏感 query 键位，挡不住 path/host 位原值，不能依赖它补救。
                    unresolved = True
                    return "{{" + key + "}}"
                return variables[key]
            unresolved = True
            return "{" + key + "}"

        return _VAR_RE.sub(_repl, str(text or "")), unresolved

    def _build_endpoint(self, doc, request, variables, folder_name, normalize_in_scope_url, safe_site):
        method = canonical_method(request.get("method", "GET"))
        url_data = request.get("url")
        raw_text = ""
        query_params: List[Dict[str, Any]] = []
        path_variables: List[Dict[str, Any]] = []
        unresolved = False

        if isinstance(url_data, dict):
            raw_text = str(url_data.get("raw") or "")
            query_params = [q for q in (url_data.get("query") or []) if isinstance(q, dict)]
            path_variables = [v for v in (url_data.get("variable") or []) if isinstance(v, dict)]
            if not raw_text:
                protocol = str(url_data.get("protocol") or "https")
                host = ".".join(str(h) for h in (url_data.get("host") or []) if str(h).strip())
                path = "/".join(str(p) for p in (url_data.get("path") or []) if str(p) != "")
                if host:
                    raw_text = "{}://{}/{}".format(protocol, host, path.lstrip("/"))
        elif isinstance(url_data, str):
            raw_text = url_data

        if not raw_text.strip():
            return None, "", False, True

        if raw_text.startswith("/") and self.doc_url:
            raw_text = str(safe_site(self.doc_url)).rstrip("/") + raw_text
        resolved, unresolved_flag = self._substitute(raw_text, variables)
        unresolved = unresolved_flag or ("{{" in resolved)

        # 查询：参数进 ParameterSpec，URL 只保留资源路径（期望口径）。
        query_keys: List[str] = []
        for query in query_params:
            key = str(query.get("key") or "").strip()
            if key:
                query_keys.append(key)
        if "?" in resolved:
            base_part, _, query_part = resolved.partition("?")
            for pair in query_part.split("&"):
                key = pair.split("=", 1)[0].strip()
                if key:
                    query_keys.append(key)
            resolved = base_part

        host = _host_of(resolved) if not unresolved else _host_of(re.sub(r"\{[^{}]*\}", "", resolved))
        if host and host not in self.allowed_hosts and not unresolved:
            return None, host, False, False

        if unresolved:
            url_out = resolved  # 模板保留：不猜值；桥接层抑制其 urlfinder_url
            confidence = 30
        elif url_has_template(resolved):
            # 冒号路径变量与花括号同口径：会丢弃模板的过滤器绕开（G1/G2）。
            url_out = resolved
            confidence = 70 if resolved != raw_text else 80
        else:
            url_out = normalize_in_scope_url(resolved, resolved, self.allowed_hosts, allow_js=False)
            confidence = 70 if resolved != raw_text else 80
        if not url_out:
            return None, "", unresolved, True

        parameters: List[ParameterSpec] = []
        seen_params: Set[Tuple[str, str]] = set()
        headers = request.get("header") if isinstance(request.get("header"), list) else []
        for header in headers:
            if isinstance(header, dict) and str(header.get("key") or "").strip():
                self._add_param(parameters, seen_params, str(header["key"]).strip(), "header", "")
        for key in query_keys:
            self._add_param(parameters, seen_params, key, "query", "")
        for var in path_variables:
            self._add_param(parameters, seen_params, str(var.get("key") or "").strip().lstrip(":"), "path", "")

        body_type, body_summary, body_params = self._body(request.get("body"))
        for name in body_params:
            self._add_param(parameters, seen_params, name, "formData" if body_type == "formdata" else "body", "")
        if body_summary:
            # raw body 的键名摘要并入 parameters 会混淆位置语义；只保留在 schema 摘要。
            pass

        auth_hint = self._auth_hint(parameters)
        path_template = self._path_template(url_out, query_keys, path_variables)
        info = doc.get("info") if isinstance(doc.get("info"), dict) else {}
        endpoint = UnifiedApiEndpoint(
            url=url_out,
            method=method,
            api_type="rest",
            path_template=path_template[:256],
            source=self.doc_url,
            parent_document=self.doc_url,
            base_url=str(safe_site(url_out) or ""),
            api_version=str(info.get("version") or "")[:64],
            operation_id=(folder_name or "")[:128],
            tags=[folder_name[:64]] if folder_name else [],
            parameters=parameters,
            request_body_type=body_type,
            request_body_schema=body_summary,
            auth_hint=auth_hint,
            confidence=confidence,
            input_signature=compute_input_signature(self.doc_url, raw_text, method, body_type),
        )
        return endpoint, "", unresolved, False

    @staticmethod
    def _add_param(parameters, seen, name, location, type_summary) -> None:
        name = str(name or "").strip()
        if not name:
            return
        key = (name, location)
        if key in seen:
            return
        seen.add(key)
        parameters.append(ParameterSpec(
            name=name, location=location, type_summary=type_summary[:128]))

    @staticmethod
    def _body(body):
        if not isinstance(body, dict):
            return "", {}, []
        mode = str(body.get("mode") or "").strip().lower()
        if mode == "raw":
            raw = str(body.get("raw") or "")
            summary = UnifiedPostmanParser._summarize_raw(raw)
            return "raw", summary, []
        if mode in ("urlencoded", "formdata"):
            entries = body.get(mode) or []
            names = [str(e.get("key") or "").strip() for e in entries
                     if isinstance(e, dict) and str(e.get("key") or "").strip()]
            return mode, {}, names
        return mode or "raw", {}, []

    @staticmethod
    def _summarize_raw(raw: str) -> Dict[str, Any]:
        text = str(raw or "").strip()
        if not text or len(text) > 65536:
            return {}
        try:
            obj = json.loads(text)
        except Exception:
            return {"type": "text"}
        if isinstance(obj, dict):
            properties: Dict[str, Any] = {}
            for key in list(obj.keys())[:50]:
                # 敏感键名整体剔除：连键值对摘要都不留（泄露守卫禁止 token/password 类键）。
                if is_sensitive_key(key):
                    continue
                value = obj[key]
                properties[str(key)[:64]] = type(value).__name__ if isinstance(value, (int, float, bool)) \
                    else ("array" if isinstance(value, list) else ("object" if isinstance(value, dict) else "string"))
            return {"type": "object", "properties": properties} if properties else {"type": "object"}
        if isinstance(obj, list):
            return {"type": "array"}
        return {"type": "string" if isinstance(obj, str) else ("number" if isinstance(obj, (int, float)) else "unknown")}

    @staticmethod
    def _auth_hint(parameters) -> str:
        names = {p.name.lower() for p in parameters if p.location == "header"}
        if "authorization" in names or "proxy-authorization" in names:
            return "bearer"
        if names & {"x-api-key", "apikey", "api-key"}:
            return "api_key"
        if "cookie" in names:
            return "cookie"
        return "unknown"

    @staticmethod
    def _path_template(url_out: str, query_keys: List[str], path_variables: List[Dict[str, Any]]) -> str:
        from urllib.parse import urlsplit

        try:
            path = str(urlsplit(url_out).path or "")
        except ValueError:
            path = ""
        template = path  # 冒号路径变量天然保留在 path 里（path_template_expected）
        if query_keys:
            template = "{}?{}".format(template, "".join("{{{}}}".format(k) for k in query_keys[:20]))
        return template

class _GraphQLParseError(Exception):
    pass


class UnifiedGraphqlParser:
    """GraphQL 文档统一解析（第 6 批 G5 闭环；T2+T3：P1-06/P1-07/P0-03）。

    三个形态：请求文档（`{query, operationName, variables}`，可嵌套在
    `{url, method, request}` 外壳里）、introspection 响应（`data.__schema`）、
    SDL 文本。Schema 面（introspection/SDL）受 `graphql_schema_enable`
    开关与 bytes/type/field/argument/depth 预算约束（P0-03：任何预算命中
    结果不得为 ok——degraded + 具体预算名进 diagnostics；结构性错误 failed；
    默认关闭 → skipped 回 legacy 现状路径）。
    operation 拆解（T2/P1-06、P1-07）：轻量 tokenizer——掩码跳过 `#` 行注释、
    `"..."` 行字符串与 `\"\"\"...\"\"\"` 块字符串（含转义），只在文档级花括号
    深度 0 识别 operation header（query/mutation/subscription + 可选 name +
    可选 variables 声明/指令），不做完整 grammar。variables 仅记名称与声明
    类型；`variables` 对象的取值在本结构下无落点（G4/脱敏）。
    """

    parser_name = "graphql_unified"
    parser_version = "v1"

    # T2 冻结（P1-06/P1-07）：operation header 只在掩码文本深度 0 识别，
    # 替换旧 `_OP_RE` 全文搜索（嵌套 selection 字段名/注释/字符串关键字误报根因）。
    _OP_KEYWORD_RE = re.compile(
        r"(?<![A-Za-z0-9_])(query|mutation|subscription)(?![A-Za-z0-9_])")
    _VAR_DEF_RE = re.compile(r"\$\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([A-Za-z_][A-Za-z0-9_\[\]! ]*?)\s*(?=,|$|\))")
    _REF_VAR_RE = re.compile(r"\$\s*([A-Za-z_][A-Za-z0-9_]*)")
    _IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
    _SDL_HEAD_RE = re.compile(
        r"^(?:extend\s+)?(schema|type|input|enum|union|scalar|interface|directive)(?![A-Za-z0-9_])")
    _FIELD_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\s*[(!:]")
    _FIELD_SIG_RE = re.compile(
        r"^(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:\((?P<args>[^()]*)\))?\s*:\s*(?P<ret>[^#=]*)")
    _MAX_OPERATIONS = 50
    _MAX_TYPES = 500
    _MAX_FIELDS_PER_TYPE = 100
    _MAX_ARGS_PER_FIELD = 100
    _MAX_OF_TYPE_CHAIN = 1000
    _MAX_QUERY_BYTES = 65536

    def __init__(self, task_id: str, doc_url: str, allowed_hosts=None, allowed_flds=None,
                 schema_max_bytes: int = 2 * 1024 * 1024):
        self.task_id = str(task_id or "")
        self.doc_url = str(doc_url or "")
        self.allowed_hosts = {str(h or "").strip().lower() for h in (allowed_hosts or set()) if str(h or "").strip()}
        self.allowed_flds = {str(f or "").strip().lower() for f in (allowed_flds or set()) if str(f or "").strip()}
        self.schema_max_bytes = max(1024, int(schema_max_bytes or 0))

    def parse(self, document_artifact: Any, parse_options: Optional[ParseOptions] = None) -> ParseResult:
        options = parse_options or ParseOptions()
        diag = ParseDiagnostics(parser=self.parser_name)
        text = document_artifact.decode("utf-8", "ignore") if isinstance(document_artifact, bytes) \
            else str(document_artifact or "")
        if not text.strip():
            diag.status = "skipped"
            diag.error_type = "empty_document"
            return ParseResult(parser=self.parser_name, diagnostics=diag)

        doc = None
        try:
            doc = json.loads(text)
        except Exception:
            doc = None

        if isinstance(doc, dict):
            if self._looks_like_sdl_request(doc):
                return self._parse_request_document(doc, diag)
            if self._looks_like_introspection(doc) or self._has_schema_key(doc):
                if not options.graphql_schema_enable:
                    diag.status = "skipped"
                    diag.error_type = "graphql_schema_disabled"
                    return ParseResult(parser=self.parser_name, diagnostics=diag)
                if len(text.encode("utf-8", "ignore")) > self.schema_max_bytes:
                    diag.status = "failed"
                    diag.error_type = "document_too_large"
                    return ParseResult(parser=self.parser_name, diagnostics=diag)
                return self._parse_introspection(doc, diag, options)
            diag.status = "skipped"
            diag.error_type = "not_graphql_document"
            return ParseResult(parser=self.parser_name, diagnostics=diag)

        # 非 JSON：SDL 文本形态
        if not options.graphql_schema_enable:
            diag.status = "skipped"
            diag.error_type = "graphql_schema_disabled"
            return ParseResult(parser=self.parser_name, diagnostics=diag)
        if len(text.encode("utf-8", "ignore")) > self.schema_max_bytes:
            diag.status = "failed"
            diag.error_type = "document_too_large"
            return ParseResult(parser=self.parser_name, diagnostics=diag)
        # P0-03 结构性错误：带 `__schema` 痕迹的断裂 JSON 是"坏掉的 introspection"，
        # 不得当成 SDL 文本静默 skipped。
        if text.lstrip().startswith("{") and '"__schema"' in text:
            return self._schema_failed(diag, "introspection", "introspection_json_broken")
        if not self._looks_like_sdl_text(text):
            diag.status = "skipped"
            diag.error_type = "not_graphql_document"
            return ParseResult(parser=self.parser_name, diagnostics=diag)
        return self._parse_sdl(text, diag, options)

    # -- 形态识别 -----------------------------------------------------------

    def _looks_like_sdl_request(self, doc: Dict[str, Any]) -> bool:
        request = doc.get("request")
        if isinstance(request, dict) and isinstance(request.get("query"), str):
            return True
        return isinstance(doc.get("query"), str)

    def _looks_like_introspection(self, doc: Dict[str, Any]) -> bool:
        data = doc.get("data")
        if isinstance(data, dict) and isinstance(data.get("__schema"), dict):
            return True
        return isinstance(doc.get("__schema"), dict)

    def _has_schema_key(self, doc: Dict[str, Any]) -> bool:
        """`__schema` 键在场但值畸形（缺失/被篡改）：按坏 introspection 判 failed，
        不当成任意 JSON 静默 skipped（P0-03 结构性错误显式化）。"""
        if "__schema" in doc:
            return True
        data = doc.get("data")
        return isinstance(data, dict) and "__schema" in data

    def _looks_like_sdl_text(self, text: str) -> bool:
        matched = 0
        for line in text.splitlines()[:400]:
            if self._SDL_HEAD_RE.match(line.strip()):
                matched += 1
        return matched >= 1

    # -- 请求文档 -----------------------------------------------------------

    def _parse_request_document(self, doc: Dict[str, Any], diag: ParseDiagnostics) -> ParseResult:
        from .web_info_intel_utils import normalize_in_scope_url, safe_site

        request = doc.get("request") if isinstance(doc.get("request"), dict) else doc
        query_text = str(request.get("query") or "")
        if not query_text.strip():
            diag.status = "skipped"
            diag.error_type = "not_graphql_document"
            return ParseResult(parser=self.parser_name, diagnostics=diag)
        query_truncated = False
        if len(query_text.encode("utf-8", "ignore")) > self._MAX_QUERY_BYTES:
            # query 字节预算：截断事实先记录，诊断在 operation 拆解后统一收口
            # （截断导致的未闭合不得升级为结构 failed，见下方 note 优先级）。
            query_truncated = True
            query_text = query_text[:self._MAX_QUERY_BYTES]

        base_url = str(doc.get("url") or "").strip() or self.doc_url
        method = canonical_method(doc.get("method") or "POST")
        host = _host_of(base_url)
        if host and host not in self.allowed_hosts:
            return ParseResult(
                parser=self.parser_name,
                # P0-01：越界 base 只作证据出口，不落 in-scope domain 资产。
                candidates=[{"record_type": OUT_OF_SCOPE_DOMAIN_RECORD_TYPE,
                             "content": host, "source": self.doc_url}],
                diagnostics=ParseDiagnostics(
                    parser=self.parser_name, status="ok", error_type="out_of_scope_base"),
            )
        normalized = normalize_in_scope_url(base_url, base_url, self.allowed_hosts, allow_js=False) \
            or base_url

        operations, unclosed, limit_hit = self._extract_operations(query_text)
        variables_obj = request.get("variables") \
            if isinstance(request.get("variables"), dict) else {}
        for op in operations:
            if op["name"] == "" and not op["variables"]:
                # 匿名 operation 变量兜底（T2 冻结语义）：名称集合 =
                # 查询文本 `$name` 引用 ∪ 请求体 variables 对象键名。
                # 只取名称——ParameterSpec 结构上无取值通道，值绝不外流（G4/脱敏）。
                names = sorted(set(op["refs"]) | {str(key) for key in variables_obj})
                op["variables"] = [(name, "") for name in names]
        requested_name = str(request.get("operationName") or "")
        endpoints: List[UnifiedApiEndpoint] = []
        for op in operations:
            variable_specs: List[ParameterSpec] = []
            for var_name, var_type in op["variables"]:
                variable_specs.append(ParameterSpec(
                    name=var_name, location="body", type_summary=var_type[:128]))
            endpoints.append(UnifiedApiEndpoint(
                url=normalized,
                method=method,
                api_type="graphql",
                path_template=str(urlsplit(normalized).path or "")[:256],
                source=self.doc_url,
                parent_document=self.doc_url,
                base_url=str(safe_site(normalized) or ""),
                operation_id=op["name"][:128],
                tags=[op["type"]],
                parameters=variable_specs,
                auth_hint="unknown",
                schema_available=False,
                graphql_operation=op["type"],
                graphql_operation_name=op["name"][:128],
                graphql_query_hash=graphql_query_hash(op["text"]),
                confidence=70,
                input_signature=compute_input_signature(
                    normalized, method, op["type"], op["name"], op["hash_source"]),
            ))
        if not endpoints and requested_name:
            endpoints.append(UnifiedApiEndpoint(
                url=normalized, method=method, api_type="graphql",
                source=self.doc_url, parent_document=self.doc_url,
                graphql_operation="unknown", graphql_operation_name=requested_name[:128],
                confidence=40,
                input_signature=compute_input_signature(normalized, method, "unknown", requested_name)))
        # T2 诊断收口（error_type 先记优先）：
        # - query 字节预算命中 → degraded + query_truncated（既有语义保留）；
        # - 未闭合：截断致因的未闭合只 degraded；无任何完整 operation 且非截断
        #   致因 → 结构性 malformed_query（failed），不得用剩余文本静默产出；
        # - operation 超上限：degraded + operation_limit_exceeded，禁止静默切片。
        diag.input_count = 1
        diag.output_count = len(endpoints)
        if query_truncated:
            self._note_diagnostic(diag, "degraded", "query_truncated")
        if unclosed and not operations and not query_truncated:
            diag.status = "failed"
            diag.error_type = "malformed_query"
        elif unclosed:
            self._note_diagnostic(diag, "degraded", "unclosed_operation")
        if limit_hit:
            self._note_diagnostic(diag, "degraded", "operation_limit_exceeded")
        candidate = ApiDocumentCandidate(
            task_id=self.task_id, url=self.doc_url, type_hint="graphql",
            source=self.doc_url, parser_version=self.parser_version,
            input_signature=compute_input_signature(_stable_dump(doc)),
            status="fetched",
            confidence=70,
        )
        return ParseResult(parser=self.parser_name, endpoints=endpoints,
                           documents=[candidate], diagnostics=diag)

    def _extract_operations(self, query_text: str) -> Tuple[List[Dict[str, Any]], bool, bool]:
        """T2（P1-06/P1-07）operation tokenizer，返回 (operations, unclosed, limit_hit)。

        - 先把 `#` 行注释、`"..."` 行字符串、`\"\"\"...\"\"\"` 块字符串（含转义）
          掩码为空白，再只在掩码文本的花括号深度 0 识别 operation header +
          花括号配平：嵌套 selection 字段名、注释/字符串里的关键字与花括号
          不再可能成 operation（Review 判定的旧 `_OP_RE` 全文搜索误报根因）；
        - 匿名 operation 仅当文档首个非空白字符是 `{` 时成立；
        - 发现 operation 起点但配平失败 → unclosed=True 并停止：绝不用剩余
          文本静默产出 operation；
        - 已产出 _MAX_OPERATIONS 个后仍见新 header → limit_hit=True
          （operations 已封顶 50，调用方必须标 degraded，禁止静默切片）。
        """
        mask = self._mask_literals(query_text)
        total = len(mask)
        first_body = 0
        while first_body < total and mask[first_body].isspace():
            first_body += 1
        operations: List[Dict[str, Any]] = []
        unclosed = False
        limit_hit = False
        index = 0
        depth = 0
        while index < total:
            char = mask[index]
            if char == "{":
                if depth == 0 and index == first_body:
                    end = self._match_brace(mask, index)
                    if end < 0:
                        unclosed = True
                        break
                    operations.append(self._make_operation(
                        mask, query_text, "query", "", "", index, end))
                    index = end
                    continue
                depth += 1
            elif char == "}":
                depth = max(0, depth - 1)
            elif depth == 0 and char != '"':
                keyword = self._OP_KEYWORD_RE.match(mask, index)
                if keyword:
                    if len(operations) >= self._MAX_OPERATIONS:
                        limit_hit = True
                        break
                    header = self._read_operation_header(mask, keyword.end())
                    if header is None:
                        unclosed = True
                        break
                    name, decl, body_open = header
                    end = self._match_brace(mask, body_open)
                    if end < 0:
                        unclosed = True
                        break
                    operations.append(self._make_operation(
                        mask, query_text, keyword.group(1), name, decl, index, end))
                    index = end
                    continue
            index += 1
        return operations, unclosed, limit_hit

    def _make_operation(self, mask: str, query_text: str, op_type: str,
                        name: str, decl: str, start: int, end: int) -> Dict[str, Any]:
        """单个 operation 记录：text 为原文完整切片（起点含 header，终点含闭合花括号）。

        query hash 继续走 models `graphql_query_hash`（语义冻结：仅折叠空白）
        对规范化前的完整 operation 文本；hash_source 供端点幂等签名复用。
        """
        text = query_text[start:end].strip()
        variables = [(var_name, var_type.strip())
                     for var_name, var_type in self._VAR_DEF_RE.findall(decl)]
        return {
            "type": op_type,
            "name": name,
            "variables": variables,
            "text": text,
            "hash_source": graphql_query_hash(text),
            # `$name` 引用集合取自掩码切片（注释/字符串内不计）：匿名兜底名称来源一。
            "refs": self._REF_VAR_RE.findall(mask[start:end]),
        }

    def _read_operation_header(self, mask: str, pos: int):
        """深度 0 keyword 之后：可选 name、可选 variables 声明、可选指令，直到 body 开 `{`。

        返回 (name, decl_text, body_open_index)；未达 body 开括号 → None（上层收口
        unclosed）。变量默认值可含花括号（如 `= {a:1}` 在括号内），故括号配平先于
        body 识别；指令括号参数不得混入 variables 声明。
        """
        total = len(mask)
        ident = self._IDENT_RE.match(mask, self._skip_space(mask, pos))
        name = ident.group(0) if ident else ""
        index = ident.end() if ident else pos
        decl = ""
        in_directive = False
        while True:
            index = self._skip_space(mask, index)
            if index >= total:
                return None
            char = mask[index]
            if char == "(":
                close = self._match_paren(mask, index)
                if close < 0:
                    return None
                if not decl and not in_directive:
                    decl = mask[index + 1:close]
                in_directive = False
                index = close + 1
                continue
            if char == "@":
                directive = self._IDENT_RE.match(mask, index + 1)
                index = directive.end() if directive else index + 1
                in_directive = True
                continue
            if char == "{":
                return name, decl, index
            return None

    @staticmethod
    def _skip_space(text: str, pos: int) -> int:
        index = pos
        while index < len(text) and text[index].isspace():
            index += 1
        return index

    @staticmethod
    def _match_paren(mask: str, start: int) -> int:
        depth = 0
        for index in range(start, len(mask)):
            if mask[index] == "(":
                depth += 1
            elif mask[index] == ")":
                depth -= 1
                if depth == 0:
                    return index
        return -1

    @staticmethod
    def _match_brace(mask: str, start: int) -> int:
        """掩码文本上的花括号配平（注释/字符串内容已空白，无绕过风险），线性一次扫描。"""
        depth = 0
        for index in range(start, len(mask)):
            if mask[index] == "{":
                depth += 1
            elif mask[index] == "}":
                depth -= 1
                if depth == 0:
                    return index + 1
        return -1

    @staticmethod
    def _mask_literals(text: str) -> str:
        """把 `#` 行注释、`"..."` 行字符串、`\"\"\"...\"\"\"` 块字符串内容替换为空格。

        返回与原文逐位等长的掩码文本：定界符与空白原样保留（花括号/引号计数
        与切片偏移直接可用），被掩码区间内的一切结构字符（含 `{}`、`(`/`)`、
        operation 关键字）对 tokenizer 不可见。块字符串按 GraphQL 规范处理
        `\\` 转义（`\\"\"\"` 不作终止符）；未闭合字面量一律掩码到文档末尾/行尾。
        """
        chars = list(text)
        index = 0
        total = len(chars)
        while index < total:
            char = chars[index]
            if char == "#":
                cursor = index
                while cursor < total and text[cursor] != "\n":
                    chars[cursor] = " "
                    cursor += 1
                index = cursor
                continue
            if char != '"':
                index += 1
                continue
            if text.startswith('"""', index):
                cursor = index + 3
                close = total
                terminated = False
                while cursor + 3 <= total:
                    if text[cursor] == "\\":
                        cursor += 2
                        continue
                    if text.startswith('"""', cursor):
                        close = cursor
                        terminated = True
                        break
                    cursor += 1
                for pos in range(index + 3, close):
                    chars[pos] = " "
                index = close + 3 if terminated else total
                continue
            cursor = index + 1
            while cursor < total:
                ch = text[cursor]
                if ch == "\\":
                    cursor += 2
                    continue
                if ch in ('"', "\n"):
                    break
                cursor += 1
            for pos in range(index + 1, min(cursor, total)):
                chars[pos] = " "
            if cursor < total and text[cursor] == '"':
                index = cursor + 1
            else:
                index = min(cursor, total)
        return "".join(chars)

    @staticmethod
    def _note_diagnostic(diag: ParseDiagnostics, status: str, error_type: str) -> None:
        """请求文档诊断注记：error_type 先记优先（query_truncated 等致因先行，
        后续 degraded 注记只升状态不覆盖收口名）；failed 由结构性分支单独设置。"""
        if not diag.error_type:
            diag.error_type = error_type
        if diag.status == "ok":
            diag.status = status

    # -- SDL / introspection --------------------------------------------------

    def _parse_sdl(self, text: str, diag: ParseDiagnostics, options: ParseOptions) -> ParseResult:
        summary = self._empty_sdl_summary()
        hits: List[str] = []
        structural = ""
        field_count = 0
        current_kind = ""
        current_fields = 0
        brace_level = 0
        max_depth = options.graphql_schema_max_depth
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if brace_level == 0:
                head = self._SDL_HEAD_RE.match(stripped)
                if head:
                    kind = head.group(1)
                    name_match = self._IDENT_RE.match(stripped[head.end():].lstrip(" \t"))
                    name = name_match.group(0) if name_match else ""
                    # P0-03 结构性错误：需要名字的 definition 缺名（如 `type {`）→ failed。
                    if kind not in ("schema", "directive") and not name:
                        structural = "sdl_invalid_header"
                        break
                    if len(summary["types"]) + len(summary["enums"]) \
                            + len(summary["inputs"]) + len(summary["scalars"]) >= self._MAX_TYPES:
                        hits.append("schema_type_limit")
                        break
                    if kind in ("type", "interface"):
                        summary["types"].append(name)
                    elif kind == "enum":
                        summary["enums"].append(name)
                    elif kind == "input":
                        summary["inputs"].append(name)
                    elif kind == "scalar":
                        summary["scalars"].append(name)
                    current_kind = kind
                    current_fields = 0
                    brace_level += stripped.count("{") - stripped.count("}")
                    if brace_level <= 0:
                        brace_level = 0
                        current_kind = ""
                    continue
            if current_kind in ("type", "input", "interface", "enum"):
                if self._FIELD_NAME_RE.match(stripped):
                    current_fields += 1
                    field_count += 1
                    if current_fields > self._MAX_FIELDS_PER_TYPE:
                        hits.append("schema_field_limit")
                    sig = self._FIELD_SIG_RE.match(stripped)
                    if sig:
                        if self._wrapper_depth(sig.group("ret") or "") > max_depth:
                            hits.append("schema_depth_exceeded")
                        args_text = sig.group("args") or ""
                        arg_items = [piece for piece in args_text[1:-1].split(",")
                                     if piece.strip()] if args_text else []
                        if len(arg_items) > self._MAX_ARGS_PER_FIELD:
                            hits.append("schema_argument_limit")
                        for piece in arg_items:
                            _, _, type_part = piece.partition(":")
                            if self._wrapper_depth(type_part) > max_depth:
                                hits.append("schema_depth_exceeded")
            brace_level += stripped.count("{") - stripped.count("}")
            if brace_level <= 0:
                brace_level = 0
                current_kind = ""
        diag.input_count = len(text.splitlines())
        diag.output_count = 0
        status, error_type = self._schema_status(hits, structural)
        summary["truncated"] = bool(hits)
        contract = self._schema_summary_contract("sdl", summary, field_count, status, error_type)
        diag.status = status
        diag.error_type = error_type
        candidate = ApiDocumentCandidate(
            task_id=self.task_id, url=self.doc_url, type_hint="graphql",
            source=self.doc_url, parser_version=self.parser_version,
            input_signature=compute_input_signature(text),
            status="fetched", confidence=80,
        )
        return ParseResult(
            parser=self.parser_name, documents=[candidate],
            candidates=[contract], diagnostics=diag,
        )

    def _parse_introspection(self, doc: Dict[str, Any], diag: ParseDiagnostics,
                             options: ParseOptions) -> ParseResult:
        data = doc.get("data") if isinstance(doc.get("data"), dict) else doc
        schema = data.get("__schema")
        if not isinstance(schema, dict):
            return self._schema_failed(diag, "introspection", "introspection_schema_missing")
        types = schema.get("types")
        if not isinstance(types, list):
            return self._schema_failed(diag, "introspection", "introspection_types_invalid")
        summary = self._empty_sdl_summary()
        hits: List[str] = []
        field_count = 0
        max_depth = options.graphql_schema_max_depth
        for pos, item in enumerate(types):
            if pos >= self._MAX_TYPES:
                hits.append("schema_type_limit")
                break
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "")
            kind = str(item.get("kind") or "").upper()
            if kind == "ENUM":
                summary["enums"].append(name)
            elif kind == "INPUT_OBJECT":
                summary["inputs"].append(name)
            elif kind == "SCALAR":
                summary["scalars"].append(name)
            elif kind in ("OBJECT", "INTERFACE"):
                summary["types"].append(name)
            fields = item.get("fields")
            if not isinstance(fields, list):
                fields = item.get("inputFields")
            if not isinstance(fields, list):
                continue
            per_type = 0
            for field in fields:
                per_type += 1
                field_count += 1
                if per_type > self._MAX_FIELDS_PER_TYPE:
                    hits.append("schema_field_limit")
                    break
                if not isinstance(field, dict):
                    continue
                if self._of_type_depth(field.get("type")) > max_depth:
                    hits.append("schema_depth_exceeded")
                args = field.get("args")
                if isinstance(args, list):
                    if len(args) > self._MAX_ARGS_PER_FIELD:
                        hits.append("schema_argument_limit")
                    for arg in args:
                        if isinstance(arg, dict) \
                                and self._of_type_depth(arg.get("type")) > max_depth:
                            hits.append("schema_depth_exceeded")
        diag.input_count = len(types)
        diag.output_count = 0
        status, error_type = self._schema_status(hits, "")
        summary["truncated"] = bool(hits)
        contract = self._schema_summary_contract(
            "introspection", summary, field_count, status, error_type)
        diag.status = status
        diag.error_type = error_type
        return ParseResult(
            parser=self.parser_name, candidates=[contract], diagnostics=diag,
        )

    @staticmethod
    def _empty_sdl_summary() -> Dict[str, Any]:
        return {"types": [], "enums": [], "inputs": [], "scalars": [], "truncated": False}

    @staticmethod
    def _schema_status(hits: List[str], structural: str) -> Tuple[str, str]:
        """P0-03 状态收口：结构性错误 failed > 预算命中 degraded（error_type 为
        首个命中预算名）> ok。预算命中永不产出 ok。"""
        if structural:
            return "failed", structural
        if hits:
            return "degraded", hits[0]
        return "ok", ""

    def _schema_failed(self, diag: ParseDiagnostics, kind: str, error_type: str) -> ParseResult:
        """结构性 Schema 错误：显式 failed + failed 形态契约候选（registry 消费侧
        按 §4.13 状态枚举处理），绝不静默 skipped。"""
        contract = self._schema_summary_contract(
            kind, self._empty_sdl_summary(), 0, "failed", error_type)
        diag.status = "failed"
        diag.error_type = error_type
        return ParseResult(parser=self.parser_name, candidates=[contract], diagnostics=diag)

    def _schema_summary_contract(self, kind: str, summary: Dict[str, Any],
                                 field_count: int, status: str, error_type: str) -> Dict[str, Any]:
        """P0-03 冻结契约（附录A §4.13）：键名/取值域与 registry 消费投影一字不差。

        depth 定义冻结：类型引用包装链展开深度——SDL 字段类型 `!`/`[...]` 嵌套
        层数（_wrapper_depth）、introspection `ofType` 链层数（_of_type_depth），
        超过 `graphql_schema_max_depth` 即预算命中（schema_depth_exceeded）。

        schema_hash = sha256(canonical json of types/enums/inputs/scalars)[:16]：
        canonical = sort_keys、紧凑分隔符、ensure_ascii=False、名单保发现序，
        同一输入两次解析必得同一 hash（确定性）。summary_bytes = 契约 json
        （按同一 canonical 规则、不含 `summary_bytes` 键自身）的 UTF-8 字节数。
        契约只含类型名单与计数：Schema 原文、变量值、Token、Header 无落点。
        """
        lists = {
            "types": list(summary.get("types") or []),
            "enums": list(summary.get("enums") or []),
            "inputs": list(summary.get("inputs") or []),
            "scalars": list(summary.get("scalars") or []),
        }
        canonical = json.dumps(lists, ensure_ascii=False, sort_keys=True,
                               separators=(",", ":"))
        contract: Dict[str, Any] = {
            "record_type": "graphql_schema_summary",
            "kind": kind,
            "status": status,
            "error_type": str(error_type or ""),
            "schema_hash": hashlib.sha256(canonical.encode("utf-8", "ignore")).hexdigest()[:16],
            "types": lists["types"],
            "enums": lists["enums"],
            "inputs": lists["inputs"],
            "scalars": lists["scalars"],
            "type_count": sum(len(items) for items in lists.values()),
            "field_count": int(field_count),
            "truncated": bool(summary.get("truncated")),
        }
        body = json.dumps(contract, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"))
        contract["summary_bytes"] = len(body.encode("utf-8"))
        return contract

    @staticmethod
    def _wrapper_depth(type_text: Any) -> int:
        """P0-03 冻结 depth 定义（SDL 侧）：字段/参数类型文本的 `[` 与 `!`
        包装层数之和（`String!`=1、`[[Int!]!]`=3、`[[[[[Int!]!]!]!]!]!`=11）。"""
        text = str(type_text or "")
        return text.count("[") + text.count("!")

    def _of_type_depth(self, node: Any) -> int:
        """P0-03 冻结 depth 定义（introspection 侧）：`ofType` 包装链上的
        NON_NULL/LIST 节点数，与 SDL 侧同一口径；_MAX_OF_TYPE_CHAIN 守卫
        被篡改数据里的伪造环（触顶即视为超预算命中）。"""
        depth = 0
        while isinstance(node, dict):
            if str(node.get("kind") or "").upper() not in ("NON_NULL", "LIST"):
                break
            node = node.get("ofType")
            depth += 1
            if depth > self._MAX_OF_TYPE_CHAIN:
                break
        return depth


_DTD_FORBIDDEN_RE = re.compile(r"<!\s*(DOCTYPE|ENTITY)", re.IGNORECASE)
_WSDL_ROOT_RE = re.compile(r"<[\w.:-]*(definitions|description)[\s>]", re.IGNORECASE)
_WSDL_MAX_OPERATIONS = 200
_WSDL_MAX_IMPORTS = 50
_WSDL_MAX_PARTS = 50


def _xml_local(tag: Any) -> str:
    """去命名空间：`{ns}local` → `local`（对前缀不敏感，兼容任意 xmlns 前缀）。"""

    text = str(tag or "")
    return text.rsplit("}", 1)[-1] if text.startswith("{") else text


def _qname_local(value: Any) -> str:
    """去前缀：`tns:PetBinding` → `PetBinding`（QName 引用按本地名解析）。"""

    text = str(value or "").strip()
    return text.rsplit(":", 1)[-1] if ":" in text else text


class UnifiedWsdlParser:
    """WSDL 1.1 / SOAP 统一解析（第 7 批，G6 闭环）。

    解析 definitions/service/port/binding/portType/operation/message 与
    `soap:operation@soapAction`、`soap:address@location`，产出
    `api_type=soap` 端点（method 语义默认 POST，wsdl:http verb 可覆盖），
    仅生成 Endpoint 资产、绝不调用真实 SOAP Operation（§6.4）。

    安全边界（§6.4/§11.3）：含 `<!DOCTYPE`/`<!ENTITY` 的文档整体判 `failed`
    且零解析零网络（防 XXE/SSRF/billion-laughs，DTD 是这些攻击的唯一载体）；
    即便通过守卫，expat 亦关闭参数实体解析并拒绝外部实体引用（belt-and-
    suspenders）；文件大小受 `max_document_bytes` 约束；`xsd:import`/`include`
    的外部与同源引用只登记为观测候选、**不获取**（计 unresolved、状态
    degraded，不伪装完整 Schema）。非 WSDL 形态返回 `skipped` 交回队列。
    """

    parser_name = "wsdl_unified"
    parser_version = "v1"

    def __init__(self, task_id: str, doc_url: str, allowed_hosts=None, allowed_flds=None):
        self.task_id = str(task_id or "")
        self.doc_url = str(doc_url or "")
        self.allowed_hosts = {str(h or "").strip().lower() for h in (allowed_hosts or set()) if str(h or "").strip()}
        self.allowed_flds = {str(f or "").strip().lower() for f in (allowed_flds or set()) if str(f or "").strip()}

    def parse(self, document_artifact: Any, parse_options: Optional[ParseOptions] = None) -> ParseResult:
        options = parse_options or ParseOptions()
        diag = ParseDiagnostics(parser=self.parser_name)
        text = document_artifact.decode("utf-8", "ignore") if isinstance(document_artifact, bytes) \
            else str(document_artifact or "")
        if not text.strip():
            diag.status = "skipped"
            diag.error_type = "empty_document"
            return ParseResult(parser=self.parser_name, diagnostics=diag)
        if not options.wsdl_parse_enable:
            diag.status = "skipped"
            diag.error_type = "wsdl_disabled"
            return ParseResult(parser=self.parser_name, diagnostics=diag)
        if not self._looks_like_wsdl(text):
            diag.status = "skipped"
            diag.error_type = "not_wsdl_document"
            return ParseResult(parser=self.parser_name, diagnostics=diag)
        if len(text.encode("utf-8", "ignore")) > options.max_document_bytes:
            diag.status = "failed"
            diag.error_type = "document_too_large"
            return ParseResult(parser=self.parser_name, diagnostics=diag)
        # XXE/DTD 硬守卫：解析前判定，任何 DTD/实体声明直接失败（不进入解析器）。
        if _DTD_FORBIDDEN_RE.search(text):
            diag.status = "failed"
            diag.error_type = "dtd_forbidden"
            return ParseResult(parser=self.parser_name, diagnostics=diag)
        root = self._safe_fromstring(text)
        if root is None:
            diag.status = "failed"
            diag.error_type = "xml_parse_error"
            return ParseResult(parser=self.parser_name, diagnostics=diag)
        return self._parse_document(root, text, diag)

    # -- 识别与安全载入 ----------------------------------------------------

    @staticmethod
    def _looks_like_wsdl(text: Any) -> bool:
        head = str(text or "").lstrip()[:8192]
        if not _looks_like_xml(head):
            return False
        lowered = head.lower()
        if "schemas.xmlsoap.org/wsdl" in lowered or "www.w3.org/ns/wsdl" in lowered:
            return True
        return bool(_WSDL_ROOT_RE.search(head))

    @staticmethod
    def _safe_fromstring(text: str):
        """DTD 已在调用前拒绝；此处再关闭 expat 外部/参数实体作为兜底。"""

        import xml.etree.ElementTree as ET

        parser = ET.XMLParser()
        expat_parser = getattr(parser, "parser", None)
        if expat_parser is not None:
            try:
                import xml.parsers.expat as expat

                expat_parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
                expat_parser.ExternalEntityRefHandler = lambda *a: False
            except Exception:  # pragma: no cover - 硬化失败不阻断（DTD 已拒）
                pass
        try:
            return ET.fromstring(text, parser=parser)
        except Exception:
            return None

    # -- 主解析 ------------------------------------------------------------

    def _parse_document(self, root, text: str, diag: ParseDiagnostics) -> ParseResult:
        from .web_info_intel_utils import normalize_in_scope_url, safe_site

        bindings: Dict[str, Any] = {}
        port_types: Dict[str, Any] = {}
        messages: Dict[str, Any] = {}
        for child in root:
            name = child.get("name")
            if not name:
                continue
            local = _xml_local(child.tag)
            if local == "binding":
                bindings[name] = child
            elif local in ("portType", "interface"):
                port_types[name] = child
            elif local == "message":
                messages[name] = child

        imports = self._collect_imports(root)

        endpoints: List[UnifiedApiEndpoint] = []
        domains: Set[str] = set()
        seen: Set[str] = set()
        rejected = 0
        op_count = 0
        truncated = False
        for service in root:
            if _xml_local(service.tag) != "service":
                continue
            service_name = str(service.get("name") or "")[:128]
            for port in service:
                if _xml_local(port.tag) not in ("port", "endpoint"):
                    continue
                port_name = str(port.get("name") or "")[:128]
                location = ""
                for addr in port:
                    if _xml_local(addr.tag) == "address":
                        location = str(addr.get("location") or "") or location
                binding = bindings.get(_qname_local(port.get("binding")))
                soap_actions, verb = self._binding_operations(binding)
                port_type = port_types.get(_qname_local(binding.get("type"))) if binding is not None else None
                op_source = port_type if port_type is not None else binding
                if op_source is None:
                    continue
                for op in op_source:
                    if _xml_local(op.tag) != "operation":
                        continue
                    if op_count >= _WSDL_MAX_OPERATIONS:
                        truncated = True
                        break
                    op_count += 1
                    op_name = str(op.get("name") or "")[:128]
                    endpoint, domain_out = self._build_endpoint(
                        op, op_name, service_name, port_name, location,
                        soap_actions.get(op_name, ""), verb, messages,
                        normalize_in_scope_url, safe_site)
                    if domain_out:
                        domains.add(domain_out)
                        if endpoint is None:
                            rejected += 1
                    if endpoint is None:
                        continue
                    key = "{} {} {}".format(endpoint.method, endpoint.url, endpoint.soap_action)
                    if key in seen:
                        continue
                    seen.add(key)
                    endpoints.append(endpoint)

        diag.input_count = op_count
        diag.output_count = len(endpoints)
        diag.rejected_count = rejected
        diag.unresolved_ref_count = len(imports)

        import_candidates: List[Dict[str, Any]] = []
        for loc, namespace in imports:
            resolved = urljoin(self.doc_url, loc) if self.doc_url else loc
            import_candidates.append({
                "record_type": "wsdl_xsd_import",
                "content": loc[:512],
                "resolved_url": str(resolved)[:512],
                "namespace": namespace[:256],
                "same_origin": _host_of(resolved) == _host_of(self.doc_url),
                "fetched": False,  # §6.4：外部/同源 XSD 默认不请求
                "source": self.doc_url,
            })

        # P0-01：越界 soap:address host 只作证据出口，不落 in-scope domain 资产。
        domain_candidates = [
            {"record_type": OUT_OF_SCOPE_DOMAIN_RECORD_TYPE,
             "content": host, "source": self.doc_url}
            for host in sorted(domains)
        ]
        if op_count == 0:
            # 全文无 operation：skipped 交回队列（legacy 亦不产 WSDL 面）。
            diag.status = "skipped"
            diag.error_type = "no_operations"
            return ParseResult(
                parser=self.parser_name,
                candidates=domain_candidates + import_candidates,
                diagnostics=diag,
            )
        # 有 operation：与 openapi 越界 server 同口径——端点即便为空（地址全越界）
        # 仍保留越界证据候选与文档，不静默丢弃发现证据。
        diag.status = "degraded" if (imports or rejected or truncated or not endpoints) else "ok"
        document_candidate = ApiDocumentCandidate(
            task_id=self.task_id, url=self.doc_url, type_hint="wsdl",
            source=self.doc_url, parser_version=self.parser_version,
            input_signature=compute_input_signature(text),
            status="fetched",
        )
        return ParseResult(
            parser=self.parser_name,
            endpoints=endpoints,
            documents=[document_candidate],
            candidates=domain_candidates + import_candidates,
            diagnostics=diag,
        )

    @staticmethod
    def _collect_imports(root) -> List[Tuple[str, str]]:
        imports: List[Tuple[str, str]] = []
        for element in root.iter():
            if _xml_local(element.tag) in ("import", "include"):
                location = element.get("schemaLocation") or element.get("location")
                if location:
                    imports.append((str(location), str(element.get("namespace") or "")))
            if len(imports) >= _WSDL_MAX_IMPORTS:
                break
        return imports

    @staticmethod
    def _binding_operations(binding) -> Tuple[Dict[str, str], str]:
        """从 binding 提取每 operation 的 soapAction 与 HTTP verb（默认 POST）。"""

        soap_actions: Dict[str, str] = {}
        verb = "POST"
        if binding is None:
            return soap_actions, verb
        for child in binding:
            local = _xml_local(child.tag)
            if local != "operation":
                continue
            op_name = child.get("name")
            for sub in child:
                if _xml_local(sub.tag) != "operation":
                    continue
                action = sub.get("soapAction")
                if action is not None:
                    soap_actions[op_name] = str(action)
                http_verb = sub.get("verb")
                if http_verb:
                    verb = canonical_method(http_verb)
        return soap_actions, verb

    def _build_endpoint(self, op, op_name, service_name, port_name, location,
                        soap_action, verb, messages, normalize_in_scope_url, safe_site):
        if not location:
            return None, ""
        host = _host_of(location)
        if host and host not in self.allowed_hosts:
            # 越界 soap:address：越界证据候选替代端点（与 openapi 越界 server 同口径）。
            return None, host
        normalized = normalize_in_scope_url(location, location, self.allowed_hosts, allow_js=False) or location
        if not normalized:
            return None, ""
        parameters = self._operation_parameters(op, messages)
        endpoint = UnifiedApiEndpoint(
            url=normalized,
            method=canonical_method(verb or "POST"),
            api_type="soap",
            path_template=str(urlsplit(normalized).path or "")[:256],
            source=self.doc_url,
            parent_document=self.doc_url,
            base_url=str(safe_site(normalized) or "")[:512],
            operation_id=op_name,
            tags=[t for t in ("soap", service_name) if t][:2],
            parameters=parameters,
            request_body_type="text/xml",
            soap_action=str(soap_action or "")[:256],
            wsdl_service=service_name,
            wsdl_port=port_name,
            auth_hint="unknown",
            schema_available=False,  # XSD 未获取解析，不伪装完整 Schema（§4.3）
            confidence=80,
            input_signature=compute_input_signature(self.doc_url, normalized, op_name, soap_action),
        )
        return endpoint, ""

    @staticmethod
    def _operation_parameters(op, messages) -> List[ParameterSpec]:
        """input message 的 part 名称摘要（仅名称+类型本地名，无取值通道）。"""

        parameters: List[ParameterSpec] = []
        input_message = None
        for child in op:
            if _xml_local(child.tag) == "input":
                input_message = child.get("message")
                break
        if not input_message:
            return parameters
        message = messages.get(_qname_local(input_message))
        if message is None:
            return parameters
        count = 0
        for part in message:
            if _xml_local(part.tag) != "part":
                continue
            if count >= _WSDL_MAX_PARTS:
                break
            count += 1
            name = str(part.get("name") or "").strip()
            if not name:
                continue
            type_ref = part.get("type") or part.get("element") or ""
            parameters.append(ParameterSpec(
                name=name, location="body", type_summary=_qname_local(type_ref)[:128]))
        return parameters


def _scheme_type_key(spec: Dict[str, Any]) -> str:
    scheme_type = str(spec.get("type") or "").strip().lower()
    if scheme_type == "http":
        sub = str(spec.get("scheme") or "").strip().lower()
        return "http:{}".format(sub) if sub else "http"
    return scheme_type


def _stable_dump(doc: Dict[str, Any]) -> str:
    try:
        return json.dumps(doc, sort_keys=True, ensure_ascii=False, default=str)
    except Exception:
        return repr(len(doc))


__all__ = ["UnifiedOpenApiParser", "UnifiedPostmanParser", "UnifiedGraphqlParser",
           "UnifiedWsdlParser", "url_has_template", "OUT_OF_SCOPE_DOMAIN_RECORD_TYPE"]
