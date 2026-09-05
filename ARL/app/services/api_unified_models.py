"""统一 API 解析数据契约（计划 6 第 1 批：接口和结果语义冻结）。

本模块只承载 schema、状态机、幂等键与脱敏不变量：
- 不发起 HTTP、不读写 Mongo/Redis/Celery、不做 AI 判断；
- Parser、Queue、Registry 在后续批次基于本契约实现，字段与键的
任何变更必须同步更新 docs/completed/[已完成]06-附录A-API契约冻结清单.md，
  并保证 ARL/test/fixtures/api_unified/ 的 golden corpus 回归通过。

与 discovery_context 的关系：URL 规范化复用 ResponseRegistry 同一
`normalize_url`，保证 API 层幂等键与响应缓存键对同一 URL 的口径一致。
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple

from app.services.discovery_context import normalize_url

# ---------------------------------------------------------------------------
# 冻结枚举：值集合与顺序即契约，扩展视为契约变更。
# ---------------------------------------------------------------------------

API_DOCUMENT_STATUSES: Tuple[str, ...] = (
    "discovered",
    "queued",
    "fetching",
    "fetched",
    "parsed",
    "failed",
    "skipped",
)

API_ENDPOINT_STATUSES: Tuple[str, ...] = (
    "discovered",
    "queued",
    "probed",
    "covered",
    "failed",
    "degraded",
    "pending",
    "skipped",
)

API_DOCUMENT_TYPE_HINTS: Tuple[str, ...] = (
    "openapi",
    "swagger",
    "postman",
    "graphql",
    "wsdl",
    "unknown",
)

API_TYPES: Tuple[str, ...] = ("rest", "graphql", "soap")

HTTP_METHODS: Tuple[str, ...] = (
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "OPTIONS",
    "HEAD",
)

# auth_hint 只允许记录鉴权“类型”，永远不记录凭据内容。
AUTH_HINTS: Tuple[str, ...] = (
    "none",
    "basic",
    "bearer",
    "api_key",
    "cookie",
    "oauth2",
    "mtls",
    "unknown",
)

# OpenAPI securitySchemes / Postman auth 类型 → auth_hint 映射（冻结）。
AUTH_SCHEME_TYPE_TO_HINT: Dict[str, str] = {
    "apikey": "api_key",
    "http:basic": "basic",
    "http:bearer": "bearer",
    "http": "bearer",
    "oauth2": "oauth2",
    "openidconnect": "oauth2",
    "mutualtls": "mtls",
    "cookie": "cookie",
    # 第 4 批扩展（附录A §4.1 同步登记）：swagger2 securityDefinitions 的
    # `type: basic` 顶层形态（无 http 前缀）。
    "basic": "basic",
}

GRAPHQL_OPERATIONS: Tuple[str, ...] = ("query", "mutation", "subscription", "unknown")

PARAMETER_LOCATIONS: Tuple[str, ...] = ("path", "query", "header", "cookie", "formData", "body")

# 请求 profile（计划 6 §8.1）：同一 URL 在不同 profile / 认证上下文下是不同观察。
REQUEST_PROFILES: Tuple[str, ...] = (
    "api_doc",
    "api_endpoint_probe",
    "graphql_schema_optional",
    "soap_endpoint_observe",
    "browser",
)

DIAGNOSTIC_STATUSES: Tuple[str, ...] = ("ok", "degraded", "failed", "skipped")

# Parser 幂等键的命名空间前缀（对齐 CandidateRegistry 的 key 形态）。
API_DOCUMENT_KEY_PREFIX = "api_doc"
API_ENDPOINT_KEY_PREFIX = "api_endpoint"

# ---------------------------------------------------------------------------
# 配置默认值（计划 6 §8.3，冻结为代码常量）。
# 运行时用 getattr(Config, name, 本表默认) 读取；Config 未定义时行为不变。
# ---------------------------------------------------------------------------

UNIFIED_API_CONFIG_DEFAULTS: Dict[str, Any] = {
    "API_UNIFIED_ENABLE": False,
    "API_UNIFIED_FALLBACK_ENABLE": True,
    "API_DOCUMENT_STAGE_TIMEOUT_SEC": 120,
    "API_DOCUMENT_MAX_TARGETS": 200,
    "API_DOCUMENT_MAX_SIZE_BYTES": 5242880,
    "API_DOCUMENT_MAX_DEPTH": 3,
    "API_DOCUMENT_MAX_REF_COUNT": 500,
    "API_EXTERNAL_REF_ENABLE": False,
    "GRAPHQL_SCHEMA_ENABLE": False,
    "GRAPHQL_SCHEMA_MAX_SIZE_BYTES": 2097152,
    "GRAPHQL_SCHEMA_MAX_DEPTH": 20,
    "WSDL_PARSE_ENABLE": True,
    "WSDL_MAX_SIZE_BYTES": 5242880,
    "API_ENDPOINT_PROBE_MAX_TARGETS": 500,
}

# ---------------------------------------------------------------------------
# 脱敏（计划 6 §2.2 / §4.3 字段规则）。
# ---------------------------------------------------------------------------

# 命中即视为敏感键：其值禁止进入 parameters、schema 摘要、日志、Mongo、导出。
_SENSITIVE_KEY_RE = re.compile(
    r"(?i)^(authorization|proxy-authorization|set-cookie|cookie|x-api-key|x-auth-token|"
    r"api[-_]?key|apikey|access[-_]?key|secret[-_]?key|client[-_]?secret|"
    r"[a-z0-9_-]*(token|password|passwd|credential|session[-_]?id|private[-_]?key)[a-z0-9_-]*)$"
)

_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(authorization|api[-_]?key|token|password|secret|cookie)\b\s*[:=]\s*[^,;\n]*"
)


def is_sensitive_key(name: Any) -> bool:
    return bool(_SENSITIVE_KEY_RE.match(str(name or "").strip()))


# 脱敏后的敏感 query 参数值占位符；守卫把该值视为“已清洗”，不再判为泄露。
_REDACTED = "<redacted>"

# URL query 中单个键值对：键不含 & 与 =，值不含 &（允许含 =，如 base64 尾缀）。
_QUERY_PAIR_RE = re.compile(r"(?P<key>[^&=]+)(?:=(?P<value>[^&]*))?")

# 作为独立安全边界的 URL/source 字段名（叶子键）：守卫对这些字符串额外查敏感 query。
_URL_SOURCE_FIELDS = frozenset(
    {"url", "source", "sources", "parent_url", "base_url", "parent_document"}
)


def _split_query(text: str) -> Tuple[str, str, str]:
    """把文本拆成 (含 ? 的前缀, query, 含 # 的 fragment)；无 ? 时原样返回前缀。

    手工拆分而非 urlsplit：保证干净 URL 逐字节不变，且只对 query 段脱敏，
    避免误伤 path 段中恰名为 token 的资产（如 /token/refresh）。
    """

    qmark = text.find("?")
    if qmark < 0:
        return text, "", ""
    base = text[: qmark + 1]
    rest = text[qmark + 1 :]
    hash_pos = rest.find("#")
    if hash_pos < 0:
        return base, rest, ""
    return base, rest[:hash_pos], rest[hash_pos:]


def _iter_sensitive_query_keys(query: str) -> List[str]:
    """找出 query 中携带非空、非占位值的敏感键（token/api_key/authorization 等）。"""

    hits: List[str] = []
    for match in _QUERY_PAIR_RE.finditer(query):
        value = match.group("value")
        # 空值与 <redacted> 占位不算泄露，与 find_sensitive_keys 的空值容忍一致。
        if value in (None, "", _REDACTED):
            continue
        if is_sensitive_key(match.group("key")):
            hits.append(match.group("key"))
    return hits


def _has_sensitive_url_query(text: str) -> bool:
    base, query, _ = _split_query(str(text or ""))
    return bool(query) and bool(_iter_sensitive_query_keys(query))


def _leaf_field(path: str) -> str:
    """取守卫路径的叶子字段名，剥离列表下标后缀（如 $.sources[0] -> sources）。"""

    return path.rsplit(".", 1)[-1].split("[", 1)[0]


def find_sensitive_keys(obj: Any, _path: str = "$") -> List[str]:
    """递归找出携带非空值的敏感键路径；空值与占位符允许存在。

    用于序列化前的守卫断言：统一层任何落库/导出结构必须返回空列表。
    """

    hits: List[str] = []
    if isinstance(obj, Mapping):
        # 参数摘要形态 {name: <敏感名>, value: ...}：敏感参数名一旦带值即泄露。
        if obj.get("value") not in (None, "", [], {}, 0, False) and is_sensitive_key(obj.get("name")):
            hits.append("{}.value[name={}]".format(_path, obj.get("name")))
        for key, value in obj.items():
            path = "{}.{}".format(_path, key)
            if is_sensitive_key(key) and value not in (None, "", [], {}, 0, False):
                hits.append(path)
            hits.extend(find_sensitive_keys(value, path))
    elif isinstance(obj, (list, tuple, set)):
        for index, item in enumerate(obj):
            hits.extend(find_sensitive_keys(item, "{}[{}]".format(_path, index)))
    elif isinstance(obj, str):
        # URL/source 是独立安全边界：即便绕过构造期清洗（如直接赋值 parent_url），
        # 残留的敏感 query 参数也必须被最终守卫检出，不放行到 Registry/Mongo/导出。
        if _leaf_field(_path) in _URL_SOURCE_FIELDS and _has_sensitive_url_query(obj):
            hits.append(_path)
        # 自由文本字段里的赋值形态（如 header 值原文）也按泄露处理。
        elif _path.endswith((".value", ".raw", ".content")) and _SENSITIVE_ASSIGNMENT_RE.search(obj):
            hits.append(_path)
    return hits


def redact_assignment_text(text: Any) -> str:
    """把自由文本中的 key=value 凭据替换为占位符（用于 source_detail 等）。"""

    value = str(text or "")
    return _SENSITIVE_ASSIGNMENT_RE.sub(
        lambda m: "{}=<redacted>".format(m.group(1)), value
    )


def sanitize_url_secrets(url: Any) -> str:
    """把 URL query 中敏感参数的值替换为 <redacted>，绝不整条删除 URL。

    干净 URL 必须逐字节返回（提前短路，不经 parse_qsl/urlencode 重编码），
    只有真实出现敏感 query 值时才重写命中参数，非敏感参数原样保留。
    """

    text = str(url or "")
    base, query, fragment = _split_query(text)
    if not query or not _iter_sensitive_query_keys(query):
        return text

    def _replace(match: "re.Match[str]") -> str:
        value = match.group("value")
        if value in (None, "", _REDACTED):
            return match.group(0)
        if is_sensitive_key(match.group("key")):
            return "{}={}".format(match.group("key"), _REDACTED)
        return match.group(0)

    return base + _QUERY_PAIR_RE.sub(_replace, query) + fragment


def sanitize_source_text(text: Any) -> str:
    """source 自由文本统一脱敏：先清赋值形态密钥，再清 URL query 形态。

    两步互补：redact_assignment_text 覆盖 _SENSITIVE_ASSIGNMENT_RE 的键集合
    （authorization/api_key/token/password/secret/cookie），sanitize_url_secrets
    覆盖更广的 _SENSITIVE_KEY_RE 键集合（access_key/client_secret/x-auth-token
    等 query 形态）。对干净文本（page_intel、无 query 的文档 URL）两步均为
    no-op，保证逐字节不变。
    """

    value = str(text or "")
    if not value:
        return value
    return sanitize_url_secrets(redact_assignment_text(value))


def _digest(*parts: Any) -> str:
    joined = "|".join(str(_stable(part)) for part in parts)
    return hashlib.sha256(joined.encode("utf-8", "ignore")).hexdigest()[:32]


def _stable(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _stable(value[k]) for k in sorted(value, key=str)}
    if isinstance(value, (set, frozenset)):
        return sorted(_stable(item) for item in value)
    if isinstance(value, (list, tuple)):
        return [_stable(item) for item in value]
    return value


def compute_input_signature(*parts: Any) -> str:
    """生产方对“同一输入”的稳定摘要（如文档正文 hash、请求上下文摘要）。"""

    return _digest(*parts)


def graphql_query_hash(query_text: Any) -> str:
    """GraphQL query 文本归一化 hash：仅折叠空白，保留大小写与语义字符。"""

    collapsed = re.sub(r"\s+", " ", str(query_text or "")).strip()
    return hashlib.sha256(collapsed.encode("utf-8", "ignore")).hexdigest()


def canonical_method(method: Any) -> str:
    text = str(method or "GET").strip().upper()
    return text if text in HTTP_METHODS else "GET"


# ---------------------------------------------------------------------------
# 参数与鉴权摘要
# ---------------------------------------------------------------------------


@dataclass
class ParameterSpec:
    """参数只记录名称、位置、类型摘要与必需性；结构上不存在取值字段。"""

    name: str
    location: str = "query"
    type_summary: str = ""
    required: bool = False

    def __post_init__(self) -> None:
        self.name = str(self.name or "").strip()[:128]
        location = str(self.location or "query").strip()
        if location not in PARAMETER_LOCATIONS:
            raise ValueError("unsupported parameter location: {}".format(location))
        self.location = location
        self.type_summary = str(self.type_summary or "").strip()[:128]
        self.required = bool(self.required)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "in": self.location,
            "type": self.type_summary,
            "required": self.required,
        }


@dataclass
class SecurityRequirementSummary:
    """security_requirements 只保留名称与类型，禁止携带凭据。"""

    name: str
    type: str = "unknown"

    def __post_init__(self) -> None:
        self.name = str(self.name or "").strip()[:128]
        scheme_type = str(self.type or "unknown").strip().lower()
        self.type = AUTH_SCHEME_TYPE_TO_HINT.get(scheme_type, "unknown")

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "type": self.type}


# ---------------------------------------------------------------------------
# ApiDocumentCandidate（计划 6 §4.2）
# ---------------------------------------------------------------------------

_API_DOCUMENT_FIELDS: Tuple[str, ...] = (
    "task_id",
    "url",
    "type_hint",
    "source",
    "sources",
    "parent_target",
    "parent_url",
    "depth",
    "priority",
    "status",
    "input_signature",
    "request_profile",
    "confidence",
    "parser_version",
    "error_type",
    "created_at",
)


@dataclass
class ApiDocumentCandidate:
    task_id: str
    url: str
    type_hint: str = "unknown"
    source: str = ""
    sources: Set[str] = field(default_factory=set)
    parent_target: str = ""
    parent_url: str = ""
    depth: int = 0
    priority: int = 0
    status: str = "discovered"
    input_signature: str = ""
    request_profile: str = "api_doc"
    confidence: int = 50
    parser_version: str = ""
    error_type: str = ""
    created_at: float = 0.0

    def __post_init__(self) -> None:
        self.task_id = str(self.task_id or "").strip()
        # 构造即清洗：发现 URL 的 query 可能直接携带凭据（?token=... 形态），
        # 必须在进入 Registry/Mongo/日志前脱敏，而不是依赖最终守卫兜底。
        self.url = sanitize_url_secrets(normalize_url(self.url))
        if not self.url:
            raise ValueError("api document candidate url must not be empty")
        type_hint = str(self.type_hint or "unknown").strip().lower()
        if type_hint not in API_DOCUMENT_TYPE_HINTS:
            raise ValueError("unsupported type_hint: {}".format(type_hint))
        self.type_hint = type_hint
        self.status = _validated_status(self.status, API_DOCUMENT_STATUSES, "document status")
        if self.request_profile not in REQUEST_PROFILES:
            raise ValueError("unsupported request_profile: {}".format(self.request_profile))
        self.depth = max(0, int(self.depth or 0))
        self.priority = int(self.priority or 0)
        self.confidence = min(100, max(0, int(self.confidence or 0)))
        self.source = sanitize_source_text(self.source)
        self.parent_url = sanitize_url_secrets(self.parent_url)
        self.sources = {sanitize_source_text(item) for item in self.sources}
        if self.source:
            self.sources.add(self.source)

    @property
    def idempotency_key(self) -> str:
        """task_id + api_doc + canonical_url + request_profile + input_signature。"""

        return "|".join(
            (
                self.task_id,
                API_DOCUMENT_KEY_PREFIX,
                self.url,
                self.request_profile,
                self.input_signature,
            )
        )

    def add_source(self, source: str, source_detail: str = "") -> bool:
        # merge 入口与构造入口同一清洗口径：追加来源不得引入 query/赋值形态密钥。
        text = sanitize_source_text(source)
        if not text or text in self.sources:
            return False
        self.sources.add(text)
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "url": self.url,
            "type_hint": self.type_hint,
            "source": self.source,
            "sources": sorted(self.sources),
            "parent_target": self.parent_target,
            # 序列化前再清洗一次 parent_url：Registry merge 会直接赋值该字段，
            # 绕过 __post_init__，此处是进入快照/导出前的最后一道 URL 边界。
            "parent_url": sanitize_url_secrets(normalize_url(self.parent_url))
            if self.parent_url
            else "",
            "depth": self.depth,
            "priority": self.priority,
            "status": self.status,
            "input_signature": self.input_signature,
            "request_profile": self.request_profile,
            "confidence": self.confidence,
            "parser_version": self.parser_version,
            "error_type": self.error_type,
            "created_at": self.created_at,
        }


def _validated_status(value: Any, allowed: Tuple[str, ...], label: str) -> str:
    text = str(value or "").strip()
    if text not in allowed:
        raise ValueError("unsupported {}: {}".format(label, value))
    return text


# ---------------------------------------------------------------------------
# UnifiedApiEndpoint（计划 6 §4.3）
# ---------------------------------------------------------------------------

_UNIFIED_ENDPOINT_FIELDS: Tuple[str, ...] = (
    "endpoint_id",
    "url",
    "path_template",
    "method",
    "api_type",
    "source",
    "sources",
    "parent_document",
    "parent_target",
    "base_url",
    "api_version",
    "operation_id",
    "tags",
    "parameters",
    "request_body_type",
    "request_body_schema",
    "response_schema",
    "auth_hint",
    "security_requirements",
    "schema_available",
    "graphql_operation",
    "graphql_operation_name",
    "graphql_query_hash",
    "soap_action",
    "wsdl_service",
    "wsdl_port",
    "confidence",
    "status",
    "input_signature",
)


@dataclass
class UnifiedApiEndpoint:
    url: str
    method: str = "GET"
    api_type: str = "rest"
    endpoint_id: str = ""
    path_template: str = ""
    source: str = ""
    sources: Set[str] = field(default_factory=set)
    parent_document: str = ""
    parent_target: str = ""
    base_url: str = ""
    api_version: str = ""
    operation_id: str = ""
    tags: List[str] = field(default_factory=list)
    parameters: List[ParameterSpec] = field(default_factory=list)
    request_body_type: str = ""
    request_body_schema: Dict[str, Any] = field(default_factory=dict)
    response_schema: Dict[str, Any] = field(default_factory=dict)
    auth_hint: str = "unknown"
    security_requirements: List[SecurityRequirementSummary] = field(default_factory=list)
    schema_available: bool = False
    graphql_operation: str = "unknown"
    graphql_operation_name: str = ""
    graphql_query_hash: str = ""
    soap_action: str = ""
    wsdl_service: str = ""
    wsdl_port: str = ""
    confidence: int = 50
    status: str = "discovered"
    input_signature: str = ""

    def __post_init__(self) -> None:
        # 构造即清洗：endpoint_id/幂等键都派生自 url，先脱敏可保证密钥不进入任何键面。
        self.url = sanitize_url_secrets(normalize_url(self.url))
        if not self.url:
            raise ValueError("endpoint url must not be empty")
        self.method = canonical_method(self.method)
        api_type = str(self.api_type or "rest").strip().lower()
        if api_type not in API_TYPES:
            raise ValueError("unsupported api_type: {}".format(api_type))
        self.api_type = api_type
        self.auth_hint = _validated_status(self.auth_hint, AUTH_HINTS, "auth_hint")
        self.status = _validated_status(self.status, API_ENDPOINT_STATUSES, "endpoint status")
        if self.graphql_operation not in GRAPHQL_OPERATIONS:
            raise ValueError("unsupported graphql_operation: {}".format(self.graphql_operation))
        self.confidence = min(100, max(0, int(self.confidence or 0)))
        self.source = sanitize_source_text(self.source)
        # parent_document/base_url 是 URL 形态证据，与 url 同一 query 清洗边界；
        # to_legacy_records 会把它们写进 legacy record 的 source，不能带原值。
        self.parent_document = sanitize_url_secrets(self.parent_document)
        self.base_url = sanitize_url_secrets(self.base_url)
        self.sources = {sanitize_source_text(item) for item in self.sources}
        if self.source:
            self.sources.add(self.source)
        if not self.endpoint_id:
            self.endpoint_id = _digest(self.url, self.method, self.api_type, self.path_template)

    @property
    def idempotency_key(self) -> str:
        """task_id 由 Registry 拼接（同一资产跨任务不复用），此处冻结资产面键。

        task_id + api_endpoint + canonical_url + method + request_signature
        中 request_signature 取 input_signature；不同 method 保留为不同端点。
        """

        return "|".join(
            (
                API_ENDPOINT_KEY_PREFIX,
                self.url,
                self.method,
                self.input_signature,
            )
        )

    def scoped_idempotency_key(self, task_id: str) -> str:
        return "{}|{}".format(str(task_id or "").strip(), self.idempotency_key)

    def probe_observation_key(self, request_profile: str = "api_endpoint_probe", auth_profile: str = "") -> str:
        """请求观察键：认证上下文或 profile 不同则不共享缓存响应（§8.1）。"""

        if request_profile not in REQUEST_PROFILES:
            raise ValueError("unsupported request_profile: {}".format(request_profile))
        return "|".join(
            (
                "api_observation",
                self.url,
                self.method,
                request_profile,
                _digest(auth_profile) if auth_profile else "",
            )
        )

    def add_source(self, source: str) -> bool:
        """新来源只追加证据，不改变探测状态（§7.2）。"""

        # merge 入口与构造入口同一清洗口径：跨来源合并（js/page/browser）时，
        # 来源串里的 URL query 凭据与赋值形态密钥都不得进入 sources 证据面。
        text = sanitize_source_text(str(source or "").strip())
        if not text or text in self.sources:
            return False
        self.sources.add(text)
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "endpoint_id": self.endpoint_id,
            "url": self.url,
            "path_template": self.path_template,
            "method": self.method,
            "api_type": self.api_type,
            "source": self.source,
            "sources": sorted(self.sources),
            "parent_document": self.parent_document,
            "parent_target": self.parent_target,
            "base_url": self.base_url,
            "api_version": self.api_version,
            "operation_id": self.operation_id,
            "tags": list(self.tags),
            "parameters": [item.to_dict() for item in self.parameters],
            "request_body_type": self.request_body_type,
            "request_body_schema": _stable(self.request_body_schema),
            "response_schema": _stable(self.response_schema),
            "auth_hint": self.auth_hint,
            "security_requirements": [item.to_dict() for item in self.security_requirements],
            "schema_available": bool(self.schema_available),
            "graphql_operation": self.graphql_operation,
            "graphql_operation_name": self.graphql_operation_name,
            "graphql_query_hash": self.graphql_query_hash,
            "soap_action": self.soap_action,
            "wsdl_service": self.wsdl_service,
            "wsdl_port": self.wsdl_port,
            "confidence": self.confidence,
            "status": self.status,
            "input_signature": self.input_signature,
        }

    def to_legacy_records(self) -> List[Dict[str, str]]:
        """兼容旧 WihRecord 的 adapter（§7.3）；内容格式冻结自 api_doc_scan。

        - rest/soap → api_doc_endpoint "{METHOD} {url}" + urlfinder_url（同 legacy _emit_endpoint）
        - graphql   → graphql 记录 "{METHOD} {url}"
        source 取 parent_document，缺失时回退 source，与 legacy 语义一致。
        """

        source = self.parent_document or self.source or self.url
        if self.api_type == "graphql":
            return [
                {
                    "record_type": "graphql",
                    "content": "{} {}".format(self.method, self.url),
                    "source": source,
                }
            ]
        return [
            {
                "record_type": "api_doc_endpoint",
                "content": "{} {}".format(self.method, self.url),
                "source": source,
            },
            {"record_type": "urlfinder_url", "content": self.url, "source": source},
        ]


# ---------------------------------------------------------------------------
# Parser 契约（计划 6 §5）
# ---------------------------------------------------------------------------


@dataclass
class ParseOptions:
    """解析选项默认值即安全默认：外部引用、Schema introspection 默认关闭。"""

    max_depth: int = UNIFIED_API_CONFIG_DEFAULTS["API_DOCUMENT_MAX_DEPTH"]
    max_ref_count: int = UNIFIED_API_CONFIG_DEFAULTS["API_DOCUMENT_MAX_REF_COUNT"]
    external_ref_enable: bool = UNIFIED_API_CONFIG_DEFAULTS["API_EXTERNAL_REF_ENABLE"]
    graphql_schema_enable: bool = UNIFIED_API_CONFIG_DEFAULTS["GRAPHQL_SCHEMA_ENABLE"]
    graphql_schema_max_depth: int = UNIFIED_API_CONFIG_DEFAULTS["GRAPHQL_SCHEMA_MAX_DEPTH"]
    wsdl_parse_enable: bool = UNIFIED_API_CONFIG_DEFAULTS["WSDL_PARSE_ENABLE"]
    max_document_bytes: int = UNIFIED_API_CONFIG_DEFAULTS["API_DOCUMENT_MAX_SIZE_BYTES"]

    def __post_init__(self) -> None:
        self.max_depth = max(1, int(self.max_depth))
        self.max_ref_count = max(1, int(self.max_ref_count))
        self.graphql_schema_max_depth = max(1, int(self.graphql_schema_max_depth))
        self.max_document_bytes = max(1024, int(self.max_document_bytes))


@dataclass
class ParseDiagnostics:
    parser: str
    input_count: int = 0
    output_count: int = 0
    deduplicated_count: int = 0
    unresolved_ref_count: int = 0
    rejected_count: int = 0
    error_type: str = ""
    status: str = "ok"

    def __post_init__(self) -> None:
        self.status = _validated_status(self.status, DIAGNOSTIC_STATUSES, "diagnostic status")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "parser": self.parser,
            "input_count": self.input_count,
            "output_count": self.output_count,
            "deduplicated_count": self.deduplicated_count,
            "unresolved_ref_count": self.unresolved_ref_count,
            "rejected_count": self.rejected_count,
            "error_type": self.error_type,
            "status": self.status,
        }


@dataclass
class ParseResult:
    """Parser 统一返回形态；未解析引用必须体现在 diagnostics，不得伪装完整。"""

    parser: str
    endpoints: List[UnifiedApiEndpoint] = field(default_factory=list)
    documents: List[ApiDocumentCandidate] = field(default_factory=list)
    candidates: List[Dict[str, Any]] = field(default_factory=list)
    diagnostics: Optional[ParseDiagnostics] = None

    def to_dict(self) -> Dict[str, Any]:
        diagnostics = self.diagnostics or ParseDiagnostics(parser=self.parser)
        payload = {
            "documents": [item.to_dict() for item in self.documents],
            "endpoints": [item.to_dict() for item in self.endpoints],
            "candidates": [_stable(item) for item in self.candidates],
            "diagnostics": diagnostics.to_dict(),
        }
        # 契约级守卫：Parser 输出结构一旦含敏感值，视为实现缺陷直接暴露。
        leaks = find_sensitive_keys(payload)
        if leaks:
            raise ValueError("parser output leaked sensitive keys: {}".format(leaks[:5]))
        return payload


# schema 字段面快照（测试冻结用；顺序即 to_dict 输出序）。
API_DOCUMENT_SCHEMA_FIELDS = _API_DOCUMENT_FIELDS
API_ENDPOINT_SCHEMA_FIELDS = _UNIFIED_ENDPOINT_FIELDS
PARSE_DIAGNOSTICS_FIELDS: Tuple[str, ...] = (
    "parser",
    "input_count",
    "output_count",
    "deduplicated_count",
    "unresolved_ref_count",
    "rejected_count",
    "error_type",
    "status",
)
PARSE_RESULT_OUTPUT_KEYS: Tuple[str, ...] = ("documents", "endpoints", "candidates", "diagnostics")

__all__ = [
    "API_DOCUMENT_STATUSES",
    "API_ENDPOINT_STATUSES",
    "API_DOCUMENT_TYPE_HINTS",
    "API_TYPES",
    "HTTP_METHODS",
    "AUTH_HINTS",
    "AUTH_SCHEME_TYPE_TO_HINT",
    "GRAPHQL_OPERATIONS",
    "PARAMETER_LOCATIONS",
    "REQUEST_PROFILES",
    "DIAGNOSTIC_STATUSES",
    "API_DOCUMENT_KEY_PREFIX",
    "API_ENDPOINT_KEY_PREFIX",
    "UNIFIED_API_CONFIG_DEFAULTS",
    "API_DOCUMENT_SCHEMA_FIELDS",
    "API_ENDPOINT_SCHEMA_FIELDS",
    "PARSE_DIAGNOSTICS_FIELDS",
    "PARSE_RESULT_OUTPUT_KEYS",
    "ParameterSpec",
    "SecurityRequirementSummary",
    "ApiDocumentCandidate",
    "UnifiedApiEndpoint",
    "ParseOptions",
    "ParseDiagnostics",
    "ParseResult",
    "is_sensitive_key",
    "find_sensitive_keys",
    "redact_assignment_text",
    "sanitize_url_secrets",
    "sanitize_source_text",
    "compute_input_signature",
    "graphql_query_hash",
    "canonical_method",
]
