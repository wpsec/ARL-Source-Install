"""基于已有观测生成目标画像，不触发网络请求。

该模块只负责把响应摘要转换为可审计的采集策略建议。画像是运行时线索，
不是目标事实；unknown 必须保持低成本默认，避免误判直接扩大扫描范围。
"""

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple


PROFILE_UNKNOWN = "unknown"
PROFILE_TRADITIONAL_MVC = "traditional_mvc"
PROFILE_SSR = "ssr"
PROFILE_SPA = "spa"
PROFILE_API_ONLY = "api_only"
PROFILE_DOCUMENT_FIRST = "document_first"

CONFIDENCE_LOW = "low"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_HIGH = "high"

COLLECTOR_HTTP = "http"
COLLECTOR_HTML = "html"
COLLECTOR_SCRIPT = "script"
COLLECTOR_API_DOCUMENT = "api_document"
COLLECTOR_BROWSER_RUNTIME = "browser_runtime"

_MAX_ITEMS = 64
_MAX_BODY_CHARS = 65536
_MAX_EVIDENCE = 16


@dataclass(frozen=True)
class TargetProfile:
    """目标画像和仅供调度器消费的策略建议。"""

    profile: str = PROFILE_UNKNOWN
    confidence: str = CONFIDENCE_LOW
    evidence: Tuple[str, ...] = ()
    recommended_collectors: Tuple[str, ...] = (COLLECTOR_HTTP,)
    optional_collectors: Tuple[str, ...] = ()
    skipped_collectors: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "profile": self.profile,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
            "recommended_collectors": list(self.recommended_collectors),
            "optional_collectors": list(self.optional_collectors),
            "skipped_collectors": list(self.skipped_collectors),
        }


class TargetProfileResolver:
    """从响应、脚本和文档摘要中解析目标画像。

    调用方可以传入已有 Registry 的记录，也可以传入简单的 mapping。解析器
    只读取有限长度的公开摘要，不保留 URL、响应正文或认证信息。
    """

    def resolve(
        self,
        pages: Iterable[Any] = (),
        scripts: Iterable[Any] = (),
        documents: Iterable[Any] = (),
        runtime_events: Iterable[Any] = (),
        response_headers: Iterable[Any] = (),
    ) -> TargetProfile:
        observations = self._bounded_items(pages)
        script_items = self._bounded_items(scripts)
        document_items = self._bounded_items(documents)
        runtime_items = self._bounded_items(runtime_events)
        header_items = self._bounded_items(response_headers)

        evidence: List[str] = []
        html_seen = False
        json_seen = False
        api_marker_seen = False
        document_marker_seen = False
        spa_marker_seen = False
        ssr_marker_seen = False
        form_seen = False

        for item in observations:
            content_type, body, url = self._observation_parts(item)
            lower_body = body.lower()
            lower_url = url.lower()
            if "text/html" in content_type or "<html" in lower_body:
                html_seen = True
                self._add_evidence(evidence, "response:html")
            if self._is_json_content(content_type, body):
                json_seen = True
                api_marker_seen = True
                self._add_evidence(evidence, "response:json")
            if self._looks_like_api_url(lower_url):
                api_marker_seen = True
                self._add_evidence(evidence, "url:api_path")
            if self._looks_like_document_url(lower_url, lower_body):
                document_marker_seen = True
                self._add_evidence(evidence, "document:well_known_path")
            if self._contains_any(lower_body, ("openapi", "swagger", "graphql", "wsdl")):
                document_marker_seen = True
                self._add_evidence(evidence, "document:format_marker")
            if self._contains_any(
                lower_body,
                (
                    'id="root"',
                    "id='root'",
                    'id="app"',
                    "id='app'",
                    "__next_data__",
                    "__nuxt__",
                    'type="module"',
                    "type='module'",
                ),
            ):
                spa_marker_seen = True
                self._add_evidence(evidence, "html:spa_marker")
            if self._contains_any(
                lower_body,
                ("data-server-rendered", "__next_data__", "__nuxt__", "server-rendered"),
            ):
                ssr_marker_seen = True
                self._add_evidence(evidence, "html:ssr_marker")
            if "<form" in lower_body:
                form_seen = True
                self._add_evidence(evidence, "html:form")

        for item in script_items:
            _, body, url = self._observation_parts(item)
            lower_body = body.lower()
            lower_url = url.lower()
            if body or url:
                self._add_evidence(evidence, "source:script")
            if self._contains_any(lower_body, ("react", "vue", "angular", "webpack", "vite")):
                spa_marker_seen = True
                self._add_evidence(evidence, "script:spa_framework")
            if self._looks_like_document_url(lower_url, lower_body):
                document_marker_seen = True
                self._add_evidence(evidence, "script:document_reference")

        for item in document_items:
            _, body, url = self._observation_parts(item)
            if body or url:
                document_marker_seen = True
                self._add_evidence(evidence, "document:candidate")
            if self._looks_like_document_url(url.lower(), body.lower()):
                self._add_evidence(evidence, "document:well_known_path")

        if runtime_items:
            self._add_evidence(evidence, "runtime:observed")
            spa_marker_seen = True

        for item in header_items:
            content_type, _, _ = self._observation_parts(item)
            if self._is_json_content(content_type, ""):
                json_seen = True
                api_marker_seen = True
                self._add_evidence(evidence, "header:json_content_type")

        if document_marker_seen and not html_seen:
            return self._profile(
                PROFILE_DOCUMENT_FIRST,
                CONFIDENCE_HIGH,
                evidence,
                (COLLECTOR_HTTP, COLLECTOR_API_DOCUMENT),
                (),
                (COLLECTOR_BROWSER_RUNTIME,),
            )
        if api_marker_seen and not html_seen:
            return self._profile(
                PROFILE_API_ONLY,
                CONFIDENCE_HIGH if json_seen else CONFIDENCE_MEDIUM,
                evidence,
                (COLLECTOR_HTTP, COLLECTOR_API_DOCUMENT),
                (),
                (COLLECTOR_BROWSER_RUNTIME,),
            )
        if spa_marker_seen:
            return self._profile(
                PROFILE_SPA,
                CONFIDENCE_HIGH if html_seen else CONFIDENCE_MEDIUM,
                evidence,
                (COLLECTOR_HTTP, COLLECTOR_HTML, COLLECTOR_SCRIPT),
                (COLLECTOR_BROWSER_RUNTIME,),
                (),
            )
        if html_seen and ssr_marker_seen:
            return self._profile(
                PROFILE_SSR,
                CONFIDENCE_HIGH,
                evidence,
                (COLLECTOR_HTTP, COLLECTOR_HTML, COLLECTOR_SCRIPT),
                (),
                (COLLECTOR_BROWSER_RUNTIME,),
            )
        if html_seen and form_seen:
            return self._profile(
                PROFILE_TRADITIONAL_MVC,
                CONFIDENCE_MEDIUM,
                evidence,
                (COLLECTOR_HTTP, COLLECTOR_HTML, COLLECTOR_SCRIPT),
                (),
                (COLLECTOR_BROWSER_RUNTIME,),
            )
        if html_seen:
            return self._profile(
                PROFILE_UNKNOWN,
                CONFIDENCE_LOW,
                evidence,
                (COLLECTOR_HTTP, COLLECTOR_HTML),
                (COLLECTOR_SCRIPT,),
                (COLLECTOR_BROWSER_RUNTIME,),
            )
        return self._profile(
            PROFILE_UNKNOWN,
            CONFIDENCE_LOW,
            evidence,
            (COLLECTOR_HTTP,),
            (COLLECTOR_HTML, COLLECTOR_SCRIPT, COLLECTOR_API_DOCUMENT),
            (COLLECTOR_BROWSER_RUNTIME,),
        )

    def resolve_records(self, records: Iterable[Any] = ()) -> TargetProfile:
        """把既有 WihRecord/候选记录转换为画像线索。

        WihRecord 通常没有响应正文，因此这里只使用记录类型和候选路径作为
        弱证据；没有 HTML/JSON 观测时不会把脚本记录直接升级为 SPA 事实。
        """

        scripts: List[Dict[str, Any]] = []
        documents: List[Dict[str, Any]] = []
        pages: List[Dict[str, Any]] = []
        for record in self._bounded_items(records):
            if isinstance(record, Mapping):
                record_type = str(record.get("recordType") or record.get("record_type") or "").lower()
                content = record.get("content") or ""
            else:
                record_type = str(
                    getattr(record, "recordType", "") or getattr(record, "record_type", "") or ""
                ).lower()
                content = getattr(record, "content", "") or ""
            item = {"url": str(content or "")[:2048]}
            if "js" in record_type or "script" in record_type:
                scripts.append(item)
            elif any(marker in record_type for marker in ("openapi", "swagger", "graphql", "wsdl", "api_doc")):
                documents.append(item)
            elif any(marker in record_type for marker in ("api", "endpoint", "path", "url")):
                pages.append(item)
        return self.resolve(pages=pages, scripts=scripts, documents=documents)

    @staticmethod
    def _bounded_items(items: Iterable[Any]) -> List[Any]:
        if items is None:
            return []
        if isinstance(items, (str, bytes, Mapping)):
            return [items]
        try:
            return list(items)[:_MAX_ITEMS]
        except (TypeError, ValueError):
            return []

    @staticmethod
    def _observation_parts(item: Any) -> Tuple[str, str, str]:
        if isinstance(item, Mapping):
            headers = item.get("headers") or {}
            content_type = item.get("content_type") or item.get("content-type") or ""
            if not content_type and isinstance(headers, Mapping):
                content_type = headers.get("content-type") or headers.get("Content-Type") or ""
            body = item.get("body") or item.get("content") or ""
            url = item.get("url") or item.get("normalized_url") or item.get("candidate") or ""
        else:
            content_type = getattr(item, "content_type", "")
            body = getattr(item, "body", "") or getattr(item, "content", "")
            url = getattr(item, "url", "") or getattr(item, "normalized_url", "")
        if isinstance(body, bytes):
            body = body[:_MAX_BODY_CHARS].decode("utf-8", errors="replace")
        else:
            body = str(body or "")[:_MAX_BODY_CHARS]
        return str(content_type or "").lower(), body, str(url or "")[:2048]

    @staticmethod
    def _contains_any(value: str, needles: Sequence[str]) -> bool:
        return any(needle in value for needle in needles)

    @staticmethod
    def _is_json_content(content_type: str, body: str) -> bool:
        return "json" in content_type or body.lstrip().startswith(("{", "["))

    @staticmethod
    def _looks_like_api_url(url: str) -> bool:
        return any(marker in url for marker in ("/api/", "/graphql", "/rest/", "/rpc/"))

    @staticmethod
    def _looks_like_document_url(url: str, body: str) -> bool:
        return any(
            marker in url or marker in body
            for marker in ("swagger", "openapi", "api-docs", "redoc", "graphql", "wsdl")
        )

    @staticmethod
    def _add_evidence(evidence: List[str], item: str) -> None:
        if item not in evidence and len(evidence) < _MAX_EVIDENCE:
            evidence.append(item)

    @staticmethod
    def _profile(
        profile: str,
        confidence: str,
        evidence: List[str],
        recommended: Sequence[str],
        optional: Sequence[str],
        skipped: Sequence[str],
    ) -> TargetProfile:
        return TargetProfile(
            profile=profile,
            confidence=confidence,
            evidence=tuple(evidence[:_MAX_EVIDENCE]),
            recommended_collectors=tuple(dict.fromkeys(recommended)),
            optional_collectors=tuple(dict.fromkeys(optional)),
            skipped_collectors=tuple(dict.fromkeys(skipped)),
        )


__all__ = [
    "COLLECTOR_API_DOCUMENT",
    "COLLECTOR_BROWSER_RUNTIME",
    "COLLECTOR_HTML",
    "COLLECTOR_HTTP",
    "COLLECTOR_SCRIPT",
    "PROFILE_API_ONLY",
    "PROFILE_DOCUMENT_FIRST",
    "PROFILE_SPA",
    "PROFILE_SSR",
    "PROFILE_TRADITIONAL_MVC",
    "PROFILE_UNKNOWN",
    "TargetProfile",
    "TargetProfileResolver",
]
