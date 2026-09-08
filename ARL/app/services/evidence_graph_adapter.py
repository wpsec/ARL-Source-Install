"""把现有候选/Endpoint Registry 汇聚到任务内 EvidenceGraph。"""

import logging
from typing import Any, Dict, Iterable, Mapping, Optional

from .evidence_graph import EvidenceGraph


logger = logging.getLogger(__name__)

_CANDIDATE_KIND_MAP = {
    "api": "endpoint",
    "api_doc": "document",
    "document": "document",
    "domain": "asset",
    "endpoint": "endpoint",
    "js": "script",
    "page": "page",
    "path": "route",
    "script": "script",
    "site": "asset",
    "url": "page",
}


def get_or_create_evidence_graph(
    discovery_context: Any,
    *,
    max_nodes: int = 2048,
    max_edges: int = 4096,
) -> Optional[EvidenceGraph]:
    """在任务上下文上懒加载 EvidenceGraph，避免改变旧初始化依赖。"""

    if discovery_context is None:
        return None
    graph = getattr(discovery_context, "evidence_graph", None)
    if isinstance(graph, EvidenceGraph):
        return graph
    graph = EvidenceGraph(max_nodes=max_nodes, max_edges=max_edges)
    try:
        setattr(discovery_context, "evidence_graph", graph)
    except (AttributeError, TypeError):
        return None
    return graph


def sync_discovery_context(
    discovery_context: Any,
    *,
    graph: Optional[EvidenceGraph] = None,
    candidate_limit: int = 0,
    document_limit: int = 0,
    endpoint_limit: int = 0,
    response_limit: int = 0,
) -> Dict[str, int]:
    """同步现有 Registry；函数只读 Registry，不触发请求或结果写回。"""

    evidence_graph = graph or get_or_create_evidence_graph(discovery_context)
    if evidence_graph is None:
        return {"nodes_added": 0, "edges_added": 0, "skipped": 0}
    summary = {"nodes_added": 0, "edges_added": 0, "skipped": 0}
    _sync_candidates(discovery_context, evidence_graph, summary, candidate_limit)
    _sync_api_registry(discovery_context, evidence_graph, summary, document_limit, endpoint_limit)
    _sync_responses(discovery_context, evidence_graph, summary, response_limit)
    return summary


def _sync_candidates(
    discovery_context: Any,
    graph: EvidenceGraph,
    summary: Dict[str, int],
    limit: int,
) -> None:
    registry = getattr(discovery_context, "candidate_registry", None)
    values = getattr(registry, "values", None)
    if not callable(values):
        return
    try:
        candidates = list(values())
    except (AttributeError, TypeError, ValueError):
        summary["skipped"] += 1
        return
    if limit and limit > 0:
        candidates = candidates[: int(limit)]
    for candidate in candidates:
        try:
            candidate_key = str(getattr(candidate, "candidate_key", "") or "").strip()
            candidate_value = str(getattr(candidate, "candidate", "") or "").strip()
            candidate_type = str(getattr(candidate, "candidate_type", "") or "unknown").lower()
            if not candidate_key or not candidate_value:
                summary["skipped"] += 1
                continue
            node_id = graph.add_node(
                _CANDIDATE_KIND_MAP.get(candidate_type, "candidate"),
                candidate_key,
                status=str(getattr(candidate, "status", "") or "discovered"),
                confidence=_confidence_from_metadata(getattr(candidate, "metadata", None)),
                sources=getattr(candidate, "sources", ()) or (),
                attributes=_candidate_attributes(candidate),
            )
            summary["nodes_added"] += 1
            parent_target = str(getattr(candidate, "parent_target", "") or "").strip()
            if parent_target:
                parent_id = graph.add_node("target", parent_target, sources=("candidate_parent",))
                summary["nodes_added"] += 1
                if graph.add_edge(parent_id, node_id, "contains", evidence=getattr(candidate, "sources", ()) or ()):
                    summary["edges_added"] += 1
        except (AttributeError, KeyError, TypeError, ValueError, OverflowError):
            summary["skipped"] += 1


def _sync_api_registry(
    discovery_context: Any,
    graph: EvidenceGraph,
    summary: Dict[str, int],
    document_limit: int,
    endpoint_limit: int,
) -> None:
    registry = getattr(discovery_context, "api_candidate_registry", None)
    if registry is None:
        return
    _sync_documents(registry, graph, summary, document_limit)
    _sync_endpoints(registry, graph, summary, endpoint_limit)


def _sync_responses(
    discovery_context: Any,
    graph: EvidenceGraph,
    summary: Dict[str, int],
    limit: int,
) -> None:
    registry = getattr(discovery_context, "response_registry", None)
    snapshot = getattr(registry, "snapshot_metadata", None)
    if not callable(snapshot):
        return
    try:
        responses = list(snapshot())
    except (AttributeError, TypeError, ValueError):
        summary["skipped"] += 1
        return
    if limit and limit > 0:
        responses = responses[: int(limit)]
    for response in responses:
        if not isinstance(response, Mapping):
            summary["skipped"] += 1
            continue
        normalized_url = str(response.get("normalized_url") or "").strip()
        if not normalized_url:
            summary["skipped"] += 1
            continue
        method = str(response.get("method") or "GET").upper()
        request_profile = str(response.get("request_profile") or "default")
        identity = "|".join((normalized_url, method, request_profile))
        try:
            response_id = graph.add_node(
                "response",
                identity,
                status="observed",
                confidence="observed",
                sources=(response.get("source") or "response_registry",)
                + tuple(response.get("consumers") or ()),
                attributes={
                    "http_method": method,
                    "request_profile": request_profile,
                    "content_type": response.get("content_type") or "",
                    "status_code": response.get("status_code") or 0,
                },
            )
            summary["nodes_added"] += 1
            resource_id = graph.add_node(
                "resource",
                normalized_url,
                sources=("response_registry",),
            )
            summary["nodes_added"] += 1
            if graph.add_edge(resource_id, response_id, "observed_as", evidence=(request_profile,)):
                summary["edges_added"] += 1
        except (KeyError, TypeError, ValueError, OverflowError):
            summary["skipped"] += 1


def _sync_documents(registry: Any, graph: EvidenceGraph, summary: Dict[str, int], limit: int) -> None:
    snapshot = getattr(registry, "snapshot_documents", None)
    if not callable(snapshot):
        return
    try:
        documents = list(snapshot())
    except (AttributeError, TypeError, ValueError):
        summary["skipped"] += 1
        return
    if limit and limit > 0:
        documents = documents[: int(limit)]
    for document in documents:
        if not isinstance(document, Mapping):
            summary["skipped"] += 1
            continue
        identity = str(document.get("url") or "").strip()
        if not identity:
            summary["skipped"] += 1
            continue
        try:
            node_id = graph.add_node(
                "document",
                identity,
                status=str(document.get("status") or "discovered"),
                confidence="observed",
                sources=document.get("sources") or (document.get("source") or "registry",),
                attributes={
                    "request_profile": document.get("request_profile") or "api_document",
                    "parser": document.get("type_hint") or "document",
                },
            )
            summary["nodes_added"] += 1
            _add_parent_edge(graph, summary, node_id, document.get("parent_target"), "references")
        except (KeyError, TypeError, ValueError, OverflowError):
            summary["skipped"] += 1


def _sync_endpoints(registry: Any, graph: EvidenceGraph, summary: Dict[str, int], limit: int) -> None:
    snapshot = getattr(registry, "snapshot_endpoints", None)
    if not callable(snapshot):
        return
    try:
        endpoints = list(snapshot())
    except (AttributeError, TypeError, ValueError):
        summary["skipped"] += 1
        return
    if limit and limit > 0:
        endpoints = endpoints[: int(limit)]
    for endpoint in endpoints:
        if not isinstance(endpoint, Mapping):
            summary["skipped"] += 1
            continue
        url = str(endpoint.get("url") or "").strip()
        if not url:
            summary["skipped"] += 1
            continue
        identity = "|".join(
            (
                str(endpoint.get("endpoint_id") or ""),
                url,
                str(endpoint.get("method") or "GET"),
                str(endpoint.get("api_type") or "rest"),
                str(endpoint.get("input_signature") or ""),
            )
        )
        try:
            node_id = graph.add_node(
                "endpoint",
                identity,
                status=str(endpoint.get("status") or "discovered"),
                confidence=_confidence_from_score(endpoint.get("confidence")),
                sources=endpoint.get("sources") or (endpoint.get("source") or "registry",),
                attributes={
                    "http_method": endpoint.get("method") or "GET",
                    "request_profile": "api_endpoint_probe",
                    "parser": endpoint.get("api_type") or "rest",
                },
            )
            summary["nodes_added"] += 1
            _add_parent_edge(graph, summary, node_id, endpoint.get("parent_document"), "describes", "document")
            _add_parent_edge(graph, summary, node_id, endpoint.get("parent_target"), "exposes", "target")
        except (KeyError, TypeError, ValueError, OverflowError):
            summary["skipped"] += 1


def _add_parent_edge(
    graph: EvidenceGraph,
    summary: Dict[str, int],
    child_id: str,
    parent_identity: Any,
    relation: str,
    parent_kind: str = "target",
) -> None:
    parent_text = str(parent_identity or "").strip()
    if not parent_text:
        return
    try:
        parent_id = graph.add_node(parent_kind, parent_text, sources=("registry_parent",))
        summary["nodes_added"] += 1
        if graph.add_edge(parent_id, child_id, relation, evidence=("registry",)):
            summary["edges_added"] += 1
    except (KeyError, TypeError, ValueError, OverflowError):
        summary["skipped"] += 1


def _candidate_attributes(candidate: Any) -> Dict[str, Any]:
    metadata = getattr(candidate, "metadata", None)
    attributes: Dict[str, Any] = {
        "request_profile": getattr(candidate, "request_profile", "") or "default",
    }
    if isinstance(metadata, Mapping):
        if metadata.get("method"):
            attributes["http_method"] = metadata.get("method")
        if metadata.get("api_type"):
            attributes["parser"] = metadata.get("api_type")
    return attributes


def _confidence_from_metadata(metadata: Any) -> str:
    if not isinstance(metadata, Mapping):
        return "observed"
    return _confidence_from_score(metadata.get("confidence"))


def _confidence_from_score(score: Any) -> str:
    try:
        value = int(score)
    except (TypeError, ValueError):
        return "observed"
    if value >= 80:
        return "high"
    if value >= 50:
        return "medium"
    return "low"


__all__ = ["get_or_create_evidence_graph", "sync_discovery_context"]
