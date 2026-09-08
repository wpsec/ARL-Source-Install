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
    resource_index: Dict[tuple, str] = {}
    _sync_candidates(discovery_context, evidence_graph, summary, candidate_limit, resource_index)
    _sync_api_registry(
        discovery_context,
        evidence_graph,
        summary,
        document_limit,
        endpoint_limit,
        resource_index,
    )
    _sync_protocol_registry(discovery_context, evidence_graph, summary)
    _sync_micro_frontend_resources(discovery_context, evidence_graph, summary)
    _sync_responses(discovery_context, evidence_graph, summary, response_limit, resource_index)
    record_metric = getattr(discovery_context, "record_metric", None)
    if callable(record_metric):
        record_metric("evidence_graph_sync_total")
        record_metric("evidence_graph_node_sync_total", summary["nodes_added"])
        record_metric("evidence_graph_edge_sync_total", summary["edges_added"])
        record_metric("evidence_graph_skip_total", summary["skipped"])
    return summary


def _sync_candidates(
    discovery_context: Any,
    graph: EvidenceGraph,
    summary: Dict[str, int],
    limit: int,
    resource_index: Dict[tuple, str],
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
            if candidate_type in {"endpoint", "api"}:
                method = _candidate_method(candidate)
                resource_index[(candidate_value, method)] = node_id
            elif candidate_type in {"page", "path", "url"}:
                resource_index[(candidate_value, "")] = node_id
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
    resource_index: Dict[tuple, str],
) -> None:
    registry = getattr(discovery_context, "api_candidate_registry", None)
    if registry is None:
        return
    _sync_documents(registry, graph, summary, document_limit, resource_index)
    _sync_endpoints(registry, graph, summary, endpoint_limit, resource_index)


def _sync_protocol_registry(
    discovery_context: Any,
    graph: EvidenceGraph,
    summary: Dict[str, int],
) -> None:
    registry = getattr(discovery_context, "protocol_registry", None)
    snapshot = getattr(registry, "snapshot", None)
    if not callable(snapshot):
        return
    try:
        observations = list(snapshot())
    except (AttributeError, TypeError, ValueError):
        summary["skipped"] += 1
        return
    for observation in observations[:64]:
        if not isinstance(observation, Mapping):
            summary["skipped"] += 1
            continue
        protocol = str(observation.get("protocol") or "unknown").strip().lower()
        url = str(observation.get("url") or "").strip()
        event = str(observation.get("event") or "handshake").strip()
        if not url or not protocol:
            summary["skipped"] += 1
            continue
        identity = "|".join((
            str(observation.get("protocol_id") or ""),
            protocol,
            url,
            event,
            str(observation.get("method") or ""),
            str(observation.get("operation") or ""),
        ))
        try:
            node_id = graph.add_node(
                "protocol",
                identity,
                status=str(observation.get("status") or "observed"),
                confidence=_confidence_from_score(observation.get("confidence")),
                sources=observation.get("sources") or (
                    observation.get("source") or "protocol_registry",
                ),
                attributes={
                    "transport": protocol,
                    "verification_status": str(observation.get("status") or "observed"),
                },
            )
            summary["nodes_added"] += 1
            host = str(observation.get("host") or "").strip()
            _add_parent_edge(graph, summary, node_id, host, "observes")
        except (KeyError, TypeError, ValueError, OverflowError):
            summary["skipped"] += 1


def _sync_micro_frontend_resources(
    discovery_context: Any,
    graph: EvidenceGraph,
    summary: Dict[str, int],
) -> None:
    resources = getattr(discovery_context, "micro_frontend_resources", None)
    if not isinstance(resources, (list, tuple)):
        return
    for resource in list(resources)[:64]:
        if not isinstance(resource, Mapping):
            summary["skipped"] += 1
            continue
        application = str(resource.get("application") or "").strip()
        entry = str(resource.get("entry") or "").strip()
        route = str(resource.get("route") or resource.get("mount_path") or "").strip()
        if not application:
            summary["skipped"] += 1
            continue
        try:
            application_id = graph.add_node(
                "application",
                application,
                status="observed",
                confidence=_confidence_from_score(resource.get("confidence")),
                sources=resource.get("evidence") or (resource.get("source") or "micro_frontend",),
                attributes={"parser": resource.get("framework") or "micro_frontend"},
            )
            summary["nodes_added"] += 1
            if route:
                route_id = graph.add_node(
                    "route",
                    "{}|{}".format(application, route),
                    status="observed",
                    confidence=_confidence_from_score(resource.get("confidence")),
                    sources=("micro_frontend",),
                )
                summary["nodes_added"] += 1
                if graph.add_edge(application_id, route_id, "contains", evidence=("micro_frontend",)):
                    summary["edges_added"] += 1
            if entry:
                asset_id = graph.add_node(
                    "asset",
                    "{}|entry|{}".format(application, entry),
                    status="observed",
                    confidence=_confidence_from_score(resource.get("confidence")),
                    sources=("micro_frontend",),
                )
                summary["nodes_added"] += 1
                if graph.add_edge(application_id, asset_id, "references", evidence=("entry",)):
                    summary["edges_added"] += 1
        except (KeyError, TypeError, ValueError, OverflowError):
            summary["skipped"] += 1


def _sync_responses(
    discovery_context: Any,
    graph: EvidenceGraph,
    summary: Dict[str, int],
    limit: int,
    resource_index: Dict[tuple, str],
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
            related_id = resource_index.get((normalized_url, method)) or resource_index.get(
                (normalized_url, "")
            )
            if related_id and graph.add_edge(related_id, response_id, "observes", evidence=(request_profile,)):
                summary["edges_added"] += 1
        except (KeyError, TypeError, ValueError, OverflowError):
            summary["skipped"] += 1


def _sync_documents(
    registry: Any,
    graph: EvidenceGraph,
    summary: Dict[str, int],
    limit: int,
    resource_index: Dict[tuple, str],
) -> None:
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
            resource_index[(identity, "")] = node_id
            _add_parent_edge(graph, summary, node_id, document.get("parent_target"), "references")
        except (KeyError, TypeError, ValueError, OverflowError):
            summary["skipped"] += 1


def _sync_endpoints(
    registry: Any,
    graph: EvidenceGraph,
    summary: Dict[str, int],
    limit: int,
    resource_index: Dict[tuple, str],
) -> None:
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
                    "request_semantics": endpoint.get("request_semantics") or "unknown",
                    "verification_status": endpoint.get("verification_status") or "pending",
                },
            )
            summary["nodes_added"] += 1
            method = str(endpoint.get("method") or "GET").upper()
            # 只把页面/路由候选视为调用方；同 URL 的 endpoint 候选只是资产镜像，
            # 不能伪造一条 endpoint -> endpoint 的调用链。
            caller_id = resource_index.get((url, ""))
            _add_parent_edge(graph, summary, node_id, endpoint.get("parent_document"), "documents", "document")
            _add_parent_edge(graph, summary, node_id, endpoint.get("parent_target"), "exposes", "target")
            _sync_endpoint_lineage(graph, summary, node_id, endpoint, identity, caller_id)
            resource_index[(url, method)] = node_id
            _sync_endpoint_parameters(graph, summary, node_id, endpoint, identity)
            _sync_auth_boundary(graph, summary, node_id, endpoint, identity)
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


def _sync_endpoint_lineage(
    graph: EvidenceGraph,
    summary: Dict[str, int],
    endpoint_node_id: str,
    endpoint: Mapping[str, Any],
    endpoint_identity: str,
    caller_id: Optional[str],
) -> None:
    """把 Endpoint 的调用来源和证据 ID 接入图，且不复制来源原文。"""

    if caller_id and caller_id != endpoint_node_id:
        try:
            if graph.add_edge(caller_id, endpoint_node_id, "calls", evidence=("candidate",)):
                summary["edges_added"] += 1
        except (KeyError, TypeError, ValueError, OverflowError):
            summary["skipped"] += 1

    path_template = str(endpoint.get("path_template") or "").strip()
    parent_target = str(endpoint.get("parent_target") or "").strip()
    if path_template:
        route_identity = "{}|{}".format(parent_target or "target", path_template)
        try:
            route_id = graph.add_node(
                "route",
                route_identity,
                status=str(endpoint.get("status") or "discovered"),
                confidence=_confidence_from_score(endpoint.get("confidence")),
                sources=("endpoint_route",),
                attributes={"request_semantics": endpoint.get("request_semantics") or "unknown"},
            )
            summary["nodes_added"] += 1
            if graph.add_edge(
                route_id,
                endpoint_node_id,
                "calls",
                evidence=(str(endpoint.get("operation_id") or endpoint.get("api_type") or "endpoint"),),
            ):
                summary["edges_added"] += 1
        except (KeyError, TypeError, ValueError, OverflowError):
            summary["skipped"] += 1

    for evidence_id in list(endpoint.get("evidence_ids") or ())[:32]:
        evidence_text = str(evidence_id or "").strip()
        if not evidence_text:
            continue
        try:
            evidence_node_id = graph.add_node(
                "evidence",
                "{}|{}".format(endpoint_identity, evidence_text),
                status="observed",
                confidence="observed",
                sources=("endpoint_evidence",),
            )
            summary["nodes_added"] += 1
            if graph.add_edge(
                endpoint_node_id,
                evidence_node_id,
                "references",
                evidence=("evidence_id",),
            ):
                summary["edges_added"] += 1
        except (KeyError, TypeError, ValueError, OverflowError):
            summary["skipped"] += 1


def _sync_endpoint_parameters(
    graph: EvidenceGraph,
    summary: Dict[str, int],
    endpoint_node_id: str,
    endpoint: Mapping[str, Any],
    endpoint_identity: str,
) -> None:
    parameters = endpoint.get("parameters")
    if not isinstance(parameters, (list, tuple)):
        return
    evidence_index = {}
    for evidence in endpoint.get("parameter_evidence") or ():
        if not isinstance(evidence, Mapping):
            continue
        evidence_name = str(evidence.get("name") or "").strip()
        evidence_location = str(
            evidence.get("in") or evidence.get("location") or ""
        ).strip().lower()
        if evidence_name and evidence_location:
            evidence_index[(evidence_name, evidence_location)] = str(
                evidence.get("evidence_kind") or "inferred"
            ).strip().lower()
    for parameter in list(parameters)[:32]:
        if isinstance(parameter, Mapping):
            name = str(parameter.get("name") or "").strip()
            location = str(
                parameter.get("in") or parameter.get("location") or "unknown"
            ).strip().lower()
            type_summary = str(
                parameter.get("type") or parameter.get("type_summary") or "unknown"
            ).strip().lower()
            evidence_kind = str(
                parameter.get("evidence_kind")
                or evidence_index.get((name, location))
                or "inferred"
            ).strip().lower()
        else:
            name = str(getattr(parameter, "name", "") or "").strip()
            location = str(getattr(parameter, "location", "unknown") or "unknown").strip().lower()
            type_summary = str(getattr(parameter, "type_summary", "unknown") or "unknown").strip().lower()
            evidence_kind = "inferred"
        if not name:
            continue
        try:
            parameter_id = graph.add_node(
                "parameter",
                "{}|{}|{}".format(endpoint_identity, location, name),
                sources=("endpoint_parameter",),
                attributes={"transport": location},
            )
            summary["nodes_added"] += 1
            if graph.add_edge(
                endpoint_node_id,
                parameter_id,
                "has_parameter",
                evidence=(location, type_summary, evidence_kind),
            ):
                summary["edges_added"] += 1
        except (KeyError, TypeError, ValueError, OverflowError):
            summary["skipped"] += 1


def _sync_auth_boundary(
    graph: EvidenceGraph,
    summary: Dict[str, int],
    endpoint_node_id: str,
    endpoint: Mapping[str, Any],
    endpoint_identity: str,
) -> None:
    auth_hint = str(endpoint.get("auth_hint") or "unknown").strip().lower()
    anomaly = bool(endpoint.get("manual_review_required") or endpoint.get("auth_anomaly_candidate"))
    if auth_hint in {"", "none", "unknown"} and not anomaly:
        return
    try:
        identity_node_id = graph.add_node(
            "identity",
            "{}|auth|{}|{}".format(endpoint_identity, auth_hint or "unknown", anomaly),
            sources=("auth_boundary",),
            attributes={"transport": "auth_anomaly_candidate" if anomaly else auth_hint},
        )
        summary["nodes_added"] += 1
        if graph.add_edge(
            endpoint_node_id,
            identity_node_id,
            "auth_required" if not anomaly else "auth_boundary",
            evidence=("manual_review" if anomaly else auth_hint,),
        ):
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


def _candidate_method(candidate: Any) -> str:
    metadata = getattr(candidate, "metadata", None)
    if isinstance(metadata, Mapping):
        return str(metadata.get("method") or "GET").upper()
    return "GET"


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
