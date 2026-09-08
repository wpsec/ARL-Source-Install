"""WIH 第一批证据图契约。

图中只保存可审计的类别化元数据和不可逆节点 ID。原始 URL、响应正文和认证
材料继续由既有 Registry 按自己的生命周期管理，避免证据图成为敏感数据副本。
"""

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple


_MAX_SOURCES = 16
_MAX_ATTRIBUTES = 12
_MAX_TEXT = 160
_SAFE_ATTRIBUTE_KEYS = {
    "content_type",
    "http_method",
    "parser",
    "request_profile",
    "status_code",
    "transport",
}
_SENSITIVE_VALUE = re.compile(
    r"(?i)(authorization|bearer|cookie|password|passwd|secret|token|api[_-]?key)"
)
_SAFE_TEXT = re.compile(r"[^a-zA-Z0-9._:/-]+")


@dataclass
class EvidenceNode:
    node_id: str
    kind: str
    status: str = "observed"
    confidence: str = "observed"
    sources: set = field(default_factory=set)
    attributes: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "kind": self.kind,
            "status": self.status,
            "confidence": self.confidence,
            "sources": sorted(self.sources),
            "attributes": dict(sorted(self.attributes.items())),
        }


@dataclass(frozen=True)
class EvidenceEdge:
    source_id: str
    target_id: str
    relation: str
    evidence: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relation": self.relation,
            "evidence": list(self.evidence),
        }


class EvidenceGraph:
    """任务内有界证据图，重复节点和关系均幂等。"""

    def __init__(self, max_nodes: int = 2048, max_edges: int = 4096):
        self.max_nodes = max(1, int(max_nodes or 1))
        self.max_edges = max(1, int(max_edges or 1))
        self._nodes: Dict[str, EvidenceNode] = {}
        self._edges: Dict[Tuple[str, str, str], EvidenceEdge] = {}

    def add_node(
        self,
        kind: Any,
        identity: Any,
        *,
        status: str = "observed",
        confidence: str = "observed",
        sources: Iterable[Any] = (),
        attributes: Optional[Mapping[str, Any]] = None,
    ) -> str:
        kind_text = self._safe_label(kind)
        if not kind_text:
            raise ValueError("kind must not be empty")
        identity_text = str(identity or "").strip()
        if not identity_text:
            raise ValueError("identity must not be empty")
        node_id = self._node_id(kind_text, identity_text)
        node = self._nodes.get(node_id)
        if node is None:
            if len(self._nodes) >= self.max_nodes:
                raise OverflowError("evidence graph node budget exceeded")
            node = EvidenceNode(
                node_id=node_id,
                kind=kind_text,
                status=self._safe_label(status) or "observed",
                confidence=self._safe_label(confidence) or "observed",
            )
            self._nodes[node_id] = node
        node.sources.update(self._safe_values(sources, _MAX_SOURCES))
        node.attributes.update(self._safe_attributes(attributes))
        return node_id

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relation: Any,
        *,
        evidence: Iterable[Any] = (),
    ) -> bool:
        source = str(source_id or "").strip()
        target = str(target_id or "").strip()
        relation_text = self._safe_label(relation)
        if not relation_text:
            raise ValueError("relation must not be empty")
        if source not in self._nodes or target not in self._nodes:
            raise KeyError("edge endpoints must be registered nodes")
        key = (source, target, relation_text)
        edge = self._edges.get(key)
        if edge is not None:
            merged = tuple(dict.fromkeys(edge.evidence + self._safe_values(evidence, _MAX_SOURCES)))
            self._edges[key] = EvidenceEdge(source, target, relation_text, merged)
            return False
        if len(self._edges) >= self.max_edges:
            raise OverflowError("evidence graph edge budget exceeded")
        self._edges[key] = EvidenceEdge(
            source,
            target,
            relation_text,
            tuple(self._safe_values(evidence, _MAX_SOURCES)),
        )
        return True

    def snapshot(self) -> Dict[str, Any]:
        return {
            "nodes": [
                node.to_dict()
                for node in sorted(self._nodes.values(), key=lambda item: item.node_id)
            ],
            "edges": [
                edge.to_dict()
                for edge in sorted(
                    self._edges.values(),
                    key=lambda item: (item.source_id, item.target_id, item.relation),
                )
            ],
        }

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    @staticmethod
    def _node_id(kind: str, identity: str) -> str:
        digest = hashlib.sha256((kind + "\0" + identity).encode("utf-8", errors="replace")).hexdigest()
        return "ev_" + digest[:32]

    @staticmethod
    def _safe_text(value: Any, required: bool = False) -> str:
        text = str(value or "").strip()[:_MAX_TEXT]
        text = _SAFE_TEXT.sub("_", text)
        if required and not text:
            raise ValueError("value must not be empty")
        return text

    @classmethod
    def _safe_values(cls, values: Iterable[Any], limit: int) -> Tuple[str, ...]:
        if values is None or isinstance(values, (str, bytes)):
            values = [values] if values else []
        result = []
        try:
            iterator = iter(values)
        except TypeError:
            iterator = iter(())
        for value in iterator:
            safe = cls._safe_label(value)
            if safe and safe not in result:
                result.append(safe)
            if len(result) >= limit:
                break
        return tuple(result)

    @classmethod
    def _safe_attributes(cls, attributes: Optional[Mapping[str, Any]]) -> Dict[str, str]:
        if not isinstance(attributes, Mapping):
            return {}
        safe: Dict[str, str] = {}
        for key, value in attributes.items():
            key_text = cls._safe_text(key)
            if key_text not in _SAFE_ATTRIBUTE_KEYS or len(safe) >= _MAX_ATTRIBUTES:
                continue
            if isinstance(value, (dict, list, tuple, set)):
                value = json.dumps(value, ensure_ascii=True, sort_keys=True, default=str)
            if _SENSITIVE_VALUE.search(str(value or "")):
                continue
            value_text = cls._safe_text(value)
            if value_text:
                safe[key_text] = value_text
        return safe

    @classmethod
    def _safe_label(cls, value: Any) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        if _SENSITIVE_VALUE.search(text) or "://" in text or len(text) > _MAX_TEXT:
            digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
            return "opaque_" + digest[:12]
        return cls._safe_text(text)


__all__ = ["EvidenceEdge", "EvidenceGraph", "EvidenceNode"]
