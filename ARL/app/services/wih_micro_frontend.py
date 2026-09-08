"""微前端资源图的可选、只读适配器。

适配器只解析调用方已经取得的 HTML/脚本文本，不执行脚本、不获取 entry，
也不把原始正文带入结果。它服务于 qiankun、Wujie 和 micro-app 的通用
application/route/entry 关系，未知框架仍返回空结果交给通用 Collector。
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set
from urllib.parse import urljoin, urlsplit, urlunsplit

from .api_unified_models import sanitize_url_secrets


_MAX_RESOURCES = 64
_MAX_TEXT = 2048
_FRAMEWORK_MARKERS = {
    "qiankun": ("qiankun", "registerMicroApps", "loadMicroApp"),
    "wujie": ("wujie", "<wujie-vue", "<wujie "),
    "micro-app": ("micro-app", "micro-app", "microapp"),
}


@dataclass
class MicroFrontendResource:
    application: str
    mount_path: str = ""
    route: str = ""
    entry: str = ""
    framework: str = "unknown"
    source: str = ""
    confidence: int = 50
    evidence: Set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        self.application = _label(self.application, 128)
        self.mount_path = _label(self.mount_path, 256)
        self.route = _label(self.route, 256)
        self.entry = _safe_entry_url(self.entry)
        self.framework = _label(self.framework, 32).lower() or "unknown"
        self.source = _safe_url(self.source)
        try:
            self.confidence = max(0, min(100, int(self.confidence or 0)))
        except (TypeError, ValueError):
            self.confidence = 0
        self.evidence = {
            _label(value, 64) for value in self.evidence if _label(value, 64)
        }

    @property
    def idempotency_key(self) -> str:
        return "|".join((
            self.application,
            self.mount_path,
            self.route,
            self.entry,
            self.framework,
        ))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "resource_id": hashlib.sha256(
                self.idempotency_key.encode("utf-8", "replace")
            ).hexdigest()[:32],
            "application": self.application,
            "mount_path": self.mount_path,
            "route": self.route,
            "entry": self.entry,
            "framework": self.framework,
            "source": self.source,
            "confidence": self.confidence,
            "evidence": sorted(self.evidence),
        }


class MicroFrontendResourceAdapter:
    """从静态观测中提取有界微前端资源关系。"""

    def collect(
        self,
        *,
        pages: Iterable[Any] = (),
        scripts: Iterable[Any] = (),
        runtime_events: Iterable[Any] = (),
        base_url: str = "",
        allowed_hosts: Optional[Iterable[str]] = None,
    ) -> List[Dict[str, Any]]:
        observations = list(pages or ()) + list(scripts or ()) + list(runtime_events or ())
        resources: Dict[str, MicroFrontendResource] = {}
        for item in observations[:96]:
            body, source = _body_source(item)
            if not body and not source:
                continue
            lower = body.lower()
            framework = _framework_for(lower)
            if not framework:
                continue
            for candidate in _extract_candidates(body, framework):
                entry = _resolve_entry(candidate.get("entry"), base_url or source)
                if entry and not _host_allowed(entry, allowed_hosts):
                    continue
                resource = MicroFrontendResource(
                    application=candidate.get("application") or _host_label(entry) or "unknown",
                    mount_path=candidate.get("mount_path") or "",
                    route=candidate.get("route") or "",
                    entry=entry,
                    framework=framework,
                    source=source,
                    confidence=80 if candidate.get("application") and entry else 60,
                    evidence={"static:micro_frontend", "framework:" + framework},
                )
                if not resource.application:
                    continue
                resources.setdefault(resource.idempotency_key, resource)
                if len(resources) >= _MAX_RESOURCES:
                    break
            if len(resources) >= _MAX_RESOURCES:
                break
        return [
            resource.to_dict()
            for resource in sorted(resources.values(), key=lambda item: item.idempotency_key)
        ]


def extract_micro_frontend_resources(**kwargs) -> List[Dict[str, Any]]:
    """函数式入口，便于 Collector 和测试按需启用适配器。"""

    return MicroFrontendResourceAdapter().collect(**kwargs)


def _extract_candidates(body: str, framework: str) -> List[Dict[str, str]]:
    candidates: List[Dict[str, str]] = []
    # qiankun registerMicroApps([{name, entry, activeRule, container}]) 及其
    # 常见无空格变体：只取单层对象，避免把任意脚本正文当成资源图。
    for match in re.finditer(r"\{([^{}]{1,4096})\}", body):
        fragment = match.group(1)
        if not any(marker.lower() in body[max(0, match.start() - 240):match.end() + 240].lower()
                   for marker in _FRAMEWORK_MARKERS.get(framework, ())):
            continue
        application = _first_value(fragment, ("name", "appName", "app"))
        entry = _first_value(fragment, ("entry", "url"))
        route = _first_value(fragment, ("activeRule", "route", "path"))
        mount = _first_value(fragment, ("container", "mount", "mountPath"))
        if application or entry or route:
            candidates.append({
                "application": application,
                "entry": entry,
                "route": route,
                "mount_path": mount,
            })

    tag_pattern = re.compile(r"<micro-app\b([^>]*)>", re.IGNORECASE)
    for match in tag_pattern.finditer(body):
        attributes = match.group(1)
        candidates.append({
            "application": _attribute(attributes, ("name", "app")),
            "entry": _attribute(attributes, ("url", "src", "entry")),
            "route": _attribute(attributes, ("route", "path")),
            "mount_path": _attribute(attributes, ("mount", "container")),
        })
    return candidates[:32]


def _first_value(fragment: str, names) -> str:
    names_text = "|".join(re.escape(name) for name in names)
    match = re.search(
        r"(?:^|[,\s])(?:{})(?:\s*[:=]\s*)['\"]([^'\"]{{1,512}})".format(names_text),
        fragment,
        re.IGNORECASE,
    )
    return _label(match.group(1), 512) if match else ""


def _attribute(attributes: str, names) -> str:
    names_text = "|".join(re.escape(name) for name in names)
    match = re.search(
        r"(?:{})(?:\s*=\s*)['\"]([^'\"]{{1,512}})".format(names_text),
        attributes,
        re.IGNORECASE,
    )
    return _label(match.group(1), 512) if match else ""


def _body_source(item: Any):
    if isinstance(item, Mapping):
        body = item.get("body") or item.get("content") or item.get("text") or ""
        source = item.get("url") or item.get("source") or ""
    else:
        body = getattr(item, "body", "") or getattr(item, "content", "")
        source = getattr(item, "url", "") or getattr(item, "source", "")
    return str(body or "")[:_MAX_TEXT * 32], _safe_url(source)


def _framework_for(value: str) -> str:
    for framework, markers in _FRAMEWORK_MARKERS.items():
        if any(marker.lower() in value for marker in markers):
            return framework
    return ""


def _resolve_entry(value: Any, base_url: Any) -> str:
    entry = str(value or "").strip()
    if not entry:
        return ""
    base = str(base_url or "").strip()
    resolved = urljoin(base, entry) if base else entry
    return _safe_entry_url(resolved)


def _host_allowed(value: str, allowed_hosts: Optional[Iterable[str]]) -> bool:
    if allowed_hosts is None:
        return True
    allowed = {
        str(item or "").strip().lower().rstrip(".")
        for item in allowed_hosts
        if str(item or "").strip()
    }
    if not allowed:
        return False
    host = str(urlsplit(value).hostname or "").lower().rstrip(".")
    return bool(host) and host in allowed


def _host_label(value: str) -> str:
    return str(urlsplit(value).hostname or "").strip().lower()


def _safe_url(value: Any) -> str:
    text = sanitize_url_secrets(str(value or "").strip()[:2048])
    try:
        parsed = urlsplit(text)
    except ValueError:
        return ""
    if parsed.scheme.lower() in {"http", "https"} and parsed.hostname:
        if parsed.username is not None or parsed.password is not None:
            return ""
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))[:2048]
    return text


def _safe_entry_url(value: Any) -> str:
    text = _safe_url(value)
    try:
        parsed = urlsplit(text)
    except ValueError:
        return ""
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        return ""
    return text


def _label(value: Any, limit: int) -> str:
    return str(value or "").strip().replace("\n", " ").replace("\r", " ")[:limit]


__all__ = [
    "MicroFrontendResource",
    "MicroFrontendResourceAdapter",
    "extract_micro_frontend_resources",
]
