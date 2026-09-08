"""WIH L2 认证边界对比的安全结果契约。

本模块只消费调用方已经得到的响应摘要，不发请求、不接收凭据。响应正文和
Header 值只允许以结构摘要进入比较结果，避免认证验证阶段把秘密带入日志、
Registry 或前端记录面。
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


AUTH_PROFILES = ("anonymous", "invalid_auth", "authorized")
AUTH_ANOMALY_CANDIDATE = "auth_anomaly_candidate"
AUTH_VERIFIED_READ = "verified_read"
AUTH_PENDING = "pending"


@dataclass(frozen=True)
class AuthBoundaryResult:
    verification_status: str
    reason_codes: Tuple[str, ...] = ()
    manual_review_required: bool = False
    comparison: Tuple[Tuple[str, Dict[str, Any]], ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verification_status": self.verification_status,
            "verification_reason_codes": list(self.reason_codes),
            "manual_review_required": self.manual_review_required,
            "auth_boundary_comparison": {
                key: dict(value) for key, value in self.comparison
            },
        }


def build_auth_boundary_jobs(
    endpoint: Mapping[str, Any], *, enabled: bool = False
) -> Tuple[Dict[str, Any], ...]:
    """生成不含凭据的 L2 作业描述。"""

    if not enabled:
        return (
            {
                "status": AUTH_PENDING,
                "reason_code": "l2_requires_explicit_enable",
                "profiles": [],
            },
        )
    method = str(endpoint.get("method") or "GET").strip().upper() or "GET"
    url = _sanitize_job_url(str(endpoint.get("url") or "").strip()[:2048])
    return tuple(
        {
            "profile": profile,
            "method": method,
            "url": url,
            "credential_ref": None,
            "status": AUTH_PENDING,
        }
        for profile in AUTH_PROFILES
    )


def compare_auth_boundary(
    responses: Mapping[str, Any], *, sibling_requires_auth: bool = False
) -> AuthBoundaryResult:
    """比较 anonymous/invalid_auth/authorized 的安全摘要。"""

    summaries = {
        profile: _response_summary(responses.get(profile))
        for profile in AUTH_PROFILES
        if isinstance(responses, Mapping) and profile in responses
    }
    reasons = []
    anonymous = summaries.get("anonymous")
    invalid = summaries.get("invalid_auth")
    authorized = summaries.get("authorized")
    if anonymous and 200 <= anonymous["status_code"] < 300:
        reasons.append("anonymous_2xx")
    if anonymous and invalid and _same_shape(anonymous, invalid):
        reasons.append("invalid_auth_same_shape")
    if sibling_requires_auth:
        reasons.append("sibling_requires_auth")

    candidate = bool(
        anonymous
        and anonymous["status_code"] >= 200
        and anonymous["status_code"] < 300
        and ((invalid and _same_shape(anonymous, invalid)) or sibling_requires_auth)
    )
    if candidate:
        status = AUTH_ANOMALY_CANDIDATE
        reasons.append("manual_review_required")
        manual_review = True
    elif authorized and anonymous and authorized["status_code"] != anonymous["status_code"]:
        status = AUTH_VERIFIED_READ
        reasons.append("auth_boundary_changed")
        manual_review = False
    elif summaries:
        status = AUTH_PENDING
        reasons.append("insufficient_auth_boundary_evidence")
        manual_review = False
    else:
        status = AUTH_PENDING
        reasons.append("no_auth_boundary_evidence")
        manual_review = False

    return AuthBoundaryResult(
        verification_status=status,
        reason_codes=tuple(_unique(reasons)),
        manual_review_required=manual_review,
        comparison=tuple(sorted(summaries.items())),
    )


def apply_auth_boundary_result(
    item: Mapping[str, Any], result: AuthBoundaryResult
) -> Dict[str, Any]:
    """把安全结果投影到候选记录，不覆盖 URL、请求体或响应原文。"""

    output = dict(item) if isinstance(item, Mapping) else {}
    output.update(result.to_dict())
    output["auth_anomaly_candidate"] = (
        result.verification_status == AUTH_ANOMALY_CANDIDATE
    )
    output["manual_review_reason"] = "认证边界异常，需要人工确认" if result.manual_review_required else ""
    return output


def _response_summary(value: Any) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    status = _safe_status(value.get("status_code", value.get("status")))
    if status <= 0:
        return {}
    content_type = str(value.get("content_type") or "unknown").split(";", 1)[0].strip().lower()
    shape = value.get("structure_hash") or value.get("body_hash") or value.get("response_hash")
    if not shape:
        shape = _stable_hash(value.get("body_shape", value.get("body_length", "")))
    return {
        "status_code": status,
        "status_class": "{}xx".format(status // 100),
        "content_type": content_type[:96],
        "structure_hash": str(shape)[:128],
        "size_bucket": _size_bucket(value.get("body_length", value.get("response_size"))),
    }


def _same_shape(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    return (
        left.get("content_type") == right.get("content_type")
        and left.get("structure_hash") == right.get("structure_hash")
        and left.get("size_bucket") == right.get("size_bucket")
    )


def _size_bucket(value: Any) -> str:
    try:
        size = max(0, int(value or 0))
    except (TypeError, ValueError):
        return "unknown"
    if size < 1024:
        return "0-1k"
    if size < 10240:
        return "1k-10k"
    if size < 102400:
        return "10k-100k"
    return "100k+"


def _safe_status(value: Any) -> int:
    try:
        return max(0, min(999, int(value or 0)))
    except (TypeError, ValueError):
        return 0


def _stable_hash(value: Any) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8", "replace")).hexdigest()[:32]


def _unique(values: Iterable[str]) -> Tuple[str, ...]:
    output = []
    for value in values:
        text = str(value or "").strip()[:64]
        if text and text not in output:
            output.append(text)
    return tuple(output)


_SENSITIVE_QUERY_KEY_RE = re.compile(
    r"(?:^|[-_])(authorization|api[-_]?key|access[-_]?token|token|password|secret|cookie)(?:$|[-_])",
    re.IGNORECASE,
)


def _sanitize_job_url(value: str) -> str:
    """认证作业只携带可展示的 URL，绝不把 query 凭据传给执行器。"""

    text = str(value or "")
    try:
        parsed = urlsplit(text)
        if parsed.username is not None or parsed.password is not None:
            hostname = parsed.hostname
            if not hostname:
                return ""
            try:
                port = parsed.port
            except ValueError:
                return ""
            if ":" in hostname and not hostname.startswith("["):
                hostname = "[{}]".format(hostname)
            netloc = hostname
            if port is not None:
                netloc = "{}:{}".format(netloc, port)
        else:
            netloc = parsed.netloc
        if not parsed.query and not parsed.fragment and netloc == parsed.netloc:
            return text
        pairs = []
        for key, item in parse_qsl(parsed.query, keep_blank_values=True):
            safe_value = "<redacted>" if _SENSITIVE_QUERY_KEY_RE.search(key) else item
            pairs.append((key, safe_value))
        return urlunsplit((parsed.scheme, netloc, parsed.path, urlencode(pairs), ""))
    except (TypeError, ValueError):
        return ""


__all__ = [
    "AUTH_ANOMALY_CANDIDATE",
    "AUTH_PENDING",
    "AUTH_PROFILES",
    "AUTH_VERIFIED_READ",
    "AuthBoundaryResult",
    "apply_auth_boundary_result",
    "build_auth_boundary_jobs",
    "compare_auth_boundary",
]
