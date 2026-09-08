"""WIH 受控验证的统一安全决策契约。

策略只返回是否允许进入验证阶段，不执行请求、不读取凭证，也不替代范围闸。
这样 L2 认证边界对比可以单独接入，而不会把 L3 安全测试混入 WIH。
"""

from dataclasses import dataclass
from typing import Any, Dict, Mapping
from urllib.parse import urlparse


LEVEL_L0 = "L0"
LEVEL_L1 = "L1"
LEVEL_L2 = "L2"
LEVEL_L3 = "L3"

STATUS_OBSERVED = "observed"
STATUS_QUEUED = "queued"
STATUS_SKIPPED = "skipped"
STATUS_PENDING = "pending"

_DANGEROUS_METHODS = {"PUT", "PATCH", "DELETE", "TRACE", "CONNECT"}
_READ_METHODS = {"GET", "HEAD"}
_POST_BODY_KINDS = {"multipart", "octet_stream", "binary", "graphql"}
_ALLOWED_L2_PROFILES = {"anonymous", "invalid_auth", "authorized"}


@dataclass(frozen=True)
class VerificationDecision:
    level: str
    method: str
    status: str
    allowed: bool
    reason_code: str
    requires_explicit_enable: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level,
            "method": self.method,
            "status": self.status,
            "allowed": self.allowed,
            "reason_code": self.reason_code,
            "requires_explicit_enable": self.requires_explicit_enable,
        }


class ControlledVerificationPolicy:
    """将 Endpoint 记录映射为 L0/L1/L2/L3 决策。"""

    def __init__(
        self,
        *,
        l1_enabled: bool = True,
        l2_enabled: bool = False,
        allowlisted_post: bool = False,
    ):
        self.l1_enabled = bool(l1_enabled)
        self.l2_enabled = bool(l2_enabled)
        self.allowlisted_post = bool(allowlisted_post)

    def decide(self, item: Mapping[str, Any], requested_level: str = LEVEL_L1) -> VerificationDecision:
        record = item if isinstance(item, Mapping) else {}
        method = str(record.get("method") or "GET").strip().upper() or "GET"
        level = str(requested_level or LEVEL_L1).strip().upper() or LEVEL_L1
        if level not in {LEVEL_L0, LEVEL_L1, LEVEL_L2, LEVEL_L3}:
            return self._skip(level, method, "invalid_verification_level")

        if _has_observed_response(record):
            return VerificationDecision(
                LEVEL_L0, method, STATUS_OBSERVED, False, "runtime_response_already_observed"
            )

        url = str(record.get("url") or "").strip()
        if not _is_http_url(url):
            return self._skip(level, method, "non_http_endpoint")
        if level == LEVEL_L3:
            return self._skip(LEVEL_L3, method, "l3_outside_wih")
        if level == LEVEL_L2:
            if not self.l2_enabled:
                return self._skip(LEVEL_L2, method, "l2_requires_explicit_enable", True)
            profile = str(record.get("auth_profile") or "").strip().lower()
            if profile not in _ALLOWED_L2_PROFILES:
                return self._skip(LEVEL_L2, method, "auth_profile_not_allowlisted")
            # L2 仅进入独立认证边界阶段；本策略不授权 L1 请求冒充 L2。
            return VerificationDecision(
                LEVEL_L2, method, STATUS_PENDING, False, "requires_auth_boundary_stage", True
            )
        if not self.l1_enabled:
            return self._skip(LEVEL_L1, method, "l1_disabled")
        if method in _DANGEROUS_METHODS:
            return self._skip(LEVEL_L3, method, "method_is_write_or_specialized")
        if method in _READ_METHODS:
            return VerificationDecision(
                LEVEL_L1, method, STATUS_QUEUED, True, "safe_read_allowlisted", True
            )
        if method == "POST" and self.allowlisted_post and _explicit_safe_read(record):
            body_kind = str(record.get("body_kind") or "").strip().lower()
            if body_kind not in _POST_BODY_KINDS:
                return VerificationDecision(
                    LEVEL_L1, method, STATUS_QUEUED, True, "allowlisted_read_only_post", True
                )
        if method == "POST":
            return self._skip(LEVEL_L1, method, "post_not_allowlisted")
        return self._skip(LEVEL_L1, method, "method_not_allowlisted")

    @staticmethod
    def _skip(level: str, method: str, reason: str, explicit: bool = False):
        return VerificationDecision(
            level if level in {LEVEL_L0, LEVEL_L1, LEVEL_L2, LEVEL_L3} else LEVEL_L1,
            method,
            STATUS_SKIPPED,
            False,
            reason,
            explicit,
        )


def _is_http_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
    except ValueError:
        return False
    return parsed.scheme.lower() in {"http", "https"} and bool(parsed.netloc)


def _explicit_safe_read(record: Mapping[str, Any]) -> bool:
    value = record.get("safe_read")
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _has_observed_response(record: Mapping[str, Any]) -> bool:
    value = record.get("status_code") or record.get("response_status")
    try:
        return int(value) > 0
    except (TypeError, ValueError):
        return False


__all__ = [
    "ControlledVerificationPolicy",
    "VerificationDecision",
    "LEVEL_L0",
    "LEVEL_L1",
    "LEVEL_L2",
    "LEVEL_L3",
    "STATUS_OBSERVED",
    "STATUS_PENDING",
    "STATUS_QUEUED",
    "STATUS_SKIPPED",
]
