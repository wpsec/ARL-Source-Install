"""独立的 WIH API 受控验证协调器。

该模块把策略、候选调度和结果脱敏组合在一起，但把实际请求器作为依赖注入。
默认调用方不传请求器时只返回 pending，不会因为启用 WIH 而隐式发起新请求。
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Iterable, Mapping, Optional

from .controlled_verification_policy import ControlledVerificationPolicy
from .api_unified_models import is_sensitive_key, sanitize_url_secrets
from .wih_auth_boundary import (
    apply_auth_boundary_result,
    compare_auth_boundary,
)
from .wih_adaptive_scheduler import schedule_candidates


def run_api_verify(
    items: Iterable[Mapping[str, Any]],
    *,
    verify_fn: Optional[Callable[[Mapping[str, Any]], Mapping[str, Any]]] = None,
    auth_boundary_fn: Optional[Callable[[Mapping[str, Any]], Mapping[str, Any]]] = None,
    policy: Optional[ControlledVerificationPolicy] = None,
    budget: float = 60.0,
    max_selected: int = 64,
) -> Dict[str, Any]:
    """执行一轮独立验证协调，不负责凭证注入和 HTTP 实现。

    ``verify_fn`` 只接收 L1 安全读取候选；``auth_boundary_fn`` 接收 L2
    候选并返回 anonymous/invalid_auth/authorized 三类安全响应摘要。两者都
    由调用方注入，协调器不会自行创建网络客户端或读取凭据。
    """

    records = [dict(item) for item in list(items or []) if isinstance(item, Mapping)]
    policy = policy or ControlledVerificationPolicy()
    candidates = [_candidate_for(item, index) for index, item in enumerate(records)]
    plan = schedule_candidates(
        candidates,
        budget=budget,
        max_selected=max_selected,
        max_per_host=max_selected,
    )
    selected = {item.candidate_id for item in plan.selected}
    by_id = {
        candidate.candidate_id: item
        for candidate, item in zip(candidates, records)
    }
    results = []
    for candidate in candidates:
        item = dict(by_id.get(candidate.candidate_id) or {})
        if candidate.candidate_id not in selected:
            item.update(
                verification_status=(
                    "skipped" if candidate.covered else "pending"
                ),
                verification_reason_codes=[
                    dict(plan.skipped).get(candidate.candidate_id, "not_selected")
                ],
            )
            results.append(_public_result(item))
            continue

        requested_level = str(
            item.get("verification_level") or item.get("requested_level") or "L1"
        ).strip().upper()
        decision = policy.decide(item, requested_level=requested_level)
        if (
            requested_level == "L2"
            and decision.reason_code == "requires_auth_boundary_stage"
        ):
            if auth_boundary_fn is None:
                item.update(
                    verification_status="pending",
                    verification_reason_codes=["auth_boundary_executor_not_configured"],
                )
                results.append(_public_result(item))
                continue
            try:
                responses = auth_boundary_fn(item)
                if not isinstance(responses, Mapping):
                    raise TypeError("auth boundary executor must return a mapping")
                boundary = compare_auth_boundary(
                    responses,
                    sibling_requires_auth=bool(item.get("sibling_requires_auth")),
                )
                item.update(apply_auth_boundary_result({}, boundary))
            except Exception as exc:
                item.update(
                    verification_status="failed",
                    verification_reason_codes=[
                        "auth_boundary_executor_{}".format(type(exc).__name__)
                    ],
                )
            results.append(_public_result(item))
            continue
        if not decision.allowed:
            status = "blocked" if "blocked" in decision.reason_code else "skipped"
            item.update(
                verification_status=status,
                verification_reason_codes=[decision.reason_code],
            )
            results.append(_public_result(item))
            continue
        if verify_fn is None:
            item.update(
                verification_status="pending",
                verification_reason_codes=["verify_executor_not_configured"],
            )
            results.append(_public_result(item))
            continue
        try:
            response = verify_fn(item)
            safe_response = _safe_response_summary(response)
            item.update(safe_response)
            item.update(
                verification_status=str(
                    safe_response.get("verification_status") or "verified_read"
                ),
                verification_reason_codes=list(
                    safe_response.get("verification_reason_codes")
                    or ["safe_read_executor_completed"]
                ),
            )
        except Exception as exc:
            item.update(
                verification_status="failed",
                verification_reason_codes=["executor_{}".format(type(exc).__name__)],
            )
        results.append(_public_result(item))

    return {"plan": plan.to_dict(), "items": results}


def build_l1_executor(*, waf_guard: Any = None, discovery_context: Any = None):
    """构造复用既有 Endpoint Probe 的 L1 执行器。

    执行器是显式依赖：构造本身不发请求，调用方必须主动把返回函数传给
    ``run_api_verify(verify_fn=...)``。这样计划七可以复用任务级缓存、single-flight、
    WAF 和 DNS 范围策略，而不会因为启用协调器就改变默认扫描行为。
    """

    from .wih_endpoint_probe import _probe_one

    def execute(item: Mapping[str, Any]) -> Dict[str, Any]:
        output = _probe_one(
            dict(item or {}),
            waf_guard=waf_guard,
            discovery_context=discovery_context,
        )
        status = str(output.get("verification_status") or "").strip().lower()
        if status in {"probed", "observed"}:
            verification_status = "verified_read"
            reason = "safe_read_executor_completed"
        elif status == "skipped":
            verification_status = "skipped"
            reason = "safe_read_executor_skipped"
        elif status in {"error", "failed"}:
            verification_status = "failed"
            reason = "safe_read_executor_failed"
        else:
            verification_status = "pending"
            reason = "safe_read_executor_pending"
        return {
            "verification_status": verification_status,
            "verification_reason_codes": [reason],
            "status_code": output.get("status_code"),
            "response_size": output.get("response_size"),
        }

    return execute


def _candidate_for(item: Mapping[str, Any], index: int):
    from .wih_adaptive_scheduler import WihScheduleCandidate

    candidate_id = str(
        item.get("endpoint_id") or item.get("url") or "candidate-{}".format(index)
    ).strip()[:128]
    method = str(item.get("method") or "GET").strip().upper()
    return WihScheduleCandidate(
        candidate_id=candidate_id,
        host=str(item.get("host") or ""),
        expected_evidence=80 if method in {"GET", "HEAD"} else 30,
        confidence=item.get("confidence", 50),
        request_cost=1 if method in {"GET", "HEAD"} else 3,
        time_cost=1,
        covered=bool(item.get("status_code") or item.get("status") == "covered"),
        source_count=len(item.get("sources") or []) or 1,
        priority=item.get("confidence", 0),
    )


def _public_result(item: Mapping[str, Any]) -> Dict[str, Any]:
    output = _sanitize_value(dict(item), depth=0)
    return output if isinstance(output, dict) else {}


def _safe_response_summary(value: Any) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        return {"verification_status": "failed", "verification_reason_codes": ["invalid_executor_result"]}
    output = {}
    for key in ("verification_status", "verification_reason_codes", "status_code", "response_size", "response_hash"):
        if key in value:
            output[key] = value[key]
    if isinstance(output.get("verification_reason_codes"), str):
        output["verification_reason_codes"] = [output["verification_reason_codes"][:64]]
    elif isinstance(output.get("verification_reason_codes"), list):
        output["verification_reason_codes"] = [str(item)[:64] for item in output["verification_reason_codes"][:16]]
    return output


_PRIVATE_OUTPUT_KEYS = {
    "_verify_candidate_id",
    "request_body",
    "request_template",
    "body",
    "body_text",
    "headers",
    "request_headers",
    "response_headers",
    "set-cookie",
    "authorization",
    "cookie",
    "token",
    "response_packet",
    "verification_response_packet",
    "response_body",
    "query",
    "query_params",
    "form_data",
    "json_data",
    "params",
}


def _sanitize_value(value: Any, *, depth: int) -> Any:
    if depth > 3:
        return None
    if isinstance(value, Mapping):
        output = {}
        for key, child in value.items():
            key_text = str(key or "").strip()
            if key_text.lower() in _PRIVATE_OUTPUT_KEYS or is_sensitive_key(key_text):
                continue
            if key_text.lower() == "url":
                output[key_text] = sanitize_url_secrets(child)
                continue
            output[key_text] = _sanitize_value(child, depth=depth + 1)
        return output
    if isinstance(value, (list, tuple)):
        return [_sanitize_value(item, depth=depth + 1) for item in list(value)[:64]]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)[:256]


__all__ = ["build_l1_executor", "run_api_verify"]
