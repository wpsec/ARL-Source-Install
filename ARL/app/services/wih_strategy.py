"""WIH 目标画像到采集策略的确定性映射。

该模块只做策略决策，不创建网络请求，也不改变候选 Registry。这样画像误判时
最多影响可选 Collector，L0/L1 基础链路和结果状态仍由现有编排器负责。
"""

from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping, Tuple


LEVEL_L0 = "L0"
LEVEL_L1 = "L1"
LEVEL_L2 = "L2"
LEVEL_L3 = "L3"

COLLECTOR_ENDPOINT_PROBE = "endpoint_probe"
COLLECTOR_AUTH_BOUNDARY = "auth_boundary"
COLLECTOR_SPECIALIZED_SECURITY = "specialized_security"
COLLECTOR_BROWSER_RUNTIME = "browser_runtime"

_MAX_REASONS = 32


@dataclass(frozen=True)
class DiscoveryStrategyPlan:
    """一个目标在当前任务内的采集决策摘要。"""

    profile: str
    confidence: str
    selected_collectors: Tuple[str, ...]
    optional_collectors: Tuple[str, ...]
    skipped_collectors: Tuple[str, ...]
    reasons: Tuple[Tuple[str, str], ...]
    max_level: str = LEVEL_L1
    stop_reason: str = ""
    budget_sec: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "profile": self.profile,
            "confidence": self.confidence,
            "max_level": self.max_level,
            "selected_collectors": list(self.selected_collectors),
            "optional_collectors": list(self.optional_collectors),
            "skipped_collectors": list(self.skipped_collectors),
            "reasons": {key: value for key, value in self.reasons},
            "stop_reason": self.stop_reason,
            "budget_sec": self.budget_sec,
        }


def build_wih_strategy_plan(
    profile: Any,
    *,
    browser_enabled: bool = False,
    auth_boundary_enabled: bool = False,
    endpoint_probe_enabled: bool = True,
    budget_sec: Any = 0,
    metrics: Mapping[str, Any] = None,
) -> DiscoveryStrategyPlan:
    """根据画像、显式开关和任务诊断选择 Collector。

    browser runtime 和认证边界都不是画像自动授权的结果；它们必须同时满足
    显式开关，避免“看起来像 SPA”直接扩大主动请求面。
    """

    profile_name, confidence, recommended, optional, skipped = _profile_values(profile)
    selected = _ordered_unique(recommended)
    optional_values = _ordered_unique(optional)
    skipped_values = _ordered_unique(skipped)
    reasons = []
    budget_value = _positive_int(budget_sec)
    metrics = metrics if isinstance(metrics, Mapping) else {}
    stop_reason = _stop_reason(metrics)

    if endpoint_probe_enabled and not stop_reason:
        selected.append(COLLECTOR_ENDPOINT_PROBE)
        reasons.append((COLLECTOR_ENDPOINT_PROBE, "l1_safe_read_default"))
    elif endpoint_probe_enabled:
        skipped_values.append(COLLECTOR_ENDPOINT_PROBE)
        reasons.append((COLLECTOR_ENDPOINT_PROBE, stop_reason))

    if COLLECTOR_BROWSER_RUNTIME in optional_values:
        if browser_enabled and not stop_reason:
            selected.append(COLLECTOR_BROWSER_RUNTIME)
            reasons.append((COLLECTOR_BROWSER_RUNTIME, "explicit_feature_enabled"))
        else:
            skipped_values.append(COLLECTOR_BROWSER_RUNTIME)
            reasons.append(
                (
                    COLLECTOR_BROWSER_RUNTIME,
                    stop_reason or "requires_explicit_enable",
                )
            )
        optional_values = [
            item for item in optional_values if item != COLLECTOR_BROWSER_RUNTIME
        ]

    if auth_boundary_enabled and not stop_reason:
        # 这里只登记 L2 入口，不代表本阶段已经发送认证对比请求。
        selected.append(COLLECTOR_AUTH_BOUNDARY)
        reasons.append((COLLECTOR_AUTH_BOUNDARY, "explicit_l2_enable"))
    else:
        skipped_values.append(COLLECTOR_AUTH_BOUNDARY)
        reasons.append(
            (
                COLLECTOR_AUTH_BOUNDARY,
                stop_reason or "requires_explicit_l2_enable",
            )
        )

    skipped_values.append(COLLECTOR_SPECIALIZED_SECURITY)
    reasons.append((COLLECTOR_SPECIALIZED_SECURITY, "l3_outside_wih"))

    if stop_reason:
        for collector in list(selected):
            if collector in _profile_l0_collectors(selected):
                continue
            selected.remove(collector)
            skipped_values.append(collector)
            reasons.append((collector, stop_reason))

    return DiscoveryStrategyPlan(
        profile=profile_name,
        confidence=confidence,
        selected_collectors=tuple(_ordered_unique(selected)),
        optional_collectors=tuple(_ordered_unique(optional_values)),
        skipped_collectors=tuple(_ordered_unique(skipped_values)),
        reasons=tuple(_ordered_reasons(reasons)),
        max_level=LEVEL_L2 if auth_boundary_enabled and not stop_reason else LEVEL_L1,
        stop_reason=stop_reason,
        budget_sec=budget_value,
    )


def _profile_values(profile: Any):
    if isinstance(profile, Mapping):
        getter = profile.get
    else:
        getter = lambda key, default=None: getattr(profile, key, default)
    return (
        str(getter("profile", "unknown") or "unknown").strip()[:64],
        str(getter("confidence", "low") or "low").strip()[:32],
        getter("recommended_collectors", ("http",)) or ("http",),
        getter("optional_collectors", ()) or (),
        getter("skipped_collectors", ()) or (),
    )


def _profile_l0_collectors(values: Iterable[str]):
    # 这些 Collector 只消费已有阶段输入，预算停止时仍保留其诊断选择。
    return {item for item in values if item in {"http", "html", "script"}}


def _stop_reason(metrics: Mapping[str, Any]) -> str:
    if _as_bool(metrics.get("budget_exhausted")) or _as_bool(
        metrics.get("wih_budget_exhausted")
    ):
        return "budget_exhausted"
    if _safe_int(metrics.get("no_gain_count")) >= 3:
        return "low_information_gain"
    if _safe_int(metrics.get("waf_block_count")) >= 3 and _safe_int(
        metrics.get("candidate_discovered_count")
    ) == 0:
        return "waf_risk_high"
    return ""


def _ordered_unique(values: Iterable[Any]):
    result = []
    for value in values if not isinstance(values, (str, bytes)) else (values,):
        text = str(value or "").strip()[:64]
        if text and text not in result:
            result.append(text)
    return result


def _ordered_reasons(values: Iterable[Tuple[Any, Any]]):
    result = []
    seen = set()
    for key, value in values:
        key_text = str(key or "").strip()[:64]
        value_text = str(value or "").strip()[:96]
        if not key_text or not value_text or key_text in seen:
            continue
        seen.add(key_text)
        result.append((key_text, value_text))
        if len(result) >= _MAX_REASONS:
            break
    return result


def _safe_int(value):
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _positive_int(value):
    return _safe_int(value)


def _as_bool(value):
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


__all__ = [
    "COLLECTOR_AUTH_BOUNDARY",
    "COLLECTOR_BROWSER_RUNTIME",
    "COLLECTOR_ENDPOINT_PROBE",
    "COLLECTOR_SPECIALIZED_SECURITY",
    "DiscoveryStrategyPlan",
    "LEVEL_L0",
    "LEVEL_L1",
    "LEVEL_L2",
    "LEVEL_L3",
    "build_wih_strategy_plan",
]
