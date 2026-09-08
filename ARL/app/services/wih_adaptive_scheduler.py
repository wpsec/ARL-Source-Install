"""WIH 候选的有界自适应调度。

调度器只计算优先级和收口原因，不创建网络请求。这样可以在不改变现有
Collector 行为的前提下，把新增候选按预期信息增益、请求成本和 WAF 风险
排序，并保留未入选候选供下一轮继续处理。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Tuple


STOP_BUDGET = "budget_exhausted"
STOP_NO_GAIN = "low_information_gain"
STOP_WAF = "waf_risk_high"
STOP_NONE = ""


@dataclass(frozen=True)
class WihScheduleCandidate:
    """调度所需的最小候选摘要，不携带 URL、请求体或凭据。"""

    candidate_id: str
    strategy: str = "endpoint_probe"
    host: str = ""
    expected_evidence: float = 0.0
    confidence: float = 0.0
    request_cost: float = 1.0
    time_cost: float = 1.0
    waf_risk: float = 0.0
    covered: bool = False
    source_count: int = 1
    priority: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "candidate_id", str(self.candidate_id or "").strip()[:128])
        object.__setattr__(self, "strategy", str(self.strategy or "endpoint_probe").strip()[:64])
        object.__setattr__(self, "host", str(self.host or "").strip().lower()[:255])
        for field_name in (
            "expected_evidence", "confidence", "request_cost", "time_cost", "waf_risk"
        ):
            value = _bounded_float(getattr(self, field_name), 0.0, 100.0)
            if field_name in {"request_cost", "time_cost"}:
                value = max(0.1, value)
            object.__setattr__(self, field_name, value)
        object.__setattr__(self, "covered", bool(self.covered))
        object.__setattr__(self, "source_count", max(0, _safe_int(self.source_count)))
        object.__setattr__(self, "priority", _safe_int(self.priority))

    @property
    def score(self) -> float:
        """信息增益/成本分数；分数只用于排序，不代表安全结论。"""

        if self.covered:
            return 0.0
        source_bonus = min(1.25, 1.0 + max(0, self.source_count - 1) * 0.05)
        priority_bonus = 1.0 + min(0.25, max(0, self.priority) / 100.0)
        gain = self.expected_evidence * max(0.0, self.confidence) / 100.0
        risk_cost = 1.0 + self.waf_risk / 100.0
        return (gain * source_bonus * priority_bonus) / (
            max(0.1, self.request_cost + self.time_cost) * risk_cost
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "strategy": self.strategy,
            "host": self.host,
            "expected_evidence": self.expected_evidence,
            "confidence": self.confidence,
            "request_cost": self.request_cost,
            "time_cost": self.time_cost,
            "waf_risk": self.waf_risk,
            "covered": self.covered,
            "source_count": self.source_count,
            "priority": self.priority,
            "score": round(self.score, 6),
        }


@dataclass(frozen=True)
class WihSchedulePlan:
    selected: Tuple[WihScheduleCandidate, ...] = ()
    pending: Tuple[WihScheduleCandidate, ...] = ()
    skipped: Tuple[Tuple[str, str], ...] = ()
    stop_reason: str = STOP_NONE
    spent_cost: float = 0.0
    candidate_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "selected": [item.to_dict() for item in self.selected],
            "pending": [item.to_dict() for item in self.pending],
            "skipped": {key: value for key, value in self.skipped},
            "stop_reason": self.stop_reason,
            "spent_cost": round(self.spent_cost, 6),
            "candidate_count": self.candidate_count,
            "selected_count": len(self.selected),
            "pending_count": len(self.pending),
        }


def schedule_candidates(
    candidates: Iterable[Any],
    *,
    budget: float = 60.0,
    max_selected: int = 64,
    max_per_host: int = 16,
    min_score: float = 0.01,
    waf_block_count: int = 0,
    no_gain_count: int = 0,
) -> WihSchedulePlan:
    """生成一轮有界计划。"""

    normalized = _normalize_candidates(candidates)
    budget_value = max(0.1, _bounded_float(budget, 60.0, 86400.0))
    selected_limit = max(0, _safe_int(max_selected))
    host_limit = max(0, _safe_int(max_per_host))
    skipped: List[Tuple[str, str]] = []
    pending: List[WihScheduleCandidate] = []
    if _safe_int(waf_block_count) >= 3:
        return _plan_with_skips(normalized, STOP_WAF, "waf_risk_high")
    if _safe_int(no_gain_count) >= 3:
        return _plan_with_skips(normalized, STOP_NO_GAIN, "low_information_gain")

    ranked = sorted(
        normalized,
        key=lambda item: (-item.score, -item.priority, item.host, item.candidate_id),
    )
    selected: List[WihScheduleCandidate] = []
    host_counts: Dict[str, int] = {}
    spent = 0.0
    stop_reason = STOP_NONE

    for candidate in ranked:
        if candidate.covered:
            skipped.append((candidate.candidate_id, "already_covered"))
            continue
        if candidate.score < max(0.0, float(min_score or 0.0)):
            pending.append(candidate)
            skipped.append((candidate.candidate_id, "low_information_gain"))
            continue
        if selected_limit and len(selected) >= selected_limit:
            pending.append(candidate)
            skipped.append((candidate.candidate_id, "selection_limit"))
            continue
        host_key = candidate.host or "unknown"
        if host_limit and host_counts.get(host_key, 0) >= host_limit:
            pending.append(candidate)
            skipped.append((candidate.candidate_id, "host_budget"))
            continue
        cost = candidate.request_cost + candidate.time_cost
        if spent + cost > budget_value:
            pending.append(candidate)
            skipped.append((candidate.candidate_id, "budget_exhausted"))
            stop_reason = STOP_BUDGET
            continue
        selected.append(candidate)
        host_counts[host_key] = host_counts.get(host_key, 0) + 1
        spent += cost

    return WihSchedulePlan(
        selected=tuple(selected),
        pending=tuple(pending),
        skipped=tuple(_unique_pairs(skipped)),
        stop_reason=stop_reason,
        spent_cost=spent,
        candidate_count=len(normalized),
    )


def _normalize_candidates(values: Iterable[Any]) -> List[WihScheduleCandidate]:
    result: List[WihScheduleCandidate] = []
    seen = set()
    for value in values or ():
        if isinstance(value, WihScheduleCandidate):
            candidate = value
        elif isinstance(value, Mapping):
            candidate = WihScheduleCandidate(**dict(value))
        else:
            continue
        if not candidate.candidate_id or candidate.candidate_id in seen:
            continue
        seen.add(candidate.candidate_id)
        result.append(candidate)
    return result


def _plan_with_skips(
    candidates: List[WihScheduleCandidate], stop_reason: str, reason: str
) -> WihSchedulePlan:
    return WihSchedulePlan(
        pending=tuple(item for item in candidates if not item.covered),
        skipped=tuple(
            (item.candidate_id, "already_covered" if item.covered else reason)
            for item in candidates
        ),
        stop_reason=stop_reason,
        candidate_count=len(candidates),
    )


def _unique_pairs(values: Iterable[Tuple[str, str]]) -> List[Tuple[str, str]]:
    result = []
    seen = set()
    for key, value in values:
        pair = (str(key or "")[:128], str(value or "")[:64])
        if not pair[0] or pair in seen:
            continue
        seen.add(pair)
        result.append(pair)
    return result


def _bounded_float(value: Any, default: float, maximum: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    if number != number:
        return default
    return min(maximum, max(0.0, number))


def _safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


__all__ = [
    "STOP_BUDGET",
    "STOP_NO_GAIN",
    "STOP_NONE",
    "STOP_WAF",
    "WihScheduleCandidate",
    "WihSchedulePlan",
    "schedule_candidates",
]
