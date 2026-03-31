"""
AI 渗透测试结果接口

功能：
- 查询结果：/ai_pen_test/
- 单条/批量重试：/ai_pen_test/retry/
- 按任务批量执行：/ai_pen_test/batch_run/
- 批量删除：/ai_pen_test/delete/
- 统计概览：/ai_pen_test/stats/
"""
from collections import defaultdict

from bson import ObjectId
from flask_restx import fields, Namespace

from app import utils
from app.modules import ErrorMsg
from app.services.commonTask import WebSiteFetch
from app.utils import auth, get_logger
from . import base_query_fields, ARLResource, get_arl_parser


ns = Namespace("ai_pen_test", description="AI 渗透测试结果")
logger = get_logger()

base_search_fields = {
    "task_id": fields.String(description="任务ID"),
    "source_collection": fields.String(description="来源集合(vuln/nuclei_result/wih/fileleak/site/url)"),
    "risk_type": fields.String(description="风险类型"),
    "risk_name": fields.String(description="风险名称"),
    "target": fields.String(description="目标"),
    "vuln_url": fields.String(description="漏洞URL"),
    "decision": fields.String(description="结论(verified/likely_false_positive/needs_manual_review)"),
    "status": fields.String(description="执行状态(ok/error/skipped)"),
    "verification_step": fields.String(description="验证阶段(http_fetch_replay/mcp_http_probe/mcp_idor_probe/mcp_api_doc_probe/mcp_jwt_probe/mcp_websocket_probe)"),
    "payload_type": fields.String(description="探针类型(xss_probe/sqli_probe/idor_probe/api_doc_probe等)"),
    "payload_variant": fields.String(description="受控payload变体标识"),
    "proof_family": fields.String(description="统一证据家族(active_execution/auth_bypass/surface_exposure等)"),
    "proof_type": fields.String(description="统一证据类型"),
    "unauth_access_type": fields.String(description="未授权直访证据类型(unauth_admin_portal/unauth_profile_data等)"),
    "unauth_probe_summary": fields.String(description="未授权复核摘要(targets/blocked/login_wall/health_like等)"),
    "unauth_negative_type": fields.String(description="未授权负信号类型(auth_blocked/login_wall/guarded_mixed/health_only)"),
    "high_value_family": fields.String(description="高价值目标家族(api_doc_surface/token_auth_flow/login_entry_surface等)"),
    "request_template_mode": fields.String(description="请求模板模式(query/form_data/json_data/body)"),
    "request_template_content_type": fields.String(description="请求模板Content-Type"),
    "tool_plan_source": fields.String(description="工具计划来源(ai_plan/retry_history/inferred)"),
    "stop_reason": fields.String(description="Agent/MCP 停止原因(final_decision/manual_required/budget_exhausted/timeout/error)"),
    "reason": fields.String(description="验证说明"),
}
base_search_fields.update(base_query_fields)

stats_search_fields = {
    "task_id": fields.String(description="任务ID"),
}
stats_search_fields.update(base_query_fields)

AI_PEN_PHASE_F_CAPABILITY_SPECS = (
    {
        "id": "login_session",
        "label": "登录/默认口令",
        "risk_types": ("weak_password", "login_surface"),
        "payload_types": ("weak_password_probe",),
        "high_value_families": ("login_entry_surface",),
    },
    {
        "id": "jwt_auth",
        "label": "JWT/认证链",
        "risk_types": ("jwt",),
        "payload_types": ("jwt_probe",),
        "high_value_families": ("token_auth_flow",),
    },
    {
        "id": "api_doc_graphql",
        "label": "API文档/GraphQL",
        "risk_types": ("api_doc", "graphql"),
        "payload_types": ("api_doc_probe", "graphql_probe"),
        "high_value_families": ("api_doc_surface", "graphql_surface"),
    },
    {
        "id": "config_exposure",
        "label": "Actuator/配置暴露",
        "risk_types": ("sensitive_info",),
        "payload_types": ("config_probe",),
        "high_value_families": ("config_exposure_surface", "admin_debug_surface", "sensitive_file_surface"),
    },
    {
        "id": "idor_access",
        "label": "未授权/对象访问线索",
        "risk_types": ("idor",),
        "payload_types": ("idor_probe",),
        "proof_families": ("unauth_access", "access_control"),
    },
    {
        "id": "sqli",
        "label": "SQL注入",
        "risk_types": ("sqli",),
        "payload_types": ("sqli_probe",),
    },
    {
        "id": "xss",
        "label": "XSS/DOM XSS",
        "risk_types": ("xss",),
        "payload_types": ("xss_probe",),
    },
    {
        "id": "file_handling",
        "label": "文件处理/路径穿越",
        "risk_types": ("file_upload", "file_read", "path_traversal"),
        "payload_types": ("upload_probe", "file_probe", "path_traversal_probe"),
        "high_value_families": ("file_handling_surface", "path_traversal_surface", "sensitive_file_surface"),
    },
    {
        "id": "ssrf_server_side",
        "label": "SSRF/XXE/SSTI/CMDI",
        "risk_types": ("ssrf", "xxe", "ssti", "cmdi"),
        "payload_types": ("ssrf_probe", "xxe_probe", "ssti_probe", "cmdi_probe"),
    },
)

retry_fields = ns.model(
    "AiPenRetryFields",
    {
        "result_id": fields.String(required=False, description="单条结果ID"),
        "result_ids": fields.List(fields.String(required=True, description="结果ID列表"), required=False),
    },
)

batch_run_fields = ns.model(
    "AiPenBatchRunFields",
    {
        "task_id": fields.String(required=False, description="任务ID（单个）"),
        "task_ids": fields.List(fields.String(required=True, description="任务ID列表"), required=False),
        "max_cases": fields.Integer(required=False, description="本次批跑最大候选数（可选）", example=80),
    },
)

delete_fields = ns.model(
    "AiPenDeleteFields",
    {
        "result_ids": fields.List(fields.String(required=True, description="结果ID列表"), required=False),
        "task_id": fields.String(required=False, description="任务ID（删除该任务全部 AI 渗透结果）"),
    },
)


def _normalize_object_id(value):
    text = str(value or "").strip()
    if len(text) != 24:
        return ""
    try:
        ObjectId(text)
        return text
    except Exception:
        return ""


def _split_task_targets(raw_target):
    text = str(raw_target or "").replace("\r", "\n")
    parts = []
    for item in text.replace(",", "\n").split("\n"):
        candidate = str(item or "").strip()
        if not candidate:
            continue
        parts.append(candidate)
    return parts


def _build_task_sites(task_id: str, task_doc: dict):
    site_set = set()
    try:
        for item in utils.conn_db("site").find({"task_id": task_id}, {"site": 1}):
            site_text = str(item.get("site") or "").strip()
            if site_text:
                site_set.add(site_text)
    except Exception as exc:
        logger.warning("load task sites failed task_id:%s err:%s", task_id, exc)

    if site_set:
        return list(site_set)

    return _split_task_targets(task_doc.get("target", ""))


def _build_scope_domains(task_doc: dict):
    task_type = str(task_doc.get("type") or "").strip().lower()
    if task_type != "domain":
        return []
    targets = _split_task_targets(task_doc.get("target", ""))
    scope_domains = []
    for item in targets:
        lower_item = str(item or "").strip().lower()
        if not lower_item:
            continue
        if lower_item.startswith("http://") or lower_item.startswith("https://"):
            parsed = utils.domain_parsed(lower_item)
            if parsed and parsed.get("fld"):
                scope_domains.append(str(parsed["fld"]).strip())
            continue
        if "/" in lower_item:
            continue
        scope_domains.append(lower_item)
    return list({x for x in scope_domains if x})


def _build_runner(task_id: str):
    task_doc = utils.conn_db("task").find_one({"_id": ObjectId(task_id)})
    if not task_doc:
        raise ValueError("task not found")
    options = task_doc.get("options") if isinstance(task_doc.get("options"), dict) else {}
    sites = _build_task_sites(task_id, task_doc)
    scope_domains = _build_scope_domains(task_doc)
    return WebSiteFetch(task_id=task_id, sites=sites, options=options, scope_domain=scope_domains)


def _normalize_decision(value):
    text = str(value or "").strip().lower()
    if text in {"verified", "likely_false_positive", "needs_manual_review"}:
        return text
    return "needs_manual_review"


def _normalize_status(value):
    text = str(value or "").strip().lower()
    if text in {"ok", "error", "skipped"}:
        return text
    return "skipped"


def _safe_ratio(numerator, denominator):
    try:
        numerator_value = float(numerator or 0.0)
    except Exception:
        numerator_value = 0.0
    try:
        denominator_value = float(denominator or 0.0)
    except Exception:
        denominator_value = 0.0
    if denominator_value <= 0:
        return 0.0
    return float("{:.4f}".format(max(0.0, numerator_value / denominator_value)))


def _extract_budget_metric(item: dict, metric_name: str):
    row = item if isinstance(item, dict) else {}
    budget_used = row.get("budget_used") if isinstance(row.get("budget_used"), dict) else {}
    try:
        value = int(budget_used.get(metric_name, 0) or 0)
    except Exception:
        value = 0
    if value > 0:
        return value

    if metric_name == "turns":
        turns = 0
        for trace_item in list(row.get("agent_trace", []) or []):
            if not isinstance(trace_item, dict):
                continue
            if str(trace_item.get("action", "") or "").strip().lower() == "agent_turn":
                turns += 1
        return turns

    if metric_name == "tool_calls":
        return len(list(row.get("tool_calls", []) or []))

    return 0


def _is_ai_pen_covered(item: dict):
    row = item if isinstance(item, dict) else {}
    status = _normalize_status(row.get("status"))
    if status in {"ok", "error"}:
        return True
    if str(row.get("verification_step", "") or "").strip():
        return True
    if _extract_budget_metric(row, "turns") > 0 or _extract_budget_metric(row, "tool_calls") > 0:
        return True
    if list(row.get("external_tool_runs", []) or []):
        return True
    return False


def _build_ai_pen_quant_metrics(rows, total: int = 0):
    items = list(rows or [])
    total_count = int(total or 0)
    if total_count <= 0:
        total_count = len(items)

    covered_count = 0
    verified_count = 0
    likely_fp_count = 0
    manual_review_count = 0
    ok_count = 0
    error_count = 0
    skipped_count = 0
    budget_sample_count = 0
    total_turns = 0
    total_tool_calls = 0

    for item in items:
        if not isinstance(item, dict):
            continue

        decision = _normalize_decision(item.get("decision"))
        status = _normalize_status(item.get("status"))

        if decision == "verified":
            verified_count += 1
        elif decision == "likely_false_positive":
            likely_fp_count += 1
        else:
            manual_review_count += 1

        if status == "ok":
            ok_count += 1
        elif status == "error":
            error_count += 1
        else:
            skipped_count += 1

        if _is_ai_pen_covered(item):
            covered_count += 1

        turns = _extract_budget_metric(item, "turns")
        tool_calls = _extract_budget_metric(item, "tool_calls")
        if turns > 0 or tool_calls > 0:
            budget_sample_count += 1
            total_turns += max(0, turns)
            total_tool_calls += max(0, tool_calls)

    avg_turns = 0.0
    avg_tool_calls = 0.0
    if budget_sample_count > 0:
        avg_turns = float("{:.4f}".format(total_turns / float(budget_sample_count)))
        avg_tool_calls = float("{:.4f}".format(total_tool_calls / float(budget_sample_count)))

    return {
        "coverage": {
            "covered_count": covered_count,
            "total_count": total_count,
            "coverage_rate": _safe_ratio(covered_count, total_count),
        },
        "decision_metrics": {
            "verified_count": verified_count,
            "likely_false_positive_count": likely_fp_count,
            "needs_manual_review_count": manual_review_count,
            "success_rate": _safe_ratio(verified_count, total_count),
            "false_positive_rate": _safe_ratio(likely_fp_count, total_count),
            "manual_review_rate": _safe_ratio(manual_review_count, total_count),
        },
        "execution_metrics": {
            "ok_count": ok_count,
            "error_count": error_count,
            "skipped_count": skipped_count,
            "ok_rate": _safe_ratio(ok_count, total_count),
            "error_rate": _safe_ratio(error_count, total_count),
            "skipped_rate": _safe_ratio(skipped_count, total_count),
        },
        "budget_metrics": {
            "sample_count": budget_sample_count,
            "avg_turns": avg_turns,
            "avg_tool_calls": avg_tool_calls,
        },
    }


def _build_ai_pen_group_benchmarks(rows, field_name: str, max_items: int = 12):
    items = list(rows or [])
    group_text = str(field_name or "").strip()
    grouped = defaultdict(list)

    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get(group_text) or "").strip()
        if not name:
            continue
        grouped[name].append(item)

    benchmark_rows = []
    for name, group_rows in grouped.items():
        total_count = len(group_rows)
        quant_metrics = _build_ai_pen_quant_metrics(group_rows, total=total_count)
        benchmark_rows.append(
            {
                "name": name,
                "total_count": total_count,
                "covered_count": int(quant_metrics["coverage"]["covered_count"]),
                "verified_count": int(quant_metrics["decision_metrics"]["verified_count"]),
                "likely_false_positive_count": int(quant_metrics["decision_metrics"]["likely_false_positive_count"]),
                "needs_manual_review_count": int(quant_metrics["decision_metrics"]["needs_manual_review_count"]),
                "coverage_rate": float(quant_metrics["coverage"]["coverage_rate"]),
                "success_rate": float(quant_metrics["decision_metrics"]["success_rate"]),
                "false_positive_rate": float(quant_metrics["decision_metrics"]["false_positive_rate"]),
                "manual_review_rate": float(quant_metrics["decision_metrics"]["manual_review_rate"]),
                "ok_rate": float(quant_metrics["execution_metrics"]["ok_rate"]),
                "error_rate": float(quant_metrics["execution_metrics"]["error_rate"]),
                "avg_turns": float(quant_metrics["budget_metrics"]["avg_turns"]),
                "avg_tool_calls": float(quant_metrics["budget_metrics"]["avg_tool_calls"]),
                "quant_metrics": quant_metrics,
            }
        )

    benchmark_rows.sort(
        key=lambda item: (
            -int(item.get("total_count") or 0),
            -float(item.get("success_rate") or 0.0),
            -float(item.get("coverage_rate") or 0.0),
            str(item.get("name") or ""),
        )
    )
    if max_items <= 0:
        return benchmark_rows
    return benchmark_rows[:max_items]


def _build_ai_pen_group_counts(rows, field_name: str, max_items: int = 20):
    items = list(rows or [])
    group_text = str(field_name or "").strip()
    grouped = defaultdict(int)

    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get(group_text) or "").strip()
        if not name:
            continue
        grouped[name] += 1

    rows = [{"name": name, "count": count} for name, count in grouped.items()]
    rows.sort(key=lambda item: (-int(item.get("count") or 0), str(item.get("name") or "")))
    if max_items <= 0:
        return rows
    return rows[:max_items]


def _build_ai_pen_unauth_negative_summary(rows):
    items = [item for item in list(rows or []) if isinstance(item, dict)]
    total_count = len(items)
    distribution = _build_ai_pen_group_counts(items, "unauth_negative_type", max_items=8)
    negative_signal_count = sum(int(item.get("count", 0) or 0) for item in distribution)
    protected_count = sum(
        int(item.get("count", 0) or 0)
        for item in distribution
        if str(item.get("name") or "").strip() in {"auth_blocked", "login_wall", "guarded_mixed"}
    )
    health_only_count = sum(
        int(item.get("count", 0) or 0)
        for item in distribution
        if str(item.get("name") or "").strip() == "health_only"
    )
    dominant_negative_type = str(distribution[0].get("name") or "").strip() if distribution else ""
    return {
        "total_count": total_count,
        "negative_signal_count": negative_signal_count,
        "negative_signal_rate": _safe_ratio(negative_signal_count, total_count),
        "protected_count": protected_count,
        "protected_rate": _safe_ratio(protected_count, total_count),
        "health_only_count": health_only_count,
        "health_only_rate": _safe_ratio(health_only_count, total_count),
        "dominant_negative_type": dominant_negative_type,
        "distribution": distribution,
    }


def _build_ai_pen_unauth_access_overview(rows):
    relevant_rows = []
    for item in list(rows or []):
        if not isinstance(item, dict):
            continue
        normalized = dict(item)
        proof_family = str(normalized.get("proof_family", "") or "").strip()
        proof_type = str(normalized.get("proof_type", "") or "").strip()
        if not proof_family and proof_type:
            proof_family = _classify_ai_pen_proof_family(
                proof_type,
                payload_type=normalized.get("payload_type"),
            )
            normalized["proof_family"] = proof_family
        unauth_access_type = str(normalized.get("unauth_access_type", "") or "").strip()
        unauth_negative_type = str(normalized.get("unauth_negative_type", "") or "").strip()
        if not unauth_access_type and proof_family == "unauth_access":
            unauth_access_type = proof_type
            normalized["unauth_access_type"] = unauth_access_type
        if proof_family in {"unauth_access", "access_control"} or unauth_access_type or unauth_negative_type:
            relevant_rows.append(normalized)

    total_count = len(relevant_rows)
    positive_rows = [
        item for item in relevant_rows
        if _normalize_decision(item.get("decision")) == "verified"
        and str(item.get("proof_family", "") or "").strip() == "unauth_access"
    ]
    manual_rows = [
        item for item in relevant_rows
        if _normalize_decision(item.get("decision")) == "needs_manual_review"
        and str(item.get("proof_family", "") or "").strip() == "unauth_access"
    ]
    positive_type_distribution = _build_ai_pen_group_counts(positive_rows, "unauth_access_type", max_items=6)
    negative_summary = _build_ai_pen_unauth_negative_summary(relevant_rows)
    dominant_positive_type = str(positive_type_distribution[0].get("name") or "").strip() if positive_type_distribution else ""
    dominant_negative_type = str(negative_summary.get("dominant_negative_type") or "").strip()

    next_actions = []
    if positive_rows:
        next_actions.append("优先复核已命中的未授权入口，重点查看 {} 等高价值面".format(dominant_positive_type or "management/profile"))
    if dominant_negative_type in {"auth_blocked", "login_wall", "guarded_mixed"}:
        next_actions.append("当前更多被鉴权拦截或登录墙阻断，后续优先补带会话复核与登录链")
    elif dominant_negative_type == "health_only":
        next_actions.append("当前主要命中健康检查/信息端点，建议下调优先级并继续补高价值管理面")
    if manual_rows and not positive_rows:
        next_actions.append("已有需人工复核的未授权线索，可优先检查管理面、账户信息接口和配置面")
    if not next_actions and total_count > 0:
        next_actions.append("当前已有未授权相关样本，但结论仍较分散，建议继续结合高价值路径与认证链复核")

    return {
        "total_count": total_count,
        "verified_count": len(positive_rows),
        "needs_manual_review_count": len(manual_rows),
        "negative_signal_count": int(negative_summary.get("negative_signal_count", 0) or 0),
        "positive_type_distribution": positive_type_distribution,
        "negative_type_distribution": list(negative_summary.get("distribution", []) or []),
        "dominant_positive_type": dominant_positive_type,
        "dominant_negative_type": dominant_negative_type,
        "recommended_action": next_actions[0] if next_actions else "",
        "next_actions": next_actions[:4],
        "negative_summary": negative_summary,
    }


def _classify_ai_pen_proof_family(proof_type, payload_type=""):
    if hasattr(WebSiteFetch, "_classify_ai_pen_proof_family"):
        try:
            return str(
                WebSiteFetch._classify_ai_pen_proof_family(
                    proof_type,
                    payload_type=payload_type,
                )
                or ""
            ).strip()
        except Exception:
            pass

    proof = str(proof_type or "").strip().lower()
    payload = str(payload_type or "").strip().lower()

    if proof in {"popup_execution", "expression_eval", "id_output"}:
        return "active_execution"
    if proof in {"boolean_based", "error_based", "time_based", "template_error", "external_tool"}:
        return "response_differential"
    if proof in {"unauth_management_surface", "unauth_admin_portal", "unauth_profile_data", "unauth_actuator_surface", "unauth_health_endpoint"}:
        return "unauth_access"
    if proof in {"login_success", "weak_secret", "alg_none", "signature_bypass"}:
        return "auth_bypass"
    if proof in {"idor_diff", "idor_vertical_indicator", "idor_access_control_signal"}:
        return "access_control"
    if proof in {"api_doc_open", "api_schema_exposed", "graphql_schema_open", "config_exposure", "auth_protocol_open"}:
        return "surface_exposure"
    if proof in {"websocket_upgrade", "websocket_upgrade_open", "websocket_upgrade_hint", "socketio_polling_open", "sockjs_info_open", "socketio_websocket_upgrade", "transport_hint"}:
        return "realtime_exposure"
    if proof in {"entity_file_read", "passwd_disclosure", "win_ini_disclosure", "metadata_disclosure", "local_network_disclosure"}:
        return "sensitive_disclosure"
    if proof.startswith("cors_") or proof in {"missing_security_headers", "weak_cache_policy", "error_exposure"}:
        return "policy_misconfig"

    if not proof:
        if payload in {"api_doc_probe", "graphql_probe", "config_probe"}:
            return "surface_exposure"
        if payload in {"websocket_probe", "socketio_probe"}:
            return "realtime_exposure"
    return ""


def _normalize_ai_pen_signal_set(values):
    normalized = set()
    for item in list(values or []):
        text = str(item or "").strip().lower()
        if text:
            normalized.add(text)
    return normalized


def _match_ai_pen_capability_row(item: dict, capability_spec: dict):
    row = item if isinstance(item, dict) else {}
    spec = capability_spec if isinstance(capability_spec, dict) else {}

    signal_pairs = (
        ("risk_type", "risk_types"),
        ("payload_type", "payload_types"),
        ("proof_family", "proof_families"),
        ("high_value_family", "high_value_families"),
        ("verification_step", "verification_steps"),
    )
    for row_key, spec_key in signal_pairs:
        expected_set = _normalize_ai_pen_signal_set(spec.get(spec_key))
        if not expected_set:
            continue
        current_value = str(row.get(row_key) or "").strip().lower()
        if current_value and current_value in expected_set:
            return True
    return False


def _build_ai_pen_phase_f_readiness(rows):
    items = list(rows or [])
    capabilities = []
    covered_count = 0
    partial_count = 0
    missing_count = 0

    for spec in AI_PEN_PHASE_F_CAPABILITY_SPECS:
        matched_rows = [item for item in items if _match_ai_pen_capability_row(item, spec)]
        total_count = len(matched_rows)
        quant_metrics = _build_ai_pen_quant_metrics(matched_rows, total=total_count)
        verified_count = int(quant_metrics["decision_metrics"]["verified_count"])
        likely_fp_count = int(quant_metrics["decision_metrics"]["likely_false_positive_count"])
        manual_review_count = int(quant_metrics["decision_metrics"]["needs_manual_review_count"])
        conclusive_count = verified_count + likely_fp_count
        conclusive_rate = _safe_ratio(conclusive_count, total_count)
        coverage_rate = float(quant_metrics["coverage"]["coverage_rate"])
        unauth_negative_summary = _build_ai_pen_unauth_negative_summary(matched_rows)
        dominant_unauth_negative_type = str(unauth_negative_summary.get("dominant_negative_type") or "").strip()

        priority_score = (
            (verified_count * 12)
            + (manual_review_count * 4)
            + int(round(coverage_rate * 20))
            + int(round(conclusive_rate * 10))
            - (likely_fp_count * 4)
        )
        if total_count <= 0:
            status = "missing"
        elif coverage_rate >= 0.8 and conclusive_rate >= 0.5:
            status = "covered"
        else:
            status = "partial"
        if (
            status == "covered"
            and verified_count <= 0
            and manual_review_count <= 0
            and dominant_unauth_negative_type in {"auth_blocked", "login_wall", "guarded_mixed", "health_only"}
        ):
            status = "partial"
        if dominant_unauth_negative_type in {"auth_blocked", "login_wall", "guarded_mixed"} and verified_count <= 0:
            priority_score -= 4 + int(round(float(unauth_negative_summary.get("protected_rate", 0.0) or 0.0) * 12))
        elif dominant_unauth_negative_type == "health_only" and verified_count <= 0:
            priority_score -= 2 + int(round(float(unauth_negative_summary.get("health_only_rate", 0.0) or 0.0) * 10))
        if status == "missing":
            missing_count += 1
        if status == "covered":
            priority_score += 10
            covered_count += 1
        elif status == "partial":
            priority_score += 4
            partial_count += 1

        if verified_count > 0:
            focus_reason = "已有 verified 命中，适合作为工程师优先入口"
        elif dominant_unauth_negative_type in {"auth_blocked", "login_wall", "guarded_mixed"}:
            focus_reason = "当前更多被鉴权拦截或登录墙阻断，优先级可后置"
        elif dominant_unauth_negative_type == "health_only":
            focus_reason = "当前主要命中健康检查/信息端点，建议继续补更高价值管理面"
        elif manual_review_count > 0 and coverage_rate >= 0.8:
            focus_reason = "覆盖充分但仍以人工复核为主，适合继续深挖"
        elif likely_fp_count > 0 and manual_review_count <= 0:
            focus_reason = "当前更多是防护生效或误报信号，优先级可后置"
        elif total_count > 0:
            focus_reason = "已有观测样本，但结论仍不够收敛"
        else:
            focus_reason = "尚无有效样本"

        capabilities.append(
            {
                "id": str(spec.get("id") or "").strip(),
                "label": str(spec.get("label") or "").strip(),
                "status": status,
                "total_count": total_count,
                "verified_count": verified_count,
                "likely_false_positive_count": likely_fp_count,
                "needs_manual_review_count": manual_review_count,
                "conclusive_count": conclusive_count,
                "coverage_rate": coverage_rate,
                "success_rate": float(quant_metrics["decision_metrics"]["success_rate"]),
                "false_positive_rate": float(quant_metrics["decision_metrics"]["false_positive_rate"]),
                "manual_review_rate": float(quant_metrics["decision_metrics"]["manual_review_rate"]),
                "conclusive_rate": conclusive_rate,
                "avg_turns": float(quant_metrics["budget_metrics"]["avg_turns"]),
                "avg_tool_calls": float(quant_metrics["budget_metrics"]["avg_tool_calls"]),
                "priority_score": priority_score,
                "dominant_unauth_negative_type": dominant_unauth_negative_type,
                "negative_signal_count": int(unauth_negative_summary["negative_signal_count"]),
                "negative_signal_rate": float(unauth_negative_summary["negative_signal_rate"]),
                "unauth_negative_summary": unauth_negative_summary,
                "focus_reason": focus_reason,
                "quant_metrics": quant_metrics,
            }
        )

    return {
        "summary": {
            "total_capabilities": len(AI_PEN_PHASE_F_CAPABILITY_SPECS),
            "covered_count": covered_count,
            "partial_count": partial_count,
            "missing_count": missing_count,
        },
        "capabilities": capabilities,
    }


def _build_ai_pen_engineer_focus_queue(phase_f_readiness, max_items: int = 6):
    readiness_obj = phase_f_readiness if isinstance(phase_f_readiness, dict) else {}
    capabilities = list(readiness_obj.get("capabilities", []) or [])
    queue = []

    for item in capabilities:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or "").strip().lower()
        if status == "missing":
            continue
        queue.append(
            {
                "id": str(item.get("id") or "").strip(),
                "label": str(item.get("label") or "").strip(),
                "status": status,
                "priority_score": int(item.get("priority_score", 0) or 0),
                "verified_count": int(item.get("verified_count", 0) or 0),
                "needs_manual_review_count": int(item.get("needs_manual_review_count", 0) or 0),
                "likely_false_positive_count": int(item.get("likely_false_positive_count", 0) or 0),
                "coverage_rate": float(item.get("coverage_rate", 0.0) or 0.0),
                "success_rate": float(item.get("success_rate", 0.0) or 0.0),
                "false_positive_rate": float(item.get("false_positive_rate", 0.0) or 0.0),
                "avg_turns": float(item.get("avg_turns", 0.0) or 0.0),
                "avg_tool_calls": float(item.get("avg_tool_calls", 0.0) or 0.0),
                "dominant_unauth_negative_type": str(item.get("dominant_unauth_negative_type") or "").strip(),
                "negative_signal_count": int(item.get("negative_signal_count", 0) or 0),
                "negative_signal_rate": float(item.get("negative_signal_rate", 0.0) or 0.0),
                "focus_reason": str(item.get("focus_reason") or "").strip(),
            }
        )

    queue.sort(
        key=lambda item: (
            -int(item.get("priority_score") or 0),
            -int(item.get("verified_count") or 0),
            -int(item.get("needs_manual_review_count") or 0),
            float(item.get("false_positive_rate") or 0.0),
            str(item.get("label") or ""),
        )
    )
    if max_items <= 0:
        return queue
    return queue[:max_items]


def _build_ai_pen_engineer_focus_entries(rows, max_items: int = 10):
    entries = []

    for item in list(rows or []):
        if not isinstance(item, dict):
            continue

        decision = _normalize_decision(item.get("decision"))
        status = _normalize_status(item.get("status"))
        high_value_rank = int(item.get("high_value_family_rank", 0) or 0)
        confidence = 0.0
        try:
            confidence = float(item.get("confidence", 0.0) or 0.0)
        except Exception:
            confidence = 0.0

        request_template_mode = str(item.get("request_template_mode", "") or "").strip()
        request_template_content_type = str(item.get("request_template_content_type", "") or "").strip()
        raw_template_params = item.get("request_template_params")
        request_template_params = []
        if not isinstance(raw_template_params, (list, tuple)):
            raw_template_params = []
        for param_name in list(raw_template_params or []):
            param_text = str(param_name or "").strip()
            if param_text and param_text not in request_template_params:
                request_template_params.append(param_text)
        request_template_summary = str(item.get("request_template_summary", "") or "").strip()
        if not request_template_summary:
            summary_parts = []
            if request_template_mode:
                summary_parts.append("mode={}".format(request_template_mode))
            if request_template_content_type:
                summary_parts.append("content_type={}".format(request_template_content_type))
            if request_template_params:
                summary_parts.append("params={}".format(",".join(request_template_params[:8])))
            request_template_summary = " | ".join(summary_parts)

        payload_variant = str(item.get("payload_variant", "") or "").strip()
        payload_expected_signal = str(item.get("payload_expected_signal", "") or "").strip()
        proof_family = str(item.get("proof_family", "") or "").strip()
        proof_type = str(item.get("proof_type", "") or "").strip()
        unauth_access_type = str(item.get("unauth_access_type", "") or "").strip()
        unauth_access_reason = str(item.get("unauth_access_reason", "") or "").strip()
        unauth_probe_summary = str(item.get("unauth_probe_summary", "") or "").strip()
        unauth_negative_type = str(item.get("unauth_negative_type", "") or "").strip()
        if not proof_family and proof_type:
            proof_family = _classify_ai_pen_proof_family(
                proof_type,
                payload_type=str(item.get("payload_type", "") or "").strip(),
            )
        if not unauth_access_type and proof_family == "unauth_access":
            unauth_access_type = proof_type
        raw_proof_signals = item.get("proof_signals")
        proof_signals = []
        if isinstance(raw_proof_signals, (list, tuple)):
            for signal_name in list(raw_proof_signals or []):
                signal_text = str(signal_name or "").strip()
                if signal_text and signal_text not in proof_signals:
                    proof_signals.append(signal_text)
        proof_summary = str(item.get("proof_summary", "") or "").strip()

        score = int(round(confidence * 30))
        score += min(24, max(0, int(high_value_rank / 4)))
        if decision == "verified":
            score += 40
        elif decision == "needs_manual_review":
            score += 18
        else:
            score -= 12

        if status == "ok":
            score += 8
        elif status == "error":
            score -= 4

        http_status = 0
        try:
            http_status = int(item.get("http_status", 0) or 0)
        except Exception:
            http_status = 0
        if http_status in {200, 201, 206}:
            score += 6
        elif http_status in {401, 403}:
            score -= 4

        if bool(item.get("session_auth_hit")) or bool(item.get("weak_password_login_proof")):
            score += 12
        if bool(item.get("external_tool_hit")):
            score += 8
        if request_template_mode in {"json_data", "form_data", "body"}:
            score += 6
        elif request_template_mode == "query":
            score += 2
        if proof_family in {"auth_bypass", "active_execution", "sensitive_disclosure", "unauth_access"}:
            score += 8
        elif proof_family in {"surface_exposure", "realtime_exposure", "policy_misconfig", "access_control"}:
            score += 4
        if proof_type:
            score += 10
        if proof_summary:
            score += 4
        if unauth_access_type:
            score += 8
        if unauth_access_type == "unauth_health_endpoint":
            score -= 10
        if unauth_negative_type in {"auth_blocked", "login_wall", "guarded_mixed"}:
            score -= 6
        elif unauth_negative_type == "health_only":
            score -= 4

        if unauth_access_type == "unauth_health_endpoint":
            focus_reason = "已观察到公开健康检查/信息端点，建议结合敏感管理面继续复核"
        elif decision == "verified" and proof_family == "unauth_access":
            focus_reason = "已命中无登录直访证据（{}），建议工程师优先接手".format(unauth_access_type or proof_type or "unauth_access")
        elif decision == "verified" and proof_type:
            focus_reason = "已获得可复核证据（{}），建议工程师优先接手".format(proof_type)
        elif decision == "verified":
            focus_reason = "已获得较高置信验证结果，建议工程师优先接手"
        elif unauth_negative_type == "auth_blocked":
            focus_reason = "已完成未授权复核，主要被鉴权拦截"
        elif unauth_negative_type == "login_wall":
            focus_reason = "已完成未授权复核，主要回到登录页/登录墙"
        elif unauth_negative_type == "guarded_mixed":
            focus_reason = "已完成未授权复核，当前更多被鉴权拦截或登录墙阻断"
        elif unauth_negative_type == "health_only":
            focus_reason = "已完成未授权复核，当前主要命中健康检查/信息端点"
        elif proof_family == "unauth_access" and (unauth_access_reason or proof_summary):
            focus_reason = "已观察到无登录直访线索，适合作为未授权入口优先复核"
        elif proof_type and proof_summary:
            focus_reason = "已收敛到 {} 证据，自动化已给出可复核摘要".format(proof_type)
        elif request_template_mode in {"json_data", "form_data", "body"} and request_template_summary:
            focus_reason = "已命中结构化接口模板，适合作为优先复核入口"
        elif bool(item.get("session_auth_hit")):
            focus_reason = "已命中登录后资源访问，具备进一步扩展价值"
        elif str(item.get("high_value_family", "") or "").strip():
            focus_reason = "命中高价值入口家族，适合作为优先复核入口"
        else:
            focus_reason = "已有自动化观测结果，适合人工复核"

        entries.append(
            {
                "result_id": str(item.get("_id") or "").strip(),
                "target": str(item.get("target", "") or "").strip(),
                "vuln_url": str(item.get("vuln_url", "") or "").strip(),
                "risk_type": str(item.get("risk_type", "") or "").strip(),
                "risk_name": str(item.get("risk_name", "") or "").strip(),
                "payload_type": str(item.get("payload_type", "") or "").strip(),
                "payload_variant": payload_variant,
                "payload_expected_signal": payload_expected_signal,
                "proof_family": proof_family,
                "unauth_access_type": unauth_access_type,
                "unauth_access_reason": unauth_access_reason[:240],
                "unauth_probe_summary": unauth_probe_summary[:240],
                "unauth_negative_type": unauth_negative_type,
                "verification_step": str(item.get("verification_step", "") or "").strip(),
                "high_value_family": str(item.get("high_value_family", "") or "").strip(),
                "request_template_mode": request_template_mode,
                "request_template_content_type": request_template_content_type,
                "request_template_params": request_template_params[:8],
                "request_template_summary": request_template_summary,
                "proof_type": proof_type,
                "proof_signals": proof_signals[:8],
                "proof_summary": proof_summary,
                "decision": decision,
                "status": status,
                "confidence": float("{:.4f}".format(max(0.0, confidence))),
                "http_status": http_status,
                "priority_score": score,
                "reason": str(item.get("reason", "") or "").strip()[:240],
                "focus_reason": focus_reason,
            }
        )

    entries.sort(
        key=lambda item: (
            -int(item.get("priority_score") or 0),
            str(item.get("decision") or "") != "verified",
            -float(item.get("confidence") or 0.0),
            str(item.get("risk_type") or ""),
            str(item.get("vuln_url") or item.get("target") or ""),
        )
    )
    if max_items <= 0:
        return entries
    return entries[:max_items]


def _build_candidate_from_result(item: dict, max_steps: int = 4):
    """从历史结果重建候选，并补齐重试所需的会话/工具上下文。"""
    default_url = str(item.get("vuln_url") or item.get("target") or "").strip()
    history_tool_plan = WebSiteFetch._build_ai_pen_retry_seed_tool_plan(
        item,
        default_url=default_url,
        max_steps=max_steps,
    )
    history_tool_result_summary = WebSiteFetch._summarize_ai_pen_tool_results_for_agent(
        item.get("tool_results"),
        max_items=4,
    )
    return {
        "source_collection": str(item.get("source_collection", "") or "").strip(),
        "source_id": str(item.get("source_id", "") or "").strip(),
        "source_module": str(item.get("source_module", "") or "").strip(),
        "target": str(item.get("target", "") or "").strip(),
        "vuln_url": str(item.get("vuln_url", "") or "").strip(),
        "risk_type": str(item.get("risk_type", "") or "").strip(),
        "risk_name": str(item.get("risk_name", "") or "").strip(),
        "severity": str(item.get("severity", "") or "").strip(),
        "evidence_seed": str(item.get("evidence_snippet", "") or "").strip(),
        "knowledge_hit_tokens": list(item.get("knowledge_hit_tokens", []) or []),
        "knowledge_hit_samples": list(item.get("knowledge_hit_samples", []) or []),
        "knowledge_hit_product_labels": list(item.get("knowledge_hit_product_labels", []) or []),
        "knowledge_hit_vuln_types": list(item.get("knowledge_hit_vuln_types", []) or []),
        "knowledge_hit_entry_paths": list(item.get("knowledge_hit_entry_paths", []) or []),
        "knowledge_hit_verify_actions": list(item.get("knowledge_hit_verify_actions", []) or []),
        "knowledge_hit_record_refs": list(item.get("knowledge_hit_record_refs", []) or []),
        "browser_surface_summary": dict(item.get("browser_surface_summary") or {}) if isinstance(item.get("browser_surface_summary"), dict) else {},
        "runtime_api_calls": list(item.get("runtime_api_calls", []) or []),
        "dom_form_summary": list(item.get("dom_form_summary", []) or []),
        "task_ai_pen_graph_summary": dict(item.get("task_ai_pen_graph_summary") or {}) if isinstance(item.get("task_ai_pen_graph_summary"), dict) else {},
        "task_ai_pen_graph_context": dict(item.get("task_ai_pen_graph_context") or {}) if isinstance(item.get("task_ai_pen_graph_context"), dict) else {},
        "login_surface_summary": dict(item.get("login_surface_summary") or {}) if isinstance(item.get("login_surface_summary"), dict) else {},
        "high_value_summary": dict(item.get("high_value_summary") or {}) if isinstance(item.get("high_value_summary"), dict) else {},
        "high_value_family": str(item.get("high_value_family", "") or "").strip(),
        "high_value_family_rank": int(item.get("high_value_family_rank", 0) or 0),
        "high_value_keywords": list(item.get("high_value_keywords", []) or [])[:8],
        "history_session_summary": dict(item.get("session_summary") or {}) if isinstance(item.get("session_summary"), dict) else {},
        "history_tool_plan": history_tool_plan,
        "history_tool_result_summary": history_tool_result_summary,
        "priority_score": int(item.get("priority_score", 0) or 0),
        "status_code_hint": int(item.get("status_code_hint", 0) or 0),
    }


def _retry_records(result_docs):
    if not result_docs:
        return {"retry_count": 0, "saved_count": 0, "verified_count": 0, "likely_fp_count": 0, "error_count": 0}

    grouped = defaultdict(list)
    for item in result_docs:
        task_id = _normalize_object_id(item.get("task_id"))
        if not task_id:
            continue
        grouped[task_id].append(item)

    retry_count = 0
    saved_count = 0
    verified_count = 0
    likely_fp_count = 0
    error_count = 0

    collection = utils.conn_db("ai_pen_test_result")

    for task_id, items in grouped.items():
        try:
            runner = _build_runner(task_id)
            ai_config = runner._load_ai_runtime_config()
            runtime_settings = runner._build_ai_pen_runtime_settings(ai_config)
            ai_prompt_content = runner._resolve_ai_pen_prompt_content(ai_config)
        except Exception as exc:
            logger.warning("build ai pen runner failed task_id:%s err:%s", task_id, exc)
            error_count += len(items)
            retry_count += len(items)
            continue

        for item in items:
            retry_count += 1
            retry_max_steps = max(
                2,
                int(runtime_settings.get("max_tool_calls", WebSiteFetch.AI_PEN_TEST_MCP_MAX_TOOL_CALLS) or WebSiteFetch.AI_PEN_TEST_MCP_MAX_TOOL_CALLS),
            )
            candidate = _build_candidate_from_result(item, max_steps=retry_max_steps)
            ai_plan = {
                "payload_type": str(item.get("payload_type", "") or "").strip(),
                "payload": str(item.get("payload", "") or "").strip(),
                "tool_plan": list(candidate.get("history_tool_plan", []) or []),
            }
            verify_result = runner._verify_ai_pen_candidate(
                candidate,
                mcp_settings=runtime_settings,
                ai_plan=ai_plan,
                planner_context={
                    "ai_config": ai_config,
                    "prompt_content": ai_prompt_content,
                },
            )

            status = _normalize_status(verify_result.get("status"))
            decision = _normalize_decision(verify_result.get("decision"))
            if status == "error":
                error_count += 1
            if decision == "verified":
                verified_count += 1
            elif decision == "likely_false_positive":
                likely_fp_count += 1

            try:
                confidence = float(verify_result.get("confidence", 0.0) or 0.0)
            except Exception:
                confidence = 0.0
            confidence = max(0.0, min(1.0, confidence))
            now_text = utils.curr_date()

            update_fields = {
                "decision": decision,
                "status": status,
                "confidence": float("{:.4f}".format(confidence)),
                "reason": str(verify_result.get("reason", "") or "").strip(),
                "payload_type": str(verify_result.get("payload_type", "") or "").strip(),
                "payload_variant": str(verify_result.get("payload_variant", "") or "").strip(),
                "payload_expected_signal": str(verify_result.get("payload_expected_signal", "") or "").strip(),
                "payload_proof_candidates": (
                    list(verify_result.get("payload_proof_candidates", []) or [])[:6]
                    if isinstance(verify_result.get("payload_proof_candidates"), (list, tuple))
                    else []
                ),
                "payload": str(verify_result.get("payload", "") or "").strip(),
                "request_method": str(verify_result.get("request_method", "") or "").strip(),
                "request_url": str(verify_result.get("request_url", "") or "").strip(),
                "request_path": str(verify_result.get("request_path", "") or "").strip(),
                "request_headers": dict(verify_result.get("request_headers") or {}) if isinstance(verify_result.get("request_headers"), dict) else {},
                "request_body": str(verify_result.get("request_body", "") or "").replace("\r\n", "\n").replace("\r", "\n")[:2600],
                "request_packet": str(verify_result.get("request_packet", "") or "").replace("\r\n", "\n").replace("\r", "\n")[:2600],
                "request_template_mode": str(verify_result.get("request_template_mode", "") or "").strip(),
                "request_template_content_type": str(verify_result.get("request_template_content_type", "") or "").strip(),
                "request_template_params": (
                    list(verify_result.get("request_template_params", []) or [])[:8]
                    if isinstance(verify_result.get("request_template_params"), (list, tuple))
                    else []
                ),
                "request_template_summary": str(verify_result.get("request_template_summary", "") or "").strip(),
                "verification_step": str(verify_result.get("verification_step", "") or "").strip(),
                "evidence_snippet": str(verify_result.get("evidence_snippet", "") or "").strip(),
                "http_status": int(verify_result.get("http_status", 0) or 0),
                "response_hash_diff": str(verify_result.get("response_hash_diff", "") or "").strip(),
                "proof_family": str(verify_result.get("proof_family", "") or "").strip(),
                "proof_type": str(verify_result.get("proof_type", "") or "").strip(),
                "unauth_access_hit": bool(verify_result.get("unauth_access_hit")),
                "unauth_access_type": str(verify_result.get("unauth_access_type", "") or "").strip(),
                "unauth_access_reason": str(verify_result.get("unauth_access_reason", "") or "").strip(),
                "unauth_probe_summary": str(verify_result.get("unauth_probe_summary", "") or "").strip(),
                "unauth_negative_type": str(verify_result.get("unauth_negative_type", "") or "").strip(),
                "proof_signals": (
                    list(verify_result.get("proof_signals", []) or [])[:8]
                    if isinstance(verify_result.get("proof_signals"), (list, tuple))
                    else []
                ),
                "proof_summary": str(verify_result.get("proof_summary", "") or "").strip(),
                "api_doc_summary": dict(verify_result.get("api_doc_summary") or {}) if isinstance(verify_result.get("api_doc_summary"), dict) else {},
                "api_surface_summary": dict(verify_result.get("api_surface_summary") or {}) if isinstance(verify_result.get("api_surface_summary"), dict) else {},
                "browser_surface_summary": dict(verify_result.get("browser_surface_summary") or {}) if isinstance(verify_result.get("browser_surface_summary"), dict) else {},
                "runtime_api_calls": list(verify_result.get("runtime_api_calls", []) or [])[:16],
                "dom_form_summary": list(verify_result.get("dom_form_summary", []) or [])[:8],
                "task_ai_pen_graph_summary": dict(verify_result.get("task_ai_pen_graph_summary") or {}) if isinstance(verify_result.get("task_ai_pen_graph_summary"), dict) else {},
                "task_ai_pen_graph_context": dict(verify_result.get("task_ai_pen_graph_context") or {}) if isinstance(verify_result.get("task_ai_pen_graph_context"), dict) else {},
                "login_surface_summary": dict(verify_result.get("login_surface_summary") or {}) if isinstance(verify_result.get("login_surface_summary"), dict) else {},
                "high_value_summary": dict(candidate.get("high_value_summary") or {}) if isinstance(candidate.get("high_value_summary"), dict) else {},
                "high_value_family": str(candidate.get("high_value_family", "") or "").strip(),
                "high_value_family_rank": int(candidate.get("high_value_family_rank", 0) or 0),
                "high_value_keywords": list(candidate.get("high_value_keywords", []) or [])[:8],
                "session_summary": dict(verify_result.get("session_summary") or {}) if isinstance(verify_result.get("session_summary"), dict) else {},
                "weak_password_login_proof": bool(verify_result.get("weak_password_login_proof")),
                "session_auth_hit": bool(verify_result.get("session_auth_hit")),
                "session_auth_url": str(verify_result.get("session_auth_url", "") or "").strip(),
                "session_auth_reason": str(verify_result.get("session_auth_reason", "") or "").strip(),
                "logout_effective": bool(verify_result.get("logout_effective")),
                "logout_url": str(verify_result.get("logout_url", "") or "").strip(),
                "logout_reason": str(verify_result.get("logout_reason", "") or "").strip(),
                "tool_trace": str(verify_result.get("tool_trace", "") or "").strip(),
                "agent_trace": list(verify_result.get("agent_trace", []) or [])[:16],
                "tool_calls": list(verify_result.get("tool_calls", []) or [])[:16],
                "tool_results": list(verify_result.get("tool_results", []) or [])[:16],
                "stop_reason": str(verify_result.get("stop_reason", "") or "").strip(),
                "budget_used": dict(verify_result.get("budget_used") or {}) if isinstance(verify_result.get("budget_used"), dict) else {},
                "runtime_version": str(verify_result.get("runtime_version", "") or "").strip(),
                "tool_plan_source": str(verify_result.get("tool_plan_source", "") or "").strip(),
                "external_tool_runs": list(verify_result.get("external_tool_runs", []) or [])[:3],
                "external_tool_hit": bool(verify_result.get("external_tool_hit")),
                "ai_plan_tool_plan": list(verify_result.get("ai_plan_tool_plan", []) or candidate.get("history_tool_plan", []) or [])[:8],
                "knowledge_hit_product_labels": list(item.get("knowledge_hit_product_labels", []) or []),
                "knowledge_hit_vuln_types": list(item.get("knowledge_hit_vuln_types", []) or []),
                "knowledge_hit_entry_paths": list(item.get("knowledge_hit_entry_paths", []) or []),
                "knowledge_hit_verify_actions": list(item.get("knowledge_hit_verify_actions", []) or []),
                "knowledge_hit_record_refs": list(item.get("knowledge_hit_record_refs", []) or [])[:4],
                "model": "mcp-rule-lite" if bool(runtime_settings.get("mcp_enable", True)) else "rule-lite",
                "provider": "local-mcp" if bool(runtime_settings.get("mcp_enable", True)) else "local",
                "update_date": now_text,
            }

            try:
                collection.update_one({"_id": item["_id"]}, {"$set": update_fields})
                runner._sync_ai_pen_result_to_source(
                    source_collection=str(item.get("source_collection", "") or "").strip(),
                    source_id=str(item.get("source_id", "") or "").strip(),
                    decision=decision,
                    confidence=confidence,
                    status=status,
                    reason=str(verify_result.get("reason", "") or "").strip(),
                    verification_step=str(verify_result.get("verification_step", "") or "").strip(),
                    payload_type=str(verify_result.get("payload_type", "") or "").strip(),
                    update_date=now_text,
                )
                saved_count += 1
            except Exception as exc:
                logger.warning(
                    "retry ai pen result failed task_id:%s result_id:%s err:%s",
                    task_id,
                    str(item.get("_id") or ""),
                    exc,
                )
                error_count += 1

    return {
        "retry_count": retry_count,
        "saved_count": saved_count,
        "verified_count": verified_count,
        "likely_fp_count": likely_fp_count,
        "error_count": error_count,
    }


def _clear_source_ai_pen_fields(item: dict):
    source_collection = str(item.get("source_collection", "") or "").strip()
    source_id = _normalize_object_id(item.get("source_id"))
    if not source_collection or not source_id:
        return
    unset_fields = {
        "ai_pen_status": "",
        "ai_pen_decision": "",
        "ai_pen_confidence": "",
        "ai_pen_reason": "",
        "ai_pen_verification_step": "",
        "ai_pen_payload_type": "",
        "ai_pen_update_date": "",
    }
    try:
        utils.conn_db(source_collection).update_one({"_id": ObjectId(source_id)}, {"$unset": unset_fields})
    except Exception as exc:
        logger.warning(
            "clear source ai pen fields failed collection:%s source_id:%s err:%s",
            source_collection,
            source_id,
            exc,
        )


@ns.route("/")
class ARLAiPenTest(ARLResource):
    """AI 渗透测试结果查询"""

    parser = get_arl_parser(base_search_fields, location="args")

    @auth
    @ns.expect(parser)
    def get(self):
        args = self.parser.parse_args()
        return self.build_data(args=args, collection="ai_pen_test_result")


@ns.route("/retry/")
class RetryAiPenTest(ARLResource):
    """重试 AI 渗透验证（单条或批量）"""

    @auth
    @ns.expect(retry_fields)
    def post(self):
        args = self.parse_args(retry_fields)
        result_ids = list(args.get("result_ids") or [])
        single = str(args.get("result_id") or "").strip()
        if single:
            result_ids.append(single)

        normalized_ids = []
        seen = set()
        for item in result_ids:
            oid = _normalize_object_id(item)
            if not oid or oid in seen:
                continue
            seen.add(oid)
            normalized_ids.append(oid)

        if not normalized_ids:
            return utils.build_ret(ErrorMsg.Error, {"error": "请提供有效 result_id 或 result_ids"})

        docs = list(
            utils.conn_db("ai_pen_test_result").find({"_id": {"$in": [ObjectId(x) for x in normalized_ids]}})
        )
        if not docs:
            return utils.build_ret(ErrorMsg.Error, {"error": "未找到可重试的 AI 渗透结果"})

        stats = _retry_records(docs)
        stats["result_ids"] = normalized_ids
        return utils.build_ret(ErrorMsg.Success, stats)


@ns.route("/batch_run/")
class BatchRunAiPenTest(ARLResource):
    """按任务批量运行 AI 渗透测试"""

    @auth
    @ns.expect(batch_run_fields)
    def post(self):
        args = self.parse_args(batch_run_fields)
        task_ids = list(args.get("task_ids") or [])
        single = str(args.get("task_id") or "").strip()
        if single:
            task_ids.append(single)

        normalized_task_ids = []
        seen = set()
        for item in task_ids:
            tid = _normalize_object_id(item)
            if not tid or tid in seen:
                continue
            seen.add(tid)
            normalized_task_ids.append(tid)

        if not normalized_task_ids:
            return utils.build_ret(ErrorMsg.Error, {"error": "请提供有效 task_id 或 task_ids"})

        max_cases = 0
        try:
            max_cases = int(args.get("max_cases", 0) or 0)
        except Exception:
            max_cases = 0
        if max_cases < 0:
            max_cases = 0
        if max_cases > 300:
            max_cases = 300

        details = []
        success_count = 0
        error_count = 0
        for task_id in normalized_task_ids:
            before_count = utils.conn_db("ai_pen_test_result").count_documents({"task_id": task_id})
            try:
                runner = _build_runner(task_id)
                if max_cases > 0:
                    runner.options = dict(runner.options or {})
                    runner.options["ai_pen_test_max_cases"] = max_cases
                runner.run_ai_penetration_test()
                after_count = utils.conn_db("ai_pen_test_result").count_documents({"task_id": task_id})
                details.append(
                    {
                        "task_id": task_id,
                        "status": "ok",
                        "before_count": int(before_count),
                        "after_count": int(after_count),
                        "delta": int(after_count - before_count),
                    }
                )
                success_count += 1
            except Exception as exc:
                logger.warning("ai pen batch run failed task_id:%s err:%s", task_id, exc)
                details.append({"task_id": task_id, "status": "error", "error": str(exc)})
                error_count += 1

        return utils.build_ret(
            ErrorMsg.Success,
            {
                "task_ids": normalized_task_ids,
                "total": len(normalized_task_ids),
                "success": success_count,
                "error": error_count,
                "max_cases": max_cases,
                "details": details,
            },
        )


@ns.route("/delete/")
class DeleteAiPenTest(ARLResource):
    """删除 AI 渗透结果"""

    @auth
    @ns.expect(delete_fields)
    def post(self):
        args = self.parse_args(delete_fields)
        task_id = _normalize_object_id(args.get("task_id"))
        result_ids = []
        for item in list(args.get("result_ids") or []):
            oid = _normalize_object_id(item)
            if oid:
                result_ids.append(oid)

        query = {}
        if result_ids:
            query["_id"] = {"$in": [ObjectId(x) for x in list({x for x in result_ids})]}
        elif task_id:
            query["task_id"] = task_id
        else:
            return utils.build_ret(ErrorMsg.Error, {"error": "请提供 result_ids 或 task_id"})

        docs = list(utils.conn_db("ai_pen_test_result").find(query, {"source_collection": 1, "source_id": 1}))
        for item in docs:
            _clear_source_ai_pen_fields(item)

        delete_ret = utils.conn_db("ai_pen_test_result").delete_many(query)
        return utils.build_ret(
            ErrorMsg.Success,
            {
                "delete_cnt": int(delete_ret.deleted_count or 0),
                "task_id": task_id or "",
                "result_ids": result_ids,
            },
        )


@ns.route("/stats/")
class StatsAiPenTest(ARLResource):
    """AI 渗透结果统计"""

    parser = get_arl_parser(stats_search_fields, location="args")

    @auth
    @ns.expect(parser)
    def get(self):
        args = self.parser.parse_args()
        task_id = _normalize_object_id(args.get("task_id"))
        query = {"task_id": task_id} if task_id else {}

        collection = utils.conn_db("ai_pen_test_result")
        total = int(collection.count_documents(query))

        def _agg_group(field_name):
            pipeline = []
            if query:
                pipeline.append({"$match": query})
            pipeline.extend(
                [
                    {"$group": {"_id": {"$ifNull": ["${}".format(field_name), ""]}, "count": {"$sum": 1}}},
                    {"$sort": {"count": -1}},
                ]
            )
            rows = list(collection.aggregate(pipeline))
            return [{"name": str(item.get("_id") or ""), "count": int(item.get("count") or 0)} for item in rows]

        decision = _agg_group("decision")
        status = _agg_group("status")
        source_collection = _agg_group("source_collection")
        risk_type = _agg_group("risk_type")
        verification_step = _agg_group("verification_step")
        high_value_family = _agg_group("high_value_family")
        payload_variant = _agg_group("payload_variant")
        proof_type = _agg_group("proof_type")
        unauth_access_type = _agg_group("unauth_access_type")
        unauth_negative_type = _agg_group("unauth_negative_type")
        request_template_mode = _agg_group("request_template_mode")
        tool_plan_source = _agg_group("tool_plan_source")
        stop_reason = _agg_group("stop_reason")
        metric_rows = list(
            collection.find(
                query,
                {
                    "decision": 1,
                    "status": 1,
                    "risk_type": 1,
                    "risk_name": 1,
                    "payload_type": 1,
                    "payload_variant": 1,
                    "payload_expected_signal": 1,
                    "payload_proof_candidates": 1,
                    "verification_step": 1,
                    "high_value_family": 1,
                    "high_value_family_rank": 1,
                    "request_template_mode": 1,
                    "request_template_content_type": 1,
                    "request_template_params": 1,
                    "request_template_summary": 1,
                    "proof_family": 1,
                    "proof_type": 1,
                    "unauth_access_hit": 1,
                    "unauth_access_type": 1,
                    "unauth_access_reason": 1,
                    "unauth_probe_summary": 1,
                    "unauth_negative_type": 1,
                    "proof_signals": 1,
                    "proof_summary": 1,
                    "target": 1,
                    "vuln_url": 1,
                    "reason": 1,
                    "confidence": 1,
                    "http_status": 1,
                    "session_auth_hit": 1,
                    "weak_password_login_proof": 1,
                    "external_tool_hit": 1,
                    "agent_trace": 1,
                    "tool_calls": 1,
                    "budget_used": 1,
                    "external_tool_runs": 1,
                },
            )
        )
        for item in metric_rows:
            if not isinstance(item, dict):
                continue
            if not str(item.get("proof_family", "") or "").strip():
                item["proof_family"] = _classify_ai_pen_proof_family(
                    item.get("proof_type"),
                    payload_type=item.get("payload_type"),
                )
            if not str(item.get("unauth_access_type", "") or "").strip() and str(item.get("proof_family", "") or "").strip() == "unauth_access":
                item["unauth_access_type"] = str(item.get("proof_type", "") or "").strip()
        quant_metrics = _build_ai_pen_quant_metrics(metric_rows, total=total)
        capability_benchmarks = {
            "risk_type": _build_ai_pen_group_benchmarks(metric_rows, "risk_type"),
            "payload_type": _build_ai_pen_group_benchmarks(metric_rows, "payload_type"),
            "payload_variant": _build_ai_pen_group_benchmarks(metric_rows, "payload_variant"),
            "proof_family": _build_ai_pen_group_benchmarks(metric_rows, "proof_family"),
            "proof_type": _build_ai_pen_group_benchmarks(metric_rows, "proof_type"),
            "unauth_access_type": _build_ai_pen_group_benchmarks(metric_rows, "unauth_access_type"),
            "unauth_negative_type": _build_ai_pen_group_benchmarks(metric_rows, "unauth_negative_type"),
            "high_value_family": _build_ai_pen_group_benchmarks(metric_rows, "high_value_family"),
            "verification_step": _build_ai_pen_group_benchmarks(metric_rows, "verification_step"),
            "request_template_mode": _build_ai_pen_group_benchmarks(metric_rows, "request_template_mode"),
        }
        phase_f_readiness = _build_ai_pen_phase_f_readiness(metric_rows)
        engineer_focus_queue = _build_ai_pen_engineer_focus_queue(phase_f_readiness)
        engineer_focus_entries = _build_ai_pen_engineer_focus_entries(metric_rows)
        unauth_negative_summary = _build_ai_pen_unauth_negative_summary(metric_rows)
        unauth_access_overview = _build_ai_pen_unauth_access_overview(metric_rows)

        return utils.build_ret(
            ErrorMsg.Success,
            {
                "task_id": task_id or "",
                "total": total,
                "decision": decision,
                "status": status,
                "source_collection": source_collection,
                "risk_type": risk_type,
                "verification_step": verification_step,
                "high_value_family": high_value_family,
                "payload_variant": payload_variant,
                "proof_family": _build_ai_pen_group_counts(metric_rows, "proof_family"),
                "proof_type": proof_type,
                "unauth_access_type": unauth_access_type,
                "unauth_negative_type": unauth_negative_type,
                "request_template_mode": request_template_mode,
                "tool_plan_source": tool_plan_source,
                "stop_reason": stop_reason,
                "quant_metrics": quant_metrics,
                "capability_benchmarks": capability_benchmarks,
                "phase_f_readiness": phase_f_readiness,
                "engineer_focus_queue": engineer_focus_queue,
                "engineer_focus_entries": engineer_focus_entries,
                "unauth_negative_summary": unauth_negative_summary,
                "unauth_access_overview": unauth_access_overview,
            },
        )
