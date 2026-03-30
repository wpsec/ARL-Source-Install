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
    "reason": fields.String(description="验证说明"),
}
base_search_fields.update(base_query_fields)

stats_search_fields = {
    "task_id": fields.String(description="任务ID"),
}
stats_search_fields.update(base_query_fields)

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


def _build_candidate_from_result(item: dict):
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
            candidate = _build_candidate_from_result(item)
            ai_plan = {
                "payload_type": str(item.get("payload_type", "") or "").strip(),
                "payload": str(item.get("payload", "") or "").strip(),
                "tool_plan": list(item.get("ai_plan_tool_plan", []) or []),
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
                "payload": str(verify_result.get("payload", "") or "").strip(),
                "request_method": str(verify_result.get("request_method", "") or "").strip(),
                "request_url": str(verify_result.get("request_url", "") or "").strip(),
                "request_path": str(verify_result.get("request_path", "") or "").strip(),
                "request_headers": dict(verify_result.get("request_headers") or {}) if isinstance(verify_result.get("request_headers"), dict) else {},
                "request_body": str(verify_result.get("request_body", "") or "").replace("\r\n", "\n").replace("\r", "\n")[:2600],
                "request_packet": str(verify_result.get("request_packet", "") or "").replace("\r\n", "\n").replace("\r", "\n")[:2600],
                "verification_step": str(verify_result.get("verification_step", "") or "").strip(),
                "evidence_snippet": str(verify_result.get("evidence_snippet", "") or "").strip(),
                "http_status": int(verify_result.get("http_status", 0) or 0),
                "response_hash_diff": str(verify_result.get("response_hash_diff", "") or "").strip(),
                "api_doc_summary": dict(verify_result.get("api_doc_summary") or {}) if isinstance(verify_result.get("api_doc_summary"), dict) else {},
                "api_surface_summary": dict(verify_result.get("api_surface_summary") or {}) if isinstance(verify_result.get("api_surface_summary"), dict) else {},
                "browser_surface_summary": dict(verify_result.get("browser_surface_summary") or {}) if isinstance(verify_result.get("browser_surface_summary"), dict) else {},
                "runtime_api_calls": list(verify_result.get("runtime_api_calls", []) or [])[:16],
                "dom_form_summary": list(verify_result.get("dom_form_summary", []) or [])[:8],
                "task_ai_pen_graph_summary": dict(verify_result.get("task_ai_pen_graph_summary") or {}) if isinstance(verify_result.get("task_ai_pen_graph_summary"), dict) else {},
                "task_ai_pen_graph_context": dict(verify_result.get("task_ai_pen_graph_context") or {}) if isinstance(verify_result.get("task_ai_pen_graph_context"), dict) else {},
                "login_surface_summary": dict(verify_result.get("login_surface_summary") or {}) if isinstance(verify_result.get("login_surface_summary"), dict) else {},
                "tool_trace": str(verify_result.get("tool_trace", "") or "").strip(),
                "agent_trace": list(verify_result.get("agent_trace", []) or [])[:16],
                "tool_calls": list(verify_result.get("tool_calls", []) or [])[:16],
                "tool_results": list(verify_result.get("tool_results", []) or [])[:16],
                "stop_reason": str(verify_result.get("stop_reason", "") or "").strip(),
                "budget_used": dict(verify_result.get("budget_used") or {}) if isinstance(verify_result.get("budget_used"), dict) else {},
                "runtime_version": str(verify_result.get("runtime_version", "") or "").strip(),
                "external_tool_runs": list(verify_result.get("external_tool_runs", []) or [])[:3],
                "external_tool_hit": bool(verify_result.get("external_tool_hit")),
                "ai_plan_tool_plan": list(item.get("ai_plan_tool_plan", []) or [])[:8],
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
            },
        )
