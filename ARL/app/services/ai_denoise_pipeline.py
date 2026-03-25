"""
扫描后 AI 去噪异步流水线

设计目标：
- AI 去噪支持按阶段增量异步执行，不阻塞主扫描链路
- 结果统一落库，前端详情仅展示落库内容，不再触发实时 AI 调用
"""
from datetime import datetime
from bson import ObjectId

from app import utils

logger = utils.get_logger()

AI_DENOISE_RESULT_COLLECTION = "ai_denoise_result"
AI_DENOISE_MODULE_COLLECTION_MAP = (
    ("site", "site"),
    ("fileleak", "fileleak"),
    ("cert", "cert"),
    ("url", "url"),
    ("vuln", "vuln"),
    ("nuclei_result", "nuclei_result"),
)
AI_DENOISE_BATCH_SIZE = 2
AI_DENOISE_MODULE_ID_SET = tuple(module_id for module_id, _ in AI_DENOISE_MODULE_COLLECTION_MAP)
AI_DENOISE_MODULE_COLLECTION_DICT = dict(AI_DENOISE_MODULE_COLLECTION_MAP)

_AI_DENOISE_RESULT_INDEX_READY = False


def _safe_list(value):
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, str):
        text = str(value or "").strip()
        return [text] if text else []
    return []


def normalize_ai_denoise_modules(raw_modules, default_all=True):
    if isinstance(raw_modules, str):
        raw_modules = [raw_modules]
    elif isinstance(raw_modules, tuple):
        raw_modules = list(raw_modules)
    elif not isinstance(raw_modules, list):
        raw_modules = []

    normalized = []
    seen = set()
    for item in raw_modules:
        module_id = str(item or "").strip()
        if not module_id or module_id not in AI_DENOISE_MODULE_COLLECTION_DICT:
            continue
        if module_id in seen:
            continue
        seen.add(module_id)
        normalized.append(module_id)

    if default_all and not normalized:
        normalized = list(AI_DENOISE_MODULE_ID_SET)
    return normalized


def _ensure_ai_denoise_result_indexes():
    global _AI_DENOISE_RESULT_INDEX_READY
    if _AI_DENOISE_RESULT_INDEX_READY:
        return

    coll = utils.conn_db(AI_DENOISE_RESULT_COLLECTION)
    try:
        coll.create_index(
            [("task_id", 1), ("module_id", 1), ("row_key", 1)],
            unique=True,
            background=True,
            name="uniq_task_module_row",
        )
    except Exception as exc:
        logger.warning("create ai_denoise_result uniq index failed: %s", exc)
    try:
        coll.create_index(
            [("task_id", 1), ("module_id", 1), ("updated_at", -1)],
            background=True,
            name="task_module_updated_at",
        )
    except Exception as exc:
        logger.warning("create ai_denoise_result updated_at index failed: %s", exc)
    _AI_DENOISE_RESULT_INDEX_READY = True


def _normalize_object_id_text(value):
    if isinstance(value, ObjectId):
        return str(value)
    if isinstance(value, dict):
        text = str(value.get("$oid") or value.get("oid") or value.get("_id") or "").strip()
        return text
    if isinstance(value, (str, int, float)):
        return str(value).strip()
    return ""


def _build_module_query(module_id, task_id):
    query = {"task_id": task_id}
    # 风险模块与前端默认查询保持一致：afrog 结果统一在 PoC 风险模块展示，避免重复分析。
    if module_id == "vuln":
        query["plg_type"] = {"$ne": "afrog"}
    return query


def _build_payload_item(api_console_module, raw_item, task_id):
    item = dict(raw_item or {})
    row_key = api_console_module._extract_row_key(item, 0)
    item["_row_key"] = row_key
    item["task_id"] = str(task_id or "").strip()
    return item, row_key


def _save_ai_denoise_result(task_id, module_id, row_key, data_id, result_item):
    now_text = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    safe_row_key = str(row_key or "").strip()
    if not safe_row_key:
        return False

    source = str(result_item.get("source") or "disabled").strip().lower()
    if source not in ("ai", "rule", "disabled"):
        source = "disabled"

    doc = {
        "task_id": str(task_id or "").strip(),
        "module_id": str(module_id or "").strip(),
        "row_key": safe_row_key,
        "data_id": str(data_id or "").strip(),
        "result_level": str(result_item.get("result_level") or "disabled"),
        "risk_level": str(result_item.get("risk_level") or "-"),
        "trust": str(result_item.get("trust") or "-"),
        "display_text": str(result_item.get("display_text") or "未分析"),
        "summary": str(result_item.get("summary") or ""),
        "evidence": _safe_list(result_item.get("evidence")),
        "suggestions": _safe_list(result_item.get("suggestions")),
        "source": source,
        "prompt_id": str(result_item.get("prompt_id") or ""),
        "prompt_name": str(result_item.get("prompt_name") or ""),
        "note": str(result_item.get("note") or ""),
        "cert_expire_at": str(result_item.get("cert_expire_at") or ""),
        "cert_expire_days": result_item.get("cert_expire_days"),
        "analyzed_at": str(result_item.get("analyzed_at") or now_text),
        "finger_result": _safe_list(result_item.get("finger_result")),
        "dialogue_records": _safe_list(result_item.get("dialogue_records")),
        "updated_at": now_text,
    }

    utils.conn_db(AI_DENOISE_RESULT_COLLECTION).update_one(
        {
            "task_id": doc["task_id"],
            "module_id": doc["module_id"],
            "row_key": doc["row_key"],
        },
        {
            "$set": doc,
            "$setOnInsert": {
                "created_at": now_text,
            },
        },
        upsert=True,
    )
    return True


def _accumulate_batch_results(module_id, task_id_text, module_stat, summary, analyzed_items, batch_row_map):
    for result_item in list(analyzed_items or []):
        row_key_text = str(result_item.get("row_key") or "").strip()
        if not row_key_text:
            continue
        raw_row = batch_row_map.get(row_key_text) or {}
        data_id = _normalize_object_id_text(raw_row.get("_id"))
        saved = _save_ai_denoise_result(
            task_id=task_id_text,
            module_id=module_id,
            row_key=row_key_text,
            data_id=data_id,
            result_item=result_item,
        )
        if saved:
            module_stat["saved"] += 1
            summary["saved_items"] += 1
        source_text = str(result_item.get("source") or "disabled").strip().lower()
        if source_text not in ("ai", "rule", "disabled"):
            source_text = "disabled"
        module_stat[source_text] += 1
        summary["source_stat"][source_text] += 1


def _run_module_ai_denoise(api_console_module, ai_config, task_id_text, module_id, collection_name, summary):
    result_coll = utils.conn_db(AI_DENOISE_RESULT_COLLECTION)
    module_query = _build_module_query(module_id, task_id_text)
    result_coll.delete_many(
        {
            "task_id": task_id_text,
            "module_id": module_id,
        }
    )

    module_stat = {
        "collection": collection_name,
        "total": 0,
        "saved": 0,
        "ai": 0,
        "rule": 0,
        "disabled": 0,
    }

    cursor = utils.conn_db(collection_name).find(module_query)
    batch_items = []
    batch_row_map = {}
    for raw_item in cursor:
        payload_item, row_key = _build_payload_item(api_console_module, raw_item, task_id_text)
        batch_items.append(payload_item)
        batch_row_map[row_key] = raw_item
        module_stat["total"] += 1
        summary["total_items"] += 1

        if len(batch_items) < AI_DENOISE_BATCH_SIZE:
            continue

        analyzed = api_console_module._analyze_ai_denoise_batch(
            ai_config=ai_config,
            module_id=module_id,
            items=batch_items,
            prefer_ai=True,
            persisted_only=False,
        )
        _accumulate_batch_results(
            module_id=module_id,
            task_id_text=task_id_text,
            module_stat=module_stat,
            summary=summary,
            analyzed_items=analyzed.get("items"),
            batch_row_map=batch_row_map,
        )
        batch_items = []
        batch_row_map = {}

    if batch_items:
        analyzed = api_console_module._analyze_ai_denoise_batch(
            ai_config=ai_config,
            module_id=module_id,
            items=batch_items,
            prefer_ai=True,
            persisted_only=False,
        )
        _accumulate_batch_results(
            module_id=module_id,
            task_id_text=task_id_text,
            module_stat=module_stat,
            summary=summary,
            analyzed_items=analyzed.get("items"),
            batch_row_map=batch_row_map,
        )

    return module_stat


def run_task_ai_denoise_pipeline(task_id, trigger="task_done", force=False, modules=None):
    """
    执行任务级 AI 去噪流水线（异步，支持按模块增量执行）。
    """
    from app.routes import api_console as api_console_module

    task_id_text = str(task_id or "").strip()
    if not task_id_text:
        return {"status": "skipped", "reason": "empty_task_id"}

    query_id = ObjectId(task_id_text) if ObjectId.is_valid(task_id_text) else task_id_text
    task_doc = utils.conn_db("task").find_one(
        {"_id": query_id},
        {
            "_id": 1,
            "status": 1,
            "name": 1,
            "type": 1,
            "options.ai_denoise": 1,
            "ai_denoise_status": 1,
        },
    )
    if not isinstance(task_doc, dict):
        return {"status": "skipped", "reason": "task_not_found", "task_id": task_id_text}

    options = task_doc.get("options") if isinstance(task_doc.get("options"), dict) else {}
    if not force and not bool(options.get("ai_denoise", True)):
        now_text = utils.curr_date()
        utils.conn_db("task").update_one(
            {"_id": query_id},
            {
                "$set": {
                    "ai_denoise_status": {
                        "status": "skipped",
                        "trigger": str(trigger or "task_done"),
                        "updated_at": now_text,
                        "message": "任务未开启 AI 去噪选项。",
                        "requested_modules": normalize_ai_denoise_modules(modules, default_all=False),
                        "pending_modules": [],
                    }
                }
            },
        )
        return {"status": "skipped", "reason": "option_disabled", "task_id": task_id_text}

    requested_modules = normalize_ai_denoise_modules(modules, default_all=True)

    _ensure_ai_denoise_result_indexes()
    started_at = utils.curr_date()
    utils.conn_db("task").update_one(
        {"_id": query_id},
        {
            "$set": {
                "ai_denoise_status": {
                    "status": "running",
                    "trigger": str(trigger or "task_done"),
                    "started_at": started_at,
                    "updated_at": started_at,
                    "requested_modules": requested_modules,
                    "pending_modules": [],
                }
            }
        },
    )

    try:
        config_path = api_console_module._resolve_config_path()
        config_obj = api_console_module._load_config_from_file(config_path)
        ai_config = api_console_module._extract_ai_config(config_obj)

        summary = {
            "task_id": task_id_text,
            "status": "done",
            "trigger": str(trigger or "task_done"),
            "requested_modules": requested_modules,
            "started_at": started_at,
            "ended_at": "",
            "modules": {},
            "total_items": 0,
            "saved_items": 0,
            "source_stat": {"ai": 0, "rule": 0, "disabled": 0},
            "error_modules": [],
            "pending_modules": [],
        }

        for module_id in requested_modules:
            collection_name = AI_DENOISE_MODULE_COLLECTION_DICT.get(module_id)
            if not collection_name:
                continue
            try:
                module_stat = _run_module_ai_denoise(
                    api_console_module=api_console_module,
                    ai_config=ai_config,
                    task_id_text=task_id_text,
                    module_id=module_id,
                    collection_name=collection_name,
                    summary=summary,
                )
            except Exception as module_exc:
                module_error = "module:{} error:{}".format(module_id, module_exc)
                logger.warning("ai denoise module failed task_id:%s %s", task_id_text, module_error)
                summary["error_modules"].append(module_error)
                module_stat = {
                    "collection": collection_name,
                    "total": 0,
                    "saved": 0,
                    "ai": 0,
                    "rule": 0,
                    "disabled": 0,
                }

            summary["modules"][module_id] = module_stat

        ended_at = utils.curr_date()
        summary["ended_at"] = ended_at
        if summary["error_modules"]:
            summary["status"] = "done_with_error"

        latest_doc = utils.conn_db("task").find_one(
            {"_id": query_id},
            {"ai_denoise_status.pending_modules": 1},
        )
        latest_status = latest_doc.get("ai_denoise_status") if isinstance(latest_doc, dict) else {}
        latest_status = latest_status if isinstance(latest_status, dict) else {}
        pending_modules = normalize_ai_denoise_modules(
            latest_status.get("pending_modules"),
            default_all=False,
        )
        summary["pending_modules"] = pending_modules

        utils.conn_db("task").update_one(
            {"_id": query_id},
            {
                "$set": {
                    "ai_denoise_status": {
                        "status": summary["status"],
                        "trigger": summary["trigger"],
                        "started_at": summary["started_at"],
                        "ended_at": summary["ended_at"],
                        "updated_at": summary["ended_at"],
                        "requested_modules": summary["requested_modules"],
                        "pending_modules": pending_modules,
                        "total_items": summary["total_items"],
                        "saved_items": summary["saved_items"],
                        "source_stat": summary["source_stat"],
                        "module_stat": summary["modules"],
                        "error_modules": summary["error_modules"],
                    }
                }
            },
        )
        logger.info(
            "ai denoise pipeline finished task_id:%s trigger:%s modules:%s status:%s total:%s saved:%s ai:%s rule:%s disabled:%s pending:%s",
            task_id_text,
            summary["trigger"],
            ",".join(requested_modules),
            summary["status"],
            summary["total_items"],
            summary["saved_items"],
            summary["source_stat"]["ai"],
            summary["source_stat"]["rule"],
            summary["source_stat"]["disabled"],
            ",".join(pending_modules),
        )
        return summary
    except Exception as exc:
        ended_at = utils.curr_date()
        utils.conn_db("task").update_one(
            {"_id": query_id},
            {
                "$set": {
                    "ai_denoise_status": {
                        "status": "error",
                        "trigger": str(trigger or "task_done"),
                        "started_at": started_at,
                        "ended_at": ended_at,
                        "updated_at": ended_at,
                        "requested_modules": requested_modules,
                        "pending_modules": [],
                        "message": str(exc),
                    }
                }
            },
        )
        logger.exception("ai denoise pipeline failed task_id:%s err:%s", task_id_text, exc)
        raise
