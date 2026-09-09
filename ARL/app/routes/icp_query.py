"""ICP 查询 API。"""

from functools import wraps

from flask import request
from flask_restx import Namespace, Resource

from app import celerytask, utils
from app.config import Config
from app.services import icp_query
from app.utils import auth

ns = Namespace("icp", description="ICP备案查询")


def _enabled():
    return bool(getattr(Config, "ICP_QUERY_ENABLE", True))


def _success(data):
    return utils.build_ret({"code": 200, "message": "success"}, data)


def _failure(message, code=400, data=None):
    return {"code": code, "message": str(message), "data": data or {}}


def _ensure_enabled():
    if not _enabled():
        return _failure("ICP 查询功能当前已关闭", 503)
    return None


def _api_error_guard(operation, fallback):
    """将存储或序列化异常收敛为统一响应，避免默认 500 泄露内部细节。"""
    def decorator(func):
        @wraps(func)
        def wrapped(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except icp_query.IcpQueryError as exc:
                return _failure(str(exc), 400)
            except Exception as exc:
                icp_query.logger.error(
                    "%s failed: %s", operation, icp_query._redact_text(exc)
                )
                return _failure(fallback, 500)
        return wrapped
    return decorator


def _query_type(value):
    text = str(value or "").strip().lower()
    if text not in icp_query.ICP_QUERY_TYPES:
        raise ValueError("不支持的 ICP 查询类型")
    return text


def _task_or_404(task_id):
    task = icp_query.get_task(task_id)
    if not task:
        return None, _failure("ICP 任务不存在", 404)
    return task, None


def _batch_task_or_404(task_id):
    task, error = _task_or_404(task_id)
    if error:
        return None, error
    if task.get("task_kind") != "batch":
        return None, _failure("批量任务不存在", 404)
    return task, None


def _single_task_or_404(task_id):
    task, error = _task_or_404(task_id)
    if error:
        return None, error
    if task.get("task_kind") != "single":
        return None, _failure("单次查询任务不存在", 404)
    return task, None


@ns.route("/meta")
class IcpMeta(Resource):
    @auth
    def get(self):
        return _success({
            "enabled": _enabled(),
            "types": [
                {"value": key, **value}
                for key, value in icp_query.ICP_QUERY_TYPES.items()
            ],
            "max_items": icp_query._config_int("ICP_QUERY_MAX_ITEMS", 200, 1, 10000),
            "page_size": icp_query._config_int("ICP_QUERY_PAGE_SIZE", 26, 1, 26),
        })


@ns.route("/query")
class IcpQueryCreate(Resource):
    @auth
    def post(self):
        disabled = _ensure_enabled()
        if disabled:
            return disabled
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return _failure("请求体必须是 JSON 对象", 400)
        try:
            query_type = _query_type(payload.get("type"))
            keyword = payload.get("keyword")
            task = icp_query.create_single_task(
                query_type,
                keyword,
                payload.get("page", 1),
                payload.get("page_size", getattr(Config, "ICP_QUERY_PAGE_SIZE", 26)),
            )
            icp_query.dispatch_task(task["task_id"])
            task = icp_query.get_task(task["task_id"])
            return _success(icp_query._task_status_payload(task))
        except (ValueError, icp_query.IcpQueryError) as exc:
            return _failure(str(exc), 400)
        except Exception as exc:
            icp_query.logger.error("create ICP query task failed: %s", icp_query._redact_text(exc))
            return _failure("ICP 查询服务暂时不可用", 500)


@ns.route("/query/<string:task_id>")
class IcpQueryStatus(Resource):
    @auth
    @_api_error_guard("get ICP query task", "ICP 任务状态暂时不可用，请稍后重试")
    def get(self, task_id):
        disabled = _ensure_enabled()
        if disabled:
            return disabled
        task, error = _single_task_or_404(task_id)
        if error:
            return error
        return _success(icp_query._task_status_payload(task))


@ns.route("/query/<string:task_id>/results")
class IcpQueryResults(Resource):
    @auth
    @_api_error_guard("get ICP query results", "ICP 查询结果暂时不可用，请稍后重试")
    def get(self, task_id):
        disabled = _ensure_enabled()
        if disabled:
            return disabled
        task, error = _single_task_or_404(task_id)
        if error:
            return error
        item_id = str(request.args.get("item_id") or "").strip()
        item = next((item for item in task.get("items", []) if item_id and item.get("item_id") == item_id), None)
        if item_id and item is None:
            return _failure("ICP 任务项不存在", 404)
        if not item_id and task.get("items"):
            item = task["items"][0]
        history_id = str((item or {}).get("history_id") or "").strip()
        if not history_id:
            return _success({"items": [], "total": 0, "page": 1, "size": 50, "task": icp_query._task_status_payload(task)})
        result = icp_query.get_history_results(
            history_id,
            request.args.get("page", 1),
            request.args.get("size", 50),
        )
        result["task"] = icp_query._task_status_payload(task)
        result["history"] = icp_query._serialize(icp_query.get_history(history_id))
        return _success(result)


@ns.route("/query/<string:task_id>/cancel")
class IcpQueryCancel(Resource):
    @auth
    @_api_error_guard("cancel ICP query task", "ICP 任务取消失败，请稍后重试")
    def post(self, task_id):
        disabled = _ensure_enabled()
        if disabled:
            return disabled
        task, error = _single_task_or_404(task_id)
        if error:
            return error
        cancelled = icp_query.request_cancel(task_id)
        celery_id = str((task or {}).get("celery_id") or "").strip()
        if celery_id:
            try:
                celerytask.celery.control.revoke(celery_id, terminate=False)
            except Exception as exc:
                icp_query.logger.warning("revoke ICP query failed: %s", icp_query._redact_text(exc))
        return _success(icp_query._task_status_payload(cancelled))


@ns.route("/batch")
class IcpBatchCreate(Resource):
    @auth
    def post(self):
        disabled = _ensure_enabled()
        if disabled:
            return disabled
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return _failure("请求体必须是 JSON 对象", 400)
        try:
            query_type = _query_type(payload.get("type"))
            keywords = payload.get("keywords")
            if isinstance(keywords, str):
                keywords = keywords.splitlines()
            if not isinstance(keywords, list):
                raise icp_query.IcpQueryError("批量关键词必须是数组或多行文本", category="validation_error")
            task = icp_query.create_batch_task(query_type, keywords)
            icp_query.dispatch_task(task["task_id"])
            return _success(icp_query._task_status_payload(icp_query.get_task(task["task_id"])))
        except (ValueError, icp_query.IcpQueryError) as exc:
            return _failure(str(exc), 400)
        except Exception as exc:
            icp_query.logger.error("create ICP batch task failed: %s", icp_query._redact_text(exc))
            return _failure("ICP 查询服务暂时不可用", 500)

    @auth
    @_api_error_guard("list ICP batch tasks", "ICP 批量任务列表暂时不可用，请稍后重试")
    def get(self):
        disabled = _ensure_enabled()
        if disabled:
            return disabled
        return _success(icp_query.list_tasks(
            request.args.get("page", 1),
            request.args.get("size", 20),
            request.args.get("status", ""),
        ))


@ns.route("/batch/<string:task_id>")
class IcpBatchDetail(Resource):
    @auth
    @_api_error_guard("get ICP batch task", "ICP 批量任务状态暂时不可用，请稍后重试")
    def get(self, task_id):
        disabled = _ensure_enabled()
        if disabled:
            return disabled
        task, error = _batch_task_or_404(task_id)
        if error:
            return error
        return _success(icp_query._task_status_payload(task))

    @auth
    def delete(self, task_id):
        disabled = _ensure_enabled()
        if disabled:
            return disabled
        try:
            task, error = _batch_task_or_404(task_id)
            if error:
                return error
            icp_query.delete_task(task_id)
            return _success({"task_id": task_id})
        except icp_query.IcpQueryError as exc:
            return _failure(str(exc), 409)
        except Exception as exc:
            icp_query.logger.error("delete ICP batch task failed: %s", icp_query._redact_text(exc))
            return _failure("ICP 任务删除失败，请稍后重试", 500)


@ns.route("/batch/<string:task_id>/cancel")
class IcpBatchCancel(Resource):
    @auth
    @_api_error_guard("cancel ICP batch task", "ICP 批量任务取消失败，请稍后重试")
    def post(self, task_id):
        disabled = _ensure_enabled()
        if disabled:
            return disabled
        task, error = _batch_task_or_404(task_id)
        if error:
            return error
        cancelled = icp_query.request_cancel(task_id)
        celery_id = str((task or {}).get("celery_id") or "").strip()
        if celery_id:
            try:
                celerytask.celery.control.revoke(celery_id, terminate=False)
            except Exception as exc:
                icp_query.logger.warning("revoke ICP task failed: %s", icp_query._redact_text(exc))
        return _success(icp_query._task_status_payload(cancelled))


@ns.route("/history")
class IcpHistoryList(Resource):
    @auth
    @_api_error_guard("list ICP history", "ICP 查询历史暂时不可用，请稍后重试")
    def get(self):
        disabled = _ensure_enabled()
        if disabled:
            return disabled
        try:
            return _success(icp_query.list_history(
                request.args.get("page", 1),
                request.args.get("size", 20),
                request.args.get("type", ""),
                request.args.get("keyword", ""),
                request.args.get("status", ""),
                request.args.get("created_from", ""),
                request.args.get("created_to", ""),
            ))
        except icp_query.IcpQueryError as exc:
            return _failure(str(exc), 400)


@ns.route("/history/<string:history_id>")
class IcpHistoryDetail(Resource):
    @auth
    @_api_error_guard("get ICP history detail", "ICP 历史详情暂时不可用，请稍后重试")
    def get(self, history_id):
        disabled = _ensure_enabled()
        if disabled:
            return disabled
        history = icp_query.get_history(history_id)
        if not history:
            return _failure("ICP 历史记录不存在", 404)
        return _success({
            "history": icp_query._serialize(history),
            "results": icp_query.get_history_results(
                history_id,
                request.args.get("page", 1),
                request.args.get("size", 50),
            ),
        })

    @auth
    @_api_error_guard("delete ICP history", "ICP 历史记录删除失败，请稍后重试")
    def delete(self, history_id):
        disabled = _ensure_enabled()
        if disabled:
            return disabled
        if not icp_query.delete_history(history_id):
            return _failure("ICP 历史记录不存在", 404)
        return _success({"history_id": history_id})


@ns.route("/history/clear")
class IcpHistoryClear(Resource):
    @auth
    @_api_error_guard("clear ICP history", "ICP 历史清理失败，请稍后重试")
    def post(self):
        disabled = _ensure_enabled()
        if disabled:
            return disabled
        return _success({"deleted": icp_query.clear_history()})


@ns.route("/logs")
class IcpLogs(Resource):
    @auth
    @_api_error_guard("list ICP logs", "ICP 系统日志暂时不可用，请稍后重试")
    def get(self):
        disabled = _ensure_enabled()
        if disabled:
            return disabled
        try:
            return _success(icp_query.list_logs(
                request.args.get("page", 1),
                request.args.get("size", 50),
                request.args.get("level", ""),
                request.args.get("created_from", ""),
                request.args.get("created_to", ""),
            ))
        except icp_query.IcpQueryError as exc:
            return _failure(str(exc), 400)


@ns.route("/logs/clear")
class IcpLogsClear(Resource):
    @auth
    @_api_error_guard("clear ICP logs", "ICP 日志清理失败，请稍后重试")
    def post(self):
        disabled = _ensure_enabled()
        if disabled:
            return disabled
        return _success({"deleted": icp_query.clear_logs()})


@ns.route("/export")
class IcpExport(Resource):
    @auth
    def get(self):
        disabled = _ensure_enabled()
        if disabled:
            return disabled
        try:
            return icp_query.export_history(
                str(request.args.get("format", "json") or "json").lower(),
                request.args.get("history_id", ""),
                request.args.get("task_id", ""),
                request.args.get("type", ""),
                request.args.get("keyword", ""),
                request.args.get("status", ""),
                request.args.get("created_from", ""),
                request.args.get("created_to", ""),
            )
        except icp_query.IcpQueryError as exc:
            return _failure(str(exc), 400)
        except Exception as exc:
            icp_query.logger.error("export ICP history failed: %s", icp_query._redact_text(exc))
            return _failure("ICP 历史导出失败，请稍后重试", 500)


@ns.route("/about")
class IcpAbout(Resource):
    @auth
    def get(self):
        disabled = _ensure_enabled()
        if disabled:
            return disabled
        return _success({
            "name": "ICP 查询",
            "description": "ICP备案、App、小程序、快应用及违规信息查询。",
            "source": "https://github.com/HG-ha/ICP_Query",
            "integration_version": "native-v1",
            "integration": "ARL 原生适配，不启动独立 ICP_Query 容器。",
            "asset_writeback": False,
        })
