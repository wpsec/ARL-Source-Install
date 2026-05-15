"""
测绘任务下发模块。

兼容说明：
- 历史命名沿用 task_fofa 路径，避免前端与外部调用立即失效
- 实际能力已扩展为 FOFA / Hunter / Shodan / Zoomeye / Quake 通用任务下发
"""
import time

from bson import ObjectId
from flask_restx import Namespace, fields

from app import celerytask, utils
from app.modules import CeleryAction, ErrorMsg
from app.services.measure_task import (
    fetch_measure_query_ips,
    get_measure_provider_label,
    get_measure_provider_label_safe,
    normalize_measure_provider,
    run_measure_query_test,
)
from app.utils import auth, build_ret, conn_db, get_logger

from . import ARLResource


ns = Namespace('task_fofa', description="测绘任务下发")

logger = get_logger()


test_measure_fields = ns.model('taskMeasureTest', {
    'provider': fields.String(required=False, description="测绘引擎，默认 fofa"),
    'query': fields.String(required=True, description="原生查询语句"),
})

add_measure_fields = ns.model('addTaskMeasure', {
    'provider': fields.String(required=False, description="测绘引擎，默认 fofa"),
    'query': fields.String(required=True, description="原生查询语句"),
    'name': fields.String(required=True, description="任务名称"),
    'policy_id': fields.String(description="策略ID（可选，自定义扫描配置）"),
})


def _resolve_provider(args):
    raw_provider = args.pop('provider', 'fofa')
    return normalize_measure_provider(raw_provider or 'fofa')


def _unsupported_provider_ret(provider_text):
    provider_label = get_measure_provider_label_safe(provider_text)
    return build_ret(
        ErrorMsg.FofaKeyError,
        {
            "error": "unsupported provider",
            "provider": str(provider_text or "").strip(),
            "provider_label": provider_label,
        },
    )


def _provider_error_ret(provider, error_text, query_text=""):
    provider_label = get_measure_provider_label(provider)
    message = "{} API异常".format(provider_label)
    error_text = str(error_text or "").strip()
    lowered = error_text.lower()
    if any(keyword in lowered for keyword in ("缺少配置", "请先", "无效", "forbidden", "unauthorized", "invalid")):
        return build_ret(
            ErrorMsg.FofaKeyError,
            {"error": error_text, "provider": provider, "provider_label": provider_label, "query": query_text},
        )

    return build_ret(
        ErrorMsg.FofaConnectError,
        {"error": error_text, "provider": provider, "provider_label": provider_label, "query": query_text},
    )


@ns.route('/test')
class TaskMeasureTest(ARLResource):
    """测绘语法测试接口"""

    @auth
    @ns.expect(test_measure_fields)
    def post(self):
        args = self.parse_args(test_measure_fields)
        query = args.pop('query')
        raw_provider = args.get('provider', 'fofa')
        try:
            provider = _resolve_provider(args)
        except ValueError:
            return _unsupported_provider_ret(raw_provider)

        try:
            item = run_measure_query_test(provider, query)
        except ValueError as exc:
            return build_ret(
                ErrorMsg.QueryResultIsEmpty,
                {"error": str(exc), "provider": provider, "provider_label": get_measure_provider_label(provider)},
            )
        except Exception as exc:
            return _provider_error_ret(provider, exc, query)

        return build_ret(ErrorMsg.Success, item)


@ns.route('/submit')
class AddMeasureTask(ARLResource):
    """提交测绘任务接口"""

    @auth
    @ns.expect(add_measure_fields)
    def post(self):
        args = self.parse_args(add_measure_fields)
        query = args.pop('query')
        name = args.pop('name')
        policy_id = args.get('policy_id')
        raw_provider = args.get('provider', 'fofa')
        try:
            provider = _resolve_provider(args)
        except ValueError:
            return _unsupported_provider_ret(raw_provider)

        task_options = {
            "port_scan_type": "test",
            "port_scan": True,
            "service_detection": False,
            "service_brute": False,
            "os_detection": False,
            "site_identify": False,
            "file_leak": False,
            "afrog_scan": False,
            "ssl_cert": False,
        }

        try:
            query_result = fetch_measure_query_ips(provider, query)
        except ValueError as exc:
            return build_ret(
                ErrorMsg.QueryResultIsEmpty,
                {"error": str(exc), "provider": provider, "provider_label": get_measure_provider_label(provider)},
            )
        except Exception as exc:
            return _provider_error_ret(provider, exc, query)

        target_ip_list = sorted(set(query_result.get("ips") or []))
        if int(query_result.get("size") or 0) <= 0 or len(target_ip_list) == 0:
            return build_ret(
                ErrorMsg.FofaResultEmpty,
                {"provider": provider, "provider_label": get_measure_provider_label(provider)},
            )

        if policy_id and len(policy_id) == 24:
            task_options.update(policy_2_task_options(policy_id))

        provider_label = get_measure_provider_label(provider)
        task_data = {
            "name": name,
            "target": "{} ip {}".format(provider_label, len(target_ip_list)),
            "start_time": "-",
            "end_time": "-",
            "task_tag": "task",
            "service": [],
            "status": "waiting",
            "options": task_options,
            "type": "fofa",
            "fofa_ip": target_ip_list,
            "provider": provider,
            "provider_label": provider_label,
            "query": query_result.get("items", []),
        }

        task_data = submit_measure_task(task_data)
        return build_ret(ErrorMsg.Success, task_data)


def policy_2_task_options(policy_id):
    options = {}
    query = {
        "_id": ObjectId(policy_id)
    }
    data = conn_db('policy').find_one(query)
    if not data:
        return options

    policy_options = dict(data.get("policy") or {})
    policy_options.pop("domain_config", None)

    ip_config = policy_options.pop("ip_config", {})
    site_config = policy_options.pop("site_config", {})
    for key in ("host_timeout_type", "host_timeout", "port_parallelism", "port_min_rate"):
        ip_config.pop(key, None)

    options.update(ip_config)
    options.update(site_config)
    options.update(policy_options)

    return options


def submit_measure_task(task_data):
    conn_db('task').insert_one(task_data)
    task_id = str(task_data.pop("_id"))
    task_data["task_id"] = task_id

    task_options = {
        "celery_action": CeleryAction.FOFA_TASK,
        "data": task_data
    }

    celery_id = celerytask.arl_task.delay(options=task_options)
    logger.info("target:{} celery_id:{}".format(task_id, celery_id))

    dispatch_now = utils.curr_date()
    dispatch_ts = int(time.time())
    values = {"$set": {
        "celery_id": str(celery_id),
        "dispatch_queue": "arltask",
        "dispatch_time": dispatch_now,
        "dispatch_ts": dispatch_ts,
    }}
    task_data["celery_id"] = str(celery_id)
    task_data["dispatch_queue"] = "arltask"
    task_data["dispatch_time"] = dispatch_now
    task_data["dispatch_ts"] = dispatch_ts
    conn_db('task').update_one({"_id": ObjectId(task_id)}, values)

    return task_data
