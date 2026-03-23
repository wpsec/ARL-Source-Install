"""
WAF 识别结果查询模块

功能说明：
- 展示任务执行中被 WAF 智能跳过的主机（来源 task.waf_skip_summary.blocked_hosts）
- 支持按任务、IP、域名、端口、WAF 厂商进行筛选
- 主要用于任务详情中快速查看“哪些主机因为 WAF 被跳过”
"""
from urllib.parse import urlparse

from bson import ObjectId
from flask_restx import fields, Namespace

from app import utils
from app.utils import auth, get_logger
from . import ARLResource, base_query_fields, get_arl_parser


ns = Namespace("waf_host", description="WAF 识别与跳过主机信息")
logger = get_logger()


base_search_fields = {
    "task_id": fields.String(required=False, description="任务ID（支持逗号/空白分隔多个）"),
    "ip": fields.String(required=False, description="IP 地址"),
    "domain": fields.String(required=False, description="域名"),
    "port": fields.Integer(required=False, description="端口"),
    "waf_name": fields.String(required=False, description="WAF 厂商"),
}
base_search_fields.update(base_query_fields)


def _split_task_ids(task_id_raw: str) -> list:
    text = str(task_id_raw or "").strip()
    if not text:
        return []
    return [item for item in text.replace(",", " ").split() if item]


def _safe_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return default


def _parse_host_port(host: str, last_url: str):
    host_text = str(host or "").strip().lower()
    last_url_text = str(last_url or "").strip()
    parsed = urlparse(last_url_text)
    if not getattr(parsed, "hostname", None) and last_url_text and "://" not in last_url_text:
        # 兼容无 scheme 的 host[:port][/path] 形态
        parsed = urlparse("//{}".format(last_url_text))

    hostname = str(parsed.hostname or "").strip().lower() or host_text
    try:
        parsed_port = parsed.port
    except Exception:
        parsed_port = 0
    port = _safe_int(parsed_port, 0)
    if port <= 0:
        if parsed.scheme == "https":
            port = 443
        elif parsed.scheme == "http":
            port = 80

    ip = ""
    domain = ""
    if hostname:
        if utils.is_ip(hostname):
            ip = hostname
        elif utils.is_valid_domain(hostname):
            domain = hostname
        else:
            domain = hostname

    return ip, domain, port


@ns.route("/")
class ARLWafHost(ARLResource):
    """WAF 跳过主机查询接口"""

    parser = get_arl_parser(base_search_fields, location="args")

    @auth
    @ns.expect(parser)
    def get(self):
        args = self.parser.parse_args()
        page = max(_safe_int(args.get("page"), 1), 1)
        size = max(_safe_int(args.get("size"), 20), 1)
        order = str(args.get("order") or "-_id").strip()

        task_id_list = _split_task_ids(args.get("task_id", ""))
        ip_kw = str(args.get("ip") or "").strip().lower()
        domain_kw = str(args.get("domain") or "").strip().lower()
        waf_name_kw = str(args.get("waf_name") or "").strip().lower()
        port_kw = _safe_int(args.get("port"), 0)

        task_query = {"waf_skip_summary.blocked_hosts.0": {"$exists": True}}
        if task_id_list:
            object_id_list = []
            for item in task_id_list:
                try:
                    object_id_list.append(ObjectId(item))
                except Exception:
                    continue
            if object_id_list:
                task_query["_id"] = {"$in": object_id_list}
            else:
                return {"code": 200, "page": page, "size": size, "total": 0, "items": []}

        task_cursor = utils.conn_db("task").find(
            task_query,
            {
                "_id": 1,
                "name": 1,
                "target": 1,
                "start_time": 1,
                "waf_skip_summary.blocked_hosts": 1,
            },
        )
        if order == "_id":
            task_cursor = task_cursor.sort([("_id", 1)])
        else:
            task_cursor = task_cursor.sort([("_id", -1)])

        rows = []
        seen = set()
        for task_item in task_cursor:
            task_id = str(task_item.get("_id"))
            blocked_hosts = (
                ((task_item.get("waf_skip_summary") or {}).get("blocked_hosts") or [])
                if isinstance(task_item.get("waf_skip_summary"), dict)
                else []
            )
            for host_item in blocked_hosts:
                if isinstance(host_item, dict):
                    host_data = host_item
                else:
                    # 兼容历史脏数据，避免前端点击“WAF识别”时接口 500
                    host_data = {"host": str(host_item or "").strip()}

                host = str(host_data.get("host", "") or "").strip().lower()
                last_url = str(host_data.get("last_url", "") or "").strip()
                waf_name = str(host_data.get("waf_name", "") or "").strip() or "unknown"
                ip, domain, port = _parse_host_port(host, last_url)

                if ip_kw and ip_kw not in ip:
                    continue
                if domain_kw and domain_kw not in domain:
                    continue
                if waf_name_kw and waf_name_kw not in waf_name.lower():
                    continue
                if port_kw > 0 and port_kw != port:
                    continue

                uniq_key = (task_id, host, port, waf_name)
                if uniq_key in seen:
                    continue
                seen.add(uniq_key)

                rows.append(
                    {
                        "_id": "{}|{}|{}|{}".format(task_id, domain or ip or host, port, waf_name),
                        "task_id": task_id,
                        "ip": ip,
                        "domain": domain,
                        "port": port if port > 0 else "",
                        "waf_name": waf_name,
                    }
                )

        total = len(rows)
        start = size * (page - 1)
        end = start + size
        items = rows[start:end]
        return {"code": 200, "page": page, "size": size, "total": total, "items": items}
