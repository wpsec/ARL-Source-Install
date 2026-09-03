"""
任务资产范围守卫。

目标：
- 统一约束 WIH / 渗透测试 / PoC 等扫描链路只能处理当前任务范围内的资产
- 默认允许：
  1) 当前任务目标域/子域
  2) 当前任务已发现站点/URL/域名
  3) 同名任务已沉淀的资产
"""
from typing import Iterable, Set
from urllib.parse import urlparse

from bson import ObjectId

from app import utils
from app.config import Config


logger = utils.get_logger()


def normalize_scope_host(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""

    try:
        parsed = urlparse(text if "://" in text else "//{}".format(text))
        host = str(parsed.hostname or "").strip().lower().rstrip(".")
        if host:
            return host
    except Exception:
        pass

    try:
        return str(utils.normalize_domain(text) or "").strip().lower().rstrip(".")
    except Exception:
        return ""


def _split_target_values(raw_target) -> list:
    text = str(raw_target or "").replace("\r", "\n")
    values = []
    for item in text.replace(",", "\n").split("\n"):
        candidate = str(item or "").strip()
        if candidate:
            values.append(candidate)
    return values


def _append_host(hosts: Set[str], flds: Set[str], value: str):
    host = normalize_scope_host(value)
    if not host:
        return
    hosts.add(host)
    try:
        parsed = utils.domain_parsed(host)
    except Exception:
        parsed = None
    fld = str(parsed.get("fld", "") if parsed else "").strip().lower()
    if fld:
        flds.add(fld)


def host_in_scope(value: str, allowed_hosts: Iterable[str], allowed_flds: Iterable[str]) -> bool:
    host = normalize_scope_host(value)
    if not host:
        return False

    allowed_host_set = {str(item or "").strip().lower() for item in (allowed_hosts or []) if str(item or "").strip()}
    allowed_fld_set = {str(item or "").strip().lower() for item in (allowed_flds or []) if str(item or "").strip()}

    if host in allowed_host_set:
        return True
    for item in allowed_host_set:
        if host.endswith("." + item):
            return True

    try:
        parsed = utils.domain_parsed(host)
    except Exception:
        parsed = None
    fld = str(parsed.get("fld", "") if parsed else "").strip().lower()
    if fld and fld in allowed_fld_set:
        return True
    return False


def url_in_scope(value: str, allowed_hosts: Iterable[str], allowed_flds: Iterable[str]) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    if text.startswith("http://") or text.startswith("https://"):
        return host_in_scope(text, allowed_hosts, allowed_flds)
    return host_in_scope(text, allowed_hosts, allowed_flds)


def load_task_scope_context(task_id: str, seed_sites=None, scope_domains=None):
    task_id_text = str(task_id or "").strip()
    allowed_hosts: Set[str] = set()
    allowed_flds: Set[str] = set()
    related_task_ids = []

    for site in seed_sites or []:
        _append_host(allowed_hosts, allowed_flds, site)
    for domain in scope_domains or []:
        _append_host(allowed_hosts, allowed_flds, domain)

    if not task_id_text or len(task_id_text) != 24:
        return {
            "allowed_hosts": sorted(allowed_hosts),
            "allowed_flds": sorted(allowed_flds),
            "task_ids": related_task_ids,
        }

    try:
        task_doc = utils.conn_db("task").find_one(
            {"_id": ObjectId(task_id_text)},
            {"name": 1, "target": 1},
            max_time_ms=Config.MONGO_SOCKET_TIMEOUT_MS,
        )
    except Exception as exc:
        # 读失败会让授权 scope 静默缩小（漏扫而非越权，但必须可见）
        logger.warning(
            "scope guard task doc load failed task_id:{} error_type:{}".format(
                task_id_text, type(exc).__name__))
        task_doc = None

    task_name = str(task_doc.get("name", "") or "").strip() if isinstance(task_doc, dict) else ""
    if isinstance(task_doc, dict):
        for value in _split_target_values(task_doc.get("target", "")):
            _append_host(allowed_hosts, allowed_flds, value)

    seen_task_ids = set()
    if task_id_text:
        seen_task_ids.add(task_id_text)
        related_task_ids.append(task_id_text)

    if task_name:
        try:
            cursor = utils.conn_db("task").find(
                {"name": task_name},
                {"_id": 1, "target": 1},
                max_time_ms=Config.MONGO_SOCKET_TIMEOUT_MS,
            )
            for row in cursor:
                row_task_id = str(row.get("_id", "") or "").strip()
                if row_task_id and row_task_id not in seen_task_ids:
                    seen_task_ids.add(row_task_id)
                    related_task_ids.append(row_task_id)
                for value in _split_target_values(row.get("target", "")):
                    _append_host(allowed_hosts, allowed_flds, value)
        except Exception as exc:
            # 同名任务扩展失败会让 scope 静默缩小，影响授权边界判断
            logger.warning(
                "scope guard same-name expansion failed task_name:{} error_type:{}".format(
                    task_name[:64], type(exc).__name__))

    if related_task_ids:
        query = {"task_id": {"$in": related_task_ids}}
        projection_map = (
            ("site", "site"),
            ("url", "url"),
            ("domain", "domain"),
        )
        for collection_name, field_name in projection_map:
            try:
                values = utils.conn_db(collection_name).distinct(
                    field_name,
                    query,
                    maxTimeMS=Config.MONGO_SOCKET_TIMEOUT_MS,
                )
            except Exception:
                values = []
            for value in values or []:
                _append_host(allowed_hosts, allowed_flds, value)

    return {
        "allowed_hosts": sorted(allowed_hosts),
        "allowed_flds": sorted(allowed_flds),
        "task_ids": related_task_ids,
    }
