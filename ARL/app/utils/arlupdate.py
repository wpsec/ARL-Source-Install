"""
系统更新检查
"""
import sys
import os
import logging
import threading
from . import conn_db
from app.config import Config

logger = logging.getLogger(__name__)


def update_task_tag():
    """更新task任务tag信息"""
    table = "task"
    items = conn_db(table).find({})
    for item in items:
        task_tag = item.get("task_tag")
        query = {"_id": item["_id"]}
        if not task_tag:
            item["task_tag"] = "task"
            conn_db(table).find_one_and_replace(query, item)


def create_index():
    # ========== 单字段索引 ==========
    index_map = {
        "cert": "task_id",
        "domain": ["task_id", "domain"],
        "fileleak": "task_id",
        "ip": "task_id",
        "npoc_service": "task_id",
        "site": ["task_id", "status", "title", "hostname", "site", "http_server"],
        "service": "task_id",
        "url": "task_id",
        "vuln": "task_id",
        "asset_ip": "scope_id",
        "asset_site": "scope_id",
        "asset_domain": ["scope_id", "domain"],
        "github_result": "github_task_id",
        "github_monitor_result": "github_scheduler_id",
        "wih": ["task_id", "record_type", "fnv_hash"],
    }
    for table in index_map:
        if isinstance(index_map[table], list):
            for index in index_map[table]:
                conn_db(table).create_index(index)
        else:
            conn_db(table).create_index(index_map[table])

    # ========== 复合索引（覆盖高频联合查询） ==========
    compound_indexes = {
        "domain": [
            [("task_id", 1), ("domain", 1)],
        ],
        "site": [
            [("task_id", 1), ("status", 1)],
            [("task_id", 1), ("hostname", 1)],
        ],
        "ip": [
            [("task_id", 1), ("ip", 1)],
        ],
        "url": [
            [("task_id", 1), ("url", 1)],
        ],
        "asset_domain": [
            [("scope_id", 1), ("domain", 1)],
        ],
        "asset_site": [
            [("scope_id", 1), ("site", 1)],
        ],
        "asset_ip": [
            [("scope_id", 1), ("ip", 1)],
        ],
        "wih": [
            [("task_id", 1), ("record_type", 1)],
        ],
        "vuln": [
            [("task_id", 1), ("target", 1)],
        ],
        "task": [
            [("status", 1), ("task_tag", 1)],
        ],
    }
    for table, indexes in compound_indexes.items():
        for index_keys in indexes:
            try:
                conn_db(table).create_index(index_keys)
            except Exception as e:
                logger.warning("create compound index failed: table=%s, keys=%s, error=%s",
                               table, index_keys, e)


def arl_update():
    if is_run_flask_routes():
        return

    npoc_info_update()

    update_lock = os.path.join(Config.TMP_PATH, 'arl_update.lock')
    if os.path.exists(update_lock):
        return

    update_task_tag()
    create_index()

    open(update_lock, 'a').close()


# 创建锁，防止多线程同时更新
lock = threading.Lock()


def npoc_info_update():
    from app.services.npoc import NPoC
    with lock:
        if conn_db('poc').count_documents({}) > 0:
            return

        n = NPoC()
        n.sync_to_db()


# 判断是否是-m flask routes 模式运行
def is_run_flask_routes():
    if len(sys.argv) == 2:
        if "flask/__main__.py" in sys.argv[0]:
            if sys.argv[1] == "routes":
                return True

    return False
