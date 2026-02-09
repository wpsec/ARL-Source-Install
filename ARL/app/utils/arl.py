"""
ARL系统工具函数
"""
from bson import ObjectId
from .conn import conn_db
from .IPy import IP
from .cache import build_cache_key, cached_call
import re


def get_task_ids(domain):
    key = build_cache_key("arl:get_task_ids", domain)

    def _loader():
        query = {"target": domain}
        task_ids = []
        for item in conn_db('task').find(query):
            task_ids.append(str(item["_id"]))
        return task_ids

    return cached_call(key, _loader, expire=120)


def get_domain_by_id(task_id):
    key = build_cache_key("arl:get_domain_by_id", task_id)

    def _loader():
        query = {"task_id": task_id}
        domains = []
        for item in conn_db('domain').find(query):
            domains.append(item["domain"])
        return domains

    return cached_call(key, _loader, expire=120)


def arl_domain(domain):
    from app.utils.domain import is_valid_domain
    domains = []
    for task_id in get_task_ids(domain):
        for item in get_domain_by_id(task_id):
            if not is_valid_domain(domain):
                continue

            if item.endswith("." + domain):
                domains.append(item)

    for scope_id in get_scope_ids(domain):
        for item in get_asset_domain_by_id(scope_id):
            if not is_valid_domain(domain):
                continue

            if item.endswith("." + domain):
                domains.append(item)

    return list(set(domains))


def get_asset_domain_by_id(scope_id):
    key = build_cache_key("arl:get_asset_domain_by_id", scope_id)

    def _loader():
        query = {"scope_id": scope_id}
        domains = []
        for item in conn_db('asset_domain').find(query):
            domains.append(item["domain"])
        return domains

    return cached_call(key, _loader, expire=120)


def get_monitor_domain_by_id(scope_id):
    key = build_cache_key("arl:get_monitor_domain_by_id", scope_id)

    def _loader():
        query = {"scope_id": scope_id}
        items = conn_db('scheduler').find(query)
        domains = []
        for item in items:
            domains.append(item["domain"])
        return domains

    return cached_call(key, _loader, expire=120)


def scope_data_by_id(scope_id):
    query = {"_id": ObjectId(scope_id)}
    item = conn_db('asset_scope').find_one(query)

    return item


def get_scope_ids(domain):
    key = build_cache_key("arl:get_scope_ids", domain)

    def _loader():
        query = {"scope_array": domain}
        scope_ids = []
        for item in conn_db('asset_scope').find(query):
            scope_ids.append(str(item["_id"]))
        return scope_ids

    return cached_call(key, _loader, expire=120)


def task_statistic(task_id=None):
    """对任务中的资产信息进行统计"""
    query = dict()
    if isinstance(task_id, str) and len(task_id) == 24:
        query["task_id"] = task_id

    key = build_cache_key("arl:task_statistic", task_id if task_id else "all")

    def _loader():
        ret = dict()
        table_list = ['site', 'domain', 'ip', 'cert', 'service', 'fileleak']
        table_list.extend(['url', 'vuln', 'npoc_service', 'cip'])
        table_list.extend(["nuclei_result", "stat_finger", "wih"])
        for table in table_list:
            cnt = conn_db(table).count_documents(query)
            stat_key = table + "_cnt"
            ret[stat_key] = cnt
        return ret

    return cached_call(key, _loader, expire=90)


def gen_cip_map(task_id=None):
    query = dict()
    if isinstance(task_id, str) and len(task_id) == 24:
        query["task_id"] = task_id

    results = list(conn_db('ip').find(query, {"ip": 1, "domain": 1}))
    cip_map = dict()

    have_domain_flag = True

    for result in results:
        if result.get("domain") is None:
            have_domain_flag = False

        cip = result["ip"] + "/24"
        cip = IP(cip, make_net=True).strNormal(1)
        count_map = cip_map.get(cip)
        if count_map is None:
            domain_set = set()
            if have_domain_flag:
                domain_set = set(result["domain"])
            cip_map[cip] = {
                "domain_set": domain_set,
                "ip_set": {result["ip"]}
            }
        else:
            if have_domain_flag:
                count_map["domain_set"] |= set(result["domain"])

            count_map["ip_set"] |= {result["ip"]}

    return cip_map


def gen_stat_finger_map(task_id=None):
    query = dict()
    if isinstance(task_id, str) and len(task_id) == 24:
        query["task_id"] = task_id

    key = build_cache_key("arl:gen_stat_finger_map", task_id if task_id else "all")

    def _loader():
        results = list(conn_db('site').find(query, {"finger": 1}))
        finger_map = dict()
        for result in results:
            if not isinstance(result.get("finger"), list):
                continue

            for finger in result["finger"]:
                finger_key = finger["name"].lower()

                if finger_key not in finger_map:
                    finger_map[finger_key] = {
                        "name": finger["name"],
                        "cnt": 1
                    }
                else:
                    finger_map[finger_key]["cnt"] += 1
        return finger_map

    return cached_call(key, _loader, expire=90)


def build_port_custom(port_custom):
    port_list = []
    splits = port_custom.split(",")
    if len(splits) < 1:
        return ""
    for item in splits:
        item = item.strip()
        if re.match(r"^[\d\-]+$", item):
            port_list.append(item)
        else:
            return item

    return port_list

