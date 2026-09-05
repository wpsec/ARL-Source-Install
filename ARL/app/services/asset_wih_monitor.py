"""
Web指纹信息监控

每次监控运行创建 `monitor|<scope_id>|<run_id>` 的任务级发现上下文：
WIH 之后的可编排阶段(URLFinder/页面情报/API文档/JS情报/敏感二次)共享
响应缓存、候选图与流量类别准入，避免周期监控重复请求同一资源。
run_wih(Go 子进程自带网络栈)与 trufflehog(外部进程)不在共享面内。
"""
import json
import uuid

from app.helpers import asset_site, asset_wih
from app.helpers.scope import get_scope_by_scope_id
from app.services import (
    run_api_doc_scan,
    run_js_intel_scan,
    run_page_intel_scan,
    run_trufflehog_js,
    run_urlfinder_extract,
    run_urlfinder_sensitive_scan,
    run_wih,
)
from app.utils import get_logger, check_domain_black
from app.modules import WihRecord
from app import utils
from app.services.discovery_context import DiscoveryContext, url_host
from app.services.infoHunter import InfoHunter

logger = get_logger()


class AssetWihMonitor(object):
    def __init__(self, scope_id: str):
        self.scope_id = scope_id
        self.scope_domains = []  # 资产分组中的域名范围
        self.scope_name = None  # 资产分组名称
        self.sites = []
        self._wih_record_fnv_hash = None

    def init_scope_data(self):
        scope_data = get_scope_by_scope_id(self.scope_id)
        if not scope_data:
            raise Exception("没有找到资产组 {}".format(self.scope_id))

        self.scope_name = scope_data.get("name", "")
        scope_type = scope_data.get("scope_type", "")

        if scope_type == "domain":
            self.scope_domains = scope_data.get("scope_array", [])

        self.sites = asset_site.find_site_by_scope_id(self.scope_id)

    def have_asset_wih_record(self, record: WihRecord) -> bool:
        """
        检查数据库中是否已经存在记录
        :param record:
        :return:
        """

        query = {"scope_id": self.scope_id, "fnv_hash": str(record.fnv_hash)}
        item = utils.conn_db('asset_wih').find_one(query)
        if item:
            return True
        return False

    def save_asset_wih_record(self, record: WihRecord):
        """
        保存到数据库
        :param record: 
        :return: 
        """

        if self.have_asset_wih_record(record):
            return

        item = record.dump_json()

        item["scope_id"] = self.scope_id
        curr_date = utils.curr_date_obj()
        item["save_date"] = curr_date
        item["update_date"] = curr_date
        utils.conn_db('asset_wih').insert_one(item)

    @property
    def wih_record_fnv_hash(self):
        if self._wih_record_fnv_hash is None:
            self._wih_record_fnv_hash = asset_wih.get_wih_record_fnv_hash(self.scope_id)
        return self._wih_record_fnv_hash

    def run(self):
        results = []
        self.init_scope_data()

        logger.info("run AssetWihMonitor, scope_id: {} sites: {}".format(self.scope_id, len(self.sites)))

        if len(self.sites) == 0:
            return results

        run_id = uuid.uuid4().hex[:12]
        discovery_context = DiscoveryContext(
            task_id="monitor|{}|{}".format(self.scope_id, run_id),
            allowed_hosts={url_host(site) for site in self.sites if url_host(site)},
        )

        # 先执行原生 WIH，再进行 URL/JS 提取增强、同目标二次敏感扫描，最后执行 TruffleHog 二次扫描
        wih_results = list(run_wih(self.sites) or [])
        # 外部边界显式记账：Go WIH 自带网络栈，请求不经过统一响应缓存，
        # 不计入"全链路一次请求"门禁（Review 20260905 §4 一般项）。
        discovery_context.record_metric("external_network_wih_go", len(self.sites))
        urlfinder_results = list(
            run_urlfinder_extract(self.sites, wih_results, discovery_context=discovery_context) or []
        )
        if urlfinder_results:
            wih_results.extend(urlfinder_results)

        page_intel_results = list(
            run_page_intel_scan(self.sites, wih_results, discovery_context=discovery_context) or []
        )
        if page_intel_results:
            wih_results.extend(page_intel_results)

        api_doc_results = list(
            run_api_doc_scan(self.sites, wih_results, discovery_context=discovery_context) or []
        )
        if api_doc_results:
            wih_results.extend(api_doc_results)

        js_intel_results = list(
            run_js_intel_scan(self.sites, wih_results, discovery_context=discovery_context) or []
        )
        if js_intel_results:
            wih_results.extend(js_intel_results)

        urlfinder_sensitive_results = list(
            run_urlfinder_sensitive_scan(self.sites, wih_results, discovery_context=discovery_context) or []
        )
        if urlfinder_sensitive_results:
            wih_results.extend(urlfinder_sensitive_results)

        # 按记录哈希去重，避免后续 TruffleHog 重复输入
        wih_results = list(set(wih_results))

        if wih_results:
            trufflehog_results = list(run_trufflehog_js(self.sites, wih_results) or [])
            # 外部边界显式记账：TruffleHog 外部进程按 JS URL 二次抓取，不在共享缓存内。
            discovery_context.record_metric("external_network_trufflehog", len(self.sites))
            if trufflehog_results:
                wih_results.extend(trufflehog_results)

        fnv_hash_set = set(self.wih_record_fnv_hash)
        for raw_item in wih_results:
            item = InfoHunter.normalize_wih_record(raw_item)
            if not item:
                continue

            # 保存到数据库的是字符串，所以这里要转换一下
            item_fnv_hash = str(item.fnv_hash)

            # 如果已经存在，就跳过
            if item_fnv_hash in fnv_hash_set:
                continue

            if item.recordType == "domain":
                if self.scope_domains:
                    if not domain_in_scope_domain(item.content, self.scope_domains):
                        continue

                # 表示域名在黑名单中
                if check_domain_black(item.content):
                    continue

            # 保存到数据库
            self.save_asset_wih_record(item)

            results.append(item)
            fnv_hash_set.add(item_fnv_hash)

        logger.info("AssetWihMonitor, scope_id: {} results: {}".format(self.scope_id, len(results)))

        # 观测收口：只进诊断日志，供监控路径的请求去重/候选传播回归核对。
        try:
            logger.info(
                "AssetWihMonitor discovery observation scope_id:{} run_id:{} metrics:{}".format(
                    self.scope_id,
                    run_id,
                    json.dumps(discovery_context.metrics_snapshot(), ensure_ascii=False),
                )
            )
        except Exception as exc:
            logger.debug(
                "AssetWihMonitor observation log failed error_type:{}".format(type(exc).__name__)
            )

        # 后面这个用不到了，清空，省内存
        self._wih_record_fnv_hash = None

        return results


def asset_wih_monitor(scope_id: str):
    monitor = AssetWihMonitor(scope_id)
    results = monitor.run()
    return results


def domain_in_scope_domain(domain: str, scope_domain: list):
    for scope in scope_domain:
        if domain.endswith("." + scope):
            return True
    return False
