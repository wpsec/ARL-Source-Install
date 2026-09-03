"""
域名站点更新同步
"""
import time
from app.services.buildDomainInfo import build_domain_info
from app.services.probeHTTP import probe_http
from app.services.fetchSite import fetch_site
from app.services.baseUpdateTask import BaseUpdateTask
from app.repositories import DomainRepository
from app.services.wildcardDomain import (
    collect_wildcard_records_from_domains,
    collect_wildcard_profiles_from_roots,
    build_wildcard_probe_roots,
    domain_info_hits_wildcard_records,
    domain_info_hits_wildcard_profile,
)

from app import utils


logger = utils.get_logger()


class DomainSiteUpdate(object):
    def __init__(self, task_id: str, domains: list, source: str):
        self.task_id = task_id
        self.domains = domains
        self.source = source
        self.domain_info_list = []
        self.available_sites = []
        self.base_update_task = BaseUpdateTask(self.task_id)
        self._wildcard_profile_cache = {}

    def save_domain_info(self):
        domain_info_list = build_domain_info(self.domains)

        # WIH 结果容易混入泛解析噪声域名，这里在入库前做一次拦截。
        if self.source == "wih" and domain_info_list:
            wildcard_record_set = self._build_wildcard_record_set_from_domains(self.domains)
            wildcard_profile_map = self._build_wildcard_profile_map_from_domains(self.domains)
            if wildcard_record_set or wildcard_profile_map:
                filtered_list, drop_count = self._clear_wildcard_domain_info(
                    domain_info_list, wildcard_record_set, wildcard_profile_map
                )
                if drop_count > 0:
                    logger.info(
                        "domain_site_update filter wildcard task_id:{} source:{} total:{} drop:{} keep:{} wildcard_record_cnt:{}".format(
                            self.task_id,
                            self.source,
                            len(domain_info_list),
                            drop_count,
                            len(filtered_list),
                            len(wildcard_record_set),
                        )
                    )
                domain_info_list = filtered_list

        for domain_info_obj in domain_info_list:
            domain_info = domain_info_obj.dump_json(flag=False)
            domain_parsed = utils.domain_parsed(domain_info["domain"])
            if domain_parsed:
                domain_info["fld"] = domain_parsed["fld"]
            DomainRepository.upsert_discovered_domain(
                task_id=self.task_id,
                domain_info=domain_info,
                primary_source=self.source,
                sources=[self.source],
            )

        self.domain_info_list = domain_info_list

    @staticmethod
    def _clear_wildcard_domain_info(domain_info_list, wildcard_record_set, wildcard_profile_map=None):
        """
        过滤命中泛解析记录的域名信息。
        """
        if not domain_info_list or (not wildcard_record_set and not wildcard_profile_map):
            return domain_info_list, 0

        filtered = []
        drop_count = 0
        for info in domain_info_list:
            wildcard_hit = False
            if wildcard_profile_map:
                wildcard_hit = domain_info_hits_wildcard_profile(info, wildcard_profile_map)
            elif wildcard_record_set:
                wildcard_hit = domain_info_hits_wildcard_records(info, wildcard_record_set)

            if wildcard_hit:
                drop_count += 1
                continue
            filtered.append(info)

        return filtered, drop_count

    def _build_wildcard_record_set_from_domains(self, domains):
        """
        通过多次随机子域探测构建泛解析记录集合。
        """
        return collect_wildcard_records_from_domains(domains)

    def _build_wildcard_profile_map_from_domains(self, domains):
        roots = build_wildcard_probe_roots(domains)
        profile_map = {}
        for root in roots:
            if root not in self._wildcard_profile_cache:
                self._wildcard_profile_cache[root] = collect_wildcard_profiles_from_roots([root]).get(root)
            if self._wildcard_profile_cache.get(root):
                profile_map[root] = self._wildcard_profile_cache[root]
        return profile_map

    def probe_sites(self):
        available_domains = []
        for domain_info_obj in self.domain_info_list:
            available_domains.append(domain_info_obj.domain)

        self.available_sites = probe_http(available_domains)

    def save_site_info(self):
        site_info_list = fetch_site(self.available_sites)
        curr_date = utils.curr_date()

        for site_info in site_info_list:
            curr_site = site_info["site"]
            site_path = "/image/" + self.task_id
            file_name = '{}/{}.jpg'.format(site_path, utils.gen_filename(curr_site))
            site_info["task_id"] = self.task_id
            site_info["screenshot"] = file_name
            site_info.setdefault("save_date", curr_date)
            site_info.setdefault("update_date", curr_date)

        if site_info_list:
            utils.conn_db('site').insert_many(site_info_list)

    # 对域名进行检查，如果域名不在任务范围内，就不进行更新
    def set_and_check_domains(self):
        # 延迟导入，避免在 worker 启动阶段触发 helpers -> celerytask 循环依赖链。
        from app.helpers.domain import find_domain_by_task_id

        task_domains = find_domain_by_task_id(self.task_id)
        self.domains = list(set(self.domains) - set(task_domains))

    def run(self):
        status_name = f"{self.source}_domain_update"

        self.set_and_check_domains()

        logger.info("start domain site update task_id: {}, len:{}, source: {}".format(self.task_id,
                                                                                      len(self.domains), self.source))
        self.base_update_task.update_task_field("status", status_name)

        t1 = time.time()
        self.save_domain_info()
        self.probe_sites()
        self.save_site_info()
        elapse = time.time() - t1

        self.base_update_task.update_services(status_name, elapse)

        logger.info("end domain site update elapse {}".format(elapse))


# 将域名直接加到任务数据中，只加到域名和站点表中，
# 没有检验添加的域名是否在任务范围中
# 会检验域名是否已经存在任务中
def domain_site_update(task_id: str, domains: list, source: str):
    DomainSiteUpdate(task_id, domains, source).run()
