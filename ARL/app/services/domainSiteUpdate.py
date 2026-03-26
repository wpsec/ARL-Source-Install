"""
域名站点更新同步
"""
import time
from app.services.buildDomainInfo import build_domain_info
from app.services.probeHTTP import probe_http
from app.services.fetchSite import fetch_site
from app.services.baseUpdateTask import BaseUpdateTask

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

    def save_domain_info(self):
        domain_info_list = build_domain_info(self.domains)

        # WIH 结果容易混入泛解析噪声域名，这里在入库前做一次拦截。
        if self.source == "wih" and domain_info_list:
            wildcard_ip_set = self._build_wildcard_ip_set_from_domains(self.domains)
            if wildcard_ip_set:
                filtered_list, drop_count = self._clear_wildcard_domain_info(
                    domain_info_list, wildcard_ip_set
                )
                if drop_count > 0:
                    logger.info(
                        "domain_site_update filter wildcard task_id:{} source:{} total:{} drop:{} keep:{} wildcard_ip_cnt:{}".format(
                            self.task_id,
                            self.source,
                            len(domain_info_list),
                            drop_count,
                            len(filtered_list),
                            len(wildcard_ip_set),
                        )
                    )
                domain_info_list = filtered_list

        for domain_info_obj in domain_info_list:
            domain_info = domain_info_obj.dump_json(flag=False)
            domain_info["task_id"] = self.task_id
            domain_info["source"] = self.source
            domain_parsed = utils.domain_parsed(domain_info["domain"])
            if domain_parsed:
                domain_info["fld"] = domain_parsed["fld"]
            utils.conn_db('domain').insert_one(domain_info)

        self.domain_info_list = domain_info_list

    @staticmethod
    def _clear_wildcard_domain_info(domain_info_list, wildcard_ip_set):
        """
        过滤命中泛解析 IP 的域名信息。
        """
        if not domain_info_list or not wildcard_ip_set:
            return domain_info_list, 0

        filtered = []
        drop_count = 0
        for info in domain_info_list:
            ip_list = set(getattr(info, "ip_list", []) or [])
            if ip_list and (ip_list & wildcard_ip_set):
                drop_count += 1
                continue
            filtered.append(info)

        return filtered, drop_count

    @staticmethod
    def _build_wildcard_probe_domains(domains):
        """
        为候选域名构造同层随机探测域名，用于判断是否存在泛解析。
        """
        probe_domains = set()
        random_name = utils.random_choices(6)
        for domain in domains:
            cut_name = utils.domain.cut_first_name(domain)
            if not cut_name:
                continue
            probe_domains.add("{}.{}".format(random_name, cut_name))
        return probe_domains

    def _build_wildcard_ip_set_from_domains(self, domains):
        """
        通过随机子域探测构建泛解析 IP 集合。
        """
        probe_domains = self._build_wildcard_probe_domains(domains)
        if not probe_domains:
            return set()

        info_list = build_domain_info(list(probe_domains))
        wildcard_ip_set = set()
        for info in info_list:
            wildcard_ip_set |= set(getattr(info, "ip_list", []) or [])

        return wildcard_ip_set

    def probe_sites(self):
        available_domains = []
        for domain_info_obj in self.domain_info_list:
            available_domains.append(domain_info_obj.domain)

        self.available_sites = probe_http(available_domains)

    def save_site_info(self):
        site_info_list = fetch_site(self.available_sites)

        for site_info in site_info_list:
            curr_site = site_info["site"]
            site_path = "/image/" + self.task_id
            file_name = '{}/{}.jpg'.format(site_path, utils.gen_filename(curr_site))
            site_info["task_id"] = self.task_id
            site_info["screenshot"] = file_name

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
