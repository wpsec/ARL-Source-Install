"""域名任务的可测试阶段服务。

这些服务只接收一个已初始化的任务上下文，负责单一阶段的业务边界；任务类
继续保留同名兼容方法，避免改变 Celery、历史重试和外部调用的入口。
"""

import random
import time
from collections import Counter
from urllib.parse import urlparse

from app import modules, services, utils
from app.config import Config
from app.modules import CollectSource
from app.services import fetchCert
from app.services.dns_query import (
    run_query_plugin,
    run_query_plugin_by_cert,
    run_query_plugin_by_ip,
)
from app.services.searchEngines import search_engines
from app.services.task_pipeline import TaskPipeline
from app.services.task_result_write_service import TaskResultWriteService
from app.services.asset_pivot_stage_services import (
    certificate_identity,
    domain_log_summary,
    endpoint_ip,
    extract_certificate_domains,
    is_public_suffix,
    should_skip_cdn_waf,
    validate_domain_binding,
    write_pivot_evidence,
)
from app.services.service_detection import resolve_service_result
from app.services.wildcardDomain import (
    domain_info_hits_wildcard_profile,
    domain_info_hits_wildcard_profile_with_details,
    domain_info_hits_wildcard_records,
)
from app.utils.log_safety import safe_error_text
from app.utils.provider_http import stage_execution_context
from app.repositories import DomainRepository


logger = utils.get_logger()
MAX_MAP_COUNT = 35


def _task_result_writer(task, utils_module=utils):
    """阶段结果写入统一走任务 Writer；兼容轻量测试任务和历史调用方。"""
    return getattr(task, "_result_writer", None) or TaskResultWriteService(
        getattr(task, "task_id", ""),
        utils_module=utils_module,
    )


def _normalize_domain_target(value):
    text = str(value or "").strip()
    if not text:
        return ""

    if "{fuzz}" in text:
        return utils.normalize_fuzz_domain(text) or text.lower().rstrip(".")

    return utils.normalize_domain(text) or text.lower().rstrip(".")


class DomainBrute(object):
    """执行域名爆破、解析和结果模型转换。"""

    def __init__(self, base_domain, word_file=Config.DOMAIN_DICT_2W, wildcard_domain_ip=None):
        if wildcard_domain_ip is None:
            wildcard_domain_ip = []
        self.base_domain = _normalize_domain_target(base_domain)
        self.base_domain_scope = "." + self.base_domain.strip(".")
        self.dicts = utils.load_file(word_file)
        self.brute_out = []
        self.resolver_map = {}
        self.domain_info_list = []
        self.domain_cnames = []
        self.brute_domain_map = {}
        self.wildcard_domain_ip = wildcard_domain_ip

    def _brute_domain(self):
        self.brute_out = services.mass_dns(
            self.base_domain,
            self.dicts,
            self.wildcard_domain_ip,
        )

    def _resolver(self):
        domains = []
        domain_cname_record = []
        for item in self.brute_out:
            current_domain = utils.normalize_domain(item.get("domain", ""))
            if not current_domain or not utils.domain_parsed(current_domain):
                continue
            if len(current_domain) - len(self.base_domain) >= Config.DOMAIN_MAX_LEN:
                continue
            if utils.check_domain_black(current_domain):
                continue

            if current_domain not in domains:
                domains.append(current_domain)
            self.brute_domain_map[current_domain] = item["record"]

            if item["type"] != "CNAME":
                continue
            self.domain_cnames.append(current_domain)
            current_record_domain = utils.normalize_domain(item.get("record", ""))
            if not current_record_domain:
                continue
            if not utils.domain_parsed(current_record_domain):
                continue
            if utils.check_domain_black(current_record_domain):
                continue
            if current_record_domain not in domain_cname_record:
                domain_cname_record.append(current_record_domain)

        for domain in domain_cname_record:
            if domain.endswith(self.base_domain_scope) and domain not in domains:
                domains.append(domain)

        start_time = time.time()
        logger.info("start resolver {} {}".format(self.base_domain, len(domains)))
        self.resolver_map = services.resolver_domain(domains)
        logger.info("end resolver {} result {}, elapse {}".format(
            self.base_domain,
            len(self.resolver_map),
            time.time() - start_time,
        ))

    def run(self):
        start_time = time.time()
        logger.info("start brute {} with dict {}".format(
            self.base_domain, len(self.dicts)))
        self._brute_domain()
        logger.info("end brute {}, result {}, elapse {}".format(
            self.base_domain,
            len(self.brute_out),
            time.time() - start_time,
        ))

        self._resolver()
        for domain, ips in self.resolver_map.items():
            if not ips:
                continue
            if domain in self.domain_cnames:
                item = {
                    "domain": domain,
                    "type": "CNAME",
                    "record": [self.brute_domain_map[domain]],
                    "ips": ips,
                }
            else:
                item = {
                    "domain": domain,
                    "type": "A",
                    "record": ips,
                    "ips": ips,
                }
            self.domain_info_list.append(modules.DomainInfo(**item))

        return list(set(self.domain_info_list))


def domain_brute(base_domain, word_file=Config.DOMAIN_DICT_2W, wildcard_domain_ip=None):
    if wildcard_domain_ip is None:
        wildcard_domain_ip = []
    return DomainBrute(base_domain, word_file, wildcard_domain_ip).run()


def scan_port(domain_info_list, option=None):
    """保留端口扫描公共入口，延迟读取任务模块避免循环导入。"""
    from app.tasks.domain import ScanPort

    return ScanPort(domain_info_list, option).run()


def ssl_cert(ip_info_list, base_domain):
    try:
        return fetchCert.SSLCert(ip_info_list, base_domain).run()
    except Exception as exc:
        logger.error("ssl certificate stage failed error:{}".format(safe_error_text(exc)))
        return {}


class AltDNS(object):
    """基于已发现域名生成 AltDNS 候选。"""

    def __init__(self, domain_info_list, base_domain, wildcard_domain_ip=None):
        self.domain_info_list = domain_info_list
        self.base_domain = utils.normalize_domain(base_domain) or str(base_domain or "").strip().lower().rstrip(".")
        self.domains = []
        self.subdomains = []
        inner_dicts = "test adm admin api app beta demo dev front int internal intra ops pre pro prod qa sit staff stage test uat"
        self.dicts = inner_dicts.split()
        self.wildcard_domain_ip = wildcard_domain_ip

    def _fetch_domains(self):
        base_len = len(self.base_domain)
        for item in self.domain_info_list:
            if not item.domain.endswith("." + self.base_domain):
                continue

            if utils.check_domain_black("a." + item.domain):
                continue

            self.domains.append(item.domain)
            subdomain = item.domain[:-(base_len + 1)]
            if "." in subdomain:
                self.subdomains.append(subdomain.split(".")[-1])

        random.shuffle(self.subdomains)

        most_cnt = 50
        if len(self.domains) < 1000:
            most_cnt = 30
            self.dicts.extend(self._load_dict())

        sub_dicts = list(dict(Counter(self.subdomains).most_common(most_cnt)).keys())
        self.dicts.extend(sub_dicts)
        self.dicts = list(set(self.dicts))

    def _load_dict(self):
        """加载内部字典。"""
        words = set()
        for value in utils.load_file(Config.altdns_dict_path):
            value = value.strip()
            if value:
                words.add(value)
        return list(words)

    def run(self):
        started_at = time.time()
        self._fetch_domains()

        logger.info("start {} AltDNS {}  dict {}".format(
            self.base_domain, len(self.domains), len(self.dicts)))
        result = services.alt_dns(
            self.domains,
            self.base_domain,
            self.dicts,
            wildcard_domain_ip=self.wildcard_domain_ip,
        )
        logger.info("end AltDNS result {}, elapse {}".format(
            len(result), time.time() - started_at))
        return result


def alt_dns(domain_info_list, base_domain, wildcard_domain_ip=None):
    """保留历史模块入口，实际实现归属 discovery service。"""
    return AltDNS(
        domain_info_list,
        base_domain,
        wildcard_domain_ip=wildcard_domain_ip,
    ).run()

def _run_measured_stage(task, name, func):
    """阶段统一经执行器产出独立 metrics（报告§4：禁止手工稀疏指标）。

    轻量测试任务可能没有 StageExecutor，回退为原手工语义。
    """

    runner = getattr(task, "_run_internal_stage", None)
    if callable(runner):
        return runner(name, func)
    task.update_task_field("status", name)
    started_at = time.time()
    func()
    task.update_services(name, time.time() - started_at)
    return None


def _domain_count_stage(task, func):
    """闭包工厂：以 domain_info_list 增量作为 output_count。"""

    def _run():
        before = len(getattr(task, "domain_info_list", []) or [])
        func()
        after = len(getattr(task, "domain_info_list", []) or [])
        return {"output_count": max(0, after - before), "metrics": {"status": "ok", "domain_total": after}}

    return _run


class DomainDiscoveryStageService(object):
    """执行域名爆破、插件发现和智能 DNS 生成。"""

    def __init__(self, task):
        self.task = task

    def build_single_domain_info(self, domain):
        """构建单个域名的 DNS 资产，保留任务级 DNS policy 缓存。"""
        task = self.task
        domain = utils.normalize_domain(domain)
        if not domain:
            return None

        if domain in task._dns_policy_cache:
            allow_scan, policy_detail = task._dns_policy_cache[domain]
        else:
            allow_scan, policy_detail = utils.check_dns_policy_for_host(domain)
            task._dns_policy_cache[domain] = (allow_scan, policy_detail)

        if not allow_scan:
            logger.info(
                "skip build_single_domain_info by dns policy domain:{} reason:{} "
                "resolver_ips:{} system_ips:{}".format(
                    domain,
                    policy_detail.get("reason", ""),
                    policy_detail.get("resolver_ips", []),
                    policy_detail.get("system_ips", []),
                )
            )
            return None

        cname = utils.get_cname(domain)
        preferred_ips = list(policy_detail.get("preferred_ips", []) or [])
        ips = preferred_ips or utils.get_ip(domain)
        if not ips:
            return None

        return modules.DomainInfo(
            domain=domain,
            type="CNAME" if cname else "A",
            record=cname if cname else ips,
            ips=ips,
        )

    def build_domain_info(self, domains):
        """构建域名资产并完成任务内去重，监控任务保留未解析的兼容语义。"""
        task = self.task
        fake_list = []
        domains_set = set()
        for item in domains or []:
            domain = item.get("domain", "") if isinstance(item, dict) else item
            domain = utils.normalize_domain(domain)
            if not domain or domain in domains_set:
                continue
            domains_set.add(domain)
            if utils.check_domain_black(domain):
                continue

            fake_info = modules.DomainInfo(
                domain=domain,
                type="CNAME",
                record=[],
                ips=[],
            )
            if fake_info not in task.domain_info_list:
                fake_list.append(fake_info)

        if task.task_tag == "monitor":
            return fake_list
        return services.build_domain_info(
            fake_list,
            dns_policy_cache=task._dns_policy_cache,
        )

    def clear_domain_info_by_record(self, domain_info_list):
        """过滤 DNS policy、泛解析和异常共享记录，收口域名发现准入。"""
        task = self.task
        task._prewarm_wildcard_profiles(domain_info_list)
        task._prewarm_wildcard_candidate_details(domain_info_list)
        new_list = []
        for info in domain_info_list or []:
            if not info.record_list:
                continue

            domain = utils.normalize_domain(getattr(info, "domain", ""))
            if not domain:
                continue

            if domain in task._dns_policy_cache:
                allow_scan, policy_detail = task._dns_policy_cache[domain]
            else:
                allow_scan, policy_detail = utils.check_dns_policy_for_host(domain)
                task._dns_policy_cache[domain] = (allow_scan, policy_detail)
            if not allow_scan:
                logger.info(
                    "skip domain by dns policy domain:{} reason:{} resolver_ips:{} "
                    "system_ips:{}".format(
                        domain,
                        policy_detail.get("reason", ""),
                        policy_detail.get("resolver_ips", []),
                        policy_detail.get("system_ips", []),
                    )
                )
                continue

            if domain in task._wildcard_domain_hit_cache:
                if task._wildcard_domain_hit_cache[domain]:
                    continue
            else:
                wildcard_profile_map = task._get_wildcard_profile_map_for_domain(domain)
                wildcard_hit = False
                if wildcard_profile_map:
                    candidate_details = task._wildcard_candidate_detail_cache.get(domain)
                    if candidate_details is None:
                        wildcard_hit = domain_info_hits_wildcard_profile(info, wildcard_profile_map)
                    else:
                        wildcard_hit = domain_info_hits_wildcard_profile_with_details(
                            info,
                            wildcard_profile_map,
                            candidate_details,
                        )
                elif domain_info_hits_wildcard_records(info, task.wildcard_domain_records):
                    wildcard_hit = True
                task._wildcard_domain_hit_cache[domain] = wildcard_hit
                if wildcard_hit:
                    continue

            record = info.record_list[0]
            task.record_map[record] = task.record_map.get(record, 0) + 1
            if task.record_map[record] > MAX_MAP_COUNT:
                continue
            new_list.append(info)
        return new_list

    def run_load_saved_domain_info(self):
        task = self.task
        if task.domain_info_list:
            return len(task.domain_info_list)

        restored = []
        source_map = {}
        cursor = DomainRepository.find_by_task_id(
            task.task_id,
            projection={
                "domain": 1,
                "record": 1,
                "type": 1,
                "ips": 1,
                "source": 1,
                "sources": 1,
            },
            batch_size=500,
        )
        for item in cursor:
            domain = utils.normalize_domain(item.get("domain"))
            if not domain:
                continue
            restored.append(modules.DomainInfo(
                domain=domain,
                record=item.get("record") or [],
                type=item.get("type") or "CNAME",
                ips=item.get("ips") or [],
            ))
            sources = item.get("sources")
            if not isinstance(sources, list):
                sources = [item.get("source", "")]
            source_map[domain] = {
                str(source or "").strip()
                for source in sources
                if str(source or "").strip()
            }

        task.domain_info_list = restored
        task.domain_source_map.update(source_map)
        logger.info(
            "restore domain info for deep scan task_id:{} count:{}".format(
                task.task_id,
                len(restored),
            )
        )
        return len(restored)

    def run_seed_base_domain(self):
        task = self.task
        base_domain_info = task.build_single_domain_info(task.base_domain)
        if not base_domain_info:
            return 0
        if base_domain_info not in task.domain_info_list:
            task.domain_info_list.append(base_domain_info)
        task.add_domain_source_map([base_domain_info], CollectSource.DOMAIN_BRUTE)
        if task.task_tag == "task":
            task.save_domain_info_list(
                [base_domain_info],
                source=CollectSource.DOMAIN_BRUTE,
            )
        return 1

    def run_discovery_preview(self):
        task = self.task
        started_at = time.time()
        preview_ip_count = 0
        preview_site_count = 0
        try:
            task.gen_ipv4_map()
            preview_ip_count = len(task.ipv4_map)
            task.save_ip_info()

            preview_sites = services.probe_http(task.domain_info_list)
            preview_sites = list(dict.fromkeys(
                str(site).strip()
                for site in preview_sites
                if str(site).strip()
            ))
            if preview_sites:
                from app.services.commonTask import WebSiteFetch

                preview_fetch = WebSiteFetch(
                    task_id=task.task_id,
                    sites=preview_sites,
                    options=task.options,
                    scope_domain=[task.base_domain],
                )
                preview_fetch.fetch_site()
                preview_fetch.save_site_info()
                preview_site_count = len(preview_fetch.site_info_list)
            task.update_services("discovery_preview", time.time() - started_at)
            logger.info(
                "discovery preview task_id:{} ips:{} sites:{} elapsed:{:.2f}s".format(
                    task.task_id,
                    preview_ip_count,
                    preview_site_count,
                    time.time() - started_at,
                )
            )
        except Exception as exc:
            logger.warning(
                "discovery preview degraded task_id:{} ips:{} sites:{} error:{}".format(
                    task.task_id,
                    preview_ip_count,
                    preview_site_count,
                    safe_error_text(exc),
                )
            )
            task.update_services(
                "discovery_preview_degraded",
                time.time() - started_at,
            )

    def run_domain_brute(self):
        task = self.task
        domain_info_list = domain_brute(
            task.base_domain,
            word_file=task.domain_word_file,
            wildcard_domain_ip=task.not_found_domain_ips,
        )
        domain_info_list = task.clear_domain_info_by_record(domain_info_list)
        task.add_domain_source_map(domain_info_list, CollectSource.DOMAIN_BRUTE)
        if task.task_tag == "task":
            task.save_domain_info_list(
                domain_info_list,
                source=CollectSource.DOMAIN_BRUTE,
            )
        task.domain_info_list.extend(domain_info_list)

    def run_arl_search(self):
        task = self.task
        started_at = time.time()
        logger.info("start arl fetch {}".format(task.base_domain))
        arl_all_domains = utils.arl_domain(task.base_domain)
        task.add_domain_source_names(arl_all_domains, CollectSource.ARL)
        domain_info_list = task.build_domain_info(arl_all_domains)
        if task.task_tag == "task":
            domain_info_list = task.clear_domain_info_by_record(domain_info_list)
            task.save_domain_info_list(domain_info_list, source=CollectSource.ARL)

        task.add_domain_source_map(domain_info_list, CollectSource.ARL)
        task.domain_info_list.extend(domain_info_list)
        logger.info("end arl fetch {} {} elapse {}".format(
            task.base_domain,
            len(domain_info_list),
            time.time() - started_at,
        ))

    def run(self):
        task = self.task
        if task.options.get("domain_brute"):
            _run_measured_stage(task, "domain_brute", _domain_count_stage(task, self.run_domain_brute))

            # 用户输入的根域名始终作为后续阶段的保底种子。
            base_domain_info = task.build_single_domain_info(task.base_domain)
            if base_domain_info and base_domain_info not in task.domain_info_list:
                task.domain_info_list.append(base_domain_info)
                task.add_domain_source_map([base_domain_info], CollectSource.DOMAIN_BRUTE)
                if task.task_tag == "task":
                    task.save_domain_info_list(
                        [base_domain_info], source=CollectSource.DOMAIN_BRUTE
                    )
        else:
            domain_info = task.build_single_domain_info(task.base_domain)
            if domain_info:
                if domain_info not in task.domain_info_list:
                    task.domain_info_list.append(domain_info)
                task.add_domain_source_map([domain_info], CollectSource.DOMAIN_BRUTE)
                task.save_domain_info_list([domain_info])

        if "{fuzz}" in task.base_domain:
            return

        if task.options.get("dns_query_plugin"):
            task.update_task_field("status", "dns_query_plugin")
            started_at = time.time()
            self.run_dns_query_plugin()
            task.update_services(
                "dns_query_plugin",
                time.time() - started_at,
                metrics=task._last_dns_query_metrics,
            )

        if task.options.get("arl_search"):
            _run_measured_stage(task, "arl_search", _domain_count_stage(task, self.run_arl_search))

        if task.options.get("alt_dns"):
            _run_measured_stage(task, "alt_dns", _domain_count_stage(task, self.run_alt_dns))

    def run_alt_dns_current(self):
        task = self.task
        primary_domain = utils.get_fld(task.base_domain)
        if primary_domain == task.base_domain or primary_domain == "":
            return []

        fake_info = modules.DomainInfo(
            domain=task.base_domain,
            type="CNAME",
            record=[],
            ips=[],
        )
        logger.info("alt_dns_current {}, primary_domain:{}".format(
            task.base_domain, primary_domain))
        return alt_dns(
            [fake_info],
            primary_domain,
            wildcard_domain_ip=task.not_found_domain_ips,
        )

    def run_alt_dns(self):
        task = self.task
        if task.task_tag == "monitor" and len(task.domain_info_list) >= 800:
            logger.info("skip alt_dns on monitor {}".format(task.base_domain))
            return

        if len(task.domain_info_list) > 300 and len(task.not_found_domain_ips) > 0:
            logger.warning("{} 域名泛解析, 当前子域名{}, 大于300, 不进行alt_dns".format(
                task.base_domain, len(task.domain_info_list)))
            return

        alt_dns_current_out = self.run_alt_dns_current()
        alt_dns_out = alt_dns(
            task.domain_info_list,
            task.base_domain,
            wildcard_domain_ip=task.not_found_domain_ips,
        )
        alt_dns_out.extend(alt_dns_current_out)
        if len(alt_dns_out) <= 0:
            return

        task.add_domain_source_names(alt_dns_out, CollectSource.ALTDNS)
        alt_domain_info_list = task.build_domain_info(alt_dns_out)
        if task.task_tag == "task":
            alt_domain_info_list = task.clear_domain_info_by_record(alt_domain_info_list)
            logger.info("alt_dns real result:{}".format(len(alt_domain_info_list)))
            if len(alt_domain_info_list) > 0:
                task.save_domain_info_list(
                    alt_domain_info_list,
                    source=CollectSource.ALTDNS,
                )

        task.add_domain_source_map(alt_domain_info_list, CollectSource.ALTDNS)
        task.domain_info_list.extend(alt_domain_info_list)

    @staticmethod
    def _chunk_list(items, chunk_size):
        try:
            size = int(chunk_size)
        except Exception:
            size = 0

        if size <= 0:
            size = len(items) if items else 1

        for index in range(0, len(items), size):
            yield items[index:index + size]

    @staticmethod
    def _format_timeout(timeout_sec):
        if int(timeout_sec or 0) <= 0:
            return "unlimited"
        return "{}s".format(int(timeout_sec))

    @staticmethod
    def _calc_dns_query_plugin_stage_timeout(source_count):
        """按来源数量计算 DNS 插件阶段预算。"""

        base = int(getattr(Config, "DNS_QUERY_PLUGIN_STAGE_TIMEOUT_SEC", 0) or 0)
        per_source = int(
            getattr(Config, "DNS_QUERY_PLUGIN_STAGE_TIMEOUT_PER_SOURCE_SEC", 0) or 0
        )
        max_budget = int(
            getattr(Config, "DNS_QUERY_PLUGIN_STAGE_TIMEOUT_MAX_SEC", 0) or 0
        )

        if base < 0:
            base = 0
        if per_source < 0:
            per_source = 0
        if max_budget < 0:
            max_budget = 0

        if base <= 0 and per_source <= 0:
            return 0

        budget = base
        if source_count > 0 and per_source > 0:
            budget += int(source_count) * per_source

        if max_budget > 0:
            budget = min(budget, max_budget)

        if budget <= 0:
            return 0
        return budget

    def _resolve_dns_query_sources(self):
        """解析可执行的 DNS 查询来源并过滤无效配置。"""

        plugins = utils.load_query_plugins(Config.dns_query_plugin_path)
        query_key = Config.QUERY_PLUGIN_CONFIG if isinstance(Config.QUERY_PLUGIN_CONFIG, dict) else {}

        source_list = []
        seen = set()
        for plugin in plugins:
            source_name = str(getattr(plugin, "source_name", "") or "").strip()
            if not source_name or source_name in seen:
                continue
            seen.add(source_name)

            source_conf = query_key.get(source_name)
            if isinstance(source_conf, dict):
                if source_conf.get("enable", None) is False:
                    continue

                required_fields = {
                    key: value
                    for key, value in source_conf.items()
                    if key != "enable"
                }
                if required_fields and not all(required_fields.values()):
                    miss_keys = [k for k, v in required_fields.items() if not v]
                    logger.warning(
                        "skip dns query source {} because required config missing:{}".format(
                            source_name, ",".join(miss_keys)
                        )
                    )
                    continue

            source_list.append(source_name)

        return source_list

    def _compat_resolve_dns_query_sources(self):
        resolver = getattr(self.task, "_resolve_dns_query_sources", None)
        if callable(resolver):
            return resolver()
        return self._resolve_dns_query_sources()

    def _compat_calc_dns_query_plugin_stage_timeout(self, source_count):
        calculator = getattr(self.task, "_calc_dns_query_plugin_stage_timeout", None)
        if callable(calculator):
            return calculator(source_count)
        return self._calc_dns_query_plugin_stage_timeout(source_count)

    def _compat_chunk_list(self, items, chunk_size):
        chunker = getattr(self.task, "_chunk_list", None)
        if callable(chunker):
            return chunker(items, chunk_size)
        return self._chunk_list(items, chunk_size)

    def _compat_format_timeout(self, timeout_sec):
        formatter = getattr(self.task, "_format_timeout", None)
        if callable(formatter):
            return formatter(timeout_sec)
        return self._format_timeout(timeout_sec)

    def _run_query_plugin(self, target, source_batch):
        runner = getattr(self.task, "_run_query_plugin", None)
        if callable(runner):
            return runner(target, source_batch)
        return run_query_plugin(target, source_batch)

    def run_dns_query_plugin(self):
        """执行 DNS 查询插件阶段，保留旧入口的预算与异常边界。"""

        task = self.task
        source_list = self._compat_resolve_dns_query_sources()
        stage_timeout_sec = self._compat_calc_dns_query_plugin_stage_timeout(len(source_list))
        with stage_execution_context("dns_query_plugin", stage_timeout_sec):
            return self._run_dns_query_plugin_impl()

    def _run_dns_query_plugin_impl(self):
        task = self.task
        logger.info("start run dns_query_plugin {}".format(task.base_domain))
        task._last_dns_query_metrics = {}
        source_batch_size = int(
            getattr(Config, "DOMAIN_DNS_QUERY_PLUGIN_SOURCE_BATCH_SIZE", 4) or 4
        )
        if source_batch_size <= 0:
            source_batch_size = 1

        source_list = self._compat_resolve_dns_query_sources()
        if not source_list:
            logger.warning("dns_query_plugin {} no available source".format(task.base_domain))
            return
        stage_timeout_sec = self._compat_calc_dns_query_plugin_stage_timeout(len(source_list))
        validation_batch_size = int(
            getattr(Config, "DNS_QUERY_PLUGIN_DOMAIN_BATCH_SIZE", 100) or 100
        )
        if validation_batch_size <= 0:
            validation_batch_size = 100

        source_batches = list(self._compat_chunk_list(source_list, source_batch_size))
        aggregate_metrics = {
            "input_count": 0,
            "output_count": 0,
            "provider_count": 0,
            "provider_success_count": 0,
            "failed_count": 0,
            "degraded_count": 0,
            "dedup_count": 0,
            "request_count": 0,
            "timeout_count": 0,
            "retry_count": 0,
            "network_wait_sec": 0.0,
            "provider_status": [],
        }
        logger.info(
            "dns_query_plugin timeout_budget:{} sources:{} batches:{} batch_size:{}".format(
                self._compat_format_timeout(stage_timeout_sec),
                len(source_list),
                len(source_batches),
                source_batch_size,
            )
        )
        stage_start = time.time()
        seen_result = set()
        results = []
        for idx, source_batch in enumerate(source_batches, start=1):
            elapsed = time.time() - stage_start
            if stage_timeout_sec > 0 and elapsed >= stage_timeout_sec:
                logger.warning(
                    "dns_query_plugin stage timeout {} elapsed:{:.2f}s timeout:{}s finished_batch:{}/{}".format(
                        task.base_domain, elapsed, stage_timeout_sec, idx - 1, len(source_batches)
                    )
                )
                break

            logger.info(
                "dns_query_plugin source batch start {} {}/{} sources:{} elapsed:{:.2f}s".format(
                    task.base_domain, idx, len(source_batches), ",".join(source_batch), elapsed
                )
            )
            batch_results = self._run_query_plugin(task.base_domain, source_batch)
            batch_metrics = dict(getattr(batch_results, "metrics", {}) or {})
            for key in (
                "input_count",
                "output_count",
                "provider_count",
                "provider_success_count",
                "failed_count",
                "degraded_count",
                "dedup_count",
                "request_count",
                "timeout_count",
                "retry_count",
            ):
                aggregate_metrics[key] += int(batch_metrics.get(key, 0) or 0)
            aggregate_metrics["network_wait_sec"] += float(
                batch_metrics.get("network_wait_sec", 0.0) or 0.0
            )
            aggregate_metrics["provider_status"].extend(
                list(batch_metrics.get("provider_status") or [])
            )
            for result in batch_results:
                domain = str(result.get("domain", "")).strip()
                source = str(result.get("source", "")).strip()
                if not domain or not source:
                    continue
                uniq_key = "{}|{}".format(domain, source)
                if uniq_key in seen_result:
                    continue
                seen_result.add(uniq_key)
                results.append({"domain": domain, "source": source})
            logger.info(
                "dns_query_plugin source batch end {} {}/{} source_result:{} merged_result:{}".format(
                    task.base_domain, idx, len(source_batches), len(batch_results), len(results)
                )
            )

        domain_sources = {}
        primary_source_map = {}
        for result in results:
            domain = utils.normalize_domain(result.get("domain", ""))
            source = str(result.get("source", "")).strip()
            if not domain or not source:
                continue
            domain_sources.setdefault(domain, set()).add(source)
            primary_source_map.setdefault(domain, source)

        # 先按来源写入关系，再按域名只执行一次 DNS 校验。
        source_domains_map = {}
        for domain, source_set in domain_sources.items():
            for source in source_set:
                source_domains_map.setdefault(source, []).append(domain)
        for source, source_domains in source_domains_map.items():
            task.add_domain_source_names(source_domains, source)

        unique_domains = list(domain_sources)
        domain_dedup_count = max(len(results) - len(unique_domains), 0)
        logger.info(
            "dns_query_plugin domain validation start {} source_relations:{} unique_domains:{} dedup:{}".format(
                task.base_domain,
                len(results),
                len(unique_domains),
                domain_dedup_count,
            )
        )

        cnt = 0
        validation_batch_count = 0
        validation_batch_total = (
            (len(unique_domains) + validation_batch_size - 1) // validation_batch_size
            if unique_domains
            else 0
        )
        for batch_index, domain_batch in enumerate(
            self._compat_chunk_list(unique_domains, validation_batch_size), start=1
        ):
            batch_started = time.time()
            domain_info_list = task.build_domain_info(domain_batch)
            if task.task_tag == "task":
                domain_info_list = task.clear_domain_info_by_record(domain_info_list)

                # 按首次来源分组保存，保证每个域名只 upsert 一次，同时保留完整 sources。
                info_by_primary_source = {}
                for info in domain_info_list:
                    domain = utils.normalize_domain(getattr(info, "domain", ""))
                    source = primary_source_map.get(domain, "")
                    if source:
                        info_by_primary_source.setdefault(source, []).append(info)
                for source, source_infos in info_by_primary_source.items():
                    task.save_domain_info_list(source_infos, source=source)

                self.register_dns_domain_candidates(domain_info_list)

            cnt += len(domain_info_list)
            task.domain_info_list.extend(domain_info_list)
            validation_batch_count += 1
            logger.info(
                "dns_query_plugin domain validation batch {} {}/{} input:{} output:{} elapsed:{:.2f}s".format(
                    task.base_domain,
                    batch_index,
                    validation_batch_total,
                    len(domain_batch),
                    len(domain_info_list),
                    time.time() - batch_started,
                )
            )

        logger.info(
            "dns_query_plugin domain validation end {} input:{} output:{} pending:0".format(
                task.base_domain,
                len(unique_domains),
                cnt,
            )
        )

        logger.info(
            "end run dns_query_plugin {}, result {}, real result:{}".format(
                task.base_domain, len(results), cnt
            )
        )
        aggregate_metrics["output_count"] = len(results)
        aggregate_metrics["unique_domain_count"] = len(domain_sources)
        aggregate_metrics["domain_dedup_count"] = domain_dedup_count
        aggregate_metrics["dns_validation_input_count"] = len(domain_sources)
        aggregate_metrics["dns_validation_output_count"] = cnt
        aggregate_metrics["dns_validation_batch_count"] = validation_batch_count
        aggregate_metrics["dns_validation_pending_count"] = 0
        aggregate_metrics["network_wait_sec"] = round(
            aggregate_metrics["network_wait_sec"], 6
        )
        task._last_dns_query_metrics = aggregate_metrics

    def register_dns_domain_candidates(self, domain_info_list):
        """将完成 DNS 校验的域名登记为统一主机候选。"""

        task = self.task
        context = getattr(task, "discovery_context", None)
        if context is None:
            return

        source_map = getattr(task, "domain_source_map", {}) or {}
        for info in domain_info_list or []:
            domain = utils.normalize_domain(getattr(info, "domain", ""))
            if not domain:
                continue
            sources = sorted(
                str(source or "").strip()
                for source in source_map.get(domain, set())
                if str(source or "").strip()
            )
            if not sources:
                sources = ["dns_query_plugin"]
            for source in sources:
                try:
                    context.register_candidate(
                        event_type="NewHostDiscovered",
                        candidate=domain,
                        candidate_type="host",
                        source=source,
                        status="discovered",
                        metadata={"stage": "dns_query_plugin"},
                    )
                except Exception as exc:
                    logger.debug(
                        "dns domain candidate register failed domain:{} error_type:{}".format(
                            domain, type(exc).__name__
                        )
                    )

    def run_search_engines(self):
        """执行搜索引擎发现并把页面证据接入统一上下文。"""

        task = self.task
        if not task.options.get("search_engines") or "{fuzz}" in task.base_domain:
            return

        task.update_task_field("status", "search_engines")
        started_at = time.time()
        search_engines_urls = search_engines(task.base_domain)
        search_engine_metrics = dict(getattr(search_engines_urls, "metrics", {}) or {})

        urls = set()
        domains = set()
        for url in search_engines_urls:
            parsed = urlparse(url)
            netloc_domain = utils.normalize_domain(parsed.netloc.split(":")[0])
            if not netloc_domain:
                continue
            if not (
                netloc_domain.endswith("." + task.base_domain)
                or task.base_domain == netloc_domain
            ):
                continue
            domains.add(netloc_domain)
            # 首页只作为站点种子，不进入 URL 结果面，保持历史结果语义。
            if parsed.path in ("", "/"):
                continue
            urls.add(url)

        domain_info_list = []
        if domains:
            task.add_domain_source_names(domains, CollectSource.SEARCHENGINE)
            domain_info_list = task.build_domain_info(domains)
            if task.task_tag == "task":
                domain_info_list = task.clear_domain_info_by_record(domain_info_list)
                task.save_domain_info_list(
                    domain_info_list,
                    source=CollectSource.SEARCHENGINE,
                )
            task.add_domain_source_map(domain_info_list, CollectSource.SEARCHENGINE)
            task.domain_info_list.extend(domain_info_list)

        task.update_services(
            "search_engines",
            time.time() - started_at,
            metrics=search_engine_metrics,
        )
        logger.info(
            "search_engines {} result domain:{} url:{}".format(
                task.base_domain,
                len(domain_info_list),
                len(urls),
            )
        )

        if not urls:
            return

        # 页面获取必须带任务上下文，避免搜索结果绕过响应复用、流量类别调度
        # 和 WAF 隔离；失败候选留给后续 url_probe 显式收口。
        page_map = services.page_fetch(
            urls,
            discovery_context=getattr(task, "discovery_context", None),
            traffic_class="crawler",
        )
        self.register_search_page_candidates(urls, page_map)
        from app.services.commonTask import build_url_item

        for url in page_map:
            item = build_url_item(url, task.task_id, source=CollectSource.SEARCHENGINE)
            item.update(page_map[url])
            _task_result_writer(task).insert_one("url", item)

    def register_search_page_candidates(self, urls, page_map):
        """将搜索结果页面登记为统一候选，保留失败候选的后续处理入口。"""

        task = self.task
        context = getattr(task, "discovery_context", None)
        if context is None:
            return
        fetched = set(page_map or {})
        for url in urls:
            try:
                context.register_candidate(
                    event_type="UrlCandidateDiscovered",
                    candidate=url,
                    candidate_type="page",
                    source="search_engine",
                    status="fetched" if url in fetched else "discovered",
                    metadata={"collect_source": str(CollectSource.SEARCHENGINE)},
                )
            except Exception as exc:
                logger.debug(
                    "search page candidate register failed error_type:%s",
                    type(exc).__name__,
                )


class DomainNetworkStageService(object):
    """执行 IP 映射、端口、证书关联和 IP 结果保存。"""

    def __init__(self, task):
        self.task = task

    def run_port_scan(self):
        task = self.task
        ip_info_list = scan_port(task.domain_info_list, task.scan_port_option)
        task._last_port_scan_metrics = dict(getattr(ip_info_list, "metrics", {}) or {})

        for ip_info_obj in ip_info_list:
            ip_info = ip_info_obj.dump_json(flag=False)
            ip_info["task_id"] = task.task_id
            _task_result_writer(task).update_one(
                "ip",
                {"task_id": task.task_id, "ip": ip_info_obj.ip},
                {"$set": ip_info},
                upsert=True,
            )

        task.ip_info_list.extend(ip_info_list)
        return ip_info_list

    def run_ssl_cert(self):
        task = self.task
        if task.options.get("port_scan"):
            task.cert_map = ssl_cert(task.ip_info_list, task.base_domain)
        else:
            fake_targets = []
            for ip in sorted(task.ip_set):
                domains = list(task.ipv4_map.get(ip, set()))
                fake_targets.append(
                    modules.IPInfo(
                        ip=ip,
                        domain=domains,
                        port_info=[modules.PortInfo(port_id=443, service_name="https")],
                        os_info={},
                        cdn_name="",
                    )
                )
            task.cert_map = ssl_cert(fake_targets, task.base_domain)

        sni_success_endpoints = set()
        for target in task.cert_map:
            cert_obj = task.cert_map.get(target, {})
            if not isinstance(cert_obj, dict):
                continue

            cert_data = dict(cert_obj)
            scan_meta = cert_data.pop("_scan_meta", {})
            if not isinstance(scan_meta, dict):
                scan_meta = {}

            endpoint = str(scan_meta.get("endpoint", "")).strip() or str(target).strip()
            ip, port = fetchCert.split_host_port(endpoint)
            if not ip or port <= 0:
                continue

            scan_mode = str(scan_meta.get("scan_mode", "default") or "default").strip().lower()
            if scan_mode != "sni":
                continue

            sni_domain = utils.normalize_domain(scan_meta.get("sni_domain", ""))
            legacy_server_name = utils.normalize_domain(scan_meta.get("server_name", ""))
            if not sni_domain:
                sni_domain = legacy_server_name
            if not sni_domain:
                continue

            domains = fetchCert.normalize_domains(scan_meta.get("domains", []))
            if sni_domain not in domains:
                domains = fetchCert.normalize_domains(domains + [sni_domain])

            matched_domains = fetchCert.match_cert_domains(cert_data, domains)
            if domains and not matched_domains:
                continue
            if matched_domains and sni_domain not in matched_domains:
                continue

            sni_success_endpoints.add(endpoint)

        for target in task.cert_map:
            cert_obj = task.cert_map.get(target, {})
            if not isinstance(cert_obj, dict):
                continue

            cert_data = dict(cert_obj)
            scan_meta = cert_data.pop("_scan_meta", {})
            if not isinstance(scan_meta, dict):
                scan_meta = {}

            endpoint = str(scan_meta.get("endpoint", "")).strip() or str(target).strip()
            ip, port = fetchCert.split_host_port(endpoint)
            if not ip or port <= 0:
                continue

            scan_mode = str(scan_meta.get("scan_mode", "default") or "default").strip().lower()
            if scan_mode not in ["default", "sni"]:
                scan_mode = "default"

            if scan_mode == "default" and endpoint in sni_success_endpoints:
                continue

            sni_domain = utils.normalize_domain(scan_meta.get("sni_domain", ""))
            legacy_server_name = utils.normalize_domain(scan_meta.get("server_name", ""))
            if not sni_domain and scan_mode == "sni":
                sni_domain = legacy_server_name

            domains = fetchCert.normalize_domains(scan_meta.get("domains", []))
            if sni_domain and sni_domain not in domains:
                domains = fetchCert.normalize_domains(domains + [sni_domain])

            matched_domains = fetchCert.match_cert_domains(cert_data, domains)
            if domains and not matched_domains:
                continue

            if scan_mode == "sni" and sni_domain and matched_domains and sni_domain not in matched_domains:
                continue

            domains = matched_domains if matched_domains else domains
            if scan_mode == "sni" and sni_domain and sni_domain in domains:
                domain = sni_domain
            elif domains:
                domain = domains[0]
            else:
                domain = ""

            fingerprint = cert_data.get("fingerprint", {})
            if not isinstance(fingerprint, dict):
                fingerprint = {}
            cert_sha256 = str(fingerprint.get("sha256", "")).strip().lower().replace(":", "")
            cert_sha1 = str(fingerprint.get("sha1", "")).strip().lower().replace(":", "")
            serial_number = str(cert_data.get("serial_number", "")).strip().lower().replace(" ", "")
            cert_identity_key = cert_sha256 or cert_sha1 or serial_number or ""

            validity = cert_data.get("validity", {})
            if not isinstance(validity, dict):
                validity = {}
            cert_end_time = str(validity.get("end", "")).strip()
            observe_id = str(scan_meta.get("observe_id", "")).strip()

            item = {
                "ip": ip,
                "port": port,
                "host": endpoint,
                "domain": domain,
                "domains": domains,
                "sni_domain": sni_domain,
                "scan_mode": scan_mode,
                "observe_id": observe_id,
                "cert_identity_key": cert_identity_key,
                "cert_end_time": cert_end_time,
                "cert": cert_data,
                "task_id": task.task_id,
            }

            query = {
                "task_id": task.task_id,
                "ip": ip,
                "port": port,
                "scan_mode": scan_mode,
                "sni_domain": sni_domain,
            }
            if cert_identity_key:
                query["cert_identity_key"] = cert_identity_key
            if cert_end_time:
                query["cert_end_time"] = cert_end_time
            if not cert_identity_key and not cert_end_time:
                query["observe_id"] = observe_id or endpoint

            _task_result_writer(task).update_one(
                "cert", query, {"$setOnInsert": item}, upsert=True
            )

    def run_gen_ipv4_map(self):
        task = self.task
        ipv4_map = {}
        for domain_info in task.domain_info_list:
            for ip in domain_info.ip_list:
                domains = ipv4_map.setdefault(ip, set())
                domains.add(domain_info.domain)
                task.ip_set.add(ip)
        task.ipv4_map = ipv4_map

    def run_save_ip_info(self):
        task = self.task
        fake_ip_info_list = []
        for ip, domains in task.ipv4_map.items():
            data = {
                "ip": ip,
                "domain": list(domains),
                "port_info": [],
                "os_info": {},
                "cdn_name": utils.get_cdn_name_by_ip(ip),
            }
            info_obj = modules.IPInfo(**data)
            if info_obj not in task.ip_info_list:
                fake_ip_info_list.append(info_obj)

        for ip_info_obj in fake_ip_info_list:
            ip_info = ip_info_obj.dump_json(flag=False)
            ip_info["task_id"] = task.task_id
            _task_result_writer(task).update_one(
                "ip",
                {"task_id": task.task_id, "ip": ip_info_obj.ip},
                {"$set": ip_info},
                upsert=True,
            )

    def run_save_service_info(self):
        task = self.task
        task.service_info_list = []
        service_map = {}
        service_seen = set()
        port_total = 0
        merged_total = 0
        nmap_merged = 0
        npoc_merged = 0

        def _append_item(service_name, ip, port_id, product="", version="", source="",
                         npoc_scheme="", proto="tcp"):
            nonlocal merged_total, nmap_merged, npoc_merged
            service_result = resolve_service_result(
                service_name=service_name,
                product=product,
                npoc_scheme=npoc_scheme,
                port=port_id,
                proto=proto,
                use_registry=True,
            )
            service = str(service_result.get("service") or "").strip()
            if not service or (
                not service_result.get("confirmed")
                and list(service_result.get("sources") or []) == ["port_only"]
            ):
                return

            ip = str(ip or "").strip()
            if not ip:
                return

            try:
                port_id = int(port_id)
            except Exception:
                return

            uniq_key = (service, ip, port_id)
            if uniq_key in service_seen:
                return
            service_seen.add(uniq_key)

            service_map.setdefault(service, [])
            normalized_product = str(product or "").strip()
            if not normalized_product:
                normalized_product = service
            service_info = {
                "ip": ip,
                "port_id": port_id,
                "product": normalized_product,
                "version": str(version or "").strip(),
                "service_confidence": service_result.get("confidence", 0),
                "service_sources": list(service_result.get("sources") or []),
            }
            if service_result.get("conflict"):
                service_info["service_conflict"] = service_result["conflict"]
            service_map[service].append(service_info)
            merged_total += 1
            if source == "nmap":
                nmap_merged += 1
            elif source == "npoc":
                npoc_merged += 1

        for ip_item in task.ip_info_list:
            port_info_list = getattr(ip_item, "port_info_list", [])
            for port_item in port_info_list:
                port_total += 1
                _append_item(
                    service_name=getattr(port_item, "service_name", ""),
                    ip=getattr(ip_item, "ip", ""),
                    port_id=getattr(port_item, "port_id", None),
                    product=getattr(port_item, "product", ""),
                    version=getattr(port_item, "version", ""),
                    source="nmap",
                    proto=getattr(port_item, "protocol", "tcp"),
                )

        for item in utils.conn_db("npoc_service").find({"task_id": task.task_id}):
            _append_item(
                service_name=item.get("scheme", ""),
                ip=item.get("host", ""),
                port_id=item.get("port", None),
                product=item.get("scheme", ""),
                version=item.get("version", ""),
                source="npoc",
                npoc_scheme=item.get("scheme", ""),
                proto=item.get("protocol", item.get("proto", "tcp")),
            )

        for service_name, info_list in service_map.items():
            task.service_info_list.append({
                "service_name": service_name,
                "service_info": info_list,
                "task_id": task.task_id,
            })

        writer = _task_result_writer(task)
        writer.delete_many("service", {"task_id": task.task_id})
        if task.service_info_list:
            writer.insert_many("service", task.service_info_list)

        logger.info(
            "save_service_info task_id:{} ports:{} merged:{} nmap:{} npoc:{} service_group:{}".format(
                task.task_id,
                port_total,
                merged_total,
                nmap_merged,
                npoc_merged,
                len(task.service_info_list),
            )
        )

    def get_ip_pivot_candidates(self):
        task = self.task
        seen_ips = getattr(task, "_asset_pivot_seen_ips", set())
        ip_map = {}
        skip_non_a = 0
        skip_non_public = 0
        skip_black = 0
        skip_cdn = 0
        for domain_info in task.domain_info_list:
            if domain_info.type != "A":
                skip_non_a += 1
                continue

            for ip in domain_info.ip_list:
                ip = str(ip or "").strip()
                if not ip or not utils.is_vaild_ip_target(ip):
                    continue

                if utils.get_ip_type(ip) != "PUBLIC":
                    skip_non_public += 1
                    continue

                if not utils.not_in_black_ips(ip):
                    skip_black += 1
                    continue

                if Config.IP_PIVOT_QUERY_SKIP_CDN and utils.get_cdn_name_by_ip(ip):
                    skip_cdn += 1
                    continue

                if ip in seen_ips:
                    continue

                ip_map.setdefault(ip, set()).add(domain_info.domain)

        all_ips = sorted(ip_map.keys())
        max_ips = max(int(Config.IP_PIVOT_QUERY_MAX_IPS or 0), 0)
        if max_ips > 0:
            remaining = max(max_ips - len(seen_ips), 0)
            if len(all_ips) > remaining:
                all_ips = all_ips[:remaining]

        logger.info(
            "ip pivot candidate total:{} selected:{} skip_non_a:{} skip_non_public:{} skip_black:{} skip_cdn:{}".format(
                len(ip_map), len(all_ips), skip_non_a, skip_non_public, skip_black, skip_cdn
            )
        )
        return all_ips

    def _limit_asset_domain_map(self, sources_map):
        """跨多轮共享新增域名预算，达到上限后保留候选而不再主动扩展。"""
        task = self.task
        seen = getattr(task, "_asset_pivot_domains", set())
        max_domains = max(
            int(getattr(Config, "ASSET_DISCOVERY_MAX_DOMAINS", 200) or 200),
            0,
        )
        limited = {}
        for source in sorted(sources_map):
            for domain in sorted(sources_map[source]):
                if domain in seen:
                    continue
                if max_domains > 0 and len(seen) >= max_domains:
                    task._asset_pivot_budget_exhausted = True
                    continue
                limited.setdefault(source, {})[domain] = sources_map[source][domain]
                seen.add(domain)
        task._asset_pivot_domains = seen
        return limited

    def run_ip_query_plugin_enhance(self):
        task = self.task
        if not Config.IP_PIVOT_QUERY_ENABLE:
            return 0
        if not task.options.get("dns_query_plugin"):
            logger.info("skip ip_query_plugin_enhance because dns_query_plugin=false")
            return 0
        if "{fuzz}" in task.base_domain:
            return 0

        candidate_ips = self.get_ip_pivot_candidates()
        if not candidate_ips:
            logger.info("skip ip_query_plugin_enhance because no candidate ip")
            return 0
        if not hasattr(task, "_asset_pivot_seen_ips"):
            task._asset_pivot_seen_ips = set()
        task._asset_pivot_seen_ips.update(candidate_ips)

        target_domain = task.base_domain if Config.IP_PIVOT_QUERY_REQUIRE_SCOPE else ""
        max_domains = int(Config.IP_PIVOT_QUERY_MAX_DOMAINS or 0)
        logger.info(
            "start run ip_query_plugin_enhance base_domain_hash:{} ip:{} source_mode:auto-enabled require_scope:{} max_domains:{}".format(
                domain_log_summary(task.base_domain),
                len(candidate_ips),
                bool(Config.IP_PIVOT_QUERY_REQUIRE_SCOPE),
                max_domains,
            )
        )

        try:
            results = run_query_plugin_by_ip(
                ip_list=candidate_ips,
                target_domain=target_domain,
                max_domains=max_domains,
            )
        except Exception as exc:
            task._last_ip_query_metrics = {
                "status": "partial",
                "provider_failed": 1,
                "end_reason": "provider_failed",
            }
            logger.error(
                "ip pivot provider failed base_domain_hash:{} error:{}".format(
                    domain_log_summary(task.base_domain), safe_error_text(exc)
                )
            )
            return 0
        task._last_ip_query_metrics = dict(getattr(results, "metrics", {}) or {})
        if not results:
            logger.info(
                "end run ip_query_plugin_enhance base_domain_hash:{} result:0".format(
                    domain_log_summary(task.base_domain)
                )
            )
            return 0

        sources_map = {}
        accepted_result_count = 0
        evidence_count = 0
        seen_relations = set()
        for result in results:
            if not isinstance(result, dict):
                continue
            pivot_ip = str(result.get("pivot_ip") or "").strip()
            source = str(result.get("source") or "provider").strip() or "provider"
            relation_key = (
                source,
                utils.normalize_domain(result.get("domain")),
                pivot_ip,
            )
            if relation_key in seen_relations:
                continue
            seen_relations.add(relation_key)
            decision = validate_domain_binding(
                result.get("domain"),
                pivot_ips=[pivot_ip],
                scopes=task.get_scope_domain_list()
                if Config.IP_PIVOT_QUERY_REQUIRE_SCOPE
                else [],
                require_ip_match=bool(
                    getattr(Config, "ASSET_DISCOVERY_REQUIRE_IP_MATCH", True)
                ),
            )
            write_pivot_evidence(
                task,
                candidate_type="domain",
                value=result.get("domain"),
                source="{}_ip_pivot".format(source),
                decision=decision,
                pivot_ip=pivot_ip,
                cdn_waf=should_skip_cdn_waf(pivot_ip, task),
            )
            if decision.get("status") != "accepted":
                evidence_count += 1
                continue
            accepted_result_count += 1
            sources_map.setdefault(source, {}).setdefault(
                decision["domain"], set()
            ).update(decision.get("matched_ips") or [pivot_ip])

        sources_map = self._limit_asset_domain_map(sources_map)
        count = 0
        for source, domain_ip_map in sources_map.items():
            source_domains = list(domain_ip_map.keys())
            if not source_domains:
                continue

            source_name = "{}_ip_pivot".format(source)
            task.add_domain_source_names(source_domains, source_name)
            logger.info("start build domain info, source:{}".format(source_name))
            domain_info_list = task.build_domain_info(source_domains)
            if task.task_tag == "task":
                domain_info_list = task.clear_domain_info_by_record(domain_info_list)
                if domain_info_list:
                    task.save_domain_info_list(domain_info_list, source=source_name)

            task.add_domain_source_map(domain_info_list, source_name)
            count += len(domain_info_list)
            task.domain_info_list.extend(domain_info_list)

        logger.info(
            "end run ip_query_plugin_enhance base_domain_hash:{}, source_result:{}, accepted_result:{}, evidence_only:{}, real_result:{}".format(
                domain_log_summary(task.base_domain),
                len(results),
                accepted_result_count,
                evidence_count,
                count,
            )
        )
        return count

    def run_incremental_port_scan_for_new_ips(self):
        task = self.task
        scanned_ip_set = {ip_info.ip for ip_info in task.ip_info_list}
        new_ips = [ip for ip in sorted(task.ipv4_map) if ip not in scanned_ip_set]
        if not new_ips:
            return 0

        domain_ip_map = {}
        for ip in new_ips:
            for domain in task.ipv4_map.get(ip, set()):
                domain_ip_map.setdefault(domain, set()).add(ip)

        new_domain_info_list = []
        for domain, ip_set in domain_ip_map.items():
            ips = sorted(ip_set)
            if ips:
                new_domain_info_list.append(modules.DomainInfo(
                    domain=domain,
                    type="A",
                    record=ips,
                    ips=ips,
                ))

        if not new_domain_info_list:
            return 0

        ip_info_list = scan_port(new_domain_info_list, task.scan_port_option)
        for ip_info_obj in ip_info_list:
            ip_info = ip_info_obj.dump_json(flag=False)
            ip_info["task_id"] = task.task_id
            _task_result_writer(task).update_one(
                "ip",
                {"task_id": task.task_id, "ip": ip_info_obj.ip},
                {"$set": ip_info},
                upsert=True,
            )

        task.ip_info_list.extend(ip_info_list)
        logger.info(
            "cert pivot incremental port_scan new_ip:{} result:{}".format(
                len(new_ips), len(ip_info_list)
            )
        )
        return len(ip_info_list)

    def run_sync_ip_domain_from_ipv4_map(self):
        task = self.task
        for ip_info_obj in task.ip_info_list:
            domain_set = task.ipv4_map.get(ip_info_obj.ip, set())
            if not domain_set:
                continue

            merged_domain = sorted(set(ip_info_obj.domain) | set(domain_set))
            if merged_domain == ip_info_obj.domain:
                continue

            ip_info_obj.domain = merged_domain
            _task_result_writer(task).update_one(
                "ip",
                {"task_id": task.task_id, "ip": ip_info_obj.ip},
                {"$set": {"domain": merged_domain}},
            )

    def get_scope_domain_list(self):
        task = self.task
        scope_domains = [task.base_domain]
        primary_domain = utils.get_fld(task.base_domain)
        if primary_domain and primary_domain not in scope_domains:
            scope_domains.append(primary_domain)
        return scope_domains

    @staticmethod
    def normalize_cert_domain(value):
        if str(value or "").strip().startswith("*."):
            return ""
        domain = utils.normalize_domain(value)
        if (
            not domain
            or not utils.is_valid_domain(domain)
            or is_public_suffix(domain)
        ):
            return ""
        return domain

    def extract_cert_domain_candidates(self, cert_obj):
        domains = set()
        if not isinstance(cert_obj, dict):
            return []

        subject = cert_obj.get("subject") or {}
        issuer = cert_obj.get("issuer") or {}
        subject_cn = self.normalize_cert_domain(subject.get("common_name"))
        if subject_cn:
            domains.add(subject_cn)
        issuer_cn = self.normalize_cert_domain(issuer.get("common_name"))
        if issuer_cn:
            domains.add(issuer_cn)

        extensions = cert_obj.get("extensions") or {}
        san_text = str(extensions.get("subjectAltName") or "").strip()
        if san_text:
            for raw_item in san_text.split(","):
                raw_item = raw_item.strip()
                if not raw_item:
                    continue
                if ":" in raw_item:
                    prefix, value = raw_item.split(":", 1)
                    if prefix.strip().lower() != "dns":
                        continue
                    domain = self.normalize_cert_domain(value)
                else:
                    domain = self.normalize_cert_domain(raw_item)
                if domain:
                    domains.add(domain)
        return sorted(domains)

    def match_cert_scope_domains(self, cert_obj):
        cert_domains = self.extract_cert_domain_candidates(cert_obj)
        if not cert_domains:
            return []

        matched = []
        for cert_domain in cert_domains:
            if any(
                utils.is_in_scope(cert_domain, scope_domain)
                for scope_domain in self.get_scope_domain_list()
            ):
                matched.append(cert_domain)
        return sorted(set(matched))

    @staticmethod
    def build_cert_pivot_key(cert_obj):
        if not isinstance(cert_obj, dict):
            return ""

        serial_number = str(cert_obj.get("serial_number") or "").strip()
        fingerprint = cert_obj.get("fingerprint") or {}
        cert_sha1 = ""
        if isinstance(fingerprint, dict):
            cert_sha1 = str(fingerprint.get("sha1") or "").strip().lower()

        if serial_number and cert_sha1:
            return "{}|{}".format(serial_number, cert_sha1)
        if serial_number:
            return "sn:{}".format(serial_number)
        if cert_sha1:
            return "sha1:{}".format(cert_sha1)
        return ""

    def get_cert_pivot_candidates(self):
        task = self.task
        cert_map = task.cert_map if isinstance(task.cert_map, dict) else {}
        if not cert_map:
            return []

        ip_cdn_map = {}
        for ip_info_obj in task.ip_info_list:
            if ip_info_obj.cdn_name:
                ip_cdn_map[ip_info_obj.ip] = ip_info_obj.cdn_name

        skip_cdn = 0
        skip_scope = 0
        skip_no_key = 0
        skip_dup = 0
        seen_cert_key = set()
        seen_cert_key.update(getattr(task, "_asset_pivot_seen_certs", set()))
        candidates = []
        for observe_id in sorted(cert_map.keys()):
            cert_obj = cert_map.get(observe_id)
            if not isinstance(cert_obj, dict):
                continue

            scan_meta = cert_obj.get("_scan_meta", {})
            if not isinstance(scan_meta, dict):
                scan_meta = {}
            endpoint = str(scan_meta.get("endpoint", "")).strip() or str(observe_id)
            curr_ip, _ = fetchCert.split_host_port(endpoint)
            if not curr_ip:
                curr_ip = endpoint.split(":")[0] if ":" in endpoint else endpoint

            if Config.CERT_PIVOT_QUERY_SKIP_CDN:
                cdn_name = ip_cdn_map.get(curr_ip) or utils.get_cdn_name_by_ip(curr_ip)
                if cdn_name:
                    skip_cdn += 1
                    continue

            matched_domains = self.match_cert_scope_domains(cert_obj)
            if not matched_domains:
                skip_scope += 1
                continue

            cert_key = self.build_cert_pivot_key(cert_obj)
            if not cert_key:
                skip_no_key += 1
                continue
            if cert_key in seen_cert_key:
                skip_dup += 1
                continue

            seen_cert_key.add(cert_key)
            candidates.append({
                "cert": cert_obj,
                "cert_key": cert_key,
                "endpoint": endpoint,
                "observe_id": str(observe_id),
                "match_domains": matched_domains,
            })

        max_certs = max(int(Config.CERT_PIVOT_QUERY_MAX_CERTS or 0), 0)
        if not hasattr(task, "_asset_pivot_seen_certs"):
            task._asset_pivot_seen_certs = set()
        if max_certs > 0:
            remaining = max(max_certs - len(task._asset_pivot_seen_certs), 0)
            candidates = candidates[:remaining]
        task._asset_pivot_seen_certs.update(
            item["cert_key"] for item in candidates
        )

        logger.info(
            "cert pivot candidate total:{} selected:{} skip_cdn:{} skip_scope:{} skip_no_key:{} skip_dup:{}".format(
                len(seen_cert_key),
                len(candidates),
                skip_cdn,
                skip_scope,
                skip_no_key,
                skip_dup,
            )
        )
        return candidates

    def run_cert_query_plugin_enhance(self):
        task = self.task
        if not task.options.get("ssl_cert"):
            logger.info("skip cert_query_plugin_enhance because ssl_cert=false")
            return 0
        if "{fuzz}" in task.base_domain:
            return 0

        cert_candidates = []
        if Config.CERT_PIVOT_QUERY_ENABLE and task.options.get("dns_query_plugin"):
            cert_candidates = self.get_cert_pivot_candidates()
        elif not task.options.get("dns_query_plugin"):
            logger.info(
                "skip cert provider query because dns_query_plugin=false; "
                "keep direct certificate identity processing"
            )
        else:
            logger.info(
                "skip cert provider query because CERT_PIVOT_QUERY_ENABLE=false"
            )

        target_domain = task.base_domain if Config.CERT_PIVOT_QUERY_REQUIRE_SCOPE else ""
        max_domains = int(Config.CERT_PIVOT_QUERY_MAX_DOMAINS or 0)
        logger.info(
            "start run cert_query_plugin_enhance base_domain_hash:{} cert:{} "
            "provider_enabled:{} require_scope:{} max_domains:{}".format(
                domain_log_summary(task.base_domain),
                len(cert_candidates),
                bool(cert_candidates),
                bool(Config.CERT_PIVOT_QUERY_REQUIRE_SCOPE),
                max_domains,
            )
        )
        provider_failed = 0
        if cert_candidates:
            try:
                results = run_query_plugin_by_cert(
                    cert_list=cert_candidates,
                    target_domain=target_domain,
                    max_domains=max_domains,
                )
            except Exception as exc:
                provider_failed = 1
                results = []
                logger.error(
                    "cert pivot provider failed base_domain_hash:{} error:{}".format(
                        domain_log_summary(task.base_domain), safe_error_text(exc)
                    )
                )
        else:
            results = []
        task._last_cert_query_metrics = {
            "status": "partial" if provider_failed else "success",
            "provider_failed": provider_failed,
            "end_reason": "provider_failed" if provider_failed else "completed",
        }
        sources_map = {}
        accepted_result_count = 0
        evidence_count = 0
        task._asset_pivot_seen_cert_domains = getattr(
            task, "_asset_pivot_seen_cert_domains", set()
        )
        for observe_id, cert_obj in (
            getattr(task, "cert_map", {}) or {}
        ).items():
            cert_key = certificate_identity(cert_obj) or "observe:{}".format(observe_id)
            scan_meta = cert_obj.get("_scan_meta", {}) if isinstance(cert_obj, dict) else {}
            endpoint = str(scan_meta.get("endpoint") or observe_id).strip()
            pivot_ip = endpoint_ip(endpoint)
            for cert_domain in extract_certificate_domains(cert_obj):
                identity_key = "{}|{}".format(cert_key, cert_domain)
                if not cert_key or identity_key in task._asset_pivot_seen_cert_domains:
                    continue
                task._asset_pivot_seen_cert_domains.add(identity_key)
                if should_skip_cdn_waf(pivot_ip, task):
                    decision = {
                        "domain": cert_domain,
                        "status": "evidence_only",
                        "reason": "cdn_waf_source",
                        "resolved_ips": [],
                        "matched_ips": [],
                    }
                else:
                    decision = validate_domain_binding(
                        cert_domain,
                        pivot_ips=[pivot_ip],
                        scopes=task.get_scope_domain_list()
                        if Config.CERT_PIVOT_QUERY_REQUIRE_SCOPE
                        else [],
                        require_ip_match=bool(
                            getattr(
                                Config,
                                "ASSET_DISCOVERY_REQUIRE_IP_MATCH",
                                True,
                            )
                        ),
                    )
                write_pivot_evidence(
                    task,
                    candidate_type="domain",
                    value=cert_domain,
                    source="certificate_cn_san",
                    decision=decision,
                    pivot_ip=pivot_ip,
                    pivot_endpoint=endpoint,
                    pivot_cert_key=cert_key,
                    cdn_waf=should_skip_cdn_waf(pivot_ip, task),
                )
                if decision.get("status") == "accepted":
                    accepted_result_count += 1
                    sources_map.setdefault("certificate_cn_san", {}).setdefault(
                        cert_domain, set()
                    ).update(decision.get("matched_ips") or [pivot_ip])
                else:
                    evidence_count += 1
        endpoint_map = {
            str(item["cert_key"]): fetchCert.split_host_port(
                item.get("endpoint", "")
            )[0]
            for item in cert_candidates
        }
        seen_relations = set()
        for result in results:
            if not isinstance(result, dict):
                continue
            cert_key = str(result.get("pivot_cert") or "")
            pivot_ip = endpoint_map.get(cert_key, "")
            source = str(result.get("source") or "provider").strip() or "provider"
            relation_key = (
                source,
                cert_key,
                utils.normalize_domain(result.get("domain")),
                pivot_ip,
            )
            if relation_key in seen_relations:
                continue
            seen_relations.add(relation_key)
            decision = validate_domain_binding(
                result.get("domain"),
                pivot_ips=[pivot_ip],
                scopes=task.get_scope_domain_list()
                if Config.CERT_PIVOT_QUERY_REQUIRE_SCOPE
                else [],
                require_ip_match=bool(
                    getattr(Config, "ASSET_DISCOVERY_REQUIRE_IP_MATCH", True)
                ),
            )
            write_pivot_evidence(
                task,
                candidate_type="domain",
                value=result.get("domain"),
                source="{}_cert_pivot".format(source),
                decision=decision,
                pivot_ip=pivot_ip,
                pivot_endpoint=str(
                    next(
                        (
                            item.get("endpoint", "")
                            for item in cert_candidates
                            if str(item.get("cert_key")) == cert_key
                        ),
                        "",
                    )
                ),
                pivot_cert_key=cert_key,
                cdn_waf=should_skip_cdn_waf(pivot_ip, task),
            )
            if decision.get("status") != "accepted":
                evidence_count += 1
                continue
            accepted_result_count += 1
            sources_map.setdefault(source, {}).setdefault(
                decision["domain"], set()
            ).update(decision.get("matched_ips") or [pivot_ip])

        task._last_cert_query_metrics.update({
            "candidate_count": len(cert_candidates),
            "provider_result_count": len(results or []),
            "accepted_result_count": accepted_result_count,
            "evidence_only": evidence_count,
        })
        sources_map = self._limit_asset_domain_map(sources_map)
        count = 0
        for source, domain_ip_map in sources_map.items():
            source_domains = list(domain_ip_map.keys())
            if not source_domains:
                continue

            source_name = (
                source
                if source == "certificate_cn_san"
                else "{}_cert_pivot".format(source)
            )
            task.add_domain_source_names(source_domains, source_name)
            logger.info("start build domain info, source:{}".format(source_name))
            domain_info_list = task.build_domain_info(source_domains)
            if task.task_tag == "task":
                domain_info_list = task.clear_domain_info_by_record(domain_info_list)
                if domain_info_list:
                    task.save_domain_info_list(domain_info_list, source=source_name)

            task.add_domain_source_map(domain_info_list, source_name)
            count += len(domain_info_list)
            task.domain_info_list.extend(domain_info_list)

        logger.info(
            "end run cert_query_plugin_enhance base_domain_hash:{}, source_result:{}, accepted_result:{}, evidence_only:{}, real_result:{}".format(
                domain_log_summary(task.base_domain),
                len(results),
                accepted_result_count,
                evidence_count,
                count,
            )
        )
        return count

    def run_asset_pivot_round(self):
        """执行一次额外闭环，供编排器在预算内重复调用。"""
        task = self.task
        before_domains = len(task.domain_info_list)
        ip_count = self.run_ip_query_plugin_enhance()
        self.run_gen_ipv4_map()
        scan_count = 0
        if task.options.get("port_scan"):
            scan_count = self.run_incremental_port_scan_for_new_ips()
        cert_count = self.run_cert_query_plugin_enhance()
        if cert_count > 0:
            self.run_gen_ipv4_map()
            if task.options.get("port_scan"):
                scan_count += self.run_incremental_port_scan_for_new_ips()
            self.run_sync_ip_domain_from_ipv4_map()
        budget_exhausted = bool(
            getattr(task, "_asset_pivot_budget_exhausted", False)
        )
        result = {
            "new_domains": max(len(task.domain_info_list) - before_domains, 0),
            "ip_domains": ip_count,
            "cert_domains": cert_count,
            "new_ip_info": scan_count,
            "budget_exhausted": budget_exhausted,
            "status": "partial" if budget_exhausted else "success",
            "end_reason": "budget_exhausted" if budget_exhausted else "completed",
        }
        result["output_count"] = result["new_domains"]
        result["metrics"] = dict(result)
        return result

    def run(self):
        task = self.task
        self.run_gen_ipv4_map()
        pipeline = TaskPipeline(task)
        pipeline.run_many([
            {
                "name": "port_scan",
                "func": self.run_port_scan,
                "enabled": bool(task.options.get("port_scan")),
            },
            {
                "name": "ssl_cert",
                "func": self.run_ssl_cert,
                "enabled": bool(task.options.get("ssl_cert")),
            },
        ])

        if task.options.get("ssl_cert"):
            def run_cert_query_plugin():
                cert_new_domain_count = self.run_cert_query_plugin_enhance()
                if cert_new_domain_count > 0:
                    self.run_gen_ipv4_map()
                    if task.options.get("port_scan"):
                        self.run_incremental_port_scan_for_new_ips()
                    self.run_sync_ip_domain_from_ipv4_map()
                return {
                    "output_count": cert_new_domain_count,
                    "metrics": dict(
                        getattr(task, "_last_cert_query_metrics", {}) or {}
                    ),
                }

            pipeline.run_stage("cert_query_plugin", run_cert_query_plugin)

        self.run_save_ip_info()


class DomainSiteStageService(object):
    """执行站点发现并移交站点级扫描编排。"""

    def __init__(self, task):
        self.task = task

    def run_find_site(self):
        task = self.task
        if not hasattr(task, "ip_info_list"):
            legacy_runner = getattr(task, "find_site", None)
            if callable(legacy_runner):
                return legacy_runner()

        if task.options.get("port_scan"):
            from app.tasks.domain import find_site

            sites = find_site(task.ip_info_list)
        else:
            sites = services.probe_http(task.domain_info_list)

        existing_sites = set(task.site_list)
        for site in sites:
            if site in existing_sites:
                continue
            existing_sites.add(site)
            task.site_list.append(site)
        return len(sites)

    def run(self):
        task = self.task
        pipeline = TaskPipeline(task)
        pipeline.run_stage("find_site", self.run_find_site)
        task.domain_info_list = []

        # 延迟导入避免把站点任务实现重新耦合到域名阶段服务的导入过程。
        from app.services.commonTask import WebSiteFetch

        web_site_fetch = WebSiteFetch(
            task_id=task.task_id,
            sites=task.site_list,
            options=task.options,
            scope_domain=[task.base_domain],
        )
        # 终态唯一 owner 是 DomainTaskOrchestrator.run_deep 的 TaskFinalizer：
        # 嵌套站点层跳过收尾，避免 drain/显影双执行。
        web_site_fetch.terminal_finalize_host_owned = True
        web_site_fetch.run()
        task.wih_domain_set = web_site_fetch.wih_domain_set
        task.web_site_fetch = web_site_fetch


class DomainPostProcessStageService(object):
    """执行协议识别、风险巡航、弱口令和 Host 碰撞等后置阶段。"""

    def __init__(self, task):
        self.task = task

    def run_npoc_service_detection(self, full_port=False):
        task = self.task
        targets, total_targets, low_conf_targets, mode = task._build_sniffer_targets(
            full_port=full_port
        )
        skip_common_http_ports = not full_port
        logger.info(
            "npoc_service_detection mode:{} selected:{} total:{} low_conf:{} skip_common_http_ports:{}".format(
                mode,
                len(targets),
                total_targets,
                low_conf_targets,
                skip_common_http_ports,
            )
        )
        if not targets:
            return 0

        from app.services import run_sniffer

        result = run_sniffer(targets, skip_common_http_ports=skip_common_http_ports)
        enriched_count = task._apply_npoc_service_result(result)
        logger.info(
            "npoc_service_detection result:{} enriched_port:{}".format(
                len(result), enriched_count
            )
        )
        for item in result:
            task.npoc_service_target_set.add(item["target"])
            item["task_id"] = task.task_id
            item["save_date"] = utils.curr_date()
            item["source"] = "npoc_sniffer"
            _task_result_writer(task).insert_one("npoc_service", item)
        return len(result)

    def run_brute_config(self):
        task = self.task
        plugins = []
        brute_config = task.options.get("brute_config")
        for item in brute_config:
            if item.get("enable"):
                plugins.append(item["plugin_name"])

        if not plugins:
            return 0

        from app.services import run_risk_cruising

        targets = task.site_list.copy()
        targets += list(task.npoc_service_target_set)
        result = run_risk_cruising(targets=targets, plugins=plugins)
        saved_count = 0
        for item in result:
            target = str(item.get("target", "") or item.get("url", "")).strip()
            if target and not task._url_in_task_scope(
                target,
                seed_sites=task.site_list,
                scope_domains=[task.base_domain],
            ):
                continue
            item["task_id"] = task.task_id
            item["save_date"] = utils.curr_date()
            _task_result_writer(task).insert_one("vuln", item)
            saved_count += 1
        return saved_count

    def run_find_vhost_vuln(self):
        task = self.task
        from app.helpers.domain import find_private_domain_by_task_id, find_public_ip_by_task_id
        from app.services.findVhost import find_vhost

        domains = find_private_domain_by_task_id(task.task_id)
        if not domains:
            return 0

        ips = find_public_ip_by_task_id(task.task_id)
        results = find_vhost(ips=ips, domains=domains)
        saved_count = 0
        for result in results:
            if not task._url_in_task_scope(
                result.get("url", ""),
                seed_sites=task.site_list,
                scope_domains=[task.base_domain],
            ):
                continue
            save_item = {
                "plg_name": "FindVhost",
                "plg_type": "scan",
                "vul_name": "发现Host碰撞漏洞",
                "app_name": "web",
                "target": result["url"],
                "verify_data": "{}-{}-{}-{}".format(
                    result["domain"],
                    result["title"],
                    result["status_code"],
                    result["body_length"],
                ),
                "verify_obj": result,
                "task_id": task.task_id,
                "save_date": utils.curr_date(),
            }
            _task_result_writer(task).insert_one("vuln", save_item)
            saved_count += 1
        return saved_count

    def run_poc(self):
        task = self.task
        if task._enable_protocol_detection():
            TaskPipeline(task).run_stage(
                "npoc_service_detection",
                lambda: self.run_npoc_service_detection(
                    full_port=bool(task.options.get("npoc_service_detection"))
                ),
            )

        if (
            task.options.get("port_scan")
            or task.options.get("service_detection")
            or task.options.get("npoc_service_detection")
        ):
            # 服务结果由网络阶段持有；后置阶段只负责触发收尾，避免迁移后调用失效入口。
            DomainNetworkStageService(task).run_save_service_info()

        poc_config = task.options.get("poc_config")
        poc_enabled = (
            any(
                isinstance(item, dict) and bool(item.get("enable"))
                for item in poc_config
            )
            if isinstance(poc_config, list)
            else bool(poc_config)
        )
        if poc_enabled:
            TaskPipeline(task).run_stage(
                "poc_run",
                lambda: task.web_site_fetch.risk_cruising(task.npoc_service_target_set),
            )

        if task.options.get("brute_config"):
            TaskPipeline(task).run_stage("weak_brute", self.run_brute_config)

    def run_find_vhost(self):
        task = self.task
        if task.options.get("findvhost"):
            TaskPipeline(task).run_stage("findvhost", self.run_find_vhost_vuln)
