"""
定时调度任务执行模块

功能说明：
- 执行定时调度的域名和IP监控任务
- 支持增量更新和资产同步

主要功能：
1. 域名监控：定期扫描域名，发现新子域名
2. IP监控：定期扫描IP段，发现新开放端口
3. 增量更新：只处理新发现的资产
4. 资产同步：同步更新到资产组
5. 消息推送：通过Webhook推送变化

主要类：
- DomainExecutor: 域名监控执行器
- IPExecutor: IP监控执行器

执行流程：
1. 检查调度器状态 -> 2. 创建任务 -> 3. 执行扫描 -> 4. 增量处理 -> 5. 资产同步 -> 6. 消息推送

说明：
- 监控任务标记task_tag='monitor'
- 支持自定义扫描选项
- 失败不影响下次调度
"""
from celery import current_task
from bson import ObjectId
from app.utils import conn_db as conn
from .domain import DomainTask
from .ip import IPTask
from app import utils
from app.modules import TaskStatus, CollectSource, SchedulerStatus
from app.services import sync_asset, build_domain_info, sync_asset
from app.services.wildcardDomain import (
    collect_wildcard_records_from_domains,
    domain_info_hits_wildcard_records,
)
import time
import traceback
# update_job_run 延迟到调用点导入：app.scheduler 模块体内会经 helpers/celerytask
# 拉回 app.tasks，顶层 `from app.scheduler import ...` 在 `import app.scheduler`
# 先行入口下触发 partial-initialization 循环（容器实测直接 ImportError）。
from app.services import webhook

logger = utils.get_logger()

def domain_executors(base_domain=None, job_id=None, scope_id=None, options=None, name=""):
    """
    域名监控任务入口
    
    参数：
        base_domain: 基础域名
        job_id: 调度任务ID
        scope_id: 资产组ID
        options: 扫描选项
        name: 任务名称
    
    说明：
    - 检查调度器状态，STOP状态不执行
    - 调用wrap_domain_executors执行具体任务
    - 被Celery定时调度调用
    """
    logger.info("start domain_executors {} {} {}".format(base_domain, scope_id, options))
    try:
        # 检查调度器状态
        query = {"_id": ObjectId(job_id)}
        item = utils.conn_db('scheduler').find_one(query)
        if not item:
            logger.info("stop  domain_executors {}  not found job_id {}".format(base_domain, job_id))
            return

        if item.get("status") == SchedulerStatus.STOP:
            logger.info("stop  ip_executors {}  job_id {} is stop ".format(base_domain, job_id))
            return

        # 执行监控任务
        wrap_domain_executors(base_domain=base_domain, job_id=job_id, scope_id=scope_id, options=options, name=name)
    except Exception as e:
        logger.exception(e)


def wrap_domain_executors(base_domain=None, job_id=None, scope_id=None, options=None, name=""):
    """
    域名监控任务包装函数
    
    参数：
        base_domain: 基础域名
        job_id: 调度任务ID
        scope_id: 资产组ID
        options: 扫描选项
        name: 任务名称
    
    说明：
    - 创建task记录
    - 使用DomainExecutor执行扫描
    - 发现新域名后同步资产和推送通知
    - 捕获异常，标记任务状态
    """
    celery_id = "celery_id_placeholder"

    if current_task._get_current_object():
        celery_id = current_task.request.id

    # 构建任务数据（默认配置）
    task_data = {
        'name': name,
        'target': base_domain,
        'start_time': '-',
        'status': 'waiting',
        'type': 'domain',
        'task_tag': 'monitor',  # 标记为监控任务
        'options': {
            'domain_brute': True,
            'domain_brute_type': 'test',
            'alt_dns': False,
            'arl_search': True,
            'port_scan_type': 'test',
            'port_scan': True,
            'service_detection': False,
            'service_brute': False,
            'os_detection': False,
            'site_identify': False,
            'site_capture': False,
            'file_leak': False,
            'afrog_scan': False,
            'site_spider': False,
            'search_engines': False,
            'ssl_cert': False,
            'fofa_search': False,
            'dns_query_plugin': True,
            'web_info_hunter': False,
            'scope_id': scope_id
        },
        'celery_id': celery_id
    }
    
    # 合并用户自定义选项
    if options is None:
        options = {}
    task_data["options"].update(options)

    # 创建任务记录
    conn('task').insert_one(task_data)
    task_id = str(task_data.pop("_id"))
    
    # 执行域名监控
    domain_executor = DomainExecutor(base_domain, task_id, task_data["options"])
    try:
        # 更新调度器运行时间
        from app.scheduler import update_job_run
        update_job_run(job_id)
        
        # 执行扫描，返回是否有新域名
        new_domain = domain_executor.run()
        
        # 有新发现，同步资产和推送通知
        if new_domain:
            sync_asset(task_id, scope_id, update_flag=True, push_flag=True, task_name=name)
            webhook.domain_asset_web_hook(task_id=task_id, scope_id=scope_id)
    except Exception as e:
        logger.exception(e)
        utils.append_task_error(
            task_id=task_id,
            error=e,
            stage="wrap_domain_executors",
            traceback_text=traceback.format_exc(),
        )

    logger.info("end domain_executors {} {} {}".format(base_domain, scope_id, options))


class DomainExecutor(DomainTask):
    """
    域名监控执行器
    
    功能说明：
    - 继承DomainTask，复用域名扫描功能
    - 增量处理，只保存新发现的域名
    - 与资产组对比，发现新子域名
    
    继承自：
    - DomainTask: 域名扫描任务类
    
    主要属性：
    - domain_set: 扫描发现的域名集合
    - scope_domain_set: 资产组现有域名集合
    - new_domain_set: 新发现的域名集合
    - task_tag: 标记为'monitor'
    
    主要方法：
    - get_scope_domain(): 获取资产组域名
    - update_domain_info(): 更新域名信息
    - build_new_domain(): 构建新域名列表
    - run(): 执行监控流程
    """
    
    def __init__(self, base_domain, task_id, options):
        """
        初始化域名监控执行器
        
        参数：
            base_domain: 基础域名
            task_id: 任务ID
            options: 扫描选项
        """
        super().__init__(base_domain, task_id, options)
        self.domain_set = set()  # 扫描发现的域名
        self.scope_id = options["scope_id"]
        self.scope_domain_set = None  # 资产组现有域名
        self.new_domain_set = None  # 新发现的域名
        self.task_tag = "monitor"  # 标记为监控任务
        self.wildcard_record_set = None  # 泛解析记录集合

    def run(self):
        """
        执行域名监控任务
        
        执行流程：
        1. 域名获取：执行域名扫描
        2. 增量对比：与资产组对比，找出新域名
        3. 泛解析检测：识别并过滤泛解析域名
        4. IP探测：对新域名进行IP探测
        5. 站点探测：对新域名进行站点探测
        6. 统计信息：生成任务统计
        
        返回：
            set: 新发现的域名集合
        """
        self.update_task_field("start_time", utils.curr_date())
        
        # 1. 域名获取
        self.domain_fetch()
        for domain_info in self.domain_info_list:
            self.domain_set.add(domain_info.domain)

        # 2. 获取资产组现有域名
        self.set_scope_domain()

        # 3. 计算新域名
        new_domain_set = self.domain_set - self.scope_domain_set
        self.new_domain_set = new_domain_set

        # 4. 泛解析检测
        self.set_wildcard_record_set()

        # 5. 重建domain_info_list（仅包含新域名）
        self.set_domain_info_list()

        # 准备返回的新域名集合
        ret_new_domain_set = set()
        for domain_info in self.domain_info_list:
            ret_new_domain_set.add(domain_info.domain)

        # 6. 仅对新增域名进行IP和站点探测
        self.start_ip_fetch()
        self.start_site_fetch()

        # 7. 统计信息
        self.insert_cip_stat()  # C段IP统计
        self.insert_finger_stat()  # 指纹统计
        self.insert_task_stat()  # 任务统计

        self.update_task_field("status", TaskStatus.DONE)
        self.update_task_field("end_time", utils.curr_date())

        return ret_new_domain_set

    def set_scope_domain(self):
        """
        获取资产组中的现有域名
        
        说明：
        - 从asset_domain表查询资产组的所有域名
        - 用于与扫描结果对比，识别新域名
        """
        self.scope_domain_set = set(utils.get_asset_domain_by_id(self.scope_id))

    def set_domain_info_list(self):
        """
        重建domain_info_list，仅包含新域名
        
        说明：
        - 清空原domain_info_list
        - 对新域名构建domain_info
        - 过滤DNS记录重复的域名
        - 过滤泛解析域名
        - 删除临时保存的域名记录
        - 重新保存新域名（标记来源为MONITOR）
        """
        self.domain_info_list = []
        self.record_map = {}
        logger.info("start build domain monitor task, new domain {}".format(len(self.new_domain_set)))
        t1 = time.time()

        # 临时标记为task，让build_domain_info正常工作
        self.task_tag = "task"
        new = self.build_domain_info(self.new_domain_set)
        new = self.clear_domain_info_by_record(new)
        self.task_tag = "monitor"

        # 泛解析过滤
        if self.wildcard_record_set:
            new = self.clear_wildcard_domain_info(new)

        elapse = time.time() - t1
        logger.info("end build domain monitor task  {}, elapse {}".format(
            len(new), elapse))

        # 删除前面步骤插入的域名
        conn('domain').delete_many({"task_id": self.task_id})

        # 重新保存新发现的域名，尽量保留真实来源（如 fofa/hunter_qax）
        self.save_domain_info_list_by_source_map(new, default_source=CollectSource.MONITOR)
        self.domain_info_list = new

    def set_wildcard_record_set(self):
        """
        检测泛解析记录集合
        
        说明：
        - 对新域名的父域名进行泛解析检测
        - 多次生成随机子域名查询 DNS
        - 合并 A/CNAME 结果，用于后续过滤
        """
        self.wildcard_record_set = collect_wildcard_records_from_domains(self.new_domain_set)
        logger.info("start get wildcard_record_set {}".format(len(self.wildcard_record_set)))

    def clear_wildcard_domain_info(self, info_list):
        """
        过滤泛解析域名
        
        参数：
            info_list: 域名信息列表
        
        返回：
            list: 过滤后的域名信息列表
        
        说明：
        - 对比域名解析的 A/CNAME 记录和泛解析记录集合
        - 如果命中泛解析记录集合，说明是泛解析域名，过滤掉
        - 保留非泛解析的真实域名
        """
        cnt = 0
        new = []
        for info in info_list:
            if domain_info_hits_wildcard_records(info, self.wildcard_record_set):
                cnt += 1
                continue
            new.append(info)
        logger.info("clear_wildcard_domain_info {}".format(cnt))
        return new


class IPExecutor(IPTask):
    """
    IP监控执行器
    
    功能说明：
    - 继承IPTask，复用IP扫描功能
    - 增量收录新端口，并用明确的连接复核纠正资产端口
    - 与资产组对比，发现新开放端口
    
    继承自：
    - IPTask: IP扫描任务类
    
    主要属性：
    - scope_id: 资产组ID
    - task_name: 任务名称
    - task_tag: 标记为'monitor'
    - asset_ip_port_set: 资产组现有IP:端口集合
    - asset_ip_info_map: 资产组现有IP信息映射
    
    主要方法：
    - insert_task_data(): 插入任务记录
    - set_asset_ip(): 获取资产组IP信息
    - async_ip_info(): 同步新端口并校正复核过的资产端口
    - run(): 执行监控流程
    """
    
    def __init__(self, target, scope_id, task_name,  options):
        """
        初始化IP监控执行器
        
        参数：
            target: 扫描目标（IP或IP段）
            scope_id: 资产组ID
            task_name: 任务名称
            options: 扫描选项
        """
        super().__init__(ip_target=target, task_id=None, options=options)
        self.scope_id = scope_id
        self.task_name = task_name
        self.task_tag = "monitor"  # 标记为监控任务

    def insert_task_data(self):
        """
        插入任务记录
        
        说明：
        - 创建IP监控任务记录
        - 使用默认扫描选项
        - 合并用户自定义选项
        - 关联资产组ID
        """
        celery_id = ""
        if current_task._get_current_object():
            celery_id = current_task.request.id

        # 默认任务配置
        task_data = {
            'name': self.task_name,
            'target': self.ip_target,
            'start_time': '-',
            'end_time': '-',
            'status': TaskStatus.WAITING,
            'type': 'ip',
            'task_tag': 'monitor',  # 标记为监控任务
            'options': {
                "port_scan_type": "test",
                "port_scan": True,
                "service_detection": False,
                "os_detection": False,
                "site_identify": False,
                "site_capture": False,
                "file_leak": False,
                "afrog_scan": False,
                "site_spider": False,
                "ssl_cert": False,
                'web_info_hunter': False,
                'scope_id': self.scope_id
            },
            'celery_id': celery_id
        }

        # 合并用户选项
        if self.options is None:
            self.options = {}

        task_data["options"].update(self.options)
        conn('task').insert_one(task_data)
        self.task_id = str(task_data.pop("_id"))
        # base_update_task 初始化在前，再设置回task_id
        self.base_update_task.task_id = self.task_id

    def set_asset_ip(self):
        if self.task_tag != 'monitor':
            return

        query = {"scope_id": self.scope_id}
        items = list(utils.conn_db('asset_ip').find(query, {"ip": 1, "port_info": 1}))
        for item in items:
            self.asset_ip_info_map[item["ip"]] = item
            for port_info in item.get("port_info", []) or []:
                port_key = self._asset_port_key(port_info)
                if port_key:
                    self.asset_ip_port_set.add((item["ip"],) + port_key)

    @staticmethod
    def _asset_port_key(port_info):
        if not isinstance(port_info, dict):
            return None
        try:
            port_id = int(port_info.get("port_id"))
        except (TypeError, ValueError):
            return None
        protocol = str(port_info.get("protocol", "tcp") or "tcp").strip().lower()
        if not protocol:
            protocol = "tcp"
        return protocol, port_id

    @staticmethod
    def _merge_asset_port_info(stored, observed):
        merged = dict(stored or {})
        observed = dict(observed or {})
        stored_sources = merged.get("service_sources") or []
        has_npoc_service = "npoc_scheme" in stored_sources
        stored_service_method = str(merged.get("nmap_service_method", "") or "").strip().lower()
        stored_service_name = str(merged.get("service_name", "") or "").strip().lower()
        table_service_name = str(observed.get("nmap_service_table_name", "") or "").strip().lower()

        observed_verified = bool(observed.get("verified"))
        stored_verified = bool(merged.get("verified"))
        if observed_verified or not stored_verified:
            for field in ("state", "reason", "scan_method"):
                if observed.get(field) not in (None, ""):
                    merged[field] = observed[field]

        if observed.get("nmap_service_method"):
            for field in (
                "nmap_service_method",
                "nmap_service_confidence",
                "nmap_service_table_name",
            ):
                merged[field] = observed.get(field, "")

        for field in (
            "nmap_service_confidence",
            "nmap_service_table_name",
        ):
            if observed.get(field) not in (None, ""):
                merged[field] = observed[field]

        if "verified" in observed and (observed_verified or not stored_verified):
            merged["verified"] = observed_verified

        for field in ("product", "version"):
            if observed.get(field) not in (None, ""):
                merged[field] = observed[field]

        if not has_npoc_service:
            if observed.get("service_name"):
                merged["service_name"] = observed["service_name"]
                for field in ("service_confidence", "service_sources", "service_conflict"):
                    if field in observed:
                        merged[field] = observed[field]
                if "service_conflict" not in observed:
                    merged.pop("service_conflict", None)
            elif (
                str(observed.get("nmap_service_method", "") or "").strip().lower() == "table"
                and table_service_name
                and stored_service_name == table_service_name
                and stored_service_method in ("", "table")
            ):
                merged["service_name"] = ""
                merged["service_confidence"] = 0
                merged["service_sources"] = []
                merged.pop("service_conflict", None)

        return merged

    def async_ip_info(self):
        new_ip_info_list = []
        removed_port_count = 0
        refreshed_port_count = 0
        for ip_info in self.ip_info_list:
            curr_ip = ip_info["ip"]
            curr_date_obj = utils.curr_date_obj()
            persisted_ip_info = dict(ip_info)
            persisted_ip_info.pop("_suspected_all_open", None)
            validation_info = persisted_ip_info.pop("_connect_validation", {})
            persisted_ip_info.pop("_scan_coverage", None)
            if not isinstance(validation_info, dict):
                validation_info = {}
            not_open_keys = {
                self._asset_port_key(port_info)
                for port_info in (validation_info.get("not_open_ports", []) or [])
            }
            not_open_keys.discard(None)

            # 新发现的IP ，直接入资产集合
            if curr_ip not in self.asset_ip_info_map:
                asset_ip_info = dict(persisted_ip_info)
                asset_ip_info["scope_id"] = self.scope_id
                asset_ip_info["domain"] = []
                asset_ip_info["save_date"] = curr_date_obj
                asset_ip_info["update_date"] = curr_date_obj
                utils.conn_db('asset_ip').insert_one(asset_ip_info)
                utils.conn_db('ip').insert_one(persisted_ip_info)
                self.asset_ip_info_map[curr_ip] = asset_ip_info
                for port_info in asset_ip_info.get("port_info", []) or []:
                    port_key = self._asset_port_key(port_info)
                    if port_key:
                        self.asset_ip_port_set.add((curr_ip,) + port_key)
                new_ip_info_list.append(ip_info)
                continue

            asset_ip_info = self.asset_ip_info_map[curr_ip]
            stored_port_info = list(asset_ip_info.get("port_info", []) or [])
            observed_port_map = {}
            for port_info in ip_info.get("port_info", []) or []:
                port_key = self._asset_port_key(port_info)
                if port_key:
                    observed_port_map[port_key] = port_info

            updated_port_info = []
            existing_port_keys = set()
            asset_changed = False
            for port_info in stored_port_info:
                port_key = self._asset_port_key(port_info)
                if port_key and port_key in not_open_keys:
                    removed_port_count += 1
                    asset_changed = True
                    continue
                if port_key:
                    existing_port_keys.add(port_key)
                observed = observed_port_map.get(port_key)
                if observed is not None:
                    merged_port_info = self._merge_asset_port_info(port_info, observed)
                    if merged_port_info != port_info:
                        refreshed_port_count += 1
                        asset_changed = True
                    updated_port_info.append(merged_port_info)
                else:
                    updated_port_info.append(port_info)

            # 只把本次新开放的端口加入发现结果；旧端口的字段按本次证据校正。
            new_port_info_list = []
            for port_info in ip_info["port_info"]:
                port_key = self._asset_port_key(port_info)
                if not port_key or port_key in not_open_keys:
                    continue
                if port_key in existing_port_keys:
                    continue
                existing_port_keys.add(port_key)
                updated_port_info.append(port_info)
                new_port_info_list.append(port_info)
                asset_changed = True
                self.asset_ip_port_set.add((curr_ip,) + port_key)

            for port_key in not_open_keys:
                self.asset_ip_port_set.discard((curr_ip,) + port_key)

            if asset_changed:
                asset_ip_info["port_info"] = updated_port_info
                update_info = dict()
                update_info["update_date"] = utils.curr_date_obj()
                update_info["port_info"] = updated_port_info
                query = {"_id": asset_ip_info["_id"]}
                utils.conn_db('asset_ip').update_one(query, {"$set": update_info})

            if new_port_info_list:
                # 只是保存新发现的端口
                persisted_ip_info["port_info"] = new_port_info_list
                utils.conn_db('ip').insert_one(persisted_ip_info)

                new_ip_info_list.append(ip_info)
                continue

        self.ip_info_list = new_ip_info_list
        logger.info(
            "monitor ip sync new_ip_info:{} removed_verified_closed_ports:{} refreshed_ports:{}".format(
                len(self.ip_info_list), removed_port_count, refreshed_port_count
            )
        )

    # 同步SITE 和 web_info_hunter 信息
    def sync_asset_site_wih(self):
        have_data = False
        query = {"task_id": self.task_id}

        if utils.conn_db('site').count_documents(query) or utils.conn_db('wih').count_documents(query):
            have_data = True

        # 有数据才同步
        if not have_data:
            return

        sync_asset(self.task_id, self.scope_id, update_flag=False, category=["site", "wih"],
                   push_flag=True, task_name=self.task_name)


def ip_executor(target, scope_id, task_name, job_id, options):
    try:
        query = {"_id": ObjectId(job_id)}
        item = utils.conn_db('scheduler').find_one(query)
        if not item:
            logger.info("stop  ip_executors {}  not found job_id {}".format(target, job_id))
            return

        if item.get("status") == SchedulerStatus.STOP:
            logger.info("stop  ip_executors {}  job_id {} is stop ".format(target, job_id))
            return

        from app.scheduler import update_job_run
        update_job_run(job_id)
    except Exception as e:
        logger.exception(e)
        return

    executor = IPExecutor(target, scope_id, task_name,  options)
    try:
        executor.insert_task_data()
        executor.run()
        executor.sync_asset_site_wih()

    except Exception as e:
        logger.warning("error on ip_executor {}".format(executor.ip_target))
        logger.exception(e)
        utils.append_task_error(
            task_id=executor.task_id,
            error=e,
            stage="ip_executor",
            traceback_text=traceback.format_exc(),
        )
