"""
风险巡航（PoC扫描）任务执行模块

功能说明：
- 执行漏洞PoC验证和弱口令爆破任务
- 针对用户指定的目标进行安全检测

主要功能：
1. PoC扫描：使用NPoc框架执行漏洞验证插件
2. 弱口令爆破：对常见服务进行弱口令检测
3. 服务识别：识别非标准端口的服务类型
4. 站点探测：验证目标站点可访问性
5. 结果保存：检测结果保存到vuln表

主要类：
- RiskCruising: 风险巡航任务主类

执行流程：
1. 目标预处理 -> 2. 站点探测 -> 3. 服务识别 -> 4. 弱口令爆破 -> 5. PoC扫描 -> 6. 结果保存

说明：
- 支持多种目标格式：URL、IP:Port、域名
- 使用多线程并发执行检测
- 实时更新任务进度
"""
from threading import Thread
from app import utils
from app.modules import TaskStatus
from app.services import npoc
from app.config import Config
import time
from bson import ObjectId
from urllib.parse import urlparse
from app.services.commonTask import CommonTask, WebSiteFetch
from app.helpers.message_notify import push_task_finish_notify

logger = utils.get_logger()


def run_risk_cruising_task(task_id):
    """
    运行风险巡航任务
    
    参数：
        task_id: 任务ID
    
    说明：
    - 从数据库获取任务配置
    - 检查任务状态为waiting才执行
    - 创建RiskCruising实例并运行
    - 被Celery调用执行异步任务
    """
    query = {"_id": ObjectId(task_id)}
    task_data = utils.conn_db('task').find_one(query)

    if not task_data:
        return
    if task_data["status"] != "waiting":
        return

    r = RiskCruising(task_id)
    r.run()


class RiskCruising(CommonTask):
    """
    风险巡航任务类
    
    功能说明：
    - 执行PoC扫描和弱口令爆破
    - 支持多种目标格式
    - 实时进度追踪
    
    主要属性：
    - task_id: 任务ID
    - options: 扫描选项配置
    - poc_plugin_name: PoC插件列表
    - brute_plugin_name: 爆破插件列表
    - targets: 扫描目标列表
    - sniffer_target_set: 需要服务识别的目标（IP:Port格式）
    - npoc_service_target_set: 识别后的服务目标
    - user_target_site_set: 用户提交的站点目标
    - available_sites: 可访问的站点列表
    
    主要方法：
    - init_plugin_name(): 初始化插件列表
    - set_relay_targets(): 处理和分类目标
    - npoc_service_detection(): NPoc服务识别
    - run_poc(): 执行PoC扫描
    - run_brute(): 执行弱口令爆破
    """
    
    def __init__(self, task_id):
        """
        初始化风险巡航任务
        
        参数：
            task_id: 任务ID
        """
        super().__init__(task_id=task_id)

        self.task_id = task_id
        query = {"_id": ObjectId(task_id)}
        self.query = query
        task_data = utils.conn_db('task').find_one(query)
        self.task_data = task_data
        self.options = self.task_data.get("options", {})

        self.poc_plugin_name = []  # PoC插件列表
        self.brute_plugin_name = []  # 爆破插件列表
        self.result_set_id = self.task_data.get("result_set_id")
        self.targets = self.task_data.get("cruising_target")
        self.sniffer_target_set = set()  # 服务识别目标集合
        self.npoc_service_target_set = set()  # NPoc识别的服务集合
        self.user_target_site_set = set()  # 用户提交的站点集合
        self.available_sites = []  # 可访问的站点列表

    def init_plugin_name(self):
        """
        初始化插件名称列表
        
        说明：
        - 从配置中提取启用的PoC插件
        - 从配置中提取启用的爆破插件
        - 只有enable=true的插件才会被使用
        """
        # 提取PoC插件
        poc_config = self.options.get("poc_config", [])
        plugin_name = []
        for item in poc_config:
            if item.get("enable"):
                plugin_name.append(item["plugin_name"])

        self.poc_plugin_name = plugin_name

        # 提取爆破插件
        brute_config = self.options.get("brute_config", [])
        plugin_name = []
        for item in brute_config:
            if item.get("enable"):
                plugin_name.append(item["plugin_name"])

        self.brute_plugin_name = plugin_name

    def set_relay_targets(self):
        """
        处理和分类扫描目标
        
        说明：
        - 将不同格式的目标分类处理
        - IP:Port格式 -> sniffer_target_set（需要服务识别）
        - HTTP/HTTPS URL -> user_target_site_set（直接扫描）
        - 如果有result_set_id，从result_set表获取目标
        
        目标格式示例：
        - 1.1.1.1:22 -> 服务识别
        - http://example.com -> 站点扫描
        - https://1.1.1.1:8443 -> 站点扫描
        """
        # 对用户提交的 1.1.1.1:22 数据 进行设置到 sniffer_target_set
        if self.targets:
            for x in self.targets:
                o = urlparse(x)
                # 没有scheme且非空，视为IP:Port格式
                if not o.scheme and x:
                    self.sniffer_target_set.add(x)
                    continue

                # HTTP/HTTPS协议跳过，后续单独处理
                if o.scheme in ["http", "https"]:
                    continue

                # 其他协议提取netloc作为服务识别目标
                if o.netloc:
                    self.sniffer_target_set.add(o.netloc)

        # 从result_set表获取批量目标
        if not self.result_set_id:
            return
        # 根据 result_set_id 查询站点
        query_result_set = {"_id": ObjectId(self.result_set_id)}
        item = utils.conn_db('result_set').find_one(query_result_set)
        targets = item["items"]
        utils.conn_db('result_set').delete_one(query_result_set)
        self.targets = targets

    def npoc_service_detection(self):
        """
        NPoc服务识别
        
        说明：
        - 对IP:Port目标进行协议识别
        - 识别非HTTP服务的具体协议类型
        - 识别结果保存到npoc_service表
        - 用于后续针对性的PoC扫描
        """
        logger.info("start npoc_service_detection {}".format(len(self.sniffer_target_set)))
        result = npoc.run_sniffer(self.sniffer_target_set)
        for item in result:
            self.npoc_service_target_set.add(item["target"])
            item["task_id"] = self.task_id
            item["save_date"] = utils.curr_date()
            utils.conn_db('npoc_service').insert_one(item)

    def run_poc(self):
        """
        运行PoC扫描
        
        说明：
        - 对所有目标执行漏洞验证插件
        - 目标包括：站点 + 识别的服务
        - 使用多线程并发执行
        - 实时更新进度状态
        - 检测结果保存到vuln表
        
        进度计算：
        - 总任务数 = 插件数量 × 目标数量
        - 实时显示 已完成/总任务数
        """
        targets = self.available_sites + list(self.npoc_service_target_set)
        logger.info("start run poc {}*{}".format(len(self.poc_plugin_name), len(targets)))

        run_total = len(self.poc_plugin_name) * len(targets)
        npoc_instance = npoc.NPoC(tmp_dir=Config.TMP_PATH, concurrency=10)
        run_thread = Thread(target=npoc_instance.run_poc, args=(self.poc_plugin_name, targets))
        run_thread.start()
        
        # 等待执行完成，每5秒更新一次进度
        while run_thread.is_alive():
            time.sleep(5)
            status = "poc {}/{}".format(npoc_instance.runner.runner_cnt, run_total)
            logger.info("[{}]runner cnt {}/{}".format(self.task_id,
                                                      npoc_instance.runner.runner_cnt, run_total))
            self.update_task_field("status", status)

        # 保存检测结果
        result = npoc_instance.result
        for item in result:
            item["task_id"] = self.task_id
            item["save_date"] = utils.curr_date()
            utils.conn_db('vuln').insert_one(item)

    def run_brute(self):
        """
        运行弱口令爆破
        
        说明：
        - 对所有目标执行弱口令爆破插件
        - 目标包括：站点 + 识别的服务
        - 使用多线程并发执行
        - 实时更新进度状态
        - 爆破成功的结果保存到vuln表
        
        支持的服务：
        - SSH, FTP, MySQL, Redis, MongoDB等
        - 使用内置字典进行爆破
        """
        target = self.available_sites + list(self.npoc_service_target_set)
        plugin_name = self.brute_plugin_name
        logger.info("start run brute {}*{}".format(len(plugin_name), len(target)))
        run_total = len(plugin_name) * len(target)

        npoc_instance = npoc.NPoC(tmp_dir=Config.TMP_PATH, concurrency=10)
        run_thread = Thread(target=npoc_instance.run_poc, args=(plugin_name, target))
        run_thread.start()
        
        # 等待执行完成，每5秒更新一次进度
        while run_thread.is_alive():
            time.sleep(5)
            status = "brute {}/{}".format(npoc_instance.runner.runner_cnt, run_total)
            logger.info("[{}]runner cnt {}/{}".format(self.task_id,
                                                      npoc_instance.runner.runner_cnt, run_total))
            self.update_task_field("status", status)

        # 保存爆破结果
        result = npoc_instance.result
        for item in result:
            item["task_id"] = self.task_id
            item["save_date"] = utils.curr_date()
            utils.conn_db('vuln').insert_one(item)

    def update_services(self, status, elapsed):
        """
        更新任务服务执行信息
        
        参数：
            status: 服务状态名称
            elapsed: 执行耗时（秒）
        
        说明：
        - 记录每个步骤的执行时间
        - 用于性能分析和任务统计
        """
        elapsed = "{:.2f}".format(elapsed)
        self.update_task_field("status", status)
        update = {"$push": {"service": {"name": status, "elapsed": float(elapsed)}}}
        utils.conn_db('task').update_one(self.query, update)

    def update_task_field(self, field=None, value=None):
        """
        更新任务字段
        
        参数：
            field: 字段名
            value: 字段值
        
        说明：
        - 更新任务的单个字段
        - 常用于更新status、start_time、end_time等
        """
        update = {"$set": {field: value}}
        utils.conn_db('task').update_one(self.query, update)

    def pre_set_site(self):
        """
        预处理站点目标
        
        说明：
        - 将用户提交的目标转换为标准URL格式
        - 没有协议的自动添加http://前缀
        - 只保留HTTP/HTTPS协议的目标
        - 保存到user_target_site_set集合
        """
        # *** 对用户提交的数据 保存到 user_target_site_set
        for x in self.targets:
            # 没有协议，添加http://
            if "://" not in x:
                self.user_target_site_set.add("http://{}".format(x))
                continue

            # 非HTTP协议跳过
            if not x.startswith("http"):
                continue

            self.user_target_site_set.add(x)

    def work(self):
        """
        执行风险巡航工作流程
        
        执行顺序：
        1. 目标预处理：分类和转换目标格式
        2. 站点探测：验证站点可访问性
        3. 服务识别：识别IP:Port的服务类型（可选）
        4. 弱口令爆破：对服务进行弱口令检测（可选）
        5. PoC扫描：执行漏洞验证（可选）
        6. 通用处理：统计信息和资产同步
        """
        # 对目标进行预先处理
        self.set_relay_targets()
        self.pre_set_site()

        # 站点探测和信息采集
        web_site_fetch = WebSiteFetch(task_id=self.task_id,
                                      sites=list(self.user_target_site_set), options=self.options)
        web_site_fetch.run()
        self.available_sites = web_site_fetch.available_sites

        # 初始化插件列表
        self.init_plugin_name()
        
        # 服务识别
        if self.options.get("npoc_service_detection"):
            self.update_task_field("status", "npoc_service_detection")
            t1 = time.time()
            self.npoc_service_detection()
            elapse = time.time() - t1
            self.update_services("npoc_service_detection", elapse)

        # 弱口令爆破
        if self.brute_plugin_name:
            self.update_task_field("status", "weak_brute")
            t1 = time.time()
            self.run_brute()
            elapse = time.time() - t1
            self.update_services("weak_brute", elapse)

        # PoC扫描
        if self.poc_plugin_name:
            self.update_task_field("status", "PoC")
            t1 = time.time()
            self.run_poc()
            elapse = time.time() - t1
            self.update_services("PoC", elapse)

        # 通用处理：统计、同步
        self.common_run()

    def run(self):
        """
        执行风险巡航任务主流程
        
        说明：
        - 捕获异常并标记任务状态
        - 记录开始和结束时间
        - 正常完成标记为DONE，异常标记为ERROR
        """
        success = False
        try:
            self.update_task_field("start_time", utils.curr_date())
            self.work()
            self.update_task_field("status", TaskStatus.DONE)
            success = True
        except Exception as e:
            self.update_task_field("status", TaskStatus.ERROR)
            logger.exception(e)

        self.update_task_field("end_time", utils.curr_date())
        if success:
            push_task_finish_notify(self.task_id)
