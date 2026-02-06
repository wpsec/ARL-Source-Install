"""
IP扫描任务执行模块

功能说明：
- IP扫描任务的核心执行逻辑
- 负责IP资产的发现、端口探测和服务识别

主要功能：
1. 端口扫描：支持多种扫描模式（测试、Top100、Top1000、全端口、自定义）
2. 服务识别：识别开放端口上运行的服务及版本
3. 操作系统识别：识别目标主机的操作系统类型
4. 站点探测：探测HTTP/HTTPS服务
5. SSL证书获取：获取HTTPS服务的SSL证书信息
6. 风险巡航：针对发现的服务进行安全检测
7. PoC扫描：使用漏洞验证插件进行检测

主要类：
- IPTask: IP扫描任务主类
- IPExecutor: IP任务执行器

执行流程：
1. 端口扫描 -> 2. 服务识别 -> 3. 站点探测 -> 4. SSL证书 -> 5. PoC扫描 -> 6. 数据保存
"""
from bson.objectid import  ObjectId
import time
from app import services
from app.modules import ScanPortType, TaskStatus
from app.services import fetchCert, run_risk_cruising, run_sniffer
from app import utils
from app.services.commonTask import CommonTask, BaseUpdateTask, WebSiteFetch
from app.config import Config


logger = utils.get_logger()


def ssl_cert(ip_info_list):
    """
    批量获取SSL证书信息
    
    参数：
        ip_info_list: IP信息列表
    
    返回：
        dict: IP:Port -> 证书信息的映射
    
    说明：
    - 遍历所有IP的开放端口
    - 跳过80端口（HTTP不使用SSL）
    - 批量获取HTTPS服务的SSL证书
    - 用于发现证书关联的域名和组织信息
    """
    try:
        targets = []
        for ip_info in ip_info_list:
            for port_info in ip_info["port_info"]:
                if port_info["port_id"] == 80:
                    continue
                targets.append("{}:{}".format(ip_info["ip"], port_info["port_id"]))

        f = fetchCert.SSLCert(targets)
        return f.run()
    except Exception as e:
        logger.exception(e)

    return {}


class IPTask(CommonTask):
    """
    IP扫描任务类
    
    功能说明：
    - 执行完整的IP扫描流程
    - 支持任务模式和监控模式
    
    主要属性：
    - ip_target: 扫描目标（IP或IP段，空格分隔）
    - task_id: 任务ID
    - options: 扫描选项配置
    - ip_info_list: IP信息列表
    - site_list: 站点列表
    - cert_map: 证书信息映射
    - task_tag: 任务标签（task/monitor）
    
    主要方法：
    - port_scan(): 端口扫描
    - find_site(): 站点探测
    - ssl_cert(): SSL证书获取
    - run_risk_cruising(): 风险巡航
    - run_poc_service(): PoC扫描
    """
    
    def __init__(self, ip_target=None, task_id=None, options=None):
        """
        初始化IP扫描任务
        
        参数：
            ip_target: 扫描目标IP（空格分隔的IP或IP段）
            task_id: 任务ID
            options: 扫描选项配置
        """
        super().__init__(task_id=task_id)

        self.ip_target = ip_target
        self.task_id = task_id
        self.options = options
        self.ip_info_list = []  # IP信息列表
        self.ip_set = set()  # IP集合（去重）
        self.site_list = []  # 站点列表
        self.cert_map = {}  # 证书映射
        self.service_info_list = []  # 服务信息列表
        self.npoc_service_target_set = set()  # PoC目标集合
        # 用来区分是正常任务还是监控任务
        self.task_tag = "task"

        self.scope_id = None  # 资产组ID（监控任务使用）
        self.task_name = None  # 任务名称
        self.asset_ip_port_set = set()  # 资产IP端口集合
        self.asset_ip_info_map = dict()  # 资产IP信息映射
        self.base_update_task = BaseUpdateTask(self.task_id)

    def set_asset_ip(self):
        """
        获取资产组中的IP信息
        
        说明：
        - 仅在监控模式下使用
        - 从asset_ip表获取已有IP信息
        - 用于增量更新资产数据
        """
        raise NotImplementedError()

    def async_ip_info(self):
        """
        同步IP信息到资产组
        
        说明：
        - 仅在监控模式下使用
        - 同步新发现的IP和端口
        - 更新资产组数据
        """
        raise NotImplementedError()

    def port_scan(self):
        """
        执行端口扫描
        
        说明：
        - 支持多种扫描模式：
          * test: 测试模式（少量常用端口）
          * top100: Top100端口
          * top1000: Top1000端口
          * all: 全端口扫描（1-65535）
          * custom: 自定义端口
        - 支持服务识别和操作系统识别
        - 支持自定义扫描参数（并行度、速率、超时）
        - 自动识别IP类型（公网/内网）
        - 获取IP地理位置和ASN信息
        """
        # 端口扫描模式映射
        scan_port_map = {
            "test": ScanPortType.TEST,
            "top100": ScanPortType.TOP100,
            "top1000": ScanPortType.TOP1000,
            "all": ScanPortType.ALL,
            "custom": self.options.get("port_custom", "80,443")
        }
        
        option_scan_port_type = self.options.get("port_scan_type", "test")
        
        # 构建扫描选项
        scan_port_option = {
            "ports": scan_port_map.get(option_scan_port_type, ScanPortType.TEST),
            "service_detect": self.options.get("service_detection", False),  # 服务识别
            "os_detect": self.options.get("os_detection", False),  # 操作系统识别
            "port_parallelism": self.options.get("port_parallelism", 32),  # 探测报文并行度
            "port_min_rate": self.options.get("port_min_rate", 64),  # 最少发包速率
            "custom_host_timeout": None  # 主机超时时间(s)
        }
        
        # 只有当设置为自定义时才会去设置超时时间
        if self.options.get("host_timeout_type") == "custom":
            scan_port_option["custom_host_timeout"] = self.options.get("host_timeout", 60 * 15)

        # 解析目标IP列表
        targets = self.ip_target.split()
        
        # 执行端口扫描
        ip_port_result = services.port_scan(targets, **scan_port_option)
        self.ip_info_list.extend(ip_port_result)

        # 监控模式：获取资产组现有IP
        if self.task_tag == 'monitor':
            self.set_asset_ip()

        # 处理扫描结果
        for ip_info in ip_port_result:
            curr_ip = ip_info["ip"]
            self.ip_set.add(curr_ip)
            
            # 检查IP黑名单
            if not utils.not_in_black_ips(curr_ip):
                continue

            # 添加基础信息
            ip_info["task_id"] = self.task_id
            ip_info["ip_type"] = utils.get_ip_type(curr_ip)
            ip_info["geo_asn"] = {}
            ip_info["geo_city"] = {}

            # 公网IP获取地理位置和ASN信息
            if ip_info["ip_type"] == "PUBLIC":
                ip_info["geo_asn"] = utils.get_ip_asn(curr_ip)
                ip_info["geo_city"] = utils.get_ip_city(curr_ip)

            # 任务模式：保存IP信息到数据库
            if self.task_tag == 'task':
                utils.conn_db('ip').insert_one(ip_info)

        # 监控模式：同步IP信息到资产组
        if self.task_tag == 'monitor':
            self.async_ip_info()

    def find_site(self):
        """
        探测HTTP/HTTPS站点
        
        说明：
        - 遍历所有开放端口
        - 构建可能的URL列表
        - 批量探测站点可访问性
        - 获取站点标题、服务器等信息
        """
        url_temp_list = []
        for ip_info in self.ip_info_list:
            for port_info in ip_info["port_info"]:
                curr_ip = ip_info["ip"]

                port_id = port_info["port_id"]
                # 80端口默认HTTP
                if port_id == 80:
                    url_temp = "http://{}".format(curr_ip)
                    url_temp_list.append(url_temp)
                    continue

                # 443端口默认HTTPS
                if port_id == 443:
                    url_temp = "https://{}".format(curr_ip)
                    url_temp_list.append(url_temp)
                    continue

                # 其他端口同时尝试HTTP和HTTPS
                url_temp1 = "http://{}:{}".format(curr_ip, port_id)
                url_temp2 = "https://{}:{}".format(curr_ip, port_id)
                url_temp_list.append(url_temp1)
                url_temp_list.append(url_temp2)

        # 批量检测URL可访问性
        check_map = services.check_http(url_temp_list)

        # 去除https和http相同的，优先保留HTTPS
        alive_site = []
        for x in check_map:
            if x.startswith("https://"):
                alive_site.append(x)

            elif x.startswith("http://"):
                x_temp = "https://" + x[7:]
                if x_temp not in check_map:
                    alive_site.append(x)

        self.site_list.extend(alive_site)

    def ssl_cert(self):
        """
        获取SSL证书信息
        
        说明：
        - 为所有HTTPS服务获取SSL证书
        - 证书信息用于发现域名、组织信息
        - 保存到cert表供后续分析
        """
        if self.options.get("port_scan"):
            self.cert_map = ssl_cert(self.ip_info_list)
        else:
            self.cert_map = ssl_cert(self.ip_set)

        # 保存证书信息到数据库
        for target in self.cert_map:
            if ":" not in target:
                continue
            ip = target.split(":")[0]
            port = int(target.split(":")[1])
            item = {
                "ip": ip,
                "port": port,
                "cert": self.cert_map[target],
                "task_id": self.task_id,
            }
            utils.conn_db('cert').insert_one(item)

    def save_service_info(self):
        """
        保存服务识别信息
        
        说明：
        - 整理所有识别到的服务信息
        - 按服务名称分组
        - 记录每个服务的IP、端口、产品、版本
        - 保存到service表
        """
        self.service_info_list = []
        services_list = set()
        for _data in self.ip_info_list:
            port_info_lsit = _data.get("port_info")
            for _info in port_info_lsit:
                if _info.get("service_name"):
                    # 新服务：创建记录
                    if _info.get("service_name") not in services_list:
                        _result = {}
                        _result["service_name"] = _info.get("service_name")
                        _result["service_info"] = []
                        _result["service_info"].append({'ip': _data.get("ip"),
                                                        'port_id': _info.get("port_id"),
                                                        'product': _info.get("product"),
                                                        'version': _info.get("version")})
                        _result["task_id"] = self.task_id
                        self.service_info_list.append(_result)
                        services_list.add(_info.get("service_name"))
                    else:
                        # 已有服务：追加信息
                        for service_info in self.service_info_list:
                            if service_info.get("service_name") == _info.get("service_name"):
                                service_info['service_info'].append({'ip': _data.get("ip"),
                                                                    'port_id': _info.get("port_id"),
                                                                    'product': _info.get("product"),
                                                                    'version': _info.get("version")})
        # 批量保存服务信息
        if self.service_info_list:
            utils.conn_db('service').insert(self.service_info_list)

    def npoc_service_detection(self):
        """
        NPoc服务识别
        
        说明：
        - 使用Python实现的服务识别（sniffer）
        - 对非常见端口进行协议识别
        - 跳过80、443、843等已知端口
        - 识别结果保存到npoc_service表
        - 识别出的服务可用于后续PoC扫描
        """
        targets = []
        for ip_info in self.ip_info_list:
            for port_info in ip_info["port_info"]:
                skip_port_list = [80, 443, 843]
                if port_info["port_id"] in skip_port_list:
                    continue

                targets.append("{}:{}".format(ip_info["ip"], port_info["port_id"]))

        # 运行服务识别
        result = run_sniffer(targets)
        for item in result:
            self.npoc_service_target_set.add(item["target"])
            item["task_id"] = self.task_id
            item["save_date"] = utils.curr_date()
            utils.conn_db('npoc_service').insert_one(item)

    def brute_config(self):
        """
        弱口令爆破
        
        说明：
        - 根据配置对发现的服务进行弱口令爆破
        - 支持多种服务：SSH、FTP、MySQL、Redis等
        - 使用风险巡航（risk_cruising）框架执行
        - 爆破成功的结果保存到vuln表
        """
        plugins = []
        brute_config = self.options.get("brute_config")
        # 收集启用的插件
        for x in brute_config:
            if not x.get("enable"):
                continue
            plugins.append(x["plugin_name"])

        if not plugins:
            return
        
        # 构建目标列表（站点+服务）
        targets = self.site_list.copy()
        targets += list(self.npoc_service_target_set)
        
        # 执行风险巡航
        result = run_risk_cruising(targets=targets, plugins=plugins)
        for item in result:
            item["task_id"] = self.task_id
            item["save_date"] = utils.curr_date()
            utils.conn_db('vuln').insert_one(item)

    def run(self):
        """
        执行IP扫描任务主流程
        
        执行顺序：
        1. 端口扫描 -> 发现开放端口
        2. 服务识别 -> 识别服务类型和版本
        3. SSL证书获取 -> 获取HTTPS证书
        4. 站点探测 -> 发现Web服务
        5. Web信息采集 -> 获取站点详细信息
        6. NPoc服务识别 -> Python实现的服务识别
        7. PoC扫描 -> 漏洞验证
        8. 弱口令爆破 -> 常见服务爆破
        9. 统计信息 -> 生成指纹、C段统计
        10. 资产同步 -> 同步到资产组
        
        说明：
        - 每个步骤可通过options配置开关
        - 每个步骤记录执行时间
        - 更新任务状态供前端展示
        """
        base_update = self.base_update_task
        base_update.update_task_field("start_time", utils.curr_date())
        
        '''***端口扫描开始***'''
        if self.options.get("port_scan"):
            base_update.update_task_field("status", "port_scan")
            t1 = time.time()
            self.port_scan()
            elapse = time.time() - t1
            base_update.update_services("port_scan", elapse)

        # 存储服务信息
        if self.options.get("service_detection"):
            self.save_service_info()

        '''***证书获取开始***'''
        if self.options.get("ssl_cert"):
            base_update.update_task_field("status", "ssl_cert")
            t1 = time.time()
            self.ssl_cert()
            elapse = time.time() - t1
            base_update.update_services("ssl_cert", elapse)

        # 站点探测
        base_update.update_task_field("status", "find_site")
        t1 = time.time()
        self.find_site()
        elapse = time.time() - t1
        base_update.update_services("find_site", elapse)

        # Web信息采集（标题、指纹、截图等）
        web_site_fetch = WebSiteFetch(task_id=self.task_id,
                                      sites=self.site_list,
                                      options=self.options)
        web_site_fetch.run()

        """服务识别（Python实现）"""
        if self.options.get("npoc_service_detection"):
            base_update.update_task_field("status", "npoc_service_detection")
            t1 = time.time()
            self.npoc_service_detection()
            elapse = time.time() - t1
            base_update.update_services("npoc_service_detection", elapse)

        """ *** NPoc 调用（PoC扫描） """
        if self.options.get("poc_config"):
            base_update.update_task_field("status", "poc_run")
            t1 = time.time()
            web_site_fetch.risk_cruising(self.npoc_service_target_set)
            elapse = time.time() - t1
            base_update.update_services("poc_run", elapse)

        """弱口令爆破服务"""
        if self.options.get("brute_config"):
            base_update.update_task_field("status", "weak_brute")
            t1 = time.time()
            self.brute_config()
            elapse = time.time() - t1
            base_update.update_services("weak_brute", elapse)

        # 加上统计信息
        self.insert_finger_stat()  # 指纹统计
        self.insert_cip_stat()  # C段统计
        self.insert_task_stat()  # 任务统计

        # 如果有关联的资产分组就进行同步
        if self.task_tag == "task":
            self.sync_asset()

        base_update.update_task_field("status", TaskStatus.DONE)
        base_update.update_task_field("end_time", utils.curr_date())


def ip_task(ip_target, task_id, options):
    """
    IP任务入口函数
    
    参数：
        ip_target: 扫描目标（空格分隔的IP或IP段）
        task_id: 任务ID
        options: 扫描选项配置
    
    说明：
    - 创建IPTask实例并执行
    - 捕获异常，标记任务状态为error
    - 被Celery调用执行异步任务
    """
    d = IPTask(ip_target=ip_target, task_id=task_id, options=options)
    try:
        d.run()
    except Exception as e:
        logger.exception(e)
        d.base_update_task.update_task_field("status", "error")

