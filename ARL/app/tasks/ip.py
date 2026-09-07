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
import traceback
from app import utils
from app.services.commonTask import CommonTask, BaseUpdateTask, WebSiteFetch
from app.config import Config
from app.services.ip_network_scan_services import (
    IPPortScanStageService,
    IPSiteDiscoveryStageService,
)
from app.services.ip_post_process_stage_services import (
    IPBruteConfigStageService,
    IPNPOCServiceDetectionStageService,
)
from app.services.service_detection import (
    apply_npoc_service_result,
    build_sniffer_targets,
    extract_detected_service,
    is_low_conf_service,
    normalize_scheme,
)
from app.services.task_orchestrator import IPTaskOrchestrator
from app.services.ip_cert_service_stage_services import (
    IPCertStageService,
    IPServiceSummaryStageService,
    fetch_cert_map,
)


logger = utils.get_logger()


def ssl_cert(ip_info_list):
    """批量获取SSL证书信息（兼容入口，实现已移至 ip_cert_service_stage_services）。"""
    return fetch_cert_map(ip_info_list)


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

    @staticmethod
    def _is_low_conf_service(port_info):
        return is_low_conf_service(port_info)

    @staticmethod
    def _normalize_scheme(value):
        return normalize_scheme(value, use_registry=True)

    @staticmethod
    def _extract_detected_service(service_name, product=""):
        return extract_detected_service(service_name, product)

    def _enable_protocol_detection(self):
        """
        兼容历史选项：
        - service_detection：启用服务识别增强（nmap -sV + sniffer）
        - npoc_service_detection：历史开关，继续兼容
        """
        return bool(self.options.get("service_detection") or self.options.get("npoc_service_detection"))

    def _build_sniffer_targets(self, full_port=False):
        return build_sniffer_targets(self, full_port=full_port)

    def _apply_npoc_service_result(self, sniffer_items):
        return apply_npoc_service_result(self, sniffer_items, use_registry=True)

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
        return IPPortScanStageService(self).run()

    def find_site(self):
        return IPSiteDiscoveryStageService(self).run()

    def ssl_cert(self):
        """获取SSL证书信息（兼容入口，实现见 IPCertStageService）。"""
        return IPCertStageService(self).run()

    def save_service_info(self):
        """保存服务识别信息（兼容入口，实现见 IPServiceSummaryStageService）。"""
        return IPServiceSummaryStageService(self).run()

    def npoc_service_detection(self, full_port=False):
        return IPNPOCServiceDetectionStageService(self).run(full_port=full_port)

    def brute_config(self):
        return IPBruteConfigStageService(self).run()

    def run(self):
        return IPTaskOrchestrator(self).run()


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
        utils.append_task_error(
            task_id=task_id,
            error=e,
            stage="ip_task",
            traceback_text=traceback.format_exc(),
        )
