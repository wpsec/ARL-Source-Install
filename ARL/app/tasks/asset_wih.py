"""
资产WIH（Web Info Hunter）监控更新任务模块

功能说明：
- 监控资产组中站点的JavaScript信息变化
- 从JS文件中提取域名、URL、API接口等敏感信息
- 自动发现新的域名资产并更新

主要功能：
1. WIH监控：定期扫描站点的JS文件，提取信息
2. 信息提取：从JS中提取域名、URL、API路径、密钥等
3. 域名更新：发现新域名后自动添加到资产组
4. 站点更新：对新域名进行站点探测
5. 资产同步：同步更新到资产组

主要类：
- AssetWihUpdateTask: 资产WIH更新监控任务

执行流程：
1. WIH监控 -> 2. 保存结果 -> 3. 域名更新 -> 4. 站点探测 -> 5. 资产同步 -> 6. 统计信息

说明：
- WIH (Web Info Hunter): JS信息采集工具
- 可以发现前端代码中泄露的域名、接口等
- 帮助发现隐藏的子域名和API接口
"""
import time
from app import utils
from app.modules import TaskStatus
from app.utils import get_logger
from app.services.commonTask import CommonTask
from app.services import BaseUpdateTask, domain_site_update, sync_asset
from app.services.asset_wih_monitor import asset_wih_monitor
from app.helpers.asset_domain import find_domain_by_scope_id
from app.helpers.scope import get_scope_by_scope_id

logger = get_logger()


class AssetWihUpdateTask(CommonTask):
    """
    资产WIH更新监控任务类
    
    功能说明：
    - 定期监控资产组中站点的JS文件
    - 提取JS中的域名、URL等敏感信息
    - 自动发现新域名并更新资产组
    
    主要属性：
    - task_id: 任务ID
    - scope_id: 资产组ID
    - wih_results: WIH监控结果列表
    - _scope_sub_domains: 资产组现有子域名集合（缓存）
    
    主要方法：
    - run_wih_monitor(): 执行WIH监控
    - wih_results_save(): 保存监控结果
    - run_wih_domain_update(): 更新发现的新域名
    """
    
    def __init__(self, task_id: str, scope_id: str):
        """
        初始化资产WIH更新任务
        
        参数：
            task_id: 任务ID
            scope_id: 资产组ID
        """
        super().__init__(task_id=task_id)

        self.task_id = task_id
        self.scope_id = scope_id
        self.base_update_task = BaseUpdateTask(self.task_id)
        self.wih_results = []  # WIH监控结果

        self._scope_sub_domains = None  # 资产组子域名缓存

    def run(self):
        """
        执行资产WIH更新任务
        
        执行流程：
        1. WIH监控：扫描JS文件提取信息
        2. 保存结果：保存到wih表
        3. 域名更新：发现的新域名进行站点探测
        4. 统计信息：生成任务统计
        """
        logger.info("run AssetWihUpdateTask, task_id:{} scope_id: {}".format(self.task_id, self.scope_id))
        
        # 执行WIH监控
        self.run_wih_monitor()

        # 保存监控结果
        self.wih_results_save()

        # 如果有结果，更新域名
        if self.wih_results:
            self.run_wih_domain_update()

        # 插入统计信息
        self.insert_stat()

        logger.info("end AssetWihUpdateTask, task_id:{} results: {}".format(self.task_id, len(self.wih_results)))

    def insert_stat(self):
        """
        插入统计信息
        
        说明：
        - 插入指纹统计
        - 插入任务统计
        """
        self.insert_finger_stat()
        self.insert_task_stat()

    def wih_results_save(self):
        """
        保存WIH监控结果
        
        说明：
        - 将WIH结果保存到wih表
        - 每条记录关联task_id
        - 用于后续分析和展示
        """
        for record in self.wih_results:
            item = record.dump_json()
            item["task_id"] = self.task_id
            utils.conn_db('wih').insert_one(item)

    def run_wih_monitor(self):
        """
        执行WIH监控
        
        说明：
        - 扫描资产组中所有站点的JS文件
        - 提取域名、URL、API接口、密钥等信息
        - 记录执行时间用于性能分析
        
        提取内容：
        - 域名：从JS中发现的新域名
        - URL：完整的URL地址
        - API路径：接口路径
        - 敏感信息：密钥、Token等
        """
        service_name = "wih_monitor"
        self.base_update_task.update_task_field("status", service_name)
        start_time = time.time()

        # 执行WIH监控
        self.wih_results = asset_wih_monitor(self.scope_id)

        elapsed = time.time() - start_time

        self.base_update_task.update_services(service_name, elapsed)

    @property
    def scope_sub_domains(self):
        """
        获取资产组现有子域名集合
        
        返回：
            set: 子域名集合
        
        说明：
        - 延迟加载，第一次访问时查询数据库
        - 后续访问使用缓存，提高性能
        - 用于去重，避免重复处理已知域名
        """
        if self._scope_sub_domains is None:
            self._scope_sub_domains = set(find_domain_by_scope_id(self.scope_id))
        return self._scope_sub_domains

    def run_wih_domain_update(self):
        """
        更新WIH发现的新域名
        
        执行流程：
        1. 检查资产组类型是否为domain类型
        2. 从WIH结果中提取域名记录
        3. 过滤已存在的域名
        4. 对新域名进行站点探测
        5. 同步更新到资产组
        
        说明：
        - 只有domain类型的资产组才会更新域名
        - 自动去重，不处理已知域名
        - 新域名会触发站点探测和资产同步
        """
        # 获取资产组信息
        scope_data = get_scope_by_scope_id(self.scope_id)
        if not scope_data:
            return

        # 只处理domain类型的资产组
        if scope_data.get("scope_type") != "domain":
            return

        # 提取新域名
        domains = []
        for item in self.wih_results:
            if item.recordType == "domain":
                # 过滤已存在的域名
                if item.content in self.scope_sub_domains:
                    continue

                domains.append(item.content)

        # 如果有新域名，进行站点更新和资产同步
        if domains:
            # 域名站点更新
            domain_site_update(self.task_id, domains, "wih")

            # 同步到资产组
            sync_asset(task_id=self.task_id, scope_id=self.scope_id)


def asset_wih_update_task(task_id, scope_id, scheduler_id):
    """
    资产WIH更新监控任务入口
    
    参数：
        task_id: 任务ID
        scope_id: 资产组ID
        scheduler_id: 调度器ID
    
    说明：
    - 由定时调度器调用
    - 更新调度器运行时间
    - 捕获异常并标记任务状态
    - 记录开始和结束时间
    """
    from app.scheduler import update_job_run

    task = AssetWihUpdateTask(task_id=task_id, scope_id=scope_id)
    task.base_update_task.update_task_field("start_time", utils.curr_date())

    try:
        # 更新调度器运行时间
        update_job_run(job_id=scheduler_id)
        
        # 执行任务
        task.run()
        
        # 标记完成
        task.base_update_task.update_task_field("status", TaskStatus.DONE)
    except Exception as e:
        logger.exception(e)

        # 标记错误
        task.base_update_task.update_task_field("status", TaskStatus.ERROR)

    task.base_update_task.update_task_field("end_time", utils.curr_date())

