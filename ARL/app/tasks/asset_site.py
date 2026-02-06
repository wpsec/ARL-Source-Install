"""
资产站点监控和更新任务模块

功能说明：
- 监控资产组中站点的变化情况
- 添加新的站点资产到资产组
- 发送站点变化通知

主要功能：
1. 站点监控：检测资产组中站点的新增、变化
2. 域名站点监控：监控域名解析出的新站点
3. 消息推送：站点变化通知（邮件、钉钉、Webhook）
4. 资产添加：向资产组批量添加站点资产

主要类：
- AssetSiteUpdateTask: 资产站点更新监控任务
- AddAssetSiteTask: 添加资产站点任务

执行流程：
监控任务：1. 获取站点变化 -> 2. 监控域名站点 -> 3. 保存结果 -> 4. 发送通知
添加任务：1. 站点去重 -> 2. 站点探测 -> 3. 保存到资产组
"""
from bson import ObjectId
from app import utils
from app.services.commonTask import CommonTask, WebSiteFetch
from app.modules import TaskStatus
from app.helpers.message_notify import push_email, push_dingding
from app.tasks.poc import RiskCruising
from app.services import webhook
logger = utils.get_logger()


class AssetSiteUpdateTask(CommonTask):
    """
    资产站点更新监控任务类
    
    功能说明：
    - 定期监控资产组中站点的变化
    - 检测新增站点和站点属性变化
    - 通过邮件、钉钉、Webhook推送变化通知
    
    主要属性：
    - task_id: 任务ID
    - scope_id: 资产组ID
    - results: 监控结果列表
    
    主要方法：
    - monitor(): 执行站点监控
    - save_task_site(): 保存站点信息
    - update_status(): 更新任务状态
    """
    
    def __init__(self, task_id, scope_id):
        """
        初始化资产站点更新任务
        
        参数：
            task_id: 任务ID
            scope_id: 资产组ID
        """
        super().__init__(task_id=task_id)

        self.task_id = task_id
        self.scope_id = scope_id
        self.collection = "task"
        self.results = []

    def update_status(self, value):
        """
        更新任务状态
        
        参数：
            value: 状态值
        """
        query = {"_id": ObjectId(self.task_id)}
        update = {"$set": {"status": value}}
        utils.conn_db(self.collection).update_one(query, update)

    def set_start_time(self):
        """
        设置任务开始时间
        """
        query = {"_id": ObjectId(self.task_id)}
        update = {"$set": {"start_time": utils.curr_date()}}
        utils.conn_db(self.collection).update_one(query, update)

    def set_end_time(self):
        """
        设置任务结束时间
        """
        query = {"_id": ObjectId(self.task_id)}
        update = {"$set": {"end_time": utils.curr_date()}}
        utils.conn_db(self.collection).update_one(query, update)

    def save_task_site(self, site_info_list):
        """
        保存站点信息到数据库
        
        参数：
            site_info_list: 站点信息列表
        
        说明：
        - 为每个站点添加task_id
        - 保存到site表
        """
        for site_info in site_info_list:
            site_info["task_id"] = self.task_id
            utils.conn_db('site').insert_one(site_info)
        logger.info("save {} to {}".format(len(site_info_list), self.task_id))

    def monitor(self):
        """
        执行站点监控
        
        监控内容：
        1. 资产站点监控：检测站点的新增、变化、失效
        2. 域名站点监控：监控域名解析出的新站点
        3. 消息推送：通过邮件、钉钉、Webhook发送变化通知
        
        通知内容：
        - 新增站点列表
        - 站点属性变化（标题、状态码、指纹等）
        - 失效站点列表
        """
        from app.services.asset_site_monitor import AssetSiteMonitor, Domain2SiteMonitor
        
        # 资产站点监控
        self.update_status("fetch site")
        monitor = AssetSiteMonitor(scope_id=self.scope_id)
        monitor.build_change_list()

        if monitor.site_change_info_list:
            self.save_task_site(monitor.site_change_info_list)

        # 域名站点监控
        self.update_status("domain site monitor")
        domain2site_monitor = Domain2SiteMonitor(scope_id=self.scope_id)
        if domain2site_monitor.run():
            self.save_task_site(domain2site_monitor.site_info_list)

        # 发送通知
        self.update_status("send notify")
        
        # 构建HTML报告（邮件）
        html_report = ""
        if monitor.site_change_info_list:
            html_report = monitor.build_html_report()

        if domain2site_monitor.site_info_list:
            html_report += "\n<br/>"
            html_report += domain2site_monitor.html_report

        if html_report:
            html_title = "[站点监控-{}] 灯塔消息推送".format(monitor.scope_name)
            push_email(title=html_title, html_report=html_report)

        # 构建Markdown报告（钉钉）
        markdown_report = ""
        if monitor.site_change_info_list:
            markdown_report = monitor.build_markdown_report()

        if domain2site_monitor.site_info_list:
            markdown_report += "\n"
            markdown_report += domain2site_monitor.dingding_markdown

        if markdown_report:
            push_dingding(markdown_report=markdown_report)

        # Webhook通知
        if html_report or markdown_report:
            webhook.site_asset_web_hook(task_id=self.task_id, scope_id=self.scope_id)

    def run(self):
        """
        执行资产站点更新任务
        
        执行流程：
        1. 记录开始时间
        2. 执行监控
        3. 生成统计信息
        4. 更新任务状态为完成
        5. 记录结束时间
        """
        self.set_start_time()
        self.monitor()
        self.insert_task_stat()
        self.update_status(TaskStatus.DONE)
        self.set_end_time()


def asset_site_update_task(task_id, scope_id, scheduler_id):
    """
    资产站点更新监控任务入口
    
    参数：
        task_id: 任务ID
        scope_id: 资产组ID
        scheduler_id: 调度器ID
    
    说明：
    - 由定时调度器调用
    - 更新调度器运行时间
    - 捕获异常并标记任务状态
    """
    from app.scheduler import update_job_run

    task = AssetSiteUpdateTask(task_id=task_id, scope_id=scope_id)
    try:
        update_job_run(job_id=scheduler_id)
        task.run()
    except Exception as e:
        logger.exception(e)
        task.update_status(TaskStatus.ERROR)
        task.set_end_time()


class AddAssetSiteTask(RiskCruising):
    """
    添加资产站点任务类
    
    功能说明：
    - 向资产组批量添加站点资产
    - 自动去重，避免重复添加
    - 探测站点可访问性和详细信息
    
    继承自：
    - RiskCruising: 复用站点探测和信息采集功能
    
    主要方法：
    - asset_site_deduplication(): 站点去重
    - work(): 执行添加流程
    """
    
    def __init__(self, task_id):
        """
        初始化添加资产站点任务
        
        参数：
            task_id: 任务ID
        """
        super().__init__(task_id=task_id)

    def asset_site_deduplication(self):
        """
        资产站点去重
        
        说明：
        - 检查站点是否已存在于资产组
        - 过滤已存在的站点
        - 只添加新站点
        
        注意：
        - 需要在options中指定related_scope_id
        - 自动补全http://协议
        - 去除URL尾部斜杠进行规范化
        """
        related_scope_id = self.options.get("related_scope_id", "")
        if not related_scope_id:
            raise Exception("not found related_scope_id, task_id:{}".format(self.task_id))

        new_targets = []

        for url in self.targets:
            # 补全协议
            if "://" not in url:
                url = "http://" + url

            # 规范化URL（去除尾部斜杠）
            url = url.strip("/")
            
            # 检查是否已存在
            site_data = utils.conn_db('asset_site').find_one({"site": url, "scope_id": related_scope_id})
            if site_data:
                logger.info("{} is in scope".format(url))
                continue
            new_targets.append(url)
        
        self.targets = new_targets

    def work(self):
        """
        执行添加资产站点工作流程
        
        执行顺序：
        1. 站点去重：过滤已存在的站点
        2. 预处理站点：转换为标准URL格式
        3. 站点探测：获取站点详细信息
        4. 通用处理：统计和资产同步
        """
        # 去重
        self.asset_site_deduplication()
        
        # 预处理
        self.pre_set_site()
        
        # 站点探测
        if self.user_target_site_set:
            web_site_fetch = WebSiteFetch(task_id=self.task_id,
                                          sites=list(self.user_target_site_set),
                                          options=self.options)
            web_site_fetch.run()

        # 通用处理
        self.common_run()


def run_add_asset_site_task(task_id):
    """
    运行添加资产站点任务
    
    参数：
        task_id: 任务ID
    
    说明：
    - 从数据库获取任务配置
    - 检查任务状态为waiting才执行
    - 创建AddAssetSiteTask实例并运行
    - 被Celery调用执行异步任务
    """
    query = {"_id": ObjectId(task_id)}
    task_data = utils.conn_db('task').find_one(query)

    if not task_data:
        return

    if task_data["status"] != "waiting":
        return

    r = AddAssetSiteTask(task_id)
    r.run()

