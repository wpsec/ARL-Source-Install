"""
Fofa任务管理模块

功能说明：
- 集成Fofa（网络空间测绘平台）进行资产发现
- 支持通过Fofa查询语句批量获取IP地址
- 自动提交扫描任务对Fofa查询结果进行深度探测

Fofa简介：
- Fofa是国内知名的网络空间测绘搜索引擎
- 可通过特征语法快速定位互联网资产
- 常用语法示例：
  * domain="example.com" - 查询指定域名
  * app="Apache" - 查询特定应用
  * country="CN" - 查询指定国家
  * port="80" - 查询指定端口

主要功能：
- 测试Fofa查询连接和语法
- 提交Fofa任务并自动扫描结果IP
- 支持策略配置自定义扫描选项
"""
from flask_restx import Namespace, fields
from app.utils import get_logger, auth, build_ret, conn_db
from app.modules import ErrorMsg, CeleryAction
from app.services.fofaClient import fofa_query, fofa_query_result
from app import celerytask
from bson import ObjectId
from . import ARLResource


ns = Namespace('task_fofa', description="Fofa 任务下发")

logger = get_logger()


# 测试Fofa查询请求模型
test_fofa_fields = ns.model('taskFofaTest',  {
    'query': fields.String(required=True, description="Fofa查询语句")
})


@ns.route('/test')
class TaskFofaTest(ARLResource):
    """Fofa查询测试接口"""

    @auth
    @ns.expect(test_fofa_fields)
    def post(self):
        """
        测试Fofa查询连接和语法
        
        请求体：
            {
                "query": "domain=\"example.com\""
            }
        
        返回：
            {
                "code": 200,
                "message": "成功",
                "size": 结果数量,
                "query": "查询语句"
            }
        
        说明：
        - 验证Fofa API连接是否正常
        - 验证查询语法是否正确
        - 返回查询结果数量（不返回具体数据）
        - 用于提交任务前的预检查
        
        常见错误：
        - FofaConnectError: 连接Fofa API失败
        - FofaKeyError: API密钥错误或无权限
        """
        args = self.parse_args(test_fofa_fields)
        query = args.pop('query')
        
        # 查询Fofa（仅获取1条用于测试）
        data = fofa_query(query, page_size=1)
        if isinstance(data, str):
            return build_ret(ErrorMsg.FofaConnectError, {'error': data})

        if data.get("error"):
            return build_ret(ErrorMsg.FofaKeyError, {'error': data.get("errmsg")})

        item = {
            "size": data["size"],
            "query": data["query"]
        }

        return build_ret(ErrorMsg.Success, item)


# 添加Fofa任务请求模型
add_fofa_fields = ns.model('addTaskFofa', {
    'query': fields.String(required=True, description="Fofa查询语句"),
    'name': fields.String(required=True, description="任务名称"),
    'policy_id': fields.String(description="策略ID（可选，自定义扫描配置）")
})


@ns.route('/submit')
class AddFofaTask(ARLResource):
    """提交Fofa任务接口"""

    @auth
    @ns.expect(add_fofa_fields)
    def post(self):
        """
        提交Fofa查询任务并自动扫描结果IP
        
        请求体：
            {
                "query": "domain=\"example.com\" && port=\"80\"",
                "name": "Fofa扫描任务",
                "policy_id": "策略ID（可选）"
            }
        
        返回：
            {
                "code": 200,
                "message": "成功",
                "task_id": "任务ID",
                "celery_id": "Celery任务ID",
                "name": "任务名称",
                "target": "Fofa ip 数量"
            }
        
        说明：
        - 通过Fofa查询获取IP列表
        - 自动提交扫描任务对这些IP进行端口探测和服务识别
        - 默认执行轻量级扫描（测试级别端口扫描）
        - 可指定策略ID使用自定义扫描配置
        
        执行流程：
        1. 验证Fofa查询语法和连接
        2. 获取完整的IP列表
        3. 创建扫描任务
        4. 提交到Celery队列执行
        
        注意事项：
        - 需要配置有效的Fofa API密钥
        - 查询结果为空时返回错误
        - 大量IP可能需要较长扫描时间
        """
        args = self.parse_args(add_fofa_fields)
        query = args.pop('query')
        name = args.pop('name')
        policy_id = args.get('policy_id')

        # 默认任务选项（轻量级扫描）
        task_options = {
            "port_scan_type": "test",  # 测试级别端口扫描
            "port_scan": True,  # 启用端口扫描
            "service_detection": False,  # 服务识别
            "service_brute": False,  # 服务暴力破解
            "os_detection": False,  # 操作系统识别
            "site_identify": False,  # 站点识别
            "file_leak": False,  # 文件泄露检测
            "ssl_cert": False  # SSL证书获取
        }

        # 测试查询（获取1条验证）
        data = fofa_query(query, page_size=1)
        if isinstance(data, str):
            return build_ret(ErrorMsg.FofaConnectError, {'error': data})

        if data.get("error"):
            return build_ret(ErrorMsg.FofaKeyError, {'error': data.get("errmsg")})

        if data["size"] <= 0:
            return build_ret(ErrorMsg.FofaResultEmpty, {})

        # 获取完整IP列表
        fofa_ip_list = fofa_query_result(query)
        if isinstance(fofa_ip_list, str):
            return build_ret(ErrorMsg.FofaConnectError, {'error': data})

        # 如果指定了策略，使用策略配置
        if policy_id and len(policy_id) == 24:
            task_options.update(policy_2_task_options(policy_id))

        # 构建任务数据
        task_data = {
            "name": name,
            "target": "Fofa ip {}".format(len(fofa_ip_list)),
            "start_time": "-",
            "end_time": "-",
            "task_tag": "task",
            "service": [],
            "status": "waiting",
            "options": task_options,
            "type": "fofa",
            "fofa_ip": fofa_ip_list
        }
        
        # 提交任务
        task_data = submit_fofa_task(task_data)

        return build_ret(ErrorMsg.Success, task_data)


def policy_2_task_options(policy_id):
    """
    将策略配置转换为任务选项
    
    参数：
        policy_id: 策略ID
    
    返回：
        dict: 任务选项字典
    
    说明：
    - 提取策略中的IP和站点配置
    - 移除域名配置（Fofa任务只扫描IP）
    - 合并配置项
    """
    options = {}
    query = {
        "_id": ObjectId(policy_id)
    }
    data = conn_db('policy').find_one(query)
    if not data:
        return options

    policy_options = data["policy"]
    # 移除域名配置（Fofa任务不需要）
    policy_options.pop("domain_config")

    # 提取IP和站点配置
    ip_config = policy_options.pop("ip_config")
    site_config = policy_options.pop("site_config")

    # 合并配置
    options.update(ip_config)
    options.update(site_config)
    options.update(policy_options)

    return options


def submit_fofa_task(task_data):
    """
    提交Fofa扫描任务
    
    参数：
        task_data: 任务数据字典
    
    返回：
        dict: 包含task_id和celery_id的任务数据
    
    说明：
    - 保存任务到数据库
    - 提交到Celery队列执行
    - 更新任务的celery_id
    """
    # 保存任务到数据库
    conn_db('task').insert_one(task_data)
    task_id = str(task_data.pop("_id"))
    task_data["task_id"] = task_id

    # 构建Celery任务选项
    task_options = {
        "celery_action": CeleryAction.FOFA_TASK,
        "data": task_data
    }

    # 提交到Celery队列
    celery_id = celerytask.arl_task.delay(options=task_options)

    logger.info("target:{} celery_id:{}".format(task_id, celery_id))

    # 更新任务的celery_id
    values = {"$set": {"celery_id": str(celery_id)}}
    task_data["celery_id"] = str(celery_id)
    conn_db('task').update_one({"_id": ObjectId(task_id)}, values)

    return task_data


