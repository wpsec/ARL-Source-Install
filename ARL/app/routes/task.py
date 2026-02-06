"""
任务管理 API
================================================

该模块是 ARL 系统的核心模块，提供资产发现任务的全生命周期管理

主要功能：
1. 任务创建和提交（域名/IP扫描）
2. 任务查询和筛选
3. 任务停止和删除
4. 任务同步到资产组
5. 任务重启
6. 通过策略批量下发任务

任务类型：
- 域名任务（domain）：子域名爆破、DNS解析、端口扫描等
- IP任务（ip）：端口扫描、服务识别、站点探测等
- 风险巡航任务（risk_cruising）：安全风险扫描

任务状态：
- waiting：等待中
- running：运行中
- done：已完成
- stop：已停止
- error：执行出错

任务选项：
- domain_brute：域名爆破（test/big/test爆破字典）
- port_scan：端口扫描（test/top100/top1000/all）
- service_detection：服务识别
- file_leak：文件泄露扫描
- site_identify：站点识别
- nuclei_scan：Nuclei漏洞扫描
- web_info_hunter：JS信息收集
等30+个可选项
"""
import re
import bson
from flask_restx import Resource, Api, reqparse, fields, Namespace
from bson import ObjectId
from app import celerytask
from app.utils import get_logger, auth
from . import base_query_fields, ARLResource, get_arl_parser, conn
from app import utils
from app.modules import TaskStatus, ErrorMsg, TaskSyncStatus, CeleryAction, TaskTag, TaskType
from app.helpers import get_options_by_policy_id, submit_task_task,\
    submit_risk_cruising, get_scope_by_scope_id, check_target_in_scope
from app.helpers.task import get_task_data, restart_task

# 创建任务信息命名空间
ns = Namespace('task', description="资产发现任务信息")

logger = get_logger()

# 任务查询字段定义
# 支持按任务的各种属性和选项进行查询
base_search_task_fields = {
    'name': fields.String(required=False, description="任务名称"),
    'target': fields.String(description="任务目标（域名或IP）"),
    'status': fields.String(description="任务状态（waiting/running/done/stop/error）"),
    '_id': fields.String(description="任务ID"),
    'task_tag': fields.String(description="任务标签（task/monitor/risk_cruising）"),
    'options.domain_brute': fields.Boolean(description="是否开启域名爆破"),
    'options.domain_brute_type': fields.String(description="域名爆破类型（test/big/test）"),
    'options.port_scan_type': fields.Boolean(description="端口扫描类型（test/top100/top1000/all）"),
    'options.port_scan': fields.Boolean(description="是否开启端口扫描"),
    'options.service_detection': fields.Boolean(description="是否开启服务识别（nmap -sV）"),
    'options.service_brute': fields.Boolean(description="是否开启服务弱口令爆破"),
    'options.os_detection': fields.Boolean(description="是否开启操作系统识别（nmap -O）"),
    'options.site_identify': fields.Boolean(description="是否开启站点识别（指纹识别）"),
    'options.file_leak': fields.Boolean(description="是否开启文件泄露扫描（敏感文件检测）"),
    'options.alt_dns': fields.Boolean(description="是否开启DNS字典智能生成（域名变异）"),
    'options.search_engines': fields.Boolean(description="是否开启搜索引擎调用（百度、必应等）"),
    'options.site_spider': fields.Boolean(description="是否开启站点爬虫（深度爬取）"),
    'options.arl_search': fields.Boolean(description="是否开启ARL历史数据查询"),
    'options.dns_query_plugin': fields.Boolean(description="是否开启DNS查询插件"),
    'options.skip_scan_cdn_ip': fields.Boolean(description="是否跳过CDN IP的端口扫描"),
    'options.nuclei_scan': fields.Boolean(description="是否开启Nuclei漏洞扫描"),
    'options.findvhost': fields.Boolean(description="是否开启虚拟主机碰撞检测"),
    'options.web_info_hunter': fields.Boolean(description="是否开启WebInfoHunter（JS信息收集）"),
}

# 合并基础查询字段
base_search_task_fields.update(base_query_fields)

search_task_fields = ns.model('SearchTask', base_search_task_fields)

# 添加任务请求模型定义
# 包含所有可选的扫描选项
add_task_fields = ns.model('AddTask', {
    'name': fields.String(required=True, example="task name", description="任务名称"),
    'target': fields.String(required=True, example="www.freebuf.com", description="扫描目标（域名或IP）"),
    "domain_brute": fields.Boolean(example=True, description="域名爆破"),
    'domain_brute_type': fields.String(example="test", description="爆破字典类型"),
    "port_scan_type": fields.String(example="test", description="端口扫描类型"),
    "port_scan": fields.Boolean(example=True, description="端口扫描"),
    "service_detection": fields.Boolean(example=False, description="服务识别"),
    "service_brute": fields.Boolean(example=False, description="服务弱口令爆破"),
    "os_detection": fields.Boolean(example=False, description="操作系统识别"),
    "site_identify": fields.Boolean(example=False, description="站点识别"),
    "site_capture": fields.Boolean(example=False, description="站点截图"),
    "file_leak": fields.Boolean(example=False, description="文件泄露扫描"),
    "search_engines": fields.Boolean(example=False, description="搜索引擎调用"),
    "site_spider": fields.Boolean(example=False, description="站点爬虫"),
    "arl_search": fields.Boolean(example=False, description="ARL历史查询"),
    "alt_dns": fields.Boolean(example=False, description="DNS字典智能生成"),
    "ssl_cert": fields.Boolean(example=False, description="SSL证书收集"),
    "dns_query_plugin": fields.Boolean(example=False, default=False, description="DNS查询插件"),
    "skip_scan_cdn_ip": fields.Boolean(example=False, default=False, description="跳过CDN IP"),
    "nuclei_scan": fields.Boolean(description="Nuclei漏洞扫描", example=False, default=False),
    "findvhost": fields.Boolean(example=False, default=False, description="虚拟主机碰撞"),
    "web_info_hunter": fields.Boolean(example=False, default=False, description="WebInfoHunter JS信息收集"),
})


@ns.route('/')
class ARLTask(ARLResource):
    """任务管理主接口"""
    parser = get_arl_parser(search_task_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        查询任务信息
        
        支持的查询条件：
        - name：任务名称
        - target：任务目标
        - status：任务状态
        - task_tag：任务标签
        - options.*：各种任务选项
        
        返回：
            分页的任务信息列表
        
        应用场景：
        - 查看所有任务
        - 筛选特定状态的任务
        - 查找特定目标的任务
        - 按选项筛选任务
        """
        args = self.parser.parse_args()
        # 从 task 集合查询数据
        data = self.build_data(args=args, collection='task')

        return data

    @auth
    @ns.expect(add_task_fields)
    def post(self):
        """
        提交新的扫描任务
        
        请求体：
            {
                "name": "任务名称",
                "target": "扫描目标",
                "domain_brute": true,  // 域名爆破
                "port_scan": true,     // 端口扫描
                ... // 其他选项
            }
        
        返回：
            创建的任务列表（一个目标可能创建多个子任务）
        
        说明：
        - 目标可以是单个域名、多个域名（逗号分隔）、IP、IP段
        - 系统会自动验证目标格式
        - 域名任务会进行子域名爆破、DNS解析、端口扫描等
        - IP任务会进行端口扫描、服务识别等
        - 任务会自动提交到Celery队列异步执行
        
        示例目标格式：
        - 单个域名：www.example.com
        - 多个域名：www.example.com,api.example.com
        - 单个IP：192.168.1.1
        - IP段：192.168.1.0/24
        - IP范围：192.168.1.1-192.168.1.100
        """
        args = self.parse_args(add_task_fields)

        name = args.pop('name')
        target = args.pop('target')

        try:
            # 提交任务（会进行目标验证和任务创建）
            task_data_list = submit_task_task(target=target, name=name, options=args)
        except Exception as e:
            logger.exception(e)
            return utils.build_ret(ErrorMsg.Error, {"error": str(e)})

        # 验证是否有有效的任务目标
        if not task_data_list:
            return utils.build_ret(ErrorMsg.TaskTargetIsEmpty, {"target": target})

        ret = {
            "code": 200,
            "message": "success",
            "items": task_data_list
        }
        return ret


# 批量停止任务请求模型
batch_stop_fields = ns.model('BatchStop', {
    "task_id": fields.List(fields.String(description="任务ID列表"), required=True),
})


@ns.route('/batch_stop/')
class BatchStopTask(ARLResource):
    """批量停止任务接口"""

    @auth
    @ns.expect(batch_stop_fields)
    def post(self):
        """
        批量停止正在运行的任务
        
        请求体：
            {
                "task_id": ["任务ID1", "任务ID2", ...]
            }
        
        返回：
            操作成功信息
        
        说明：
        - 只能停止运行中的任务
        - 已完成、已停止、出错的任务无法停止
        - 会向Celery Worker发送SIGTERM信号终止任务
        - 任务状态会更新为stop
        """
        args = self.parse_args(batch_stop_fields)
        task_id_list = args.pop("task_id", [])

        # 遍历停止每个任务
        for task_id in task_id_list:
            if not task_id:
                continue
            stop_task(task_id)

        # 这里直接返回成功了
        return utils.build_ret(ErrorMsg.Success, {})


@ns.route('/stop/<string:task_id>')
class StopTask(ARLResource):
    """单个任务停止接口"""
    
    @auth
    def get(self, task_id=None):
        """
        停止指定的任务
        
        路径参数：
            task_id：任务ID
        
        返回：
            操作结果
        """
        return stop_task(task_id=task_id)


def stop_task(task_id):
    """
    停止任务的核心函数
    
    参数：
        task_id：任务ID
    
    返回：
        操作结果
    
    流程：
        1. 查询任务是否存在
        2. 检查任务状态（只能停止运行中的任务）
        3. 获取Celery任务ID
        4. 向Worker发送终止信号
        5. 更新任务状态为stop
        6. 记录结束时间
    """
    # 终态状态列表（这些状态的任务无法停止）
    done_status = [TaskStatus.DONE, TaskStatus.STOP, TaskStatus.ERROR]

    # 查询任务信息
    task_data = utils.conn_db('task').find_one({'_id': ObjectId(task_id)})
    if not task_data:
        return utils.build_ret(ErrorMsg.NotFoundTask, {"task_id": task_id})

    # 检查任务状态
    if task_data["status"] in done_status:
        return utils.build_ret(ErrorMsg.TaskIsDone, {"task_id": task_id})

    # 获取Celery任务ID
    celery_id = task_data.get("celery_id")
    if not celery_id:
        return utils.build_ret(ErrorMsg.CeleryIdNotFound, {"task_id": task_id})

    # 向Celery Worker发送终止信号
    control = celerytask.celery.control
    control.revoke(celery_id, signal='SIGTERM', terminate=True)

    # 更新任务状态为停止
    utils.conn_db('task').update_one({'_id': ObjectId(task_id)}, {"$set": {"status": TaskStatus.STOP}})

    # 记录任务结束时间
    utils.conn_db('task').update_one({'_id': ObjectId(task_id)}, {"$set": {"end_time": utils.curr_date()}})

    return utils.build_ret(ErrorMsg.Success, {"task_id": task_id})


# 删除任务请求模型
delete_task_fields = ns.model('DeleteTask',  {
    'del_task_data': fields.Boolean(required=False, default=False, description="是否删除任务数据"),
    'task_id': fields.List(fields.String(required=True, description="任务ID"))
})


@ns.route('/delete/')
class DeleteTask(ARLResource):
    """任务删除接口"""
    
    @auth
    @ns.expect(delete_task_fields)
    def post(self):
        """
        删除已完成的任务
        
        请求体：
            {
                "task_id": ["任务ID1", "任务ID2", ...],
                "del_task_data": true/false  // 是否同时删除任务产生的资产数据
            }
        
        返回：
            操作成功信息
        
        说明：
        - 只能删除已完成、已停止、出错的任务
        - 正在运行的任务无法删除（需先停止）
        - del_task_data为true时会删除关联的资产数据：
          * 证书(cert)、域名(domain)、IP(ip)、服务(service)
          * 站点(site)、URL(url)、漏洞(vuln)、文件泄露(fileleak)
          * CIP、NPoC服务、WIH、Nuclei结果、指纹统计等
        - 删除操作不可逆，请谨慎使用
        """
        # 终态状态列表（只有这些状态的任务可以删除）
        done_status = [TaskStatus.DONE, TaskStatus.STOP, TaskStatus.ERROR]
        args = self.parse_args(delete_task_fields)
        task_id_list = args.pop('task_id')
        del_task_data_flag = args.pop('del_task_data')

        # 第一步：验证所有任务是否可以删除
        for task_id in task_id_list:
            task_data = utils.conn_db('task').find_one({'_id': ObjectId(task_id)})
            if not task_data:
                return utils.build_ret(ErrorMsg.NotFoundTask, {"task_id": task_id})

            # 检查任务状态，运行中的任务不能删除
            if task_data["status"] not in done_status:
                return utils.build_ret(ErrorMsg.TaskIsRunning, {"task_id": task_id})

        # 第二步：执行删除操作
        for task_id in task_id_list:
            # 删除任务记录
            utils.conn_db('task').delete_many({'_id': ObjectId(task_id)})
            
            # 相关资产数据表列表
            table_list = ["cert", "domain", "fileleak","ip", "service",
                          "site", "url", "vuln", "cip", "npoc_service", "wih", "nuclei_result", "stat_finger"]

            # 如果选择删除任务数据，则删除所有相关资产
            if del_task_data_flag:
                for name in table_list:
                    utils.conn_db(name).delete_many({'task_id': task_id})

        return utils.build_ret(ErrorMsg.Success, {"task_id": task_id_list})



# 任务同步请求模型
sync_task_fields = ns.model('SyncTask',  {
    'task_id': fields.String(required=True, description="任务ID"),
    'scope_id': fields.String(required=True, description="资产范围ID"),
})


@ns.route('/sync/')
class SyncTask(ARLResource):
    """任务结果同步接口"""
    
    @auth
    @ns.expect(sync_task_fields)
    def post(self):
        """
        将任务扫描结果同步到资产范围
        
        请求体：
            {
                "task_id": "任务ID",
                "scope_id": "资产范围ID"
            }
        
        返回：
            操作成功信息
        
        说明：
        - 只能同步已完成的域名类型任务
        - 任务目标必须在资产范围内
        - 同步操作是异步的，会创建新的同步任务执行
        - 同步状态包括：
          * default: 未同步
          * synchronizing: 同步中
          * synchronized: 已同步
        
        应用场景：
        - 将临时扫描任务的结果纳入资产管理
        - 将外部任务结果导入到资产组
        """
        # 终态状态列表
        done_status = [TaskStatus.DONE, TaskStatus.STOP, TaskStatus.ERROR]
        args = self.parse_args(sync_task_fields)
        task_id = args.pop('task_id')
        scope_id = args.pop('scope_id')

        # 查询任务信息
        query = {'_id': ObjectId(task_id)}
        task_data = utils.conn_db('task').find_one(query)
        if not task_data:
            return utils.build_ret(ErrorMsg.NotFoundTask, {"task_id": task_id})

        # 查询资产范围信息
        asset_scope_data = utils.conn_db('asset_scope').find_one({'_id': ObjectId(scope_id)})
        if not asset_scope_data:
            return utils.build_ret(ErrorMsg.NotFoundScopeID, {"task_id": task_id})

        # 检查任务类型（只支持域名类型）
        if task_data.get("type") != "domain":
            return utils.build_ret(ErrorMsg.TaskTypeIsNotDomain, {"task_id": task_id})

        # 检查任务目标是否在资产范围内
        if not utils.is_in_scopes(task_data["target"], asset_scope_data["scope_array"]):
            return utils.build_ret(ErrorMsg.TaskTargetNotInScope, {"task_id": task_id})

        # 检查任务状态（只能同步已完成的任务）
        if task_data["status"] not in done_status:
            return utils.build_ret(ErrorMsg.TaskIsRunning, {"task_id": task_id})

        # 检查同步状态
        task_sync_status = task_data.get("sync_status", TaskSyncStatus.DEFAULT)

        # 如果任务正在同步或已同步，则不能重复同步
        if task_sync_status not in [TaskSyncStatus.DEFAULT, TaskSyncStatus.ERROR]:
            return utils.build_ret(ErrorMsg.TaskSyncDealing, {"task_id": task_id})

        # 更新任务同步状态为等待中
        task_data["sync_status"] = TaskSyncStatus.WAITING

        # 创建异步同步任务
        options = {
            "celery_action": CeleryAction.DOMAIN_TASK_SYNC_TASK,
            "data": {
                "task_id": task_id,
                "scope_id": scope_id
            }
        }
        celerytask.arl_task.delay(options=options)

        # 更新任务数据
        conn('task').find_one_and_replace(query, task_data)

        return utils.build_ret(ErrorMsg.Success, {"task_id": task_id})



# 目标到资产范围映射请求模型
sync_scope_fields = ns.model('SyncScope',  {
    'target': fields.String(required=True, description="需要同步的目标"),
})


# ******* 根据目标找到要同步的资产分组ID *********
@ns.route('/sync_scope/')
class Target2Scope(ARLResource):
    """目标到资产范围映射接口"""
    
    parser = get_arl_parser(sync_scope_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        根据目标域名反查匹配的资产范围
        
        参数：
            target: 目标域名（如 www.example.com）
        
        返回：
            匹配的资产范围列表
        
        说明：
        - 通过提取目标的根域名进行匹配
        - 检查目标是否在资产范围的 scope_array 中
        - 返回所有匹配的资产范围
        
        应用场景：
        - 任务同步前查找对应的资产范围
        - 判断目标是否属于已管理的资产
        """
        args = self.parser.parse_args()
        target = args.pop("target")
        
        # 验证域名格式
        if not utils.is_valid_domain(target):
            return utils.build_ret(ErrorMsg.DomainInvalid, {"target": target})

        # 提取根域名作为查询条件
        args["scope_array"] = utils.get_fld(target)
        args["size"] = 100
        args["order"] = "_id"

        # 查询资产范围数据
        data = self.build_data(args=args, collection='asset_scope')
        ret = []
        
        # 筛选出真正包含目标的资产范围
        for item in data["items"]:
            if utils.is_in_scopes(target, item["scope_array"]):
                ret.append(item)

        data["items"] = ret
        data["total"] = len(ret)
        return data




# 任务通过策略下发字段
task_by_policy_fields = ns.model('TaskByPolicy', {
    "name": fields.String(description="任务名称", default=True, required=True),
    "task_tag": fields.String(description="任务类型标签", enum=["task", "risk_cruising"], required=True),
    "target": fields.String(description="任务目标", example="", required=False),
    "policy_id": fields.String(description="策略 ID", example="603c65316591e73dd717d176", required=True),
    "result_set_id": fields.String(description="结果集 ID", example="603c65316591e73dd717d176", required=False)
})


# ******* 通过指定策略ID 下发任务 *********
@ns.route('/policy/')
class TaskByPolicy(ARLResource):
    """通过策略创建任务接口"""
    
    @auth
    @ns.expect(task_by_policy_fields)
    def post(self):
        """
        使用预定义的策略创建扫描任务
        
        请求体：
            {
                "name": "任务名称",
                "task_tag": "task|risk_cruising",  // 任务类型标签
                "policy_id": "策略ID",
                "target": "扫描目标（可选）",
                "result_set_id": "结果集ID（可选）"
            }
        
        返回：
            任务创建结果
        
        说明：
        - task_tag 类型：
          * task: 普通扫描任务
          * risk_cruising: 风险巡航任务
        - 策略包含了扫描选项的预设配置
        - 无需手动配置扫描参数，使用策略中的配置
        
        应用场景：
        - 快速使用预设配置创建任务
        - 批量创建相同配置的任务
        - 定期风险巡航扫描
        """
        args = self.parse_args(task_by_policy_fields)
        name = args.pop("name")
        policy_id = args.pop("policy_id")
        target = args.pop("target")
        task_tag = args.pop("task_tag")
        result_set_id = args.pop("result_set_id")
        task_tag_enum = task_by_policy_fields["task_tag"].enum

        # 验证任务标签
        if task_tag not in task_tag_enum:
            return utils.build_ret("task_tag 只能取 {}".format(",".join(task_tag_enum)), {})

        # 根据策略ID获取扫描选项
        # 根据策略ID获取扫描选项
        options = get_options_by_policy_id(policy_id, task_tag)

        if not options:
            return utils.build_ret(ErrorMsg.PolicyIDNotFound, {"policy_id": policy_id})

        task_data_list = []
        try:
            # 处理普通任务
            if task_tag == TaskTag.TASK:
                # 对于资产发现任务，检验通过策略关联的资产组
                related_scope_id = options.get("related_scope_id", "")
                if related_scope_id:
                    scope_data = get_scope_by_scope_id(scope_id=related_scope_id)
                    if not scope_data:
                        return utils.build_ret(ErrorMsg.NotFoundScopeID, {"scope_id": related_scope_id})
                    
                    # 检查目标是否在资产范围内
                    check_target_in_scope(target=target, scope_list=scope_data["scope_array"])

                # 提交任务
                task_data_list = submit_task_task(target=target, name=name, options=options)
                if not task_data_list:
                    return utils.build_ret(ErrorMsg.TaskTargetIsEmpty, {"target": target})

            # 处理风险巡航任务
            if task_tag == TaskTag.RISK_CRUISING:
                # 如果指定了结果集ID，从结果集中获取目标
                if result_set_id:
                    query = {"_id": ObjectId(result_set_id)}
                    item = utils.conn_db('result_set').find_one(query, {"total": 1})
                    if not item:
                        return utils.build_ret(ErrorMsg.ResultSetIDNotFound, {"result_set_id": result_set_id})

                    target_len = item["total"]

                    if target_len == 0:
                        return utils.build_ret(ErrorMsg.ResultSetIsEmpty, {"result_set_id": result_set_id})

                    options["result_set_id"] = result_set_id
                    options["result_set_len"] = target_len

                    task_data_list = submit_risk_cruising(target=target, name=name, options=options)
                    if not task_data_list:
                        return utils.build_ret(ErrorMsg.Error, {"result_set_id": result_set_id})

                else:
                    # 使用指定的目标进行风险巡航
                    task_data_list = submit_risk_cruising(target=target, name=name, options=options)
                    if not task_data_list:
                        return utils.build_ret(ErrorMsg.TaskTargetIsEmpty, {"target": target})
        except Exception as e:
            logger.exception(e)
            return utils.build_ret(ErrorMsg.Error, {"error": str(e)})

        return utils.build_ret(ErrorMsg.Success, {"items": task_data_list})




# 重启任务请求模型
restart_task_fields = ns.model('DeleteTask',  {
    'task_id': fields.List(fields.String(required=True, description="任务ID"))
})


# ******* 重新下发任务功能 *********
@ns.route('/restart/')
class TaskRestart(ARLResource):
    """任务重启接口"""
    
    @auth
    @ns.expect(restart_task_fields)
    def post(self):
        """
        重新启动已完成或失败的任务
        
        请求体：
            {
                "task_id": ["任务ID1", "任务ID2", ...]
            }
        
        返回：
            操作成功信息
        
        说明：
        - 只能重启已完成、已停止、出错的任务
        - 重启会创建新的任务实例
        - 新任务使用原任务的配置和目标
        - 正在运行的任务无法重启
        
        应用场景：
        - 重新扫描失败的任务
        - 定期重复扫描
        - 对比不同时间的扫描结果
        """
        # 终态状态列表
        done_status = [TaskStatus.DONE, TaskStatus.STOP, TaskStatus.ERROR]
        args = self.parse_args(restart_task_fields)
        task_id_list = args.pop('task_id')

        try:
            # 验证所有任务是否可以重启
            for task_id in task_id_list:
                task_data = get_task_data(task_id)
                if not task_data:
                    return utils.build_ret(ErrorMsg.NotFoundTask, {"task_id": task_id})

                # 检查任务状态
                if task_data["status"] not in done_status:
                    return utils.build_ret(ErrorMsg.TaskIsRunning, {"task_id": task_id})

            # 执行重启操作
            for task_id in task_id_list:
                restart_task(task_id)

        except Exception as e:
            return utils.build_ret(ErrorMsg.Error, {"error": str(e)})

        return utils.build_ret(ErrorMsg.Success, {"task_id": task_id_list})


