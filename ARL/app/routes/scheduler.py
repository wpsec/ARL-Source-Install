"""
定时监控任务管理模块

功能说明：
- 管理资产监控的定时任务（周期性扫描）
- 支持域名监控、IP监控、站点更新监控、WIH监控
- 提供任务的添加、删除、停止、恢复等完整生命周期管理

监控任务类型：
1. 域名/IP监控：周期性扫描资产组内的域名或IP
2. 站点更新监控：监控资产组内站点的变化
3. WIH监控：监控JavaScript文件的信息变化

主要功能：
- 添加监控任务（单个/批量）
- 删除监控任务（批量）
- 停止监控任务（单个/批量）
- 恢复监控任务（单个/批量）
- 查询监控任务状态和运行历史
"""
from bson import ObjectId
from flask_restx import Resource, Api, reqparse, fields, Namespace
from app.utils import get_logger, auth, truncate_string
from app.modules import ErrorMsg
from . import base_query_fields, ARLResource, get_arl_parser
from app import scheduler as app_scheduler, utils
from app.modules import SchedulerStatus, AssetScopeType, TaskTag
from app.helpers import get_options_by_policy_id
from app.helpers.scheduler import have_same_site_update_monitor, have_same_wih_update_monitor

ns = Namespace('scheduler', description="资产监控任务信息")

# 监控任务查询字段定义
base_search_fields = {
    '_id': fields.String(description="监控任务job_id"),
    'domain': fields.String(description="要监控的域名或IP"),
    'scope_id': fields.String(description="所属资产组ID"),
    'interval': fields.String(description="运行间隔（单位：秒）"),
    'next_run_time': fields.String(description="下一次运行时间戳"),
    'next_run_date': fields.Integer(description="下一次运行日期"),
    'last_run_time': fields.Integer(description="上一次运行时间戳"),
    'last_run_date': fields.String(description="上一次运行日期"),
    'run_number': fields.String(description="已运行次数"),
    "name": fields.String(description="任务名称")
}

base_search_fields.update(base_query_fields)


@ns.route('/')
class ARLScheduler(ARLResource):
    """监控任务查询接口"""
    
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        查询监控任务列表
        
        参数：
            - _id: 任务ID过滤
            - domain: 监控目标过滤
            - scope_id: 资产组ID过滤
            - name: 任务名称过滤
            - interval: 运行间隔过滤
            - page: 页码
            - size: 每页数量
        
        返回：
            {
                "code": 200,
                "items": [
                    {
                        "_id": "任务ID",
                        "name": "任务名称",
                        "domain": "监控目标",
                        "scope_id": "资产组ID",
                        "interval": 运行间隔（秒）,
                        "next_run_time": 下次运行时间戳,
                        "next_run_date": "下次运行日期",
                        "last_run_time": 上次运行时间戳,
                        "last_run_date": "上次运行日期",
                        "run_number": 运行次数,
                        "status": "任务状态（running/stop）"
                    }
                ],
                "total": 总数
            }
        
        说明：
        - 监控任务会按设定的间隔自动执行
        - 每次运行会提交一个新的扫描任务
        - 可通过停止/恢复控制任务状态
        """
        args = self.parser.parse_args()
        data = self.build_data(args=args, collection='scheduler')

        return data


# 添加监控任务请求模型
add_scheduler_fields = ns.model('addScheduler', {
    "scope_id": fields.String(required=True, description="资产组ID"),
    "domain": fields.String(required=True, description="域名或IP，多个用逗号分隔"),
    "interval": fields.Integer(description="运行间隔（单位：秒，最小6小时）"),
    "name": fields.String(description="监控任务名称（为空则自动生成）"),
    "policy_id": fields.String(description="策略ID（可选，使用策略配置）")
})


@ns.route('/add/')
class AddARLScheduler(ARLResource):
    """添加监控任务接口"""

    @auth
    @ns.expect(add_scheduler_fields)
    def post(self):
        """
        添加周期性监控任务
        
        请求体：
            {
                "scope_id": "资产组ID",
                "domain": "example.com,test.com",
                "interval": 86400,
                "name": "监控任务名称",
                "policy_id": "策略ID（可选）"
            }
        
        返回：
            {
                "code": 200,
                "message": "成功",
                "data": [
                    {
                        "domain": "目标",
                        "scope_id": "资产组ID",
                        "job_id": "任务ID"
                    }
                ]
            }
        
        说明：
        - interval最小值为21600秒（6小时）
        - 域名监控：为每个域名创建单独的监控任务
        - IP监控：多个IP作为整体创建一个监控任务
        - 验证目标是否在资产组范围内
        - 避免对同一目标创建重复监控
        - 可指定策略ID使用预定义的扫描配置
        """
        args = self.parse_args(add_scheduler_fields)
        scope_id = args.pop("scope_id")
        domain = args.pop("domain")
        interval = args.pop("interval")
        name = args.pop("name")
        policy_id = args.pop("policy_id", "")

        # 验证最小间隔（6小时）
        if interval < 3600 * 6:
            return utils.build_ret(ErrorMsg.IntervalLessThan3600, {"interval": interval})

        # 获取资产组的监控域名和数据
        monitor_domain = utils.arl.get_monitor_domain_by_id(scope_id)
        scope_data = utils.arl.scope_data_by_id(scope_id)

        if not scope_data:
            return utils.build_ret(ErrorMsg.NotFoundScopeID, {"scope_id": scope_id})

        # 获取策略配置（如果指定）
        task_options = None
        if policy_id and len(policy_id) == 24:
            task_options = get_options_by_policy_id(policy_id, TaskTag.TASK)
            if task_options is None:
                return utils.build_ret(ErrorMsg.PolicyIDNotFound, {"policy_id": policy_id})

        # 资产组类型（域名或IP）
        scope_type = scope_data.get("scope_type")
        if not scope_type:
            scope_type = AssetScopeType.DOMAIN

        # 解析并验证目标列表
        domains = domain.split(",")
        for x in domains:
            curr_domain = x.strip()
            # 验证目标是否在资产组范围内
            if curr_domain not in scope_data["scope_array"]:
                return utils.build_ret(ErrorMsg.DomainNotFoundViaScope,
                                       {"domain": curr_domain, "scope_id": scope_id})

            # 验证是否已有监控任务
            if curr_domain in monitor_domain:
                return utils.build_ret(ErrorMsg.DomainViaJob,
                                       {"domain": curr_domain, "scope_id": scope_id})

        ret_data = []
        
        # 下发域名类型监控任务（每个域名单独监控）
        if scope_type == AssetScopeType.DOMAIN:
            for x in domains:
                curr_name = name
                if not name:
                    curr_name = "监控-{}-{}".format(scope_data["name"], x)

                curr_name = truncate_string(curr_name)

                job_id = app_scheduler.add_job(domain=x, scope_id=scope_id,
                                               options=task_options, interval=interval,
                                               name=curr_name, scope_type=scope_type)
                ret_data.append({"domain": x, "scope_id": scope_id, "job_id": job_id})

        # 下发IP类型监控任务（多个IP作为整体监控）
        if scope_type == AssetScopeType.IP:
            curr_name = name
            ip_target = " ".join(domains)
            if not name:
                curr_name = "监控-{}-{}".format(scope_data["name"], ip_target)

            curr_name = truncate_string(curr_name)

            job_id = app_scheduler.add_job(domain=ip_target, scope_id=scope_id,
                                           options=task_options, interval=interval,
                                           name=curr_name, scope_type=scope_type)
            ret_data.append({"domain": ip_target, "scope_id": scope_id, "job_id": job_id})

        return utils.build_ret(ErrorMsg.Success, ret_data)


# 删除监控任务请求模型
delete_scheduler_fields = ns.model('deleteScheduler', {
    "job_id": fields.List(fields.String(description="监控任务ID列表"))
})


@ns.route('/delete/')
class DeleteARLScheduler(ARLResource):
    """删除监控任务接口"""

    @auth
    @ns.expect(delete_scheduler_fields)
    def post(self):
        """
        批量删除监控任务
        
        请求体：
            {
                "job_id": ["任务ID1", "任务ID2", ...]
            }
        
        返回：
            {
                "code": 200,
                "message": "成功",
                "job_id": ["已删除的任务ID列表"]
            }
        
        说明：
        - 支持批量删除多个监控任务
        - 删除后任务将不再自动运行
        - 删除操作不可逆
        - 验证所有任务是否存在后再执行删除
        """
        args = self.parse_args(delete_scheduler_fields)
        job_id_list = args.get("job_id", [])

        ret_data = {"job_id": job_id_list}

        # 先验证所有任务是否存在
        for job_id in job_id_list:
            item = app_scheduler.find_job(job_id)
            if not item:
                return utils.build_ret(ErrorMsg.JobNotFound, ret_data)

        # 批量删除任务
        for job_id in job_id_list:
            app_scheduler.delete_job(job_id)

        return utils.build_ret(ErrorMsg.Success, ret_data)


# 恢复监控任务请求模型
recover_scheduler_fields = ns.model('recoverScheduler', {
    "job_id": fields.String(required=True, description="监控任务ID")
})


@ns.route('/recover/')
class RecoverARLScheduler(ARLResource):
    """恢复单个监控任务接口（将被批量接口替代）"""

    @auth
    @ns.expect(recover_scheduler_fields)
    def post(self):
        """
        恢复单个停止的监控任务
        
        请求体：
            {
                "job_id": "任务ID"
            }
        
        返回：
            {
                "code": 200,
                "message": "成功",
                "job_id": "任务ID"
            }
        
        说明：
        - 只能恢复状态为stop的任务
        - 恢复后任务将按原定间隔继续运行
        - 该接口将被批量恢复接口替代
        """
        args = self.parse_args(recover_scheduler_fields)
        job_id = args.get("job_id")

        # 验证任务是否存在
        item = app_scheduler.find_job(job_id)
        if not item:
            return utils.build_ret(ErrorMsg.JobNotFound, {"job_id": job_id})

        # 验证任务状态是否为停止
        status = item.get("status", SchedulerStatus.RUNNING)
        if status != SchedulerStatus.STOP:
            return utils.build_ret(ErrorMsg.SchedulerStatusNotStop, {"job_id": job_id})

        # 恢复任务运行
        app_scheduler.recover_job(job_id)

        return utils.build_ret(ErrorMsg.Success, {"job_id": job_id})


# 批量恢复监控任务请求模型
batch_recover_scheduler_fields = ns.model('batchRecoverScheduler', {
    "job_id": fields.List(fields.String(required=True, description="监控任务ID列表"))
})


@ns.route('/recover/batch')
class BatchRecoverARLScheduler(ARLResource):
    """批量恢复监控任务接口"""

    @auth
    @ns.expect(batch_recover_scheduler_fields)
    def post(self):
        """
        批量恢复停止的监控任务
        
        请求体：
            {
                "job_id": ["任务ID1", "任务ID2", ...]
            }
        
        返回：
            {
                "code": 200,
                "message": "成功",
                "job_id": ["已恢复的任务ID列表"]
            }
        
        说明：
        - 支持批量恢复多个任务
        - 只能恢复状态为stop的任务
        - 验证所有任务状态后再执行恢复
        - 恢复后任务将按原定间隔继续运行
        """
        args = self.parse_args(batch_recover_scheduler_fields)
        job_id_list = args.get("job_id", [])
        
        # 验证所有任务是否存在且状态正确
        for job_id in job_id_list:
            item = app_scheduler.find_job(job_id)
            if not item:
                return utils.build_ret(ErrorMsg.JobNotFound, {"job_id": job_id})

            status = item.get("status", SchedulerStatus.RUNNING)
            if status != SchedulerStatus.STOP:
                return utils.build_ret(ErrorMsg.SchedulerStatusNotStop, {"job_id": job_id})

        # 批量恢复任务
        for job_id in job_id_list:
            app_scheduler.recover_job(job_id)

        return utils.build_ret(ErrorMsg.Success, {"job_id": job_id_list})


# 停止监控任务请求模型
stop_scheduler_fields = ns.model('stopScheduler', {
    "job_id": fields.String(required=True, description="监控任务ID")
})


@ns.route('/stop/')
class StopARLScheduler(ARLResource):
    """停止单个监控任务接口（将被批量接口替代）"""

    @auth
    @ns.expect(stop_scheduler_fields)
    def post(self):
        """
        停止单个运行中的监控任务
        
        请求体：
            {
                "job_id": "任务ID"
            }
        
        返回：
            {
                "code": 200,
                "message": "成功",
                "job_id": "任务ID"
            }
        
        说明：
        - 只能停止状态为running的任务
        - 停止后任务不会自动运行，需手动恢复
        - 该接口将被批量停止接口替代
        """
        args = self.parse_args(stop_scheduler_fields)
        job_id = args.get("job_id")

        # 验证任务是否存在
        item = app_scheduler.find_job(job_id)
        if not item:
            return utils.build_ret(ErrorMsg.JobNotFound, {"job_id": job_id})

        # 验证任务状态是否为运行中
        status = item.get("status", SchedulerStatus.RUNNING)
        if status != SchedulerStatus.RUNNING:
            return utils.build_ret(ErrorMsg.SchedulerStatusNotRunning, {"job_id": job_id})

        # 停止任务
        app_scheduler.stop_job(job_id)

        return utils.build_ret(ErrorMsg.Success, {"job_id": job_id})


# 批量停止监控任务请求模型
batch_stop_scheduler_fields = ns.model('batchStopScheduler', {
    "job_id": fields.List(fields.String(required=True, description="监控任务ID列表"))
})


@ns.route('/stop/batch')
class BatchStopARLScheduler(ARLResource):
    """批量停止监控任务接口"""

    @auth
    @ns.expect(batch_stop_scheduler_fields)
    def post(self):
        """
        批量停止运行中的监控任务
        
        请求体：
            {
                "job_id": ["任务ID1", "任务ID2", ...]
            }
        
        返回：
            {
                "code": 200,
                "message": "成功",
                "job_id": ["已停止的任务ID列表"]
            }
        
        说明：
        - 支持批量停止多个任务
        - 只能停止状态为running的任务
        - 验证所有任务状态后再执行停止
        - 停止后任务不会自动运行，需手动恢复
        """
        args = self.parse_args(batch_stop_scheduler_fields)
        job_id_list = args.get("job_id", [])
        
        # 验证所有任务是否存在且状态正确
        for job_id in job_id_list:
            item = app_scheduler.find_job(job_id)
            if not item:
                return utils.build_ret(ErrorMsg.JobNotFound, {"job_id": job_id})

            status = item.get("status", SchedulerStatus.RUNNING)
            if status != SchedulerStatus.RUNNING:
                return utils.build_ret(ErrorMsg.SchedulerStatusNotRunning, {"job_id": job_id})

        # 批量停止任务
        for job_id in job_id_list:
            app_scheduler.stop_job(job_id)

        return utils.build_ret(ErrorMsg.Success, {"job_id": job_id_list})


# 添加站点监控请求模型
add_scheduler_site_fields = ns.model('addSchedulerSite', {
    "scope_id": fields.String(required=True, description="资产组ID"),
    "interval": fields.Integer(description="运行间隔（单位：秒，最小6小时）", example=3600 * 23),
    "name": fields.String(description="监控任务名称（为空则自动生成）"),
})


@ns.route('/add/site_monitor/')
class AddSiteScheduler(ARLResource):
    """添加站点更新监控接口"""

    @auth
    @ns.expect(add_scheduler_site_fields)
    def post(self):
        """
        添加站点更新监控任务
        
        请求体：
            {
                "scope_id": "资产组ID",
                "interval": 82800,
                "name": "站点监控任务"
            }
        
        返回：
            {
                "code": 200,
                "message": "成功",
                "schedule_id": "任务ID"
            }
        
        说明：
        - 监控资产组内所有站点的变化
        - interval最小值为21600秒（6小时）
        - 每个资产组只能有一个站点监控任务
        - 检测站点的新增、变更等
        - 任务名称为空时自动生成
        """
        args = self.parse_args(add_scheduler_site_fields)
        scope_id = args.pop("scope_id")
        interval = args.pop("interval")
        name = args.pop("name")

        # 验证最小间隔（6小时）
        if interval < 3600 * 6:
            return utils.build_ret(ErrorMsg.IntervalLessThan3600, {"interval": interval})

        # 验证资产组是否存在
        scope_data = utils.arl.scope_data_by_id(scope_id)

        if not scope_data:
            return utils.build_ret(ErrorMsg.NotFoundScopeID, {"scope_id": scope_id})

        # 检查是否已有相同的站点监控任务
        if have_same_site_update_monitor(scope_id=scope_id):
            return utils.build_ret(ErrorMsg.DomainSiteViaJob, {"scope_id": scope_id,
                                                               "scope_name": scope_data['name']})

        # 生成任务名称
        if not name:
            name = "站点监控-{}".format(scope_data["name"])

        # 添加站点监控任务
        _id = app_scheduler.add_asset_site_monitor_job(scope_id=scope_id,
                                                       name=name,
                                                       interval=interval)

        return utils.build_ret(ErrorMsg.Success, {"schedule_id": _id})


# 添加WIH监控请求模型
add_scheduler_wih_fields = ns.model('addSchedulerWih', {
    "scope_id": fields.String(required=True, description="资产组ID"),
    "interval": fields.Integer(description="运行间隔（单位：秒，最小6小时）", example=3600 * 23),
    "name": fields.String(description="监控任务名称（为空则自动生成）", example=""),
})


@ns.route('/add/wih_monitor/')
class AddWihScheduler(ARLResource):
    """添加WIH更新监控接口"""

    @auth
    @ns.expect(add_scheduler_wih_fields)
    def post(self):
        """
        添加WIH（Web Info Hunter）更新监控任务
        
        请求体：
            {
                "scope_id": "资产组ID",
                "interval": 82800,
                "name": "WIH监控任务"
            }
        
        返回：
            {
                "code": 200,
                "message": "成功",
                "schedule_id": "任务ID"
            }
        
        说明：
        - 监控资产组内JavaScript文件的信息变化
        - interval最小值为21600秒（6小时）
        - 每个资产组只能有一个WIH监控任务
        - 检测JS文件中新增的API、URL、敏感信息等
        - 任务名称为空时自动生成
        """
        args = self.parse_args(add_scheduler_wih_fields)
        scope_id = args.pop("scope_id")
        interval = args.pop("interval")
        name = args.pop("name")

        # 验证最小间隔（6小时）
        if interval < 3600 * 6:
            return utils.build_ret(ErrorMsg.IntervalLessThan3600, {"interval": interval})

        # 验证资产组是否存在
        scope_data = utils.arl.scope_data_by_id(scope_id)

        if not scope_data:
            return utils.build_ret(ErrorMsg.NotFoundScopeID, {"scope_id": scope_id})

        # 检查是否已有相同的WIH监控任务
        if have_same_wih_update_monitor(scope_id=scope_id):
            return utils.build_ret(ErrorMsg.DomainSiteViaJob, {"scope_id": scope_id,
                                                               "scope_name": scope_data['name']})

        # 生成任务名称
        if not name:
            name = "WIH 监控-{}".format(scope_data["name"])

        # 添加WIH监控任务
        _id = app_scheduler.add_asset_wih_monitor_job(scope_id=scope_id,
                                                      name=name,
                                                      interval=interval)

        return utils.build_ret(ErrorMsg.Success, {"schedule_id": _id})

