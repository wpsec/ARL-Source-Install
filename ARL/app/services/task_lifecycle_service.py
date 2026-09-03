"""任务统计、资产同步和终态收尾服务。

该服务只处理任务生命周期副作用，扫描阶段仍由各自任务和 stage service 负责；
这样可以让 DomainTask、IPTask、定时任务和站点任务共享同一套收尾语义。
"""

from bson import ObjectId

from app import services
from app import utils


logger = utils.get_logger()


class TaskLifecycleService(object):
    """承载任务统计、资产同步和最终收尾。"""

    def __init__(self, task):
        self.task = task

    @property
    def task_id(self):
        return str(getattr(self.task, "task_id", "") or "")

    def insert_task_stat(self):
        task_id = self.task_id
        query = {"_id": ObjectId(task_id)}

        # 收尾时强制刷新，避免运行中缓存覆盖本轮已落库结果。
        stat = utils.arl.task_statistic(task_id, force_refresh=True)
        logger.info("insert task stat task_id:{} stat:{}".format(task_id, stat))
        utils.conn_db("task").update_one(query, {"$set": {"statistic": stat}})

    def insert_finger_stat(self):
        task_id = self.task_id
        finger_stat_map = utils.arl.gen_stat_finger_map(task_id, force_refresh=True)
        logger.info("insert finger stat {}".format(len(finger_stat_map)))

        # 统计是任务级派生数据：先清后建，重复 finalize / worker 恢复不产生重复行。
        utils.conn_db("stat_finger").delete_many({"task_id": task_id})
        for data in finger_stat_map.values():
            item = data.copy()
            item["task_id"] = task_id
            utils.conn_db("stat_finger").insert_one(item)

    def insert_cip_stat(self):
        task_id = self.task_id
        cip_map = utils.arl.gen_cip_map(task_id)
        logger.info("insert cip stat {}".format(len(cip_map)))

        # 写入集合是 cip（历史命名）；幂等重建必须打在同一个集合上。
        utils.conn_db("cip").delete_many({"task_id": task_id})
        for cidr_ip, value in cip_map.items():
            ip_list = list(value["ip_set"])
            domain_list = list(value["domain_set"])
            item = {
                "cidr_ip": cidr_ip,
                "ip_count": len(ip_list),
                "ip_list": ip_list,
                "domain_count": len(domain_list),
                "domain_list": domain_list,
                "task_id": task_id,
            }
            utils.conn_db("cip").insert_one(item)

    def sync_asset(self):
        task = self.task
        options = getattr(task, "options", {})
        if not options:
            logger.warning("not found options {}".format(self.task_id))
            return

        related_scope_id = options.get("related_scope_id", "")
        if not related_scope_id:
            return

        if len(related_scope_id) != 24:
            logger.warning(
                "related_scope_id len not eq 24 {}".format(self.task_id)
            )
            return

        services.sync_asset(task_id=self.task_id, scope_id=related_scope_id)

    def finalize(self, sync_asset=True):
        self.insert_finger_stat()
        self.insert_cip_stat()
        self.insert_task_stat()
        if sync_asset:
            self.sync_asset()

    def run_finalize(self, sync_asset=True):
        """通过统一阶段执行器运行收尾，兼容没有执行器的轻量任务测试。"""
        runner = getattr(self.task, "_run_internal_stage", None)
        if callable(runner):
            return runner(
                "task_finalize",
                lambda: self.finalize(sync_asset=sync_asset),
            )
        return self.finalize(sync_asset=sync_asset)
