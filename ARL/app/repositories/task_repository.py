"""
任务仓储。

路由和任务执行器只通过这里访问 task 集合，避免把 Mongo 查询细节扩散到业务流程。
"""

from bson import ObjectId

from app import utils


class TaskRepository(object):
    collection_name = "task"
    RELATED_COLLECTIONS = (
        "cert",
        "domain",
        "fileleak",
        "ip",
        "service",
        "site",
        "url",
        "vuln",
        "cip",
        "npoc_service",
        "wih",
        "wih_endpoint",
        "nuclei_result",
        "stat_finger",
    )

    @staticmethod
    def _normalize_object_id(task_id):
        if isinstance(task_id, ObjectId):
            return task_id
        return ObjectId(task_id)

    @classmethod
    def find_by_id(cls, task_id, projection=None):
        return utils.conn_db(cls.collection_name).find_one(
            {"_id": cls._normalize_object_id(task_id)},
            projection,
        )

    @classmethod
    def update_by_id(cls, task_id, update):
        return utils.conn_db(cls.collection_name).update_one(
            {"_id": cls._normalize_object_id(task_id)},
            update,
        )

    @classmethod
    def replace_by_id(cls, task_id, task_data):
        return utils.conn_db(cls.collection_name).find_one_and_replace(
            {"_id": cls._normalize_object_id(task_id)},
            task_data,
        )

    @classmethod
    def delete_by_id(cls, task_id):
        return utils.conn_db(cls.collection_name).delete_many(
            {"_id": cls._normalize_object_id(task_id)}
        )

    @classmethod
    def delete_related_data(cls, task_id, delete_asset_data=False):
        """按任务删除关联数据，保留任务删除接口原有的两档语义。"""
        task_id_text = str(task_id or "").strip()
        if not task_id_text:
            return {}

        # 执行账本属恢复元数据，不随资产数据开关保留，任务删除即清理。
        collection_names = ["ai_denoise_result", "task_stage_ledger"]
        if delete_asset_data:
            collection_names.extend(cls.RELATED_COLLECTIONS)

        deleted = {}
        for collection_name in collection_names:
            result = utils.conn_db(collection_name).delete_many({"task_id": task_id_text})
            deleted[collection_name] = int(getattr(result, "deleted_count", 0) or 0)
        return deleted
