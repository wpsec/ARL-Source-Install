"""
导出查询仓储。

导出格式、报表渲染和 HTTP 响应不应感知 Mongo 查询细节；集中查询入口也便于
异步导出和同步导出复用同一套字段投影与批量读取策略。
"""

from bson import ObjectId

from app import utils


class ExportRepository(object):
    JOB_COLLECTION = "export_job"

    @classmethod
    def collection(cls, collection_name):
        return utils.conn_db(collection_name)

    @classmethod
    def find_one(cls, collection_name, query, projection=None):
        return cls.collection(collection_name).find_one(query, projection=projection)

    @classmethod
    def find(cls, collection_name, query, projection=None, batch_size=0):
        cursor = cls.collection(collection_name).find(query, projection=projection)
        if batch_size > 0:
            cursor = cursor.batch_size(batch_size)
        return cursor

    @classmethod
    def find_by_task_id(cls, collection_name, task_id, projection=None, batch_size=0):
        return cls.find(
            collection_name,
            {"task_id": task_id},
            projection=projection,
            batch_size=batch_size,
        )

    @classmethod
    def find_by_task_ids(cls, collection_name, task_ids, projection=None, batch_size=0):
        normalized_ids = [str(item).strip() for item in task_ids or [] if str(item).strip()]
        if not normalized_ids:
            return []
        query = {"task_id": normalized_ids[0]}
        if len(normalized_ids) > 1:
            query = {"task_id": {"$in": normalized_ids}}
        return cls.find(
            collection_name,
            query,
            projection=projection,
            batch_size=batch_size,
        )

    @classmethod
    def find_fileleak_by_task_id(cls, task_id, excluded_source, projection=None, batch_size=0):
        return cls.find(
            "fileleak",
            {"task_id": task_id, "source": {"$ne": excluded_source}},
            projection=projection,
            batch_size=batch_size,
        )

    @classmethod
    def find_ai_denoise_by_task_ids(cls, task_ids, module_id, projection=None, batch_size=0):
        normalized_ids = [str(item).strip() for item in task_ids or [] if str(item).strip()]
        module_text = str(module_id or "").strip()
        if not normalized_ids or not module_text:
            return []
        task_query = normalized_ids[0]
        if len(normalized_ids) > 1:
            task_query = {"$in": normalized_ids}
        return cls.find(
            "ai_denoise_result",
            {"task_id": task_query, "module_id": module_text},
            projection=projection,
            batch_size=batch_size,
        )

    @classmethod
    def find_by_ids(cls, collection_name, id_values, projection=None, batch_size=0):
        text_ids = set()
        object_ids = []
        for raw_id in id_values or []:
            data_id = str(raw_id or "").strip()
            if not data_id:
                continue
            text_ids.add(data_id)
            is_valid = getattr(ObjectId, "is_valid", None)
            if callable(is_valid) and is_valid(data_id):
                object_ids.append(ObjectId(data_id))

        query_parts = []
        if object_ids:
            query_parts.append({"_id": {"$in": object_ids}})
        if text_ids:
            query_parts.append({"_id": {"$in": list(text_ids)}})
        if not query_parts:
            return []
        query = query_parts[0] if len(query_parts) == 1 else {"$or": query_parts}
        return cls.find(
            collection_name,
            query,
            projection=projection,
            batch_size=batch_size,
        )

    @classmethod
    def find_job(cls, job_id):
        return cls.find_one(cls.JOB_COLLECTION, {"_id": cls._object_id(job_id)})

    @classmethod
    def insert_job(cls, document):
        return cls.collection(cls.JOB_COLLECTION).insert_one(document)

    @classmethod
    def update_job(cls, job_id, update):
        return cls.collection(cls.JOB_COLLECTION).update_one(
            {"_id": cls._object_id(job_id)},
            update,
        )

    @classmethod
    def ensure_job_indexes(cls):
        collection = cls.collection(cls.JOB_COLLECTION)
        collection.create_index("created_at", background=True)
        collection.create_index("status", background=True)
        collection.create_index("expire_at", expireAfterSeconds=0, background=True)

    @staticmethod
    def _object_id(value):
        if isinstance(value, ObjectId):
            return value
        return ObjectId(value)
