"""任务结果写回服务。

该服务集中封装任务执行链的 Mongo 写操作，保留业务层对结果字段和幂等条件的
控制；查询、网络请求和任务编排不放入这里，避免形成新的全能服务。
"""

from app import utils


class TaskResultWriteService(object):
    """提供受控的任务结果写入入口。"""

    def __init__(self, task_id):
        self.task_id = str(task_id or "")

    @staticmethod
    def _collection(collection_name):
        return utils.conn_db(collection_name)

    def insert_one(self, collection_name, document):
        return self._collection(collection_name).insert_one(document)

    def bulk_write(self, collection_name, operations, ordered=False):
        return self._collection(collection_name).bulk_write(
            operations,
            ordered=ordered,
        )

    def upsert_one(self, collection_name, key_document, document):
        """按自然键(task_id + collection 幂等键)幂等写入，替代可重试路径上的 insert_one。"""
        payload = {
            str(key): value
            for key, value in dict(document or {}).items()
            if str(key) != "_id"
        }
        payload.update({str(key): value for key, value in dict(key_document or {}).items()})
        return self._collection(collection_name).update_one(
            dict(key_document),
            {"$set": payload},
            upsert=True,
        )

    def update_one(self, collection_name, query, update, upsert=False):
        return self._collection(collection_name).update_one(
            query,
            update,
            upsert=upsert,
        )

    def replace_one(self, collection_name, query, document, upsert=False):
        return self._collection(collection_name).replace_one(
            query,
            document,
            upsert=upsert,
        )

    def delete_many(self, collection_name, query):
        return self._collection(collection_name).delete_many(query)
