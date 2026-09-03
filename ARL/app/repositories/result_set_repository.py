"""
结果集仓储
"""

from bson import ObjectId

from app import utils


class ResultSetRepository(object):
    collection_name = "result_set"

    @staticmethod
    def _normalize_object_id(result_set_id):
        if isinstance(result_set_id, ObjectId):
            return result_set_id
        return ObjectId(result_set_id)

    @classmethod
    def insert(cls, items, result_type):
        data = {
            "items": items,
            "type": result_type,
            "total": len(items),
        }
        return utils.conn_db(cls.collection_name).insert_one(data)

    @classmethod
    def find_total_by_id(cls, result_set_id):
        return utils.conn_db(cls.collection_name).find_one(
            {"_id": cls._normalize_object_id(result_set_id)},
            {"total": 1},
        )
