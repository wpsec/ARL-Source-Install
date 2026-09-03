"""
站点仓储
"""

from bson import ObjectId

from app import utils


class SiteRepository(object):
    collection_name = "site"

    @staticmethod
    def _normalize_object_id(site_id):
        if isinstance(site_id, ObjectId):
            return site_id
        return ObjectId(site_id)

    @classmethod
    def find_by_id(cls, site_id):
        return utils.conn_db(cls.collection_name).find_one({
            "_id": cls._normalize_object_id(site_id)
        })

    @classmethod
    def update_tags(cls, site_id, tag_list):
        return utils.conn_db(cls.collection_name).update_one(
            {"_id": cls._normalize_object_id(site_id)},
            {"$set": {"tag": tag_list}}
        )

    @classmethod
    def delete_many_by_ids(cls, id_list):
        object_ids = [cls._normalize_object_id(item) for item in id_list if item]
        if not object_ids:
            return None
        return utils.conn_db(cls.collection_name).delete_many({"_id": {"$in": object_ids}})

    @classmethod
    def distinct_sites(cls, query):
        return utils.conn_db(cls.collection_name).distinct("site", query)

    @classmethod
    def find_by_task_id(cls, task_id, projection=None, batch_size=0):
        cursor = utils.conn_db(cls.collection_name).find(
            {"task_id": task_id},
            projection=projection,
        )
        if batch_size > 0:
            cursor = cursor.batch_size(batch_size)
        return cursor
