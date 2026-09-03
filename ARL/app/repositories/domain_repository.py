"""
域名仓储
"""

from bson import ObjectId

from app import utils


class DomainRepository(object):
    collection_name = "domain"

    @staticmethod
    def _normalize_object_id(domain_id):
        if isinstance(domain_id, ObjectId):
            return domain_id
        return ObjectId(domain_id)

    @classmethod
    def delete_many_by_ids(cls, id_list):
        object_ids = [cls._normalize_object_id(item) for item in id_list if item]
        if not object_ids:
            return None
        return utils.conn_db(cls.collection_name).delete_many({"_id": {"$in": object_ids}})

    @classmethod
    def find_by_task_id(cls, task_id, projection=None, batch_size=0):
        cursor = utils.conn_db(cls.collection_name).find(
            {"task_id": task_id},
            projection=projection,
        )
        if batch_size > 0:
            cursor = cursor.batch_size(batch_size)
        return cursor

    @staticmethod
    def normalize_sources(sources):
        """标准化来源集合，避免空值和重复来源进入存储。"""
        if not isinstance(sources, (list, tuple, set)):
            sources = [sources]

        normalized = []
        seen = set()
        for source in sources:
            text = str(source or "").strip()
            if not text or text in seen:
                continue
            seen.add(text)
            normalized.append(text)
        return normalized

    @classmethod
    def add_sources_by_domains(cls, task_id, domains, sources):
        """
        为已存在的域名记录合并来源。

        域名发现链路会在 DNS 解析前先记录来源；此时部分记录尚未入库，
        因而只更新已存在的记录，后续首次入库时由 upsert_discovered_domain
        一次性写入完整来源集合。
        """
        source_list = cls.normalize_sources(sources)
        domain_list = []
        seen_domains = set()
        for domain in domains or []:
            normalized_domain = utils.normalize_domain(domain)
            if not normalized_domain or normalized_domain in seen_domains:
                continue
            seen_domains.add(normalized_domain)
            domain_list.append(normalized_domain)

        if not task_id or not domain_list or not source_list:
            return None

        # 兼容历史文档：sources 不存在时先把旧 source 纳入集合，再并入新来源。
        legacy_sources = {
            "$cond": [
                {"$isArray": "$sources"},
                "$sources",
                {
                    "$cond": [
                        {"$ne": [{"$ifNull": ["$source", ""]}, ""]},
                        ["$source"],
                        [],
                    ]
                },
            ]
        }
        return utils.conn_db(cls.collection_name).update_many(
            {"task_id": task_id, "domain": {"$in": domain_list}},
            [{"$set": {"sources": {"$setUnion": [legacy_sources, source_list]}}}],
        )

    @classmethod
    def upsert_discovered_domain(cls, task_id, domain_info, primary_source, sources=None):
        """按 task_id + domain 写入记录，同时保留完整且可查询的来源集合。"""
        if not isinstance(domain_info, dict) or not task_id:
            return None

        domain = utils.normalize_domain(domain_info.get("domain"))
        source_list = cls.normalize_sources(list(sources or []) + [primary_source])
        if not domain or not source_list:
            return None

        primary_source = str(primary_source or "").strip() or source_list[0]
        payload = dict(domain_info)
        payload.pop("_id", None)
        payload.pop("source", None)
        payload.pop("sources", None)
        payload["task_id"] = task_id
        payload["domain"] = domain

        return utils.conn_db(cls.collection_name).update_one(
            {"task_id": task_id, "domain": domain},
            {
                "$set": payload,
                # 旧 source 是兼容字段，始终保留第一次发现时的来源。
                "$setOnInsert": {"source": primary_source},
                "$addToSet": {"sources": {"$each": source_list}},
            },
            upsert=True,
        )
