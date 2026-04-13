"""
周期任务 WIH 结果保守复用服务

设计目标：
- 仅为计划任务提供“同 schedule + 同 target + 同站点签名”条件下的结果复用能力
- 第一阶段只做保守复用骨架，不做模糊相似度判断
- 复用失败时必须无条件回退为现有完整扫描链路
"""
import hashlib
import json
from types import SimpleNamespace
from urllib.parse import urlparse

from bson import ObjectId

from app import utils
from app.config import Config
from app.modules import CollectSource, TaskStatus
from .infoHunter import InfoHunter

logger = utils.get_logger()


class WihPeriodicReuseService(object):
    def __init__(self, task_id: str, sites: list, options: dict):
        self.task_id = str(task_id or "").strip()
        self.sites = [str(item or "").strip() for item in list(sites or []) if str(item or "").strip()]
        self.options = dict(options or {}) if isinstance(options, dict) else {}
        self.schedule_id = str(self.options.get("task_schedule_id", "") or "").strip()
        self.schedule_name = str(self.options.get("task_schedule_name", "") or "").strip()
        self.schedule_run_number = int(self.options.get("task_schedule_run_number", 0) or 0)
        self.enable = bool(getattr(Config, "WIH_PERIODIC_REUSE_ENABLE", False))
        self.max_baseline_tasks = int(getattr(Config, "WIH_PERIODIC_REUSE_MAX_BASELINE_TASKS", 5) or 5)
        self.log_detail = bool(getattr(Config, "WIH_PERIODIC_REUSE_LOG_DETAIL", True))
        if self.max_baseline_tasks < 1:
            self.max_baseline_tasks = 1

    @staticmethod
    def _extract_host(value: str) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        parsed = urlparse(text)
        host = str(parsed.hostname or "").strip().lower().rstrip(".")
        if host:
            return host
        parsed = urlparse("//{}".format(text))
        return str(parsed.hostname or "").strip().lower().rstrip(".")

    @classmethod
    def _normalize_origin(cls, value: str) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        parsed = urlparse(text)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            return "{}://{}".format(parsed.scheme.lower(), parsed.netloc.lower().rstrip("/"))
        host = cls._extract_host(text)
        return host

    @staticmethod
    def _normalize_finger_names(finger_list) -> list:
        names = []
        for item in list(finger_list or []):
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "") or "").strip().lower()
            if name:
                names.append(name)
        return sorted(set(names))

    @classmethod
    def build_site_signature(cls, site_doc: dict) -> tuple:
        doc = dict(site_doc or {})
        site = cls._normalize_origin(doc.get("site", ""))
        if not site:
            return "", ""

        payload = {
            "site": site,
            "title": str(doc.get("title", "") or "").strip(),
            "status": int(doc.get("status", 0) or 0),
            "http_server": str(doc.get("http_server", "") or "").strip().lower(),
            "body_length": int(doc.get("body_length", 0) or 0),
            "favicon_hash": str((doc.get("favicon", {}) or {}).get("hash", "") or "").strip(),
            "finger": cls._normalize_finger_names(doc.get("finger", [])),
        }
        digest = hashlib.md5(
            json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8", errors="ignore")
        ).hexdigest()
        return site, digest

    def _current_task_target(self) -> str:
        if not ObjectId.is_valid(self.task_id):
            return ""
        item = utils.conn_db("task").find_one(
            {"_id": ObjectId(self.task_id)},
            {"target": 1},
        ) or {}
        return str(item.get("target", "") or "").strip().lower()

    def _load_site_signature_map(self, task_id: str) -> dict:
        query = {"task_id": str(task_id or "").strip()}
        if self.sites:
            query["site"] = {"$in": self.sites}

        signature_map = {}
        fields = {
            "site": 1,
            "title": 1,
            "status": 1,
            "http_server": 1,
            "body_length": 1,
            "favicon": 1,
            "finger": 1,
        }
        for item in utils.conn_db("site").find(query, fields):
            site, signature = self.build_site_signature(item)
            if not site or not signature:
                continue
            signature_map[site] = signature
        return signature_map

    def _find_previous_task_id(self) -> str:
        if not self.schedule_id:
            return ""

        current_target = self._current_task_target()
        if not current_target:
            return ""

        query = {
            "status": TaskStatus.DONE,
            "target": current_target,
            "options.from_task_schedule": True,
            "options.task_schedule_id": self.schedule_id,
        }

        if ObjectId.is_valid(self.task_id):
            query["_id"] = {"$ne": ObjectId(self.task_id)}

        cursor = utils.conn_db("task").find(query, {"_id": 1, "end_time": 1}).sort(
            [("end_time", -1), ("_id", -1)]
        ).limit(self.max_baseline_tasks)
        for item in cursor:
            previous_task_id = str(item.get("_id", "") or "").strip()
            if previous_task_id:
                return previous_task_id
        return ""

    def _clone_wih_records(self, previous_task_id: str, reusable_sites: set) -> tuple:
        docs = []
        normalized_records = []
        current_date = getattr(utils, "curr_date", lambda: "")()

        for item in utils.conn_db("wih").find({"task_id": previous_task_id}):
            site = self._normalize_origin(item.get("site", ""))
            if site not in reusable_sites:
                continue

            doc = dict(item)
            doc.pop("_id", None)
            doc["task_id"] = self.task_id
            doc["save_date"] = current_date
            docs.append(doc)

            normalized = InfoHunter.normalize_wih_record(
                SimpleNamespace(
                    record_type=doc.get("record_type", ""),
                    content=doc.get("content", ""),
                    source=doc.get("source", ""),
                    site=doc.get("site", ""),
                )
            )
            if normalized:
                normalized_records.append(normalized)

        if docs:
            utils.conn_db("wih").insert_many(docs)
        return len(docs), normalized_records

    def _clone_wih_endpoints(self, previous_task_id: str, reusable_sites: set) -> int:
        docs = []
        current_date = getattr(utils, "curr_date", lambda: "")()
        for item in utils.conn_db("wih_endpoint").find({"task_id": previous_task_id}):
            target = self._normalize_origin(item.get("target", "") or item.get("site", ""))
            if target not in reusable_sites:
                continue

            doc = dict(item)
            doc.pop("_id", None)
            doc["task_id"] = self.task_id
            doc["save_date"] = current_date
            docs.append(doc)

        if docs:
            utils.conn_db("wih_endpoint").insert_many(docs)
        return len(docs)

    def _clone_wih_urls(self, previous_task_id: str, reusable_sites: set) -> tuple:
        docs = []
        reused_urls = []
        current_date = getattr(utils, "curr_date", lambda: "")()
        reusable_hosts = {self._extract_host(item) for item in reusable_sites if self._extract_host(item)}
        for item in utils.conn_db("url").find({"task_id": previous_task_id, "source": CollectSource.WIH_URL_PROBE}):
            target_host = self._extract_host(item.get("url", "") or item.get("site", ""))
            if not target_host or target_host not in reusable_hosts:
                continue

            doc = dict(item)
            doc.pop("_id", None)
            doc["task_id"] = self.task_id
            doc["save_date"] = current_date
            docs.append(doc)
            url_text = str(doc.get("url", "") or doc.get("site", "") or "").strip()
            if url_text:
                reused_urls.append(url_text)

        if docs:
            utils.conn_db("url").insert_many(docs)
        return len(docs), reused_urls

    def run(self) -> dict:
        summary = {
            "enabled": bool(self.enable),
            "schedule_id": self.schedule_id,
            "schedule_name": self.schedule_name,
            "schedule_run_number": self.schedule_run_number,
            "previous_task_id": "",
            "compared_sites": 0,
            "reused_sites": [],
            "reused_record_count": 0,
            "reused_endpoint_count": 0,
            "reused_url_count": 0,
            "reused_urls": [],
            "records": [],
            "reason": "disabled",
        }

        if not self.enable:
            return summary
        if not self.options.get("from_task_schedule"):
            summary["reason"] = "not_schedule_task"
            return summary
        if not self.schedule_id:
            summary["reason"] = "missing_schedule_id"
            return summary
        if not self.sites:
            summary["reason"] = "empty_sites"
            return summary

        previous_task_id = self._find_previous_task_id()
        if not previous_task_id:
            summary["reason"] = "baseline_not_found"
            return summary

        current_map = self._load_site_signature_map(self.task_id)
        previous_map = self._load_site_signature_map(previous_task_id)
        compared_sites = sorted(set(current_map.keys()) & set(previous_map.keys()))
        reusable_sites = sorted(
            site for site in compared_sites
            if current_map.get(site) and current_map.get(site) == previous_map.get(site)
        )

        summary["previous_task_id"] = previous_task_id
        summary["compared_sites"] = len(compared_sites)
        summary["reused_sites"] = reusable_sites

        if not reusable_sites:
            summary["reason"] = "no_signature_match"
            return summary

        reusable_site_set = set(reusable_sites)
        reused_record_count, normalized_records = self._clone_wih_records(previous_task_id, reusable_site_set)
        reused_endpoint_count = self._clone_wih_endpoints(previous_task_id, reusable_site_set)
        reused_url_count, reused_urls = self._clone_wih_urls(previous_task_id, reusable_site_set)

        summary["reason"] = "ok"
        summary["reused_record_count"] = reused_record_count
        summary["reused_endpoint_count"] = reused_endpoint_count
        summary["reused_url_count"] = reused_url_count
        summary["reused_urls"] = reused_urls
        summary["records"] = normalized_records

        if self.log_detail:
            logger.info(
                "wih periodic reuse hit task_id:{} schedule_id:{} baseline_task:{} compared_sites:{} reused_sites:{} reused_records:{} reused_endpoints:{} reused_urls:{}".format(
                    self.task_id,
                    self.schedule_id,
                    previous_task_id,
                    len(compared_sites),
                    len(reusable_sites),
                    reused_record_count,
                    reused_endpoint_count,
                    reused_url_count,
                )
            )

        return summary


def run_wih_periodic_reuse(task_id: str, sites: list, options: dict) -> dict:
    service = WihPeriodicReuseService(task_id=task_id, sites=sites, options=options)
    return service.run()
