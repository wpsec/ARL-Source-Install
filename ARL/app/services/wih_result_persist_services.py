"""WIH 结果持久化与风险提升边界服务。

功能说明：
- 收敛 WIH 记录/接口/风险的落库、任务范围校验与敏感提升判定
- 保留 task 上的兼容方法名，wih_orchestrator 与任务入口不改调用方式
- Mongo 写操作仍经 task._result_writer，字段组装仍经 task._result_item_service
"""

import re

from app import utils
from app.services.infoHunter import InfoHunter
from app.utils.log_safety import safe_error_text


logger = utils.get_logger()

SENSITIVE_RECORD_TYPE_SET = {
    "app_key",
    "api_key",
    "access_key",
    "secret_key",
    "client_secret",
    "private_key",
    "token",
    "jwt",
    "authorization",
    "password",
    "passwd",
    "credential",
}


class WihResultPersistService(object):
    """WIH 记录落库与提升判定的可测试服务。"""

    def __init__(self, task, infohunter_module=None, utils_module=None):
        self.task = task
        self.infohunter = infohunter_module or InfoHunter
        self.utils = utils_module or utils

    @staticmethod
    def is_http_url(value) -> bool:
        text = str(value or "").strip().lower()
        return text.startswith("http://") or text.startswith("https://")

    def add_domain_set(self, record) -> None:
        task = self.task
        if not getattr(task, "scope_domain", None):
            return
        if str(getattr(record, "recordType", "") or "").strip().lower() != "domain":
            return

        from app.services.commonTask import domain_in_scope_domain

        content = str(getattr(record, "content", "") or "").strip()
        if not content:
            return
        if not domain_in_scope_domain(content, task.scope_domain):
            return
        try:
            if self.utils.check_domain_black(content):
                return
        except Exception as exc:
            # 黑名单读取异常按保守策略跳过该域名，不中断 WIH 记录链路。
            logger.debug(
                "wih domain blacklist check failed domain:{} error_type:{}".format(
                    content[:120], type(exc).__name__
                )
            )
            return

        task.wih_domain_set.add(content)

    def extract_scope_urls(self, record) -> list:
        record_type = str(getattr(record, "recordType", "") or "").strip().lower()
        content = str(getattr(record, "content", "") or "").strip()
        source = str(getattr(record, "source", "") or "").strip()
        site = str(getattr(record, "site", "") or "").strip()
        candidates = []
        for value in (content, source, site):
            if self.is_http_url(value) and value not in candidates:
                candidates.append(value)

        if record_type == "page_form":
            match = re.match(r"^\s*([A-Za-z]+)\s+(\S+?)(?:\s+\[([^\]]*)\])?\s*$", content)
            if match:
                action_url = str(match.group(2) or "").strip()
                if self.is_http_url(action_url) and action_url not in candidates:
                    candidates.append(action_url)
        elif record_type == "api_doc_endpoint":
            match = re.match(r"^\s*([A-Za-z]+)\s+(\S+)\s*$", content)
            if match:
                endpoint_url = str(match.group(2) or "").strip()
                if self.is_http_url(endpoint_url) and endpoint_url not in candidates:
                    candidates.append(endpoint_url)

        return candidates

    def record_in_task_scope(self, record) -> bool:
        task = self.task
        for value in self.extract_scope_urls(record):
            if not task._url_in_task_scope(value):
                return False

        record_type = str(getattr(record, "recordType", "") or "").strip().lower()
        content = str(getattr(record, "content", "") or "").strip()
        if record_type == "domain" and content:
            return task._host_in_task_scope(content)
        return True

    def is_obvious_secret_noise(self, record_type: str, content: str, source: str = "", site: str = "") -> bool:
        """复用 WIH 统一规则，过滤已明确判定为占位值或调试代码的敏感命中。"""
        normalized_type = str(record_type or "").strip().lower()
        if not self.infohunter._is_secret_like_record_type(normalized_type):
            return False
        return not self.infohunter._should_keep_secret_content(
            normalized_type,
            content,
            source=source,
            site=site,
        )

    def is_sensitive_record(self, record_type: str, content: str, source: str = "", site: str = "") -> bool:
        """判断 WIH 记录是否属于可进入风险提升链的敏感类型。"""
        normalized_type = str(record_type or "").strip().lower()
        if not normalized_type or not str(content or "").strip():
            return False
        if self.is_obvious_secret_noise(normalized_type, content, source=source, site=site):
            return False
        if normalized_type.startswith("trufflehog_"):
            return True
        return (
            normalized_type in SENSITIVE_RECORD_TYPE_SET
            or normalized_type.endswith("_key")
            or normalized_type.endswith("_token")
        )

    def should_promote_to_risk(self, record) -> bool:
        """判断 WIH 记录是否需要同步到风险(vuln)模块。"""
        record_type = str(getattr(record, "recordType", "") or "").strip().lower()
        if not record_type:
            return False
        content = str(getattr(record, "content", "") or "").strip()
        source = str(getattr(record, "source", "") or "").strip()
        if self.is_obvious_secret_noise(record_type, content, source=source):
            return False

        if record_type.startswith("trufflehog_"):
            return True
        if record_type in SENSITIVE_RECORD_TYPE_SET:
            return True
        if record_type.endswith("_key") or record_type.endswith("_token"):
            return True
        return False

    @staticmethod
    def infer_risk_severity(record_type: str, content: str) -> str:
        """基于记录类型和内容推断风险等级。"""
        merged = "{} {}".format(str(record_type or "").lower(), str(content or "").lower())
        high_keywords = (
            "private_key",
            "secret_key",
            "client_secret",
            "password",
            "passwd",
            "(verified)",
        )
        medium_keywords = (
            "app_key",
            "api_key",
            "access_key",
            "token",
            "jwt",
            "(unknown)",
            "(unverified)",
        )
        if any(keyword in merged for keyword in high_keywords):
            return "high"
        if any(keyword in merged for keyword in medium_keywords):
            return "medium"
        return "info"

    def build_vuln_item(self, record):
        task = self.task
        item = task._result_item_service.build_wih_vuln_document(
            record=record,
            should_promote=self.should_promote_to_risk,
            record_in_scope=self.record_in_task_scope,
            is_http_url=self.is_http_url,
            url_in_scope=task._url_in_task_scope,
            infer_severity=self.infer_risk_severity,
        )
        return item or None

    def save_risk(self, record) -> None:
        """将敏感 WIH 记录写入风险库，按任务+WIH哈希去重。"""
        task = self.task
        item = self.build_vuln_item(record)
        if not item:
            return

        try:
            task._result_writer.update_one(
                "vuln",
                {
                    "task_id": task.task_id,
                    "wih_fnv_hash": item["wih_fnv_hash"],
                },
                {"$setOnInsert": item},
                upsert=True,
            )
        except Exception as e:
            logger.warning("save wih risk failed task_id:{} err:{}".format(task.task_id, safe_error_text(e)))

    def save_endpoints(self, endpoints) -> None:
        """WIH 结构化接口需要独立落库，前台才能按任务维度分页查询。"""
        task = self.task
        scoped_endpoints = []
        for raw_item in list(endpoints or []):
            if not isinstance(raw_item, dict):
                continue

            endpoint_url = str(raw_item.get("url") or "").strip()
            page_url = str(raw_item.get("page_url") or "").strip()
            if endpoint_url and not task._url_in_task_scope(endpoint_url):
                continue
            if page_url and not task._url_in_task_scope(page_url):
                continue
            scoped_endpoints.append(raw_item)

        for raw_item in scoped_endpoints:
            item = task._result_item_service.build_wih_endpoint_document(raw_item)
            if not item:
                continue

            try:
                task._result_writer.replace_one(
                    "wih_endpoint",
                    {
                        "task_id": task.task_id,
                        "fnv_hash": item["fnv_hash"],
                    },
                    item,
                    upsert=True,
                )
            except Exception as e:
                logger.warning("save wih endpoint failed task_id:{} err:{}".format(task.task_id, safe_error_text(e)))

    def save_record(self, record) -> None:
        """保存已经完成范围校验和去重的 WIH 记录。"""
        task = self.task
        item = task._result_item_service.build_wih_record_document(record)
        if not item:
            raise ValueError("WIH record cannot be serialized")
        fnv_hash = item.get("fnv_hash")
        if fnv_hash in (None, ""):
            raise ValueError("WIH record is missing fnv_hash")
        task._result_writer.replace_one(
            "wih",
            {
                "task_id": task.task_id,
                "fnv_hash": fnv_hash,
            },
            item,
            upsert=True,
        )
        task.wih_record_set.add(record.fnv_hash)
        self.save_risk(record)

    def apply_reused_records(self, records) -> int:
        """周期复用记录只补风险与去重集合，不重复写 wih 主表。"""
        task = self.task
        record_list = list(records or [])
        if not record_list:
            return 0

        applied = 0
        for record in record_list:
            normalized = self.infohunter.normalize_wih_record(record)
            if not normalized:
                continue
            if normalized.fnv_hash in task.wih_record_set:
                continue
            if not self.record_in_task_scope(normalized):
                continue

            self.add_domain_set(normalized)
            self.save_risk(normalized)
            task.wih_record_set.add(normalized.fnv_hash)
            applied += 1

        return applied
