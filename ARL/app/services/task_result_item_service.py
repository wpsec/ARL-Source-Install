"""扫描结果文档组装服务。

这里只负责把阶段输出转换成既有 Mongo 文档，不执行写库、网络请求或任务编排。
这样可以独立验证字段兼容性，并让 CommonTask 保留范围校验、幂等和写入时机。
"""

import json
from urllib.parse import urlparse

from app import utils
from app.modules import CollectSource
from app.services.fingerprint_cache import split_fingerprint_result_items


class TaskResultItemService(object):
    """构造各 collection 使用的任务结果文档。"""

    def __init__(self, task_id, curr_date=None, logger=None):
        self.task_id = str(task_id or "")
        self.curr_date = curr_date or utils.curr_date
        self.logger = logger

    def build_site_document(self, site_info, web_analyze_map=None):
        if not isinstance(site_info, dict):
            return {}

        item = site_info
        site = item.get("site")
        if not site:
            return {}
        curr_date = self.curr_date()
        site_text = str(site).strip()
        item["task_id"] = self.task_id
        item["screenshot"] = "/image/{}/{}.jpg".format(
            self.task_id,
            utils.gen_filename(site_text),
        )
        item.setdefault("save_date", curr_date)
        item.setdefault("update_date", curr_date)

        merged_fingers = list(item.get("finger", []) or [])
        merged_fingers.extend(item.get("finger_candidates", []) or [])
        result_map = web_analyze_map if isinstance(web_analyze_map, dict) else {}
        finger_result = result_map.get(site_text, {})
        if isinstance(finger_result, dict):
            merged_fingers.extend(finger_result.get("confirmed", []) or [])
            merged_fingers.extend(finger_result.get("candidates", []) or [])
        elif isinstance(finger_result, list):
            merged_fingers.extend(finger_result)

        confirmed, candidates = split_fingerprint_result_items(merged_fingers)
        item["finger"] = confirmed
        if candidates:
            item["finger_candidates"] = candidates
        else:
            item.pop("finger_candidates", None)
        return item

    def build_fileleak_document(self, page, site_scope_map=None):
        if isinstance(page, dict):
            item = page
        elif hasattr(page, "dump_json"):
            item = page.dump_json()
        else:
            return {}
        if not isinstance(item, dict):
            return {}

        item["task_id"] = self.task_id
        page_url = str(item.get("url", "") or "").strip()
        parsed_page = urlparse(page_url)
        page_scope = "{}://{}".format(parsed_page.scheme, parsed_page.netloc)
        scope_map = site_scope_map if isinstance(site_scope_map, dict) else {}
        item["site"] = scope_map.get(page_scope, page_scope)
        item.setdefault("source", CollectSource.FILE_LEAK_DICT_BRUTE)
        return item

    def build_nuclei_document(self, result):
        if not isinstance(result, dict):
            return {}
        item = result
        item["task_id"] = self.task_id
        item["save_date"] = self.curr_date()
        return item

    def build_risk_document(self, result):
        """补齐风险插件结果的任务归属和写入时间，不改动插件原始字段。"""
        if not isinstance(result, dict):
            return {}
        item = result
        item["task_id"] = self.task_id
        item["save_date"] = self.curr_date()
        return item

    @staticmethod
    def build_afrog_detail_text(result, target, poc_id):
        verify_payload = {}
        verify_data_text = str((result or {}).get("verify_data", "") or "").strip()
        if verify_data_text:
            try:
                parsed_payload = json.loads(verify_data_text)
                if isinstance(parsed_payload, dict):
                    verify_payload = parsed_payload
            except (TypeError, ValueError):
                verify_payload = {}

        vuln_name = str((result or {}).get("vuln_name", "") or "").strip()
        severity = str((result or {}).get("severity", "") or "").strip().lower()
        references = verify_payload.get("reference", [])
        if isinstance(references, str):
            references = [references]
        if not isinstance(references, list):
            references = []
        references = [str(item or "").strip() for item in references if str(item or "").strip()][:2]

        parts = ["source=afrog", "poc_id={}".format(poc_id or "-")]
        if vuln_name:
            parts.append("name={}".format(vuln_name[:120]))
        if severity:
            parts.append("severity={}".format(severity[:24]))
        if target:
            parts.append("target={}".format(str(target)[:180]))
        if references:
            parts.append("reference={}".format(" ; ".join(item[:140] for item in references)))
        return " | ".join(parts)[:900]

    def build_afrog_document(self, result, target, poc_id):
        if not isinstance(result, dict):
            return {}
        return {
            "plg_name": "afrog:{}".format(poc_id) if poc_id else "afrog",
            "plg_type": "afrog",
            "vul_name": str(result.get("vuln_name", "") or "afrog 漏洞").strip(),
            "app_name": "afrog",
            "target": target,
            "severity": str(result.get("severity", "") or "info").strip().lower(),
            "description": str(result.get("description", "") or "").strip(),
            "detail": self.build_afrog_detail_text(result, target, poc_id),
            "verify_data": str(result.get("verify_data", "") or "").strip(),
            "task_id": self.task_id,
            "save_date": self.curr_date(),
        }
    def build_wih_record_document(self, record):
        if not hasattr(record, "dump_json"):
            return {}
        item = record.dump_json()
        if not isinstance(item, dict):
            return {}
        item["task_id"] = self.task_id
        return item

    def build_wih_endpoint_document(self, raw_item):
        if not isinstance(raw_item, dict):
            return {}
        item = raw_item.copy()
        item["task_id"] = self.task_id
        item["save_date"] = self.curr_date()
        endpoint_hash = str(item.get("fnv_hash") or "")
        if not endpoint_hash:
            endpoint_hash = "{}|{}|{}|{}".format(
                item.get("target", ""),
                item.get("page_url", ""),
                item.get("method", ""),
                item.get("url", ""),
            )
        item["fnv_hash"] = endpoint_hash
        return item

    def build_wih_vuln_document(
        self,
        record,
        should_promote,
        record_in_scope,
        is_http_url,
        url_in_scope,
        infer_severity,
    ):
        if not record or not callable(should_promote) or not should_promote(record):
            return {}
        if not callable(record_in_scope) or not record_in_scope(record):
            return {}

        record_type = str(getattr(record, "recordType", "") or "").strip()
        content_raw = str(getattr(record, "content", "") or "").strip()
        source = str(getattr(record, "source", "") or "").strip()
        site = str(getattr(record, "site", "") or "").strip()
        fnv_hash = str(getattr(record, "fnv_hash", "") or "").strip()
        verify_data = content_raw
        if len(verify_data) > 2048:
            verify_data = "{}...[truncated]".format(verify_data[:2048])

        normalized_type = record_type.lower()
        is_trufflehog = normalized_type.startswith("trufflehog_")
        detector_name = normalized_type.replace("trufflehog_", "", 1) if is_trufflehog else normalized_type
        detector_name = detector_name or "secret"
        if is_trufflehog:
            vul_name = "TruffleHog 检测到敏感信息 ({})".format(detector_name)
            plg_name = "trufflehog"
            app_name = "trufflehog"
        else:
            vul_name = "WIH 检测到敏感信息 ({})".format(detector_name)
            plg_name = "wih"
            app_name = "wih"

        target = source if callable(is_http_url) and is_http_url(source) else (site or source or "-")
        if callable(is_http_url) and is_http_url(target):
            if not callable(url_in_scope) or not url_in_scope(target):
                return {}
        detail = "record_type={} source={} site={}".format(
            record_type or "-", source or "-", site or "-"
        )
        return {
            "task_id": self.task_id,
            "plg_name": plg_name,
            "plg_type": "敏感信息泄露",
            "vul_name": vul_name,
            "app_name": app_name,
            "target": target,
            "severity": infer_severity(normalized_type, content_raw),
            "description": detail,
            "detail": detail,
            "verify_data": verify_data,
            "save_date": self.curr_date(),
            "wih_fnv_hash": fnv_hash,
            "wih_record_type": record_type,
            "wih_source": source,
        }
