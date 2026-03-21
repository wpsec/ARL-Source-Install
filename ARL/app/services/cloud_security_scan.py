"""
云安全只读检测执行器。

设计目标：
- 复用当前任务已沉淀的 WIH / URL / 页面线索，补齐云安全专项检测
- 默认仅做只读检测，不执行上传、删除、ACL 写入等高副作用操作
- 不引入 DNSLog，优先覆盖云凭证泄露、存储桶遍历、接管与 ACL/Policy 泄露
"""
import json
import math
import re
from collections import Counter
from typing import Dict, List
from urllib.parse import urlparse, urlunparse

from app import utils

logger = utils.get_logger()


class CloudSecurityScanService(object):
    """
    云安全只读检测服务。

    当前实现说明：
    - 云凭证检测优先复用 WIH / TruffleHog 已发现的敏感记录，再做轻量归一和上下文判断
    - 存储桶检测仅执行 GET 类只读请求，不进行上传/删除等副作用操作
    """

    CLOUD_RECORD_TYPE_RULES = {
        "aliyun_ak_id": {"provider": "阿里云", "name": "AccessKey ID", "severity": "critical"},
        "qcloud_ak_id": {"provider": "腾讯云", "name": "SecretId", "severity": "critical"},
        "jdcloud_ak_id": {"provider": "京东云", "name": "AccessKey ID", "severity": "high"},
        "aws_ak_id": {"provider": "AWS", "name": "AccessKey ID", "severity": "critical"},
        "volcanoengine_ak_id": {"provider": "火山引擎", "name": "AccessKey ID", "severity": "critical"},
        "kingsoft_ak_id": {"provider": "金山云", "name": "AccessKey ID", "severity": "high"},
        "gcp_ak_id": {"provider": "Google Cloud", "name": "API Key", "severity": "high"},
        "gemini_api_key": {"provider": "Google Cloud", "name": "Gemini API Key", "severity": "high"},
        "firebase_api_key": {"provider": "Firebase", "name": "API Key", "severity": "high"},
    }
    CLOUD_KEY_REGEX_RULES = (
        {
            "provider": "百度智能云",
            "name": "AccessKey",
            "pattern": r"\bAK[A-Za-z0-9]{16,40}\b",
            "contexts": ("baidu", "bce", "bos"),
            "severity": "high",
        },
        {
            "provider": "华为云",
            "name": "AccessKey",
            "pattern": r"\b[A-Z0-9]{20}\b",
            "contexts": ("huaweicloud", "myhuaweicloud", "obs", "credential", "accesskey"),
            "severity": "critical",
        },
        {
            "provider": "Azure",
            "name": "AccountKey",
            "pattern": r"(?i)(?:accountkey|azure|blob|storage)[^\r\n]{0,80}\b[A-Za-z0-9+/=]{40,120}\b",
            "contexts": ("azure", "blob", "storage", "accountkey"),
            "severity": "critical",
        },
        {
            "provider": "七牛云",
            "name": "AccessKey",
            "pattern": r"\b[A-Za-z0-9_-]{32,40}\b",
            "contexts": ("qiniu", "qiniucs", "qiniudn", "clouddn", "accesskey", "secretkey"),
            "severity": "high",
        },
        {
            "provider": "又拍云",
            "name": "AccessKey",
            "pattern": r"\b[A-Za-z0-9]{32}\b",
            "contexts": ("upyun", "upaiyun", "b0.upaiyun"),
            "severity": "high",
        },
        {
            "provider": "Firebase",
            "name": "API Key",
            "pattern": r"\bAIza[0-9A-Za-z_-]{35}\b",
            "contexts": ("firebase", "firestore", "firebaseio"),
            "severity": "high",
        },
    )
    BUCKET_PROVIDERS = {
        "aliyun_oss": {
            "name": "阿里云 OSS",
            "patterns": (r"(?:^|//)[a-z0-9.-]+\.oss-[a-z0-9-]+\.aliyuncs\.com",),
            "list_tests": (
                ("", ("listbucketresult", "<contents>", "<key>")),
                ("?list-type=2", ("listbucketresult", "<contents>", "<key>")),
            ),
            "acl_tests": (("?acl", ("accesscontrolpolicy", "<grant>", "<grantee>")),),
            "policy_tests": (("?policy", ("version", "statement", "effect")),),
            "takeover_keywords": ("nosuchbucket", "the specified bucket does not exist"),
        },
        "tencent_cos": {
            "name": "腾讯云 COS",
            "patterns": (r"(?:^|//)[a-z0-9.-]+\.cos\.[a-z0-9-]+\.myqcloud\.com",),
            "list_tests": (
                ("", ("listbucketresult", "<contents>", "<key>")),
                ("?list-type=2", ("listbucketresult", "<contents>", "<key>")),
            ),
            "acl_tests": (("?acl", ("accesscontrolpolicy", "<grant>", "<grantee>")),),
            "policy_tests": (("?policy", ("version", "statement", "principal")),),
            "takeover_keywords": ("nosuchbucket", "the specified bucket does not exist"),
        },
        "huawei_obs": {
            "name": "华为云 OBS",
            "patterns": (r"(?:^|//)[a-z0-9.-]+\.obs\.[a-z0-9-]+\.myhuaweicloud\.com",),
            "list_tests": (
                ("", ("listbucketresult", "<contents>", "<key>")),
                ("?list-type=2", ("listbucketresult", "<contents>", "<key>")),
            ),
            "acl_tests": (("?acl", ("accesscontrolpolicy", "<grant>", "<grantee>")),),
            "policy_tests": (("?policy", ("version", "statement", "effect")),),
            "takeover_keywords": ("nosuchbucket", "specified bucket does not exist"),
        },
        "aws_s3": {
            "name": "AWS S3",
            "patterns": (
                r"(?:^|//)[a-z0-9.-]+\.s3[.-][a-z0-9-]+\.amazonaws\.com",
                r"(?:^|//)[a-z0-9.-]+\.s3\.amazonaws\.com",
            ),
            "list_tests": (
                ("", ("listbucketresult", "<contents>", "<key>")),
                ("?list-type=2", ("listbucketresult", "<contents>", "<key>")),
            ),
            "acl_tests": (("?acl", ("accesscontrolpolicy", "<grant>", "<grantee>")),),
            "policy_tests": (("?policy", ("version", "statement", "effect", "principal")),),
            "takeover_keywords": ("nosuchbucket", "the specified bucket does not exist"),
        },
        "baidu_bos": {
            "name": "百度云 BOS",
            "patterns": (r"(?:^|//)[a-z0-9.-]+\.bcebos\.com",),
            "list_tests": (
                ("", ("listbucketresult", "<contents>", "<key>")),
                ("?list-type=2", ("listbucketresult", "<contents>", "<key>")),
            ),
            "acl_tests": (),
            "policy_tests": (("?policy", ("version", "statement", "effect")),),
            "takeover_keywords": ("nosuchbucket",),
        },
        "jdcloud_oss": {
            "name": "京东云对象存储",
            "patterns": (
                r"(?:^|//)[a-z0-9.-]+\.s3\.[a-z0-9-]+\.jdcloud-oss\.com",
                r"(?:^|//)[a-z0-9.-]+\.jcloudcs\.com",
            ),
            "list_tests": (
                ("", ("listbucketresult", "<contents>", "<key>")),
                ("?list-type=2", ("listbucketresult", "<contents>", "<key>")),
            ),
            "acl_tests": (),
            "policy_tests": (("?policy", ("version", "statement", "effect")),),
            "takeover_keywords": ("nosuchbucket",),
        },
        "qiniu_kodo": {
            "name": "七牛云 Kodo",
            "patterns": (r"(?:^|//)[a-z0-9.-]+\.(?:qiniudn|clouddn|qiniucs)\.com",),
            "list_tests": (("", ("<item>", "\"items\"", "\"key\"")),),
            "acl_tests": (),
            "policy_tests": (),
            "takeover_keywords": ("no such bucket", "bucket not found"),
        },
        "upyun_uss": {
            "name": "又拍云 USS",
            "patterns": (r"(?:^|//)[a-z0-9.-]+\.b0\.upaiyun\.com",),
            "list_tests": (),
            "acl_tests": (),
            "policy_tests": (),
            "takeover_keywords": ("bucket not found", "not exist"),
        },
        "azure_blob": {
            "name": "Azure Blob",
            "patterns": (r"(?:^|//)[a-z0-9-]+\.blob\.core\.windows\.net(?:/[a-z0-9._-]+)?",),
            "list_tests": (("?restype=container&comp=list", ("enumerationresults", "<blobs>", "<blob>")),),
            "acl_tests": (("?restype=container&comp=acl", ("signedidentifiers", "publicaccess")),),
            "policy_tests": (),
            "takeover_keywords": ("containernotfound", "the specified container does not exist"),
        },
    }
    MAX_BUCKET_TARGETS = 40
    MAX_WIH_RECORDS = 4000
    REQUEST_TIMEOUT = (5, 12)

    def __init__(self, task_id: str, sites: list, page_url_set=None, waf_guard=None):
        self.task_id = str(task_id or "").strip()
        self.sites = list(sites or [])
        self.page_url_set = set(page_url_set or [])
        self.waf_guard = waf_guard
        self.dns_policy_cache = {}
        self.finding_hash_set = set()
        self.wih_records_cache = None

    @staticmethod
    def _stable_hash(*parts) -> str:
        text = "|".join(str(part or "").strip() for part in parts)
        return utils.gen_md5(text)

    @staticmethod
    def _safe_json(value) -> str:
        try:
            return json.dumps(value, ensure_ascii=False, sort_keys=True)
        except Exception:
            return str(value)

    @staticmethod
    def _is_http_url(value: str) -> bool:
        text = str(value or "").strip().lower()
        return text.startswith("http://") or text.startswith("https://")

    def _load_wih_records(self):
        if self.wih_records_cache is not None:
            return list(self.wih_records_cache)

        if not self.task_id:
            return []

        try:
            cursor = utils.conn_db("wih").find(
                {"task_id": self.task_id},
                {
                    "record_type": 1,
                    "content": 1,
                    "source": 1,
                    "site": 1,
                },
            ).limit(self.MAX_WIH_RECORDS)
            self.wih_records_cache = list(cursor or [])
            return list(self.wih_records_cache)
        except Exception as e:
            logger.warning("load cloud security wih records failed task_id:{} err:{}".format(self.task_id, e))
            return []

    def _load_db_urls(self):
        if not self.task_id:
            return []

        try:
            return list(utils.conn_db("url").distinct("url", {"task_id": self.task_id}) or [])
        except Exception as e:
            logger.warning("load cloud security url assets failed task_id:{} err:{}".format(self.task_id, e))
            return []

    @staticmethod
    def _mask_secret(value: str) -> str:
        text = str(value or "").strip()
        if len(text) <= 12:
            return text
        return "{}...{}".format(text[:6], text[-4:])

    @staticmethod
    def _entropy(value: str) -> float:
        text = str(value or "")
        if not text:
            return 0.0
        counts = Counter(text)
        total = float(len(text))
        entropy = 0.0
        for count in counts.values():
            p = count / total
            entropy -= p * (0 if p <= 0 else math.log(p, 2))
        return entropy

    @staticmethod
    def _looks_like_example(value: str) -> bool:
        lowered = str(value or "").strip().lower()
        if not lowered:
            return True
        example_keywords = (
            "example",
            "sample",
            "demo",
            "test",
            "placeholder",
            "your_",
            "your-",
            "replace",
            "dummy",
            "fake",
            "mock",
            "000000",
            "111111",
            "aaaaaa",
            "bbbbbb",
            "cccccc",
        )
        return any(keyword in lowered for keyword in example_keywords)

    def _is_valid_secret(self, value: str) -> bool:
        text = str(value or "").strip().strip("\"'")
        if len(text) < 16:
            return False
        if self._looks_like_example(text):
            return False
        if text.lower().startswith("http"):
            return False
        if len(set(text)) <= 4:
            return False
        return self._entropy(text) >= 3.0

    def _append_finding(
        self,
        findings: List[Dict],
        vuln_type: str,
        vuln_name: str,
        severity: str,
        url: str,
        detail: str,
        evidence: str,
        source: str = "",
        payload: str = "",
        request_text: str = "",
        response_text: str = "",
    ):
        finding_hash = self._stable_hash(vuln_type, url, detail, evidence)
        if finding_hash in self.finding_hash_set:
            return

        self.finding_hash_set.add(finding_hash)
        findings.append(
            {
                "type": vuln_type,
                "name": vuln_name,
                "severity": severity,
                "url": url,
                "method": "GET",
                "param": "",
                "payload": payload,
                "detail": detail,
                "source": source,
                "evidence": evidence,
                "request": request_text,
                "response": response_text,
            }
        )

    def _scan_cloud_keys(self, records: List[Dict], findings: List[Dict]):
        for record in records or []:
            record_type = str(record.get("record_type", "") or "").strip().lower()
            content = str(record.get("content", "") or "").strip()
            source = str(record.get("source", "") or "").strip()
            site = str(record.get("site", "") or "").strip()
            merged_lower = "{} {} {} {}".format(record_type, content, source, site).lower()

            if record_type in self.CLOUD_RECORD_TYPE_RULES:
                rule = self.CLOUD_RECORD_TYPE_RULES[record_type]
                if self._is_valid_secret(content):
                    target = source if self._is_http_url(source) else (site or source or "-")
                    self._append_finding(
                        findings,
                        vuln_type="cloud_key_leak",
                        vuln_name="云凭证泄露",
                        severity=rule["severity"],
                        url=target,
                        detail="检测到 {} {} 泄露".format(rule["provider"], rule["name"]),
                        evidence=self._mask_secret(content),
                        source=record_type,
                        payload=self._mask_secret(content),
                    )

            for rule in self.CLOUD_KEY_REGEX_RULES:
                if not any(keyword in merged_lower for keyword in rule["contexts"]):
                    continue
                for match in re.finditer(rule["pattern"], content, flags=re.I):
                    secret = str(match.group(0) or "").strip().strip("\"'")
                    if not self._is_valid_secret(secret):
                        continue
                    target = source if self._is_http_url(source) else (site or source or "-")
                    self._append_finding(
                        findings,
                        vuln_type="cloud_key_leak",
                        vuln_name="云凭证泄露",
                        severity=rule["severity"],
                        url=target,
                        detail="检测到 {} {} 泄露".format(rule["provider"], rule["name"]),
                        evidence=self._mask_secret(secret),
                        source=record_type or "content_match",
                        payload=self._mask_secret(secret),
                    )

    @staticmethod
    def _normalize_bucket_url(url: str, provider_key: str = "") -> str:
        raw = str(url or "").strip()
        if not raw:
            return ""

        parsed = urlparse(raw if "://" in raw else "https://{}".format(raw))
        if parsed.scheme.lower() not in {"http", "https"}:
            return ""
        host = str(parsed.hostname or "").strip().lower()
        if not host:
            return ""

        scheme = parsed.scheme.lower()
        netloc = host
        if parsed.port:
            netloc = "{}:{}".format(host, parsed.port)

        path = ""
        if provider_key == "azure_blob":
            path_parts = [part for part in str(parsed.path or "").split("/") if part]
            if path_parts:
                path = "/{}".format(path_parts[0])

        return urlunparse((scheme, netloc, path, "", "", ""))

    def _detect_bucket_provider(self, value: str) -> str:
        text = str(value or "").strip().lower()
        if not text:
            return ""

        for provider_key, rule in self.BUCKET_PROVIDERS.items():
            for pattern in rule.get("patterns", ()):
                if re.search(pattern, text, flags=re.I):
                    return provider_key
        return ""

    def _extract_bucket_urls_from_text(self, text: str) -> List[str]:
        content = str(text or "").strip()
        if not content:
            return []

        results = []
        result_set = set()
        for provider_key, rule in self.BUCKET_PROVIDERS.items():
            for pattern in rule.get("patterns", ()):
                for match in re.finditer(pattern, content, flags=re.I):
                    candidate = str(match.group(0) or "").strip().strip("'\"()[]{}<>")
                    normalized = self._normalize_bucket_url(candidate, provider_key=provider_key)
                    if normalized and normalized not in result_set:
                        result_set.add(normalized)
                        results.append(normalized)
        return results

    def _collect_bucket_targets(self, records: List[Dict]) -> List[Dict]:
        targets = []
        target_set = set()

        def _append(candidate: str, source: str):
            provider_key = self._detect_bucket_provider(candidate)
            if not provider_key:
                return

            normalized = self._normalize_bucket_url(candidate, provider_key=provider_key)
            if not normalized or normalized in target_set:
                return

            allow_scan, policy_detail = utils.check_dns_policy_for_url(normalized, cache_map=self.dns_policy_cache)
            if not allow_scan:
                logger.info(
                    "skip cloud bucket target by dns policy url:{} reason:{} resolver_ips:{} system_ips:{}".format(
                        normalized,
                        policy_detail.get("reason", ""),
                        policy_detail.get("resolver_ips", []),
                        policy_detail.get("system_ips", []),
                    )
                )
                return

            target_set.add(normalized)
            targets.append(
                {
                    "url": normalized,
                    "provider": provider_key,
                    "source": str(source or "").strip(),
                }
            )

        for site in self.sites:
            _append(site, "site")
        for url in list(self.page_url_set) + self._load_db_urls():
            _append(url, "url_asset")

        for record in records or []:
            record_type = str(record.get("record_type", "") or "").strip()
            content = str(record.get("content", "") or "").strip()
            source = str(record.get("source", "") or "").strip()
            site = str(record.get("site", "") or "").strip()
            for candidate in (content, source, site):
                _append(candidate, record_type or "wih")
            for candidate in self._extract_bucket_urls_from_text(content):
                _append(candidate, record_type or "wih")
            for candidate in self._extract_bucket_urls_from_text(source):
                _append(candidate, record_type or "wih")

        targets.sort(key=lambda item: (0 if item.get("source") == "site" else 1, item.get("url", "")))
        return targets[: self.MAX_BUCKET_TARGETS]

    def _request(self, url: str):
        return utils.http_req(
            url,
            method="get",
            timeout=self.REQUEST_TIMEOUT,
            waf_guard=self.waf_guard,
            waf_module="cloud_security",
        )

    @staticmethod
    def _build_test_url(base_url: str, suffix: str) -> str:
        base = str(base_url or "").rstrip("/")
        if not suffix:
            return base
        if suffix.startswith("?"):
            return "{}{}".format(base, suffix)
        return "{}/{}".format(base, suffix.lstrip("/"))

    @staticmethod
    def _summarize_response(resp, body: str) -> str:
        headers = dict(getattr(resp, "headers", {}) or {})
        preview = str(body or "")[:300]
        return "status={} headers={} body={}".format(
            int(getattr(resp, "status_code", 0) or 0),
            json.dumps(headers, ensure_ascii=False)[:300],
            preview,
        )

    def _test_bucket_takeover(self, target: Dict, findings: List[Dict]):
        provider_rule = self.BUCKET_PROVIDERS.get(target.get("provider"), {})
        if not provider_rule:
            return

        try:
            resp = self._request(target["url"])
        except Exception:
            return

        body = str(getattr(resp, "text", "") or "")
        lowered = body.lower()
        for keyword in provider_rule.get("takeover_keywords", ()):
            if keyword in lowered:
                self._append_finding(
                    findings,
                    vuln_type="cloud_bucket_takeover",
                    vuln_name="云存储桶可接管",
                    severity="critical",
                    url=target["url"],
                    detail="{} 返回缺失桶特征，存在接管风险".format(provider_rule.get("name", "对象存储")),
                    evidence=keyword,
                    source=target.get("source", ""),
                    request_text=self._safe_json({"method": "GET", "url": target["url"]}),
                    response_text=self._summarize_response(resp, body),
                )
                return

    def _test_bucket_variants(self, target: Dict, findings: List[Dict], variant_key: str, vuln_type: str, vuln_name: str, severity: str):
        provider_rule = self.BUCKET_PROVIDERS.get(target.get("provider"), {})
        for suffix, indicators in provider_rule.get(variant_key, ()):
            test_url = self._build_test_url(target["url"], suffix)
            try:
                resp = self._request(test_url)
            except Exception:
                continue

            status_code = int(getattr(resp, "status_code", 0) or 0)
            if status_code != 200:
                continue

            body = str(getattr(resp, "text", "") or "")
            lowered = body.lower()
            if not any(str(indicator or "").lower() in lowered for indicator in indicators):
                continue

            self._append_finding(
                findings,
                vuln_type=vuln_type,
                vuln_name=vuln_name,
                severity=severity,
                url=test_url,
                detail="{} 存在{}".format(provider_rule.get("name", "对象存储"), vuln_name),
                evidence=str(body[:240] or "").strip(),
                source=target.get("source", ""),
                payload=suffix,
                request_text=self._safe_json({"method": "GET", "url": test_url}),
                response_text=self._summarize_response(resp, body),
            )
            return

    def run(self):
        records = self._load_wih_records()
        findings = []

        self._scan_cloud_keys(records, findings)

        targets = self._collect_bucket_targets(records)
        for target in targets:
            self._test_bucket_takeover(target, findings)
            self._test_bucket_variants(
                target,
                findings,
                variant_key="list_tests",
                vuln_type="cloud_bucket_traversal",
                vuln_name="云存储桶遍历",
                severity="high",
            )
            self._test_bucket_variants(
                target,
                findings,
                variant_key="acl_tests",
                vuln_type="cloud_bucket_acl_leak",
                vuln_name="云存储桶 ACL 泄露",
                severity="high",
            )
            self._test_bucket_variants(
                target,
                findings,
                variant_key="policy_tests",
                vuln_type="cloud_bucket_policy_leak",
                vuln_name="云存储桶 Policy 泄露",
                severity="high",
            )

        logger.info(
            "cloud security scan done task_id:{} bucket_targets:{} findings:{}".format(
                self.task_id,
                len(targets),
                len(findings),
            )
        )
        return {
            "targets": targets,
            "findings": findings,
        }


def run_cloud_security_scan(task_id: str, sites: list, page_url_set=None, waf_guard=None):
    service = CloudSecurityScanService(
        task_id=task_id,
        sites=sites,
        page_url_set=page_url_set,
        waf_guard=waf_guard,
    )
    return service.run()
