"""
浏览器情报采集服务。

能力说明：
- 基于 Playwright 对高价值页面做低侵入浏览器采集
- 采集运行时加载的脚本、XHR/fetch 请求与表单结构
- 不做复杂点击流，不做自动绕过，只补浏览器视角下的结构化情报
"""
import json
import re
from typing import Dict, List
from urllib.parse import parse_qsl

from app import utils
from app.config import Config
from .baseThread import BaseThread

logger = utils.get_logger()


class BrowserIntelScan(BaseThread):
    SENSITIVE_HEADER_KEYS = {
        "authorization",
        "cookie",
        "set-cookie",
        "proxy-authorization",
        "x-csrf-token",
        "x-xsrf-token",
    }

    def __init__(self, sites: List[str], concurrency=2):
        super().__init__(targets=list(sites or []), concurrency=concurrency)
        self.result_map: Dict[str, Dict] = {}
        self.timeout_ms = max(1000, int(getattr(Config, "BROWSER_INTEL_TIMEOUT_MS", 12000) or 12000))
        self.wait_ms = max(0, int(getattr(Config, "BROWSER_INTEL_WAIT_MS", 800) or 800))

    @staticmethod
    def _normalize_records(items, max_items=12):
        results = []
        seen = set()
        for item in items or []:
            if isinstance(item, dict):
                normalized = {}
                for key, value in item.items():
                    text = str(value or "").strip()
                    if text:
                        normalized[str(key)] = text[:240]
                cache_key = json.dumps(normalized, ensure_ascii=False, sort_keys=True)
            else:
                normalized = str(item or "").strip()[:240]
                cache_key = normalized
            if not normalized or cache_key in seen:
                continue
            seen.add(cache_key)
            results.append(normalized)
            if len(results) >= max_items:
                break
        return results

    @staticmethod
    def _clip_text(value, max_len=240):
        text = str(value or "").strip()
        if len(text) <= max_len:
            return text
        return "{}...".format(text[: max_len - 3])

    @classmethod
    def _normalize_header_map(cls, header_obj, max_items=16):
        headers = header_obj if isinstance(header_obj, dict) else {}
        normalized = {}
        for key, value in headers.items():
            key_text = str(key or "").strip()
            lowered = key_text.lower()
            if not key_text:
                continue
            value_text = "<redacted>" if lowered in cls.SENSITIVE_HEADER_KEYS else cls._clip_text(value, 180)
            normalized[key_text] = value_text
            if len(normalized) >= max(1, int(max_items or 1)):
                break
        return normalized

    @classmethod
    def _safe_request_headers(cls, request):
        request_obj = request
        if request_obj is None:
            return {}
        for attr_name in ("headers", "all_headers"):
            try:
                attr_value = getattr(request_obj, attr_name, None)
                value = attr_value() if callable(attr_value) else attr_value
            except Exception:
                value = None
            if isinstance(value, dict) and value:
                return cls._normalize_header_map(value)
        return {}

    @staticmethod
    def _extract_request_text(request, attr_name: str):
        try:
            attr_value = getattr(request, attr_name, None)
            value = attr_value() if callable(attr_value) else attr_value
        except Exception:
            value = None
        if value is None:
            return ""
        if isinstance(value, bytes):
            try:
                return value.decode("utf-8", "ignore")
            except Exception:
                return ""
        return str(value or "")

    @staticmethod
    def _build_template_object(payload_obj, depth=0):
        if depth >= 3:
            return "<value>"
        if isinstance(payload_obj, dict):
            result = {}
            for key, value in list(payload_obj.items())[:16]:
                key_text = str(key or "").strip()
                if not key_text:
                    continue
                result[key_text] = BrowserIntelScan._build_template_object(value, depth=depth + 1)
            return result
        if isinstance(payload_obj, list):
            if not payload_obj:
                return []
            return [BrowserIntelScan._build_template_object(payload_obj[0], depth=depth + 1)]
        return "<value>"

    @classmethod
    def _extract_multipart_field_names(cls, text: str):
        fields = []
        files = []
        seen = set()
        for match in re.finditer(r'name="([^"]{1,80})"', str(text or ""), flags=re.I):
            field_name = str(match.group(1) or "").strip()
            lowered = field_name.lower()
            if not field_name or lowered in seen:
                continue
            seen.add(lowered)
            fields.append(field_name)
        for match in re.finditer(r'filename="([^"]{1,160})"', str(text or ""), flags=re.I):
            file_name = str(match.group(1) or "").strip()
            if file_name:
                files.append(file_name)
        return fields[:12], files[:4]

    @classmethod
    def _analyze_runtime_request_payload(cls, headers, raw_post_data: str, raw_post_json):
        header_map = headers if isinstance(headers, dict) else {}
        content_type = str(header_map.get("Content-Type") or header_map.get("content-type") or "").strip().lower()
        body_text = str(raw_post_data or "").strip()
        json_data = {}
        form_data = {}
        param_names = []
        query_params = []
        mode = ""
        body_kind = ""
        contains_file = False
        body_template = ""

        def append_param(name_text):
            text = str(name_text or "").strip()
            if not text or text in param_names:
                return
            param_names.append(text)

        if isinstance(raw_post_json, dict):
            json_data = cls._build_template_object(raw_post_json)
            for key in list(json_data.keys())[:16]:
                append_param(key)
            mode = "json_data"
            body_kind = "graphql" if any(key in raw_post_json for key in ("query", "variables", "operationName")) else "json"
            body_template = json.dumps(json_data, ensure_ascii=False)
            if not content_type:
                content_type = "application/json"
        elif isinstance(raw_post_json, list):
            mode = "json_data"
            body_kind = "json"
            body_template = json.dumps(cls._build_template_object(raw_post_json), ensure_ascii=False)
            if not content_type:
                content_type = "application/json"

        if body_text and not mode:
            if "multipart/form-data" in content_type:
                field_names, file_names = cls._extract_multipart_field_names(body_text)
                for field_name in field_names:
                    append_param(field_name)
                    form_data[field_name] = "<value>"
                contains_file = bool(file_names)
                mode = "form_data"
                body_kind = "multipart"
                if contains_file:
                    for file_field in file_names[:1]:
                        form_data["file"] = "@{}".format(file_field)
                body_template = "\n".join(
                    ["{}={}".format(name, form_data.get(name, "<value>")) for name in field_names[:12]]
                )
            elif "application/x-www-form-urlencoded" in content_type:
                mode = "form_data"
                body_kind = "form_urlencoded"
                for key_text, _ in parse_qsl(body_text, keep_blank_values=True):
                    key_name = str(key_text or "").strip()
                    if not key_name:
                        continue
                    append_param(key_name)
                    form_data[key_name] = "<value>"
                body_template = urlencode([(key, "<value>") for key in list(form_data.keys())[:16]], doseq=True)
            else:
                looks_like_json = body_text[:1] in "{[" or "json" in content_type
                if looks_like_json:
                    try:
                        parsed_obj = json.loads(body_text)
                    except Exception:
                        parsed_obj = None
                    if isinstance(parsed_obj, (dict, list)):
                        json_data = cls._build_template_object(parsed_obj)
                        if isinstance(json_data, dict):
                            for key in list(json_data.keys())[:16]:
                                append_param(key)
                        mode = "json_data"
                        body_kind = "graphql" if isinstance(parsed_obj, dict) and any(key in parsed_obj for key in ("query", "variables", "operationName")) else "json"
                        body_template = json.dumps(json_data, ensure_ascii=False)
                        if not content_type:
                            content_type = "application/json"
                if not mode and "=" in body_text and "&" in body_text:
                    mode = "form_data"
                    body_kind = "form_urlencoded"
                    for key_text, _ in parse_qsl(body_text, keep_blank_values=True):
                        key_name = str(key_text or "").strip()
                        if not key_name:
                            continue
                        append_param(key_name)
                        form_data[key_name] = "<value>"
                    body_template = urlencode([(key, "<value>") for key in list(form_data.keys())[:16]], doseq=True)
                if not mode:
                    mode = "body"
                    if "xml" in content_type or body_text.startswith("<"):
                        body_kind = "xml"
                    elif content_type.startswith("text/"):
                        body_kind = "text"
                    else:
                        body_kind = "unknown"
                    if body_kind == "xml":
                        root_match = re.search(r"<([A-Za-z_][\\w:.-]{0,63})", body_text)
                        root_name = str(root_match.group(1) or "root").strip() if root_match else "root"
                        append_param(root_name)
                        body_template = f"<{root_name}>...</{root_name}>"
                    else:
                        body_template = cls._clip_text(body_text, 220)

        if not mode:
            mode = "query"
            body_kind = ""

        request_body_text = body_template or cls._clip_text(body_text, 600)
        return {
            "content_type": content_type[:120],
            "mode": mode[:32],
            "body_kind": body_kind[:32],
            "param_names": param_names[:16],
            "query_params": query_params[:16],
            "json_data": json_data if isinstance(json_data, dict) else {},
            "form_data": form_data if isinstance(form_data, dict) else {},
            "request_body": request_body_text[:800],
            "request_body_template": request_body_text[:800],
            "contains_file": "true" if contains_file else "false",
        }

    @classmethod
    def _normalize_runtime_api_calls(cls, items, max_items=12):
        results = []
        seen = set()
        for item in items or []:
            if not isinstance(item, dict):
                continue
            method_text = cls._clip_text(item.get("method", "GET"), 16).upper() or "GET"
            url_text = cls._clip_text(item.get("url", ""), 240)
            if not url_text:
                continue
            status_text = cls._clip_text(item.get("status", ""), 24)
            mode_text = cls._clip_text(item.get("mode", ""), 32)
            content_type_text = cls._clip_text(item.get("content_type", ""), 120)
            param_names = [str(name or "").strip() for name in list(item.get("param_names", []) or []) if str(name or "").strip()][:16]
            request_headers = cls._normalize_header_map(item.get("request_headers"), max_items=16)
            normalized = {
                "method": method_text,
                "url": url_text,
                "status": status_text,
                "mode": mode_text,
                "content_type": content_type_text,
                "body_kind": cls._clip_text(item.get("body_kind", ""), 32),
                "param_names": param_names,
                "query_params": [str(name or "").strip() for name in list(item.get("query_params", []) or []) if str(name or "").strip()][:16],
                "request_headers": request_headers,
                "request_body": cls._clip_text(item.get("request_body", ""), 800),
                "request_body_template": cls._clip_text(item.get("request_body_template", ""), 800),
                "contains_file": str(item.get("contains_file") or "").strip().lower() in {"true", "1", "yes"},
            }
            json_data = item.get("json_data") if isinstance(item.get("json_data"), dict) else {}
            form_data = item.get("form_data") if isinstance(item.get("form_data"), dict) else {}
            if json_data:
                normalized["json_data"] = json_data
            if form_data:
                normalized["form_data"] = form_data
            cache_key = json.dumps(normalized, ensure_ascii=False, sort_keys=True)
            if cache_key in seen:
                continue
            seen.add(cache_key)
            results.append(normalized)
            if len(results) >= max_items:
                break
        return results

    @classmethod
    def _normalize_form_summaries(cls, items, max_items=8):
        results = []
        seen = set()
        for item in items or []:
            if not isinstance(item, dict):
                continue
            normalized = {
                "action": cls._clip_text(item.get("action", ""), 240),
                "method": cls._clip_text(item.get("method", "GET"), 16).upper() or "GET",
                "enctype": cls._clip_text(item.get("enctype", ""), 120),
                "has_file_input": str(item.get("has_file_input") or "").strip().lower() in {"true", "1", "yes"},
                "has_password_input": str(item.get("has_password_input") or "").strip().lower() in {"true", "1", "yes"},
                "password_fields": cls._clip_text(item.get("password_fields", ""), 180),
                "has_captcha_hint": str(item.get("has_captcha_hint") or "").strip().lower() in {"true", "1", "yes"},
                "submit_text": cls._clip_text(item.get("submit_text", ""), 120),
                "fields": cls._clip_text(item.get("fields", ""), 220),
                "hidden_fields": {},
            }
            hidden_obj = item.get("hidden_fields") if isinstance(item.get("hidden_fields"), dict) else {}
            if hidden_obj:
                normalized["hidden_fields"] = {
                    str(key or "").strip(): cls._clip_text(value, 60)
                    for key, value in list(hidden_obj.items())[:12]
                    if str(key or "").strip()
                }
            cache_key = json.dumps(normalized, ensure_ascii=False, sort_keys=True)
            if cache_key in seen:
                continue
            seen.add(cache_key)
            results.append(normalized)
            if len(results) >= max_items:
                break
        return results

    @staticmethod
    def _collect_form_summary(page):
        return page.evaluate(
            """
            () => Array.from(document.querySelectorAll('form')).slice(0, 8).map((form) => {
              const action = form.getAttribute('action') || location.href;
              const method = (form.getAttribute('method') || 'GET').toUpperCase();
              const enctype = (form.getAttribute('enctype') || '').trim();
              const hasFileInput = form.querySelector('input[type="file"]') ? 'true' : 'false';
              const passwordInputs = Array.from(form.querySelectorAll('input[type="password"][name], input[type="password"]'))
                .map((el) => (el.getAttribute('name') || '').trim()).filter(Boolean).slice(0, 6);
              const fieldNameList = Array.from(
                form.querySelectorAll('input[name], textarea[name], select[name]')
              ).map((el) => (el.getAttribute('name') || '').trim()).filter(Boolean).slice(0, 12);
              const lowerFields = fieldNameList.map((item) => item.toLowerCase());
              const hasCaptchaHint = lowerFields.some((item) =>
                ['captcha', 'verifycode', 'verification', 'checkcode', 'validatecode', 'randcode', 'yzm'].some((keyword) => item.includes(keyword))
              ) ? 'true' : 'false';
              const submitText = Array.from(form.querySelectorAll('button, input[type="submit"]')).map((el) => {
                return ((el.textContent || el.getAttribute('value') || '') + '').trim();
              }).filter(Boolean).slice(0, 2).join(' | ');
              const fields = Array.from(
                form.querySelectorAll('input[name], textarea[name], select[name]')
              ).map((el) => (el.getAttribute('name') || '').trim()).filter(Boolean).slice(0, 12);
              const hiddenFields = {};
              Array.from(form.querySelectorAll('input[type="hidden"][name]')).slice(0, 12).forEach((el) => {
                const key = (el.getAttribute('name') || '').trim();
                if (key) hiddenFields[key] = '<hidden>';
              });
              return {
                action,
                method,
                enctype,
                has_file_input: hasFileInput,
                has_password_input: passwordInputs.length > 0 ? 'true' : 'false',
                password_fields: passwordInputs.join(','),
                has_captcha_hint: hasCaptchaHint,
                submit_text: submitText,
                fields: fields.join(','),
                hidden_fields: hiddenFields,
              };
            })
            """
        )

    @staticmethod
    def _collect_script_summary(page):
        return page.evaluate(
            """
            () => Array.from(document.querySelectorAll('script[src]')).slice(0, 16).map((el) => {
              const src = el.getAttribute('src') || '';
              return { src };
            })
            """
        )

    def _collect_site(self, site: str):
        chromium_bin = utils.resolve_executable(getattr(Config, "PLAYWRIGHT_CHROMIUM_BIN", ""))
        launch_kwargs = {
            "headless": True,
            "args": [
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
            ],
        }
        if chromium_bin:
            launch_kwargs["executable_path"] = chromium_bin

        from playwright.sync_api import sync_playwright

        runtime_api_calls = []
        browser_surface_summary = {}
        dom_form_summary = []
        browser = None
        context = None
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(**launch_kwargs)
                context = browser.new_context(
                    viewport={"width": 1280, "height": 960},
                    ignore_https_errors=True,
                    user_agent=(
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/124.0.0.0 Safari/537.36"
                    ),
                )
                page = context.new_page()

                def handle_response(resp):
                    try:
                        req = resp.request
                        resource_type = str(req.resource_type or "").strip().lower()
                        if resource_type not in {"xhr", "fetch"}:
                            return
                        request_headers = self._safe_request_headers(req)
                        raw_post_data = self._extract_request_text(req, "post_data")
                        raw_post_json = None
                        try:
                            post_json_value = getattr(req, "post_data_json", None)
                            raw_post_json = post_json_value() if callable(post_json_value) else post_json_value
                        except Exception:
                            raw_post_json = None
                        payload_summary = self._analyze_runtime_request_payload(
                            request_headers,
                            raw_post_data,
                            raw_post_json,
                        )
                        runtime_api_calls.append(
                            {
                                "method": str(req.method or "").strip().upper(),
                                "url": str(resp.url or "").strip(),
                                "status": str(resp.status or "").strip(),
                                "request_headers": request_headers,
                                "content_type": str(payload_summary.get("content_type") or ""),
                                "mode": str(payload_summary.get("mode") or ""),
                                "body_kind": str(payload_summary.get("body_kind") or ""),
                                "param_names": list(payload_summary.get("param_names", []) or []),
                                "query_params": list(payload_summary.get("query_params", []) or []),
                                "json_data": dict(payload_summary.get("json_data") or {}) if isinstance(payload_summary.get("json_data"), dict) else {},
                                "form_data": dict(payload_summary.get("form_data") or {}) if isinstance(payload_summary.get("form_data"), dict) else {},
                                "request_body": str(payload_summary.get("request_body") or ""),
                                "request_body_template": str(payload_summary.get("request_body_template") or ""),
                                "contains_file": str(payload_summary.get("contains_file") or ""),
                            }
                        )
                    except Exception:
                        return

                page.on("response", handle_response)
                page.goto(site, wait_until="domcontentloaded", timeout=self.timeout_ms)
                if self.wait_ms > 0:
                    page.wait_for_timeout(self.wait_ms)

                dom_form_summary = self._normalize_records(self._collect_form_summary(page), max_items=8)
                script_items = self._normalize_records(self._collect_script_summary(page), max_items=16)
                browser_surface_summary = {
                    "source_role": "runtime_enrichment",
                    "interaction_level": "passive",
                    "capture_scope": "scripts_forms_runtime_api",
                    "page_title": str(page.title() or "").strip()[:160],
                    "page_url": str(page.url or "").strip()[:240],
                    "form_count": len(dom_form_summary),
                    "script_count": len(script_items),
                    "scripts": script_items[:8],
                    "runtime_api_count": len(runtime_api_calls),
                }
        finally:
            try:
                if context:
                    context.close()
            except Exception:
                pass
            try:
                if browser:
                    browser.close()
            except Exception:
                pass

        return {
            "browser_surface_summary": browser_surface_summary,
            "runtime_api_calls": self._normalize_runtime_api_calls(runtime_api_calls, max_items=16),
            "dom_form_summary": self._normalize_form_summaries(dom_form_summary, max_items=8),
        }

    def work(self, site):
        site_text = str(site or "").strip()
        if not site_text:
            return
        self.result_map[site_text] = self._collect_site(site_text)

    def run(self):
        if not bool(getattr(Config, "BROWSER_INTEL_ENABLE", False)):
            logger.info("browser intel scan skip, disabled")
            return {}

        logger.info("start browser intel scan {}".format(len(self.targets)))
        self._run()
        logger.info("end browser intel scan results:{}".format(len(self.result_map)))
        return self.result_map


def run_browser_intel_scan(sites: List[str], concurrency=None):
    worker = BrowserIntelScan(
        sites=sites,
        concurrency=max(1, int(concurrency or getattr(Config, "BROWSER_INTEL_CONCURRENCY", 2) or 2)),
    )
    return worker.run()
