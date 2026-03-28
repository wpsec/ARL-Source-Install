"""
浏览器情报采集服务。

能力说明：
- 基于 Playwright 对高价值页面做低侵入浏览器采集
- 采集运行时加载的脚本、XHR/fetch 请求与表单结构
- 不做复杂点击流，不做自动绕过，只补浏览器视角下的结构化情报
"""
import json
from typing import Dict, List

from app import utils
from app.config import Config
from .baseThread import BaseThread

logger = utils.get_logger()


class BrowserIntelScan(BaseThread):
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
    def _collect_form_summary(page):
        return page.evaluate(
            """
            () => Array.from(document.querySelectorAll('form')).slice(0, 8).map((form) => {
              const action = form.getAttribute('action') || location.href;
              const method = (form.getAttribute('method') || 'GET').toUpperCase();
              const fields = Array.from(
                form.querySelectorAll('input[name], textarea[name], select[name]')
              ).map((el) => (el.getAttribute('name') || '').trim()).filter(Boolean).slice(0, 12);
              return { action, method, fields: fields.join(',') };
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
                        runtime_api_calls.append(
                            {
                                "method": str(req.method or "").strip().upper(),
                                "url": str(resp.url or "").strip(),
                                "status": str(resp.status or "").strip(),
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
            "runtime_api_calls": self._normalize_records(runtime_api_calls, max_items=16),
            "dom_form_summary": dom_form_summary,
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
