"""
网站截图获取
"""
import os
import re
import time
import subprocess
import requests
from app import utils
from app.config import Config
from .baseThread import BaseThread
logger = utils.get_logger()


class SiteScreenshot(BaseThread):
    """
    站点截图执行器

    功能：
    1. 优先调用 Playwright 生成站点截图（支持 x86_64/aarch64）
    2. 当 Playwright 不可用时回退 PhantomJS（legacy 兼容）
    2. 在启用配置时，回传截图到 web 内部接口，解决 K8s 多 Pod 本地盘不共享问题
    """

    def __init__(self, sites, concurrency=3, capture_dir="./", task_id=""):
        super().__init__(sites, concurrency=concurrency)
        self.capture_dir = capture_dir
        self.task_id = task_id
        self.screenshot_map = {}
        self.screenshot_engine = str(Config.SCREENSHOT_ENGINE or "playwright").strip().lower()
        if self.screenshot_engine not in ["playwright", "phantomjs", "auto"]:
            self.screenshot_engine = "playwright"
        self.phantomjs_bin = None
        self.sync_upload_url = ""
        self.sync_auth_token = ""
        self.sync_enable = False
        self.sync_timeout = Config.SCREENSHOT_SYNC_TIMEOUT
        self.playwright_disabled = False

        os.makedirs(self.capture_dir, 0o777, True)
        self.init_screenshot_sync()

    def init_screenshot_sync(self):
        """
        初始化截图回传配置（默认开启，缺省配置时自动降级）
        """
        if not Config.SCREENSHOT_SYNC_ENABLE:
            return

        if not self.task_id:
            logger.warning("screenshot sync enabled but task_id is empty")
            return

        web_url = str(Config.SCREENSHOT_SYNC_WEB_URL or "").strip()
        if not web_url:
            # 非 K8s/共享目录场景可不配置回传地址，直接降级为本地读图模式
            logger.info("screenshot sync enabled but web_url is empty, fallback local mode")
            return

        self.sync_upload_url = web_url.rstrip("/") + "/api/image/internal/upload"
        if Config.AUTH:
            api_token = str(Config.API_KEY or "").strip()
            if not api_token:
                logger.warning("screenshot sync requires ARL.API_KEY when ARL.AUTH=true")
                return
            self.sync_auth_token = api_token

        if self.sync_timeout <= 0:
            self.sync_timeout = 10

        self.sync_enable = True
        logger.info("screenshot sync enabled upload_url={}".format(self.sync_upload_url))

    def get_phantomjs_bin(self):
        if self.phantomjs_bin is None:
            self.phantomjs_bin = utils.get_phantomjs_bin(logger=logger)
        return self.phantomjs_bin

    def disable_playwright_once(self, reason):
        """
        仅在当前任务运行周期内禁用 Playwright，避免每个站点重复报错刷屏。
        """
        if self.playwright_disabled:
            return
        self.playwright_disabled = True
        logger.warning("playwright disabled for current task, fallback phantomjs reason={}".format(reason))

    def upload_screenshot(self, site, file_path):
        """
        worker 将截图回传到 web 内部接口。
        失败时仅记录日志，不影响主扫描流程。
        """
        if not self.sync_enable:
            return True

        if not os.path.exists(file_path):
            return False

        file_size = os.path.getsize(file_path)
        if file_size <= 0:
            logger.warning("screenshot sync skip empty file {}".format(file_path))
            return False

        if file_size > Config.SCREENSHOT_SYNC_MAX_SIZE:
            logger.warning(
                "screenshot sync skip oversize site={} size={} max={}".format(
                    site, file_size, Config.SCREENSHOT_SYNC_MAX_SIZE
                )
            )
            return False

        file_name = os.path.basename(file_path)
        headers = {}
        if self.sync_auth_token:
            # 复用系统原生鉴权头，保持接口行为一致
            headers["Token"] = self.sync_auth_token
        data = {
            "task_id": self.task_id,
            "file_name": file_name
        }

        try:
            with open(file_path, "rb") as f:
                files = {
                    "file": (file_name, f, "image/jpeg")
                }
                with requests.Session() as session:
                    # 内部服务调用不读取环境代理，避免被外部代理劫持或误转发
                    session.trust_env = False
                    response = session.post(
                        self.sync_upload_url,
                        headers=headers,
                        data=data,
                        files=files,
                        timeout=(5, self.sync_timeout),
                        verify=False,
                        allow_redirects=False
                    )

            if response.status_code >= 300:
                logger.warning(
                    "screenshot sync failed site={} status={} body={}".format(
                        site, response.status_code, response.text[:500]
                    )
                )
                return False

            response_code = None
            response_message = ""
            try:
                response_json = response.json()
                response_code = response_json.get("code")
                response_message = str(response_json.get("message", ""))
            except Exception:
                response_message = response.text[:500]

            if response_code not in [None, 200]:
                logger.warning(
                    "screenshot sync business failed site={} code={} message={}".format(
                        site, response_code, response_message[:500]
                    )
                )
                return False

            logger.debug("screenshot sync success site={} file={}".format(site, file_name))
            return True
        except Exception as e:
            logger.warning("screenshot sync error site={} {}".format(site, e))
            return False

    def screenshot_by_playwright(self, site, file_name):
        if self.playwright_disabled:
            return False

        timeout_ms = max(1000, int(Config.PLAYWRIGHT_TIMEOUT_MS))
        wait_ms = max(0, int(Config.PLAYWRIGHT_WAIT_MS))
        chromium_bin = utils.resolve_executable(Config.PLAYWRIGHT_CHROMIUM_BIN)
        launch_kwargs = {
            "headless": True,
            "args": [
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
            ]
        }
        if chromium_bin:
            launch_kwargs["executable_path"] = chromium_bin

        browser = None
        context = None
        try:
            from playwright.sync_api import sync_playwright
        except Exception as e:
            self.disable_playwright_once("import_failed:{}".format(str(e)[:300]))
            return False

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(**launch_kwargs)
                context = browser.new_context(
                    viewport={"width": 1280, "height": 1024},
                    ignore_https_errors=True,
                    user_agent=(
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/124.0.0.0 Safari/537.36"
                    )
                )
                page = context.new_page()
                try:
                    page.goto(site, wait_until="domcontentloaded", timeout=timeout_ms)
                except Exception as e:
                    # 即使导航超时也尝试截图，尽量保留可视化证据
                    logger.debug("playwright goto timeout site={} err={}".format(site, e))

                if wait_ms > 0:
                    page.wait_for_timeout(wait_ms)
                page.screenshot(path=file_name, type="jpeg", quality=95, full_page=False)
            return os.path.exists(file_name)
        except Exception as e:
            err_text = str(e)
            if ("Executable doesn't exist" in err_text) or ("playwright install" in err_text):
                self.disable_playwright_once("browser_missing")
                logger.warning(
                    "playwright chromium not found site={} err={} fallback phantomjs".format(site, err_text[:300])
                )
            else:
                logger.warning("playwright screenshot failed site={} err={}".format(site, err_text[:500]))
            return False
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

    def screenshot_by_phantomjs(self, site, file_name):
        phantomjs_bin = self.get_phantomjs_bin()
        if not phantomjs_bin:
            return False

        cmd_parameters = [phantomjs_bin,
                          '--ignore-ssl-errors true',
                          '--ssl-protocol any',
                          '--ssl-ciphers ALL',
                          Config.SCREENSHOT_JS,
                          '-u={}'.format(site),
                          '-s={}'.format(file_name),
                          ]
        logger.debug("screenshot fallback {}".format(" ".join(cmd_parameters)))

        try:
            completed = utils.exec_system(
                cmd_parameters,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
        except OSError as e:
            logger.warning("phantomjs screenshot run error {} {}".format(site, e))
            return False

        if completed.returncode != 0:
            stderr_text = ""
            stdout_text = ""
            if completed.stderr:
                stderr_text = completed.stderr.decode("utf-8", errors="ignore").strip()
            if completed.stdout:
                stdout_text = completed.stdout.decode("utf-8", errors="ignore").strip()
            logger.warning(
                "phantomjs screenshot failed {} rc={} stderr={} stdout={}".format(
                    site, completed.returncode, stderr_text[:500], stdout_text[:500]
                )
            )
            return False

        return os.path.exists(file_name)

    def work(self, site):
        file_name = '{}/{}.jpg'.format(self.capture_dir, self.gen_filename(site))
        capture_ok = False

        if self.screenshot_engine in ["playwright", "auto"]:
            capture_ok = self.screenshot_by_playwright(site, file_name)

        if (not capture_ok) and self.screenshot_engine in ["phantomjs", "auto", "playwright"]:
            # playwright 失败时自动回退到 phantomjs，避免中断旧环境
            capture_ok = self.screenshot_by_phantomjs(site, file_name)

        if not capture_ok:
            logger.warning("screenshot failed all engines site={}".format(site))
            return

        if not os.path.exists(file_name):
            logger.warning("screenshot file not created {} {}".format(site, file_name))
            return

        sync_ok = self.upload_screenshot(site, file_name)
        if self.sync_enable and not sync_ok:
            logger.warning("screenshot upload not confirmed site={} file={}".format(site, file_name))

        self.screenshot_map[site] = file_name

    def gen_filename(self, site):
        filename = site.replace('://', '_')

        return re.sub('[^\w\-_\. ]', '_', filename)

    def run(self):
        t1 = time.time()
        logger.info("start screen shot {}".format(len(self.targets)))
        self._run()
        elapse = time.time() - t1
        logger.info("end screen shot elapse {}".format(elapse))


def site_screenshot(sites, concurrency=3, capture_dir="./", task_id=""):
    s = SiteScreenshot(sites, concurrency=concurrency, capture_dir=capture_dir, task_id=task_id)
    s.run()
