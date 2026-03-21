"""
渗透测试请求策略层。

功能说明：
- 按 host 维护自适应请求延迟
- 轮换真实浏览器画像，降低“工具默认头”特征
- 为渗透测试链路统一补齐浏览器风格 Header
"""
from urllib.parse import urlparse


class PenetrationRequestPolicy(object):
    """
    轻量请求策略控制器。

    设计原则：
    - 只服务 `penetration_test` 主动链路
    - 优先降低噪声与被拦截概率，不追求激进对抗
    - 不依赖外部状态，按 host 本地自适应调节
    """

    BROWSER_PROFILES = (
        {
            "name": "chrome_windows",
            "user_agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/122.0.0.0 Safari/537.36"
            ),
            "accept_language": "zh-CN,zh;q=0.9,en;q=0.8",
            "accept_encoding": "gzip, deflate",
            "sec_ch_ua": '"Chromium";v="122", "Google Chrome";v="122", "Not:A-Brand";v="99"',
            "sec_ch_mobile": "?0",
            "sec_ch_platform": '"Windows"',
        },
        {
            "name": "chrome_macos",
            "user_agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/122.0.0.0 Safari/537.36"
            ),
            "accept_language": "zh-CN,zh;q=0.9,en;q=0.8",
            "accept_encoding": "gzip, deflate",
            "sec_ch_ua": '"Chromium";v="122", "Google Chrome";v="122", "Not:A-Brand";v="99"',
            "sec_ch_mobile": "?0",
            "sec_ch_platform": '"macOS"',
        },
        {
            "name": "firefox_windows",
            "user_agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) "
                "Gecko/20100101 Firefox/123.0"
            ),
            "accept_language": "zh-CN,zh;q=0.9,en;q=0.8",
            "accept_encoding": "gzip, deflate",
            "sec_ch_ua": "",
            "sec_ch_mobile": "",
            "sec_ch_platform": "",
        },
        {
            "name": "safari_macos",
            "user_agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/605.1.15 (KHTML, like Gecko) "
                "Version/17.3 Safari/605.1.15"
            ),
            "accept_language": "zh-CN,zh;q=0.9,en;q=0.8",
            "accept_encoding": "gzip, deflate",
            "sec_ch_ua": "",
            "sec_ch_mobile": "",
            "sec_ch_platform": "",
        },
    )
    BLOCK_STATUS_SET = {403, 406, 429, 444, 503}

    def __init__(self):
        self.host_state = {}

    @staticmethod
    def _extract_host(url: str) -> str:
        parsed = urlparse(str(url or "").strip())
        return str(parsed.hostname or "").strip().lower().rstrip(".")

    def _get_state(self, host: str) -> dict:
        state = self.host_state.get(host)
        if state is None:
            state = {
                "request_count": 0,
                "delay": 0.0,
                "success_count": 0,
                "block_count": 0,
                "error_count": 0,
                "avg_response_time": 0.0,
            }
            self.host_state[host] = state
        return state

    @staticmethod
    def _build_origin(url: str) -> str:
        parsed = urlparse(str(url or "").strip())
        if not parsed.scheme or not parsed.netloc:
            return ""
        return "{}://{}".format(parsed.scheme, parsed.netloc)

    @staticmethod
    def _merge_headers(base_headers: dict, overlay: dict) -> dict:
        headers = dict(base_headers or {})
        for key, value in (overlay or {}).items():
            if value:
                headers[key] = value
        return headers

    def prepare(self, url: str, method: str = "GET", headers=None):
        """
        构造浏览器风格请求头，并返回建议延迟。
        """
        method_name = str(method or "GET").strip().upper() or "GET"
        host = self._extract_host(url)
        state = self._get_state(host)
        profile = self.BROWSER_PROFILES[state["request_count"] % len(self.BROWSER_PROFILES)]
        origin = self._build_origin(url)

        base_headers = {
            "User-Agent": profile["user_agent"],
            "Accept-Language": profile["accept_language"],
            "Accept-Encoding": profile["accept_encoding"],
            "Pragma": "no-cache",
            "Cache-Control": "no-cache",
            "DNT": "1",
            "Upgrade-Insecure-Requests": "1" if method_name == "GET" else "",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "navigate" if method_name == "GET" else "cors",
            "Sec-Fetch-Dest": "document" if method_name == "GET" else "empty",
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
                if method_name == "GET"
                else "application/json, text/plain, */*"
            ),
            "Referer": origin + "/" if origin else "",
            "Origin": origin if origin and method_name != "GET" else "",
        }

        if profile["sec_ch_ua"]:
            base_headers["Sec-CH-UA"] = profile["sec_ch_ua"]
            base_headers["Sec-CH-UA-Mobile"] = profile["sec_ch_mobile"]
            base_headers["Sec-CH-UA-Platform"] = profile["sec_ch_platform"]

        merged = self._merge_headers(base_headers, headers or {})
        return merged, float(state.get("delay", 0.0) or 0.0), profile["name"]

    def observe(self, url: str, status_code: int, elapsed: float = 0.0):
        """
        根据响应表现动态调节延迟。
        """
        host = self._extract_host(url)
        state = self._get_state(host)
        state["request_count"] += 1

        elapsed = max(0.0, float(elapsed or 0.0))
        if elapsed > 0:
            history = float(state.get("avg_response_time", 0.0) or 0.0)
            if history <= 0:
                state["avg_response_time"] = elapsed
            else:
                state["avg_response_time"] = round(history * 0.7 + elapsed * 0.3, 4)

        status = int(status_code or 0)
        delay = float(state.get("delay", 0.0) or 0.0)

        if status in self.BLOCK_STATUS_SET:
            state["block_count"] += 1
            delay = min(3.0, max(delay + 0.35, 0.35))
        elif status >= 500:
            state["error_count"] += 1
            delay = min(2.0, max(delay + 0.2, 0.2))
        elif 200 <= status < 400:
            state["success_count"] += 1
            if elapsed > 2.5:
                delay = min(2.0, max(delay, min(1.2, elapsed / 3.0)))
            else:
                delay = max(0.0, delay - 0.05)
        else:
            delay = min(1.5, max(delay + 0.05, 0.0))

        state["delay"] = round(delay, 3)

    def observe_error(self, url: str, elapsed: float = 0.0):
        """
        网络异常时，适度提升延迟，避免连续冲击目标。
        """
        host = self._extract_host(url)
        state = self._get_state(host)
        state["request_count"] += 1
        state["error_count"] += 1
        state["delay"] = round(min(2.5, max(float(state.get("delay", 0.0) or 0.0) + 0.2, 0.2)), 3)

        elapsed = max(0.0, float(elapsed or 0.0))
        if elapsed > 0 and float(state.get("avg_response_time", 0.0) or 0.0) <= 0:
            state["avg_response_time"] = elapsed
