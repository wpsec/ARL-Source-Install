"""页面语义证据采集。

功能说明：
- 从页面状态码/标题/正文摘要派生保守的语义标签与响应摘要，供
  site / url / fileleak 文档携带"证据优先去噪"所需的最小上下文
  （WIH 提速与调度优化实施计划 §5.5 第 5 点的采集侧闭环）。
- 纯函数、无 IO：调用方决定落库位置；本模块只新增字段，绝不覆盖既有字段。

设计边界：
- 标签只做"弱证据"标注（如 auth_wall 表示响应更像登录壳），
  是否降级由 AI 去噪链判断，这里不做价值结论。
- 摘要截断长度与标签数量硬上限，避免文档膨胀。
"""

import re

BODY_EXCERPT_LIMIT = 600
SEMANTIC_TAGS_MAX = 8

_AUTH_HINT_RE = re.compile(
    r"(登录|登陆|统一认证|单点登录|\boauth\b|\bsso\b|\bcas\b|sign[\s\-]?in|log[\s\-]?in|password)",
    re.I,
)
_ERROR_HINT_RE = re.compile(
    r"(whitelabel|internal server error|bad gateway|service unavailable|\bexception\b|栈调用|地址异常|页面不存在)",
    re.I,
)
_PLACEHOLDER_HINT_RE = re.compile(
    r"(welcome to nginx|apache2 ubuntu default|it works|welcome page|默认站点|欢迎页|coming soon)",
    re.I,
)
_TAG_STRIP_RE = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.S | re.I)
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")

_STATIC_CONTENT_TYPES = (
    "image/", "text/css", "application/javascript", "text/javascript",
    "font/", "application/font", "video/", "audio/",
)


def extract_body_excerpt(body, limit=BODY_EXCERPT_LIMIT) -> str:
    """把页面正文压缩成短文本证据；二进制/异常输入返回空串而不是抛错。"""

    if body is None:
        return ""
    if isinstance(body, (bytes, bytearray)):
        # 含 NUL 视为二进制，直接放弃摘要，避免乱码污染 AI 上下文。
        if b"\x00" in bytes(body[:2048]):
            return ""
        try:
            text = bytes(body).decode("utf-8", "ignore")
        except Exception:
            return ""
    else:
        text = str(body)
    if not text.strip():
        return ""

    text = _TAG_STRIP_RE.sub(" ", text)
    text = _HTML_TAG_RE.sub(" ", text)
    text = _WS_RE.sub(" ", text).strip()
    if len(text) > limit:
        text = text[:limit]
    return text


def build_semantic_tags(status_code=0, title="", content_type="", excerpt="") -> list:
    """从弱信号派生语义标签，只描述"响应形态"，不下价值结论。"""

    tags = []

    def _add(tag):
        if tag not in tags and len(tags) < SEMANTIC_TAGS_MAX:
            tags.append(tag)

    try:
        status = int(status_code or 0)
    except (TypeError, ValueError):
        status = 0
    content_type_text = str(content_type or "").lower()
    text_blob = "{} {}".format(str(title or ""), str(excerpt or ""))

    if status in (401, 403):
        _add("auth_wall")
    elif status == 404:
        _add("not_found")
    elif status >= 500:
        _add("server_error")

    if _AUTH_HINT_RE.search(text_blob):
        _add("login_page")
    if _ERROR_HINT_RE.search(text_blob):
        _add("error_page")
    if _PLACEHOLDER_HINT_RE.search(text_blob):
        _add("placeholder_page")

    if any(token in content_type_text for token in _STATIC_CONTENT_TYPES):
        _add("static_asset")
    elif "json" in content_type_text and str(excerpt or "").strip()[:1] in ("{", "["):
        _add("api_json")

    body_length = len(str(excerpt or "").strip())
    if status == 200 and body_length == 0:
        _add("empty_body")

    return tags


def _header_value(headers, name):
    if not isinstance(headers, dict):
        return ""
    target = str(name).lower()
    for key, value in headers.items():
        if str(key).lower() == target:
            return str(value or "")
    return ""


def enrich_page_item(item, body=None, headers=None) -> dict:
    """为页面类文档补充 body_excerpt / semantic_tags；已有字段一律不动。"""

    if not isinstance(item, dict):
        return item

    excerpt = item.get("body_excerpt")
    if not isinstance(excerpt, str):
        excerpt = extract_body_excerpt(body)
        if excerpt:
            item["body_excerpt"] = excerpt

    if not isinstance(item.get("semantic_tags"), list):
        tags = build_semantic_tags(
            status_code=item.get("status_code") or item.get("status"),
            title=item.get("title"),
            content_type=_header_value(headers, "Content-Type"),
            excerpt=excerpt,
        )
        if tags:
            item["semantic_tags"] = tags

    return item
