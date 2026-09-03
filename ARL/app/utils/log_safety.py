"""日志文本脱敏工具。

异常对象有时会把带查询参数的请求 URL 拼进消息；统一在写入日志或任务指标前清理，
避免网络失败时把 provider 凭据或认证信息带出进程日志。
"""
import re


_QUERY_SECRET_PATTERN = re.compile(
    r"([?&](?:key|api[_-]?key|apikey|token|access[_-]?token|authorization|"
    r"password|passwd|secret|email|user(?:name)?|x-[a-z0-9_-]*token)=[^&#\s]+)",
    re.IGNORECASE,
)
_HEADER_SECRET_PATTERN = re.compile(
    r"((?:authorization|cookie|set-cookie|x-api-key|x-auth-token|"
    r"x-[a-z0-9_-]*token)\s*[:=]\s*)[^,;\s]+",
    re.IGNORECASE,
)
_USERINFO_SECRET_PATTERN = re.compile(
    r"(https?://[^/\s:@]+:)[^@\s]+(@)",
    re.IGNORECASE,
)


def _redact_query_value(fragment):
    separator = fragment.split("=", 1)[0]
    return separator + "=[REDACTED]"


def sanitize_log_text(value, max_length=1200):
    """清理异常、URL 和 header 中可能出现的凭据，并限制日志长度。"""
    text = str(value or "")
    text = _QUERY_SECRET_PATTERN.sub(lambda match: _redact_query_value(match.group(1)), text)
    text = _HEADER_SECRET_PATTERN.sub(r"\1[REDACTED]", text)
    text = _USERINFO_SECRET_PATTERN.sub(r"\1[REDACTED]\2", text)
    if max_length and len(text) > max_length:
        return text[:max_length] + "..."
    return text


def safe_error_text(error, max_length=1200):
    """返回适合日志和阶段 detail 使用的脱敏异常文本。"""
    return sanitize_log_text(error, max_length=max_length)
