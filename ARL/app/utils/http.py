"""
HTTP请求和连接工具
"""
import re


def get_title(body):
    """
    根据页面源码返回标题
    :param body: <title>sss</title>
    :return: sss
    """
    result = ''
    title_patten = re.compile(rb'<title>([^<]{1,200})</title>', re.I)
    title = title_patten.findall(body)
    if len(title) > 0:
        try:
            result = title[0].decode("utf-8")
        except Exception as e:
            result = title[0].decode("gbk", errors="replace")
    return result.strip()


def get_headers(conn):
    # version 字段目前只能是10或者11

    version = str(getattr(conn, "_arl_http_version", "") or "1.1")
    status = getattr(conn, "_arl_status", getattr(conn, "status_code", 0))
    reason = getattr(conn, "_arl_reason", getattr(conn, "reason", ""))
    first_line = "HTTP/{} {} {}\n".format(version, status, reason)

    headers = str(getattr(conn, "_arl_raw_headers", "") or "").strip()
    if not headers:
        headers = "\n".join(["{}: {}".format(k, v) for k, v in (conn.headers or {}).items()])

    if not conn.headers.get("Content-Length"):
        headers = "{}\nContent-Length: {}".format(headers, len(conn.content))

    return first_line + headers
