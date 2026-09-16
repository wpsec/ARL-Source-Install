"""ARL-NPoC YAML POC 适配器。

该模块只解释 dt 规范化后的规则，不执行规则中的 Python。表达式先经过
白名单 AST 解析，再由本模块逐节点解释，以避免扫描规则获得任意代码执行能力。
"""

import ast
import base64 as base64_module
import hashlib
import hmac
import html
import gzip
import io
import json
import random
import re
import secrets
import socket
import string
import time
import zipfile
from copy import deepcopy
from pathlib import Path
from urllib.parse import quote, urlsplit, urlunsplit

import yaml

from xing.conf import Conf
from xing.core.BasePlugin import BasePlugin
from xing.core.const import PluginType
from xing.core.request_context import (
    NPoCRequestSkipped,
    NPoCExecutionTimeout,
    current_request_context,
)
from xing.utils import get_logger, http_req


MAX_EVIDENCE_LENGTH = 1200
MAX_EXPRESSION_LENGTH = 65536
HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "MOVE"}
TCP_TARGET_SCHEMES = {
    "http", "https", "tcp", "udp", "ajp", "activemq", "dubbo", "fcgi", "ftp",
    "jdwp", "memcached", "mongodb", "redis", "rmi", "rocketmq", "rpc", "rsync",
    "ssh", "zookeeper",
}
SENSITIVE_HEADER_NAMES = {"authorization", "proxy-authorization", "cookie", "set-cookie"}


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def canonical_bytes(rule):
    return json.dumps(rule, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


class YamlPocError(RuntimeError):
    """规则执行失败，调用方会将其写入 partial 结果。"""


class _HeaderMap(dict):
    """同时满足字符串匹配和按名称读取的响应头视图。"""

    def __getitem__(self, key):
        if key in self:
            return super().__getitem__(key)
        wanted = str(key).lower()
        for name, value in self.items():
            if str(name).lower() == wanted:
                return value
        raise KeyError(key)

    def __str__(self):
        return "\n".join("{}: {}".format(key, value) for key, value in self.items())


def _limited_text(value, length=MAX_EVIDENCE_LENGTH):
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    text = str(value)
    text = re.sub(
        r"(?i)\b(authorization|proxy-authorization|cookie|set-cookie|password|passwd|token|secret)\b"
        r"\s*[:=]\s*[^,\r\n;&]+",
        r"\1=<redacted>",
        text,
    )
    text = re.sub(
        r'''(?is)(["'])(authorization|proxy-authorization|cookie|set-cookie|password|passwd|token|secret)\1\s*:\s*(["'])(?:\\.|(?!\3).)*\3''',
        lambda match: '{}{}{}:{}<redacted>{}'.format(
            match.group(1), match.group(2), match.group(1), match.group(3), match.group(3)
        ),
        text,
    )
    text = re.sub(
        r"(?i)\b(authorization|proxy-authorization|cookie|set-cookie|password|passwd|token|secret)\b"
        r"(?!\s*[:=])",
        lambda match: match.group(1) + "=<redacted>",
        text,
    )
    text = re.sub(r"(?i)(basic\s+|bearer\s+)[^\s,;]+", r"\1<redacted>", text)
    if len(text) > length:
        return text[:length] + "..."
    return text


def _safe_headers(headers):
    result = {}
    for key, value in (headers or {}).items():
        name = str(key)
        if name.lower() in SENSITIVE_HEADER_NAMES:
            result[name] = "<redacted>"
        elif name.lower() in {"content-type", "server", "location", "content-length"}:
            result[name] = _limited_text(value, 240)
    return result


def _render(value, variables):
    if isinstance(value, dict):
        return {str(key): _render(item, variables) for key, item in value.items()}
    if isinstance(value, list):
        return [_render(item, variables) for item in value]
    if isinstance(value, tuple):
        return tuple(_render(item, variables) for item in value)
    if not isinstance(value, str):
        return value

    pattern = re.compile(r"\{\{\s*\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")

    def replace(match):
        name = match.group(1)
        if name not in variables:
            raise YamlPocError("变量不存在: {}".format(name))
        item = variables[name]
        if isinstance(item, bytes):
            return item.decode("latin1", errors="replace")
        return str(item)

    return pattern.sub(replace, value)


def _normalize_expression_operators(expression):
    """只在字符串字面量之外转换 dt 的逻辑运算符和保留字变量。"""
    output = []
    index = 0
    quote_char = None
    escaped = False
    while index < len(expression):
        char = expression[index]
        if quote_char:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote_char:
                quote_char = None
            index += 1
            continue
        if char in {"'", '"'}:
            quote_char = char
            output.append(char)
            index += 1
            continue
        if expression.startswith("&&", index):
            output.append(" and ")
            index += 2
            continue
        if expression.startswith("||", index):
            output.append(" or ")
            index += 2
            continue
        if char == "!" and not expression.startswith("!=", index):
            output.append(" not ")
            index += 1
            continue
        if expression.startswith("pass", index):
            before = expression[index - 1] if index else " "
            after_index = index + 4
            after = expression[after_index] if after_index < len(expression) else " "
            if not (before.isalnum() or before == "_") and not (after.isalnum() or after == "_"):
                output.append("pass_")
                index = after_index
                continue
        output.append(char)
        index += 1
    return "".join(output)


def _replace_backtick_literals(expression):
    """只转换 DSL 的反引号字面量，保留请求载荷字符串中的反引号。"""
    output = []
    index = 0
    quote_char = None
    escaped = False
    while index < len(expression):
        char = expression[index]
        if quote_char:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote_char:
                quote_char = None
            index += 1
            continue
        if char in {"'", '"'}:
            quote_char = char
            output.append(char)
            index += 1
            continue
        if char != "`":
            output.append(char)
            index += 1
            continue
        end = index + 1
        while end < len(expression) and expression[end] != "`":
            end += 1
        if end >= len(expression):
            raise YamlPocError("反引号字面量未闭合")
        output.append(repr(expression[index + 1:end]))
        index = end + 1
    return "".join(output)


class _DnsLogContext:
    def __init__(self):
        self.domain = ""
        self.token = ""
        self._verified = False

    def Domain(self):
        if not self.domain:
            from xing.utils.dnslog import xn_9tr_com_get

            self.domain, self.token = xn_9tr_com_get()
        return self.domain

    def Verify(self):
        if not self.token:
            return False
        from xing.utils.dnslog import xn_9tr_com_verify

        self._verified = bool(xn_9tr_com_verify(self.token, raise_error=False))
        return self._verified

    def Url(self):
        domain = self.Domain()
        return "http://{}".format(domain) if domain else ""

    def Sleep(self, seconds=0):
        _bounded_sleep(seconds)
        return self.Verify()


class _TcpConnection:
    def __init__(self, host, port, timeout, use_tls=False, request_context=None,
                 request_url=""):
        self.request_context = request_context
        self.request_url = request_url
        self._timeout_reported = False
        self.socket = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            import ssl

            context = ssl.create_default_context()
            if not Conf.TLS_VERIFY:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            self.socket = context.wrap_socket(self.socket, server_hostname=host)
        self.socket.settimeout(timeout)
        self.buffer = b""

    def _observe_read_timeout(self):
        if self._timeout_reported or self.request_context is None:
            return
        self._timeout_reported = True
        self.request_context.observe_error(self.request_url, socket.timeout("read timed out"))

    def WriteStr(self, value):
        if isinstance(value, str):
            value = value.encode("latin1", errors="replace")
        self.socket.sendall(bytes(value))
        return True

    def ReadStr(self):
        chunks = []
        while True:
            try:
                chunk = self.socket.recv(65535)
            except socket.timeout:
                if not chunks and not self.buffer:
                    self._observe_read_timeout()
                break
            if not chunk:
                break
            chunks.append(chunk)
            if len(b"".join(chunks)) >= 1024 * 1024:
                break
            if len(chunk) < 65535:
                break
        self.buffer += b"".join(chunks)
        return self.buffer.decode("latin1", errors="replace")

    def ReadLine(self):
        while b"\n" not in self.buffer:
            try:
                chunk = self.socket.recv(4096)
            except socket.timeout:
                if not self.buffer:
                    self._observe_read_timeout()
                break
            if not chunk:
                break
            self.buffer += chunk
            if len(self.buffer) >= 1024 * 1024:
                break
        if b"\n" in self.buffer:
            line, self.buffer = self.buffer.split(b"\n", 1)
        else:
            line, self.buffer = self.buffer, b""
        return line.rstrip(b"\r").decode("latin1", errors="replace")

    def Close(self):
        try:
            self.socket.close()
        except OSError:
            return False
        return True


class _ArchiveBuilder:
    """在内存中构造规则需要上传的归档，避免规则接触本地文件系统。"""

    def __init__(self, archive_type):
        if str(archive_type or "").lower() != "zip":
            raise YamlPocError("只支持 zip 归档")
        self._files = []

    def Add(self, filename, content):
        filename = str(filename or "")
        if not filename or "\x00" in filename:
            raise YamlPocError("归档文件名无效")
        if isinstance(content, str):
            content = content.encode("latin1", errors="replace")
        elif not isinstance(content, bytes):
            content = str(content).encode("utf-8")
        self._files.append((filename, content))
        return True

    def Build(self, output_type="raw"):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for filename, content in self._files:
                archive.writestr(filename, content)
        payload = output.getvalue()
        output_type = str(output_type or "raw").lower()
        if output_type == "raw":
            return payload
        if output_type == "base64":
            return base64_module.b64encode(payload).decode("ascii")
        if output_type == "hex":
            return payload.hex()
        raise YamlPocError("不支持的归档输出类型: {}".format(output_type))


class _ExpressionEvaluator:
    """受限表达式解释器，不调用 eval/exec。"""

    FUNCTIONS = {
        "contains",
        "starts_with",
        "startswith",
        "ends_with",
        "endswith",
        "matches",
        "maches",
        "contians",
        "regex_find",
        "regex_match",
        "regex_mtach",
        "compare_versions",
        "random_int",
        "random_str",
        "md5",
        "base64",
        "base64_decode",
        "hex_decode",
        "hex_encode",
        "len",
        "str",
        "sleep",
        "to_lower",
        "to_upper",
        "url_encode",
        "urlencode",
        "trim",
        "substr",
        "find_json",
        "gbk_decode",
        "gbk_encode",
        "gunzip",
        "concat",
        "sha1",
        "int",
        "datetime",
        "timestamp",
        "repeat",
        "replace",
        "pad_left",
        "pad_right",
        "urldecode",
        "dec_to_hex",
        "CHR",
        "UPPER",
        "gzip",
        "ase_cbc_encrypt",
        "ase_cbc_encrypt_with_iv",
        "gen_jwt",
        "new_archive",
        "java_dns_url_gadget",
        "set_var",
        "check_ftp_anonymous",
        "check_ssh_terrapin_attack",
        "check_fastcgi_unauth",
        "check_vmware_aria_static_ssh_key",
        "check_rpc_nfs_unauth",
        "check_mongodb_unauth",
        "interactsh",
        "new_dns_log",
    }

    def __init__(self, context, variable_sink=None):
        self.context = context
        self.variable_sink = variable_sink

    @staticmethod
    def parse(expression):
        expression = str(expression or "").strip()
        if not expression or len(expression) > MAX_EXPRESSION_LENGTH:
            raise YamlPocError("表达式为空或超过长度限制")
        expression = _replace_backtick_literals(expression)
        expression = re.sub(r"[\r\n]+", " ", expression)
        normalized = _normalize_expression_operators(expression)
        normalized = normalized.strip()
        normalized = re.sub(r"(?:\band\b|\bor\b)\s*$", "", normalized).strip()
        try:
            return ast.parse(normalized, mode="eval").body
        except SyntaxError as exc:
            raise YamlPocError("表达式语法错误: {}".format(str(exc)[:180]))

    def evaluate(self, expression):
        return self._eval(self.parse(expression))

    def resolve_name(self, name):
        if name == "true":
            return True
        if name == "false":
            return False
        if name == "null":
            return None
        if name in self.FUNCTIONS:
            return self._function(name)
        if name in self.context:
            return self.context[name]
        if name == "pass_" and "pass" in self.context:
            return self.context["pass"]
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", name) and any(char.isdigit() for char in name):
            # dt 的少数旧规则把未加引号的密码/测试值作为字符串传给函数。
            return name
        raise YamlPocError("表达式名称不存在: {}".format(name))

    def _eval(self, node):  # noqa: C901 - AST 白名单分支必须显式列出
        if isinstance(node, ast.Name):
            return self.resolve_name(node.id)
        if isinstance(node, ast.Constant):
            if isinstance(node.value, (str, int, float, bool, bytes)) or node.value is None:
                return node.value
            raise YamlPocError("不支持的常量类型")
        if isinstance(node, ast.Attribute):
            if node.attr.startswith("_"):
                raise YamlPocError("禁止访问私有属性")
            owner = self._eval(node.value)
            if not isinstance(owner, (_DnsLogContext, _TcpConnection, _ArchiveBuilder)):
                raise YamlPocError("不支持的属性访问")
            try:
                return getattr(owner, node.attr)
            except AttributeError as exc:
                raise YamlPocError("不支持的属性: {}".format(node.attr)) from exc
        if isinstance(node, ast.List):
            return [self._eval(item) for item in node.elts]
        if isinstance(node, ast.Tuple):
            return tuple(self._eval(item) for item in node.elts)
        if isinstance(node, ast.Subscript):
            owner = self._eval(node.value)
            if isinstance(node.slice, ast.Constant):
                key = node.slice.value
            else:
                key = self._eval(node.slice)
            if not isinstance(owner, (dict, list, tuple, str)):
                raise YamlPocError("不支持的下标访问")
            try:
                return owner[key]
            except (KeyError, IndexError, TypeError) as exc:
                raise YamlPocError("下标不存在") from exc
        if isinstance(node, ast.UnaryOp):
            value = self._eval(node.operand)
            if isinstance(node.op, ast.Not):
                return not bool(value)
            if isinstance(node.op, ast.USub) and isinstance(value, (int, float)):
                return -value
            raise YamlPocError("不支持的一元运算")
        if isinstance(node, ast.BoolOp):
            if isinstance(node.op, ast.And):
                return all(bool(self._eval(item)) for item in node.values)
            if isinstance(node.op, ast.Or):
                return any(bool(self._eval(item)) for item in node.values)
            raise YamlPocError("不支持的逻辑运算")
        if isinstance(node, ast.Compare):
            left = self._eval(node.left)
            for operator, comparator in zip(node.ops, node.comparators):
                right = self._eval(comparator)
                try:
                    if isinstance(operator, ast.Eq):
                        result = left == right
                    elif isinstance(operator, ast.NotEq):
                        result = left != right
                    elif isinstance(operator, ast.Lt):
                        result = left < right
                    elif isinstance(operator, ast.LtE):
                        result = left <= right
                    elif isinstance(operator, ast.Gt):
                        result = left > right
                    elif isinstance(operator, ast.GtE):
                        result = left >= right
                    elif isinstance(operator, ast.In):
                        result = left in right
                    elif isinstance(operator, ast.NotIn):
                        result = left not in right
                    else:
                        raise YamlPocError("不支持的比较运算")
                except (TypeError, ValueError) as exc:
                    raise YamlPocError("比较类型错误") from exc
                if not result:
                    return False
                left = right
            return True
        if isinstance(node, ast.BinOp) and isinstance(
            node.op, (ast.Add, ast.Mod, ast.Mult, ast.Sub, ast.Div)
        ):
            left = self._eval(node.left)
            right = self._eval(node.right)
            try:
                if isinstance(node.op, ast.Add):
                    if isinstance(left, (str, bytes)) and isinstance(right, type(left)):
                        return left + right
                    if isinstance(left, (str, bytes)) or isinstance(right, (str, bytes)):
                        return str(left) + str(right)
                    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
                        return left + right
                if isinstance(node.op, ast.Mod) and isinstance(left, str):
                    return left % right
                if isinstance(node.op, ast.Mult):
                    if isinstance(left, str) and isinstance(right, int):
                        return left * right
                    if isinstance(left, int) and isinstance(right, str):
                        return right * left
                    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
                        return left * right
                if isinstance(node.op, ast.Sub) and isinstance(left, (int, float)) and isinstance(right, (int, float)):
                    return left - right
                if isinstance(node.op, ast.Div) and isinstance(left, (int, float)) and isinstance(right, (int, float)):
                    if right == 0:
                        raise YamlPocError("除数不能为零")
                    return left / right
            except (TypeError, ValueError) as exc:
                raise YamlPocError("二元运算类型错误") from exc
            raise YamlPocError("不支持的二元运算")
        if isinstance(node, ast.Call):
            if node.keywords:
                raise YamlPocError("不支持关键字参数")
            function = self._eval(node.func)
            if not callable(function):
                raise YamlPocError("表达式目标不可调用")
            return function(*[self._eval(item) for item in node.args])
        raise YamlPocError("不支持的表达式节点: {}".format(type(node).__name__))

    def _function(self, name):
        def as_text(value):
            if isinstance(value, bytes):
                return value.decode("latin1", errors="replace")
            return str(value)

        if name == "contains":
            return lambda value, needle: as_text(needle) in as_text(value)
        if name in {"starts_with", "startswith"}:
            return lambda value, prefix: as_text(value).startswith(as_text(prefix))
        if name in {"ends_with", "endswith"}:
            return lambda value, suffix: as_text(value).endswith(as_text(suffix))
        if name in {"matches", "maches", "contians", "regex_find", "regex_match", "regex_mtach"}:
            def regex(value, pattern):
                if name == "contians":
                    return as_text(pattern) in as_text(value)
                try:
                    match = re.search(as_text(pattern), as_text(value), re.I | re.M)
                except re.error as exc:
                    raise YamlPocError("正则表达式错误") from exc
                if name in {"matches", "maches"}:
                    return bool(match)
                if not match:
                    return ""
                return match.groupdict() or match.group(0)
            return regex
        if name == "compare_versions":
            return lambda left, *constraints: _compare_version_constraints(
                as_text(left), *(as_text(item) for item in constraints)
            )
        if name == "random_int":
            return lambda lower=0, upper=100: random.randint(int(lower), int(upper))
        if name == "random_str":
            return lambda length=8: "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(int(length)))
        if name == "md5":
            return lambda value: hashlib.md5(as_text(value).encode("utf-8")).hexdigest()
        if name == "base64":
            return lambda value: base64_module.b64encode(as_text(value).encode()).decode()
        if name == "base64_decode":
            return lambda value: base64_module.b64decode(as_text(value), validate=False).decode("latin1", errors="replace")
        if name == "hex_decode":
            return lambda value: bytes.fromhex(re.sub(r"\s+", "", as_text(value)))
        if name == "hex_encode":
            return lambda value: (value if isinstance(value, bytes) else as_text(value).encode()).hex()
        if name == "len":
            return lambda value: len(value)
        if name == "str":
            return lambda value="": as_text(value)
        if name == "sleep":
            return lambda seconds=0: _bounded_sleep(seconds)
        if name == "to_lower":
            return lambda value: as_text(value).lower()
        if name == "to_upper":
            return lambda value: as_text(value).upper()
        if name == "url_encode":
            return lambda value: quote(as_text(value), safe="")
        if name == "urlencode":
            return lambda value: quote(as_text(value), safe="")
        if name == "trim":
            return lambda value: as_text(value).strip()
        if name == "substr":
            return lambda value, start=0, length=None: as_text(value)[int(start):] if length is None else as_text(value)[int(start):int(start) + int(length)]
        if name == "find_json":
            return lambda value, key: _find_json_value(value, key)
        if name == "gbk_decode":
            return lambda value: _decode_text(value, "gbk")
        if name == "gbk_encode":
            return lambda value: as_text(value).encode("gbk", errors="ignore").decode("latin1", errors="ignore")
        if name == "gunzip":
            return lambda value: gzip.decompress(value if isinstance(value, bytes) else as_text(value).encode("latin1")).decode("utf-8", errors="replace")
        if name == "concat":
            return lambda *values: "".join(as_text(value) for value in values)
        if name == "sha1":
            return lambda value: hashlib.sha1(as_text(value).encode("utf-8")).hexdigest()
        if name == "int":
            return lambda value=0: int(value)
        if name == "datetime":
            return lambda value: as_text(value)
        if name == "timestamp":
            return lambda: int(time.time())
        if name == "repeat":
            return lambda value, count: as_text(value) * int(count)
        if name == "replace":
            return lambda value, old, new: as_text(value).replace(as_text(old), as_text(new))
        if name == "pad_left":
            return lambda value, fill, length: as_text(value).rjust(int(length), as_text(fill)[:1] or " ")
        if name == "pad_right":
            return lambda value, fill, length: as_text(value).ljust(int(length), as_text(fill)[:1] or " ")
        if name == "urldecode":
            from urllib.parse import unquote

            return lambda value: unquote(as_text(value))
        if name == "dec_to_hex":
            return lambda value: format(int(value), "x")
        if name == "CHR":
            return lambda value: chr(int(value))
        if name == "UPPER":
            return lambda value: as_text(value).upper()
        if name == "gzip":
            return lambda value: gzip.compress(value if isinstance(value, bytes) else as_text(value).encode())
        if name == "gen_jwt":
            return _generate_jwt
        if name == "new_archive":
            return _ArchiveBuilder
        if name == "java_dns_url_gadget":
            def unsupported_gadget(*_):
                raise YamlPocError("Java DNS gadget 尚未纳入安全 YAML 执行器")

            return unsupported_gadget
        if name == "set_var":
            def set_var(variable_name, value=""):
                if self.variable_sink is None:
                    raise YamlPocError("set_var 缺少变量上下文")
                variable_name = str(variable_name or "")
                if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", variable_name):
                    raise YamlPocError("set_var 变量名称非法")
                self.variable_sink[variable_name] = value
                return value

            return set_var
        if name == "check_ftp_anonymous":
            def check_ftp_anonymous(conn):
                if not isinstance(conn, _TcpConnection):
                    raise YamlPocError("FTP 检查缺少 TCP 连接")
                conn.WriteStr("USER anonymous\r\nPASS anonymous\r\n")
                return bool(re.search(r"(?:^|\s)230\s", conn.ReadStr(), re.M))

            return check_ftp_anonymous
        if name in {
            "check_ssh_terrapin_attack",
            "check_fastcgi_unauth",
            "check_vmware_aria_static_ssh_key",
            "check_rpc_nfs_unauth",
            "check_mongodb_unauth",
        }:
            def unsupported_network_check(*_):
                raise YamlPocError("TCP 专项检查尚未纳入安全 YAML 执行器")

            return unsupported_network_check
        if name in {"ase_cbc_encrypt", "ase_cbc_encrypt_with_iv"}:
            return lambda *values: _aes_cbc_encrypt(*values, with_iv=name.endswith("with_iv"))
        if name == "interactsh":
            return lambda: ""
        if name == "new_dns_log":
            return _DnsLogContext
        raise YamlPocError("不支持的函数: {}".format(name))


def _bounded_sleep(seconds):
    try:
        seconds = max(0.0, min(float(seconds), 5.0))
    except (TypeError, ValueError) as exc:
        raise YamlPocError("sleep 参数无效") from exc
    context = current_request_context()
    if context is not None:
        remaining = context.remaining_sec()
        if remaining is not None:
            if remaining <= 0:
                raise NPoCExecutionTimeout("NPoC execution deadline exceeded")
            seconds = min(seconds, max(0.0, remaining))
    time.sleep(seconds)
    if context is not None and context.deadline_reached():
        raise NPoCExecutionTimeout("NPoC execution deadline exceeded")
    return True


def _compare_versions(left, right):
    def parts(value):
        return tuple(int(item) if item.isdigit() else item.lower() for item in re.findall(r"\d+|[A-Za-z]+", value))

    l_value, r_value = parts(left), parts(right)
    if l_value == r_value:
        return 0
    return 1 if l_value > r_value else -1


def _compare_version_constraints(left, *constraints):
    if not constraints:
        raise YamlPocError("compare_versions 缺少版本条件")
    if len(constraints) == 1 and not re.match(r"^(<=|>=|==|!=|<|>)", constraints[0]):
        return _compare_versions(left, constraints[0])
    for constraint in constraints:
        match = re.match(r"^(<=|>=|==|!=|<|>)?\s*(.+)$", constraint)
        if not match:
            raise YamlPocError("版本条件无效")
        operator, version = match.groups()
        comparison = _compare_versions(left, version)
        if operator == "<" and not comparison < 0:
            return False
        if operator == "<=" and not comparison <= 0:
            return False
        if operator == ">" and not comparison > 0:
            return False
        if operator == ">=" and not comparison >= 0:
            return False
        if operator == "==" and not comparison == 0:
            return False
        if operator == "!=" and not comparison != 0:
            return False
        if operator is None and comparison != 0:
            return False
    return True


def _decode_text(value, encoding):
    if isinstance(value, bytes):
        raw = value
    else:
        raw = str(value or "").encode("latin1", errors="replace")
    return raw.decode(encoding, errors="replace")


def _find_json_value(value, key):
    try:
        payload = json.loads(value)
    except (TypeError, ValueError):
        return ""
    current = payload
    for part in str(key).split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return ""
    return current


def _aes_cbc_encrypt(value, key, iv=None, with_iv=False):
    """兼容 Shiro 类规则的 AES-CBC/PKCS5 payload 生成。"""
    try:
        from Cryptodome.Cipher import AES
        from Cryptodome.Util.Padding import pad
    except ImportError as exc:
        raise YamlPocError("AES 扩展未安装") from exc
    raw_value = value if isinstance(value, bytes) else str(value).encode("latin1", errors="replace")
    raw_key = key if isinstance(key, bytes) else str(key).encode("latin1", errors="replace")
    raw_iv = iv if isinstance(iv, bytes) else str(iv or "\x00" * 16).encode("latin1", errors="replace")
    if len(raw_key) not in {16, 24, 32} or len(raw_iv) != 16:
        raise YamlPocError("AES key/iv 长度无效")
    return AES.new(raw_key, AES.MODE_CBC, raw_iv).encrypt(pad(raw_value, AES.block_size))


def _generate_jwt(payload, algorithm="HS256", secret=""):
    """仅实现规则数据中实际使用的 HMAC-SHA256 JWT。"""
    if str(algorithm or "").upper() != "HS256":
        raise YamlPocError("JWT 算法不支持: {}".format(algorithm))
    if isinstance(payload, (dict, list)):
        payload = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    header = json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":"))

    def encode(value):
        raw = value if isinstance(value, bytes) else str(value).encode("utf-8")
        return base64_module.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    signing_input = "{}.{}".format(encode(header), encode(payload))
    key = secret if isinstance(secret, bytes) else str(secret).encode("utf-8")
    signature = hmac.new(key, signing_input.encode("ascii"), hashlib.sha256).digest()
    return "{}.{}".format(signing_input, encode(signature))


class _ResponseContext:
    def __init__(self, response=None, request=None, duration=0.0, raw_text="", status_code=None):
        self.response = response
        self.request = request or {}
        self.duration = duration
        self.raw_text = raw_text
        self.status_code = status_code if status_code is not None else getattr(response, "status_code", -1)
        if response is not None:
            self.body = getattr(response, "text", None)
            if self.body is None:
                self.body = getattr(response, "content", "")
        else:
            self.body = raw_text
        response_headers = getattr(response, "headers", {}) if response is not None else {}
        if response is None and raw_text:
            if re.search(r"HTTP/\d(?:\.\d)?\s+\d{3}", str(raw_text), re.I):
                parsed_status, parsed_headers, parsed_body = _parse_raw_response(raw_text)
                if status_code is None or status_code == -1:
                    self.status_code = parsed_status
                response_headers = parsed_headers
                self.body = parsed_body
            else:
                # TCP 服务返回的不是 HTTP 报文时，原始字节内容本身就是匹配主体。
                self.body = raw_text
        self.headers_map = _HeaderMap(response_headers or {})
        self.headers = str(self.headers_map)
        self.header = self.headers
        self.content_type = next(
            (value for key, value in self.headers_map.items() if str(key).lower() == "content-type"),
            "",
        )
        self.title = _extract_title(self.body)
        raw_headers = self.headers
        self.raw = raw_text or "HTTP/1.1 {}\n{}\n\n{}".format(
            self.status_code,
            raw_headers,
            self.body,
        )

    def as_context(self):
        return {
            "status_code": self.status_code,
            "body": self.body,
            "header": self.header,
            "headers": self.headers_map,
            "content": self.body,
            "status": self.status_code,
            "content_type": self.content_type,
            "title": self.title,
            "raw": self.raw,
            "duration": self.duration,
            "res": self.body,
        }


def _extract_title(body):
    match = re.search(r"<title[^>]*>(.*?)</title>", str(body or ""), re.I | re.S)
    return html.unescape(re.sub(r"\s+", " ", match.group(1)).strip()) if match else ""


def _looks_like_variable_expression(text, variables):
    candidate = str(text or "").strip()
    if not candidate:
        return False
    function_match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*\(", candidate)
    if function_match and function_match.group(1) in _ExpressionEvaluator.FUNCTIONS:
        return True
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*\s*\(", candidate):
        return True
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*[+*]\s*[A-Za-z0-9_\'\"]", candidate):
        return True
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s+-\s+[A-Za-z0-9_\'\"]", candidate):
        return True
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s+/\s+", candidate):
        return True
    if _has_top_level_operator(candidate, {"+", "-", "*", "/"}) and any(
        name in variables for name in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", candidate)
    ):
        return True
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", candidate) and candidate in variables:
        return True
    return False


def _has_top_level_operator(text, operators):
    quote_char = None
    escaped = False
    text = str(text)
    for index, char in enumerate(text):
        if quote_char:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote_char:
                quote_char = None
            continue
        if char in {"'", '"'}:
            quote_char = char
        elif char in operators and (
            index == 0
            or index == len(text) - 1
            or text[index - 1].isspace()
            or text[index + 1].isspace()
        ):
            return True
    return False


class YamlPocExecutor:
    def __init__(self, rule, timeout=None):
        self.rule = deepcopy(rule)
        self.timeout = timeout or float(getattr(Conf, "READ_TIMEOUT", 10.1) or 10.1)
        self.variables = {}
        self.last_evidence = {}
        self.last_request_index = -1
        self.last_expression = ""
        self._dns_contexts = {}

    def execute(self, target):
        target = str(target or "").strip()
        if not target:
            raise YamlPocError("目标为空")
        self._validate_target(target)
        self._init_variables(target)
        request_items = []
        if isinstance(self.rule.get("firstRequest"), dict):
            request_items.append(("firstRequest", self.rule["firstRequest"]))
        request_items.extend(("requests[{}]".format(index), item) for index, item in enumerate(self.rule.get("requests") or []))
        request_items.extend(("tcpRequests[{}]".format(index), item) for index, item in enumerate(self.rule.get("tcpRequests") or []))
        if not request_items:
            raise YamlPocError("没有可执行请求")

        matched = False
        for index, (label, request) in enumerate(request_items):
            self.last_request_index = index
            try:
                result = self._execute_request(target, request, label)
                if label == "firstRequest":
                    if not result:
                        return False
                    continue
                if not result:
                    return False
                matched = True
                self.last_evidence = result["evidence"]
                self.last_expression = result["expression"]
                if request.get("stop-at-first-match"):
                    break
            except (NPoCRequestSkipped, NPoCExecutionTimeout):
                # 熔断和 deadline 不能被规则的 ignoreError 继续吞掉，否则后续请求仍会放大封禁。
                raise
            except Exception:
                if request.get("ignoreError"):
                    continue
                raise
        return matched

    def _validate_target(self, target):
        candidate = target if "://" in target else "http://" + target
        parsed = urlsplit(candidate)
        transport = str(self.rule.get("transport") or "http").lower()
        allowed_schemes = {"http", "https"} if transport == "http" else TCP_TARGET_SCHEMES
        if parsed.scheme not in allowed_schemes or not parsed.hostname:
            raise YamlPocError("目标协议或主机不符合规则传输类型")
        if parsed.username or parsed.password:
            raise YamlPocError("目标不允许携带用户名密码")

    def _init_variables(self, target=None):
        if target:
            base_url = self._base_url(target)
            parsed = urlsplit(base_url)
            self.variables.update({
                "base_url": base_url,
                "target": base_url,
                "scheme": parsed.scheme or "http",
                "host": parsed.hostname or "",
                "domain": parsed.hostname or "",
                "port": parsed.port or (443 if parsed.scheme == "https" else 80),
            })
        variables = self.rule.get("variables") or {}
        if not isinstance(variables, dict):
            raise YamlPocError("variables 必须是对象")
        for name, expression in variables.items():
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", str(name)):
                raise YamlPocError("变量名称非法: {}".format(name))
            text = str(expression or "")
            if re.search(r"\b{}\b".format(re.escape(str(name))), text):
                self.variables.setdefault(str(name), "")
            if not _looks_like_variable_expression(text, self.variables):
                self.variables[str(name)] = expression
                continue
            try:
                value = _ExpressionEvaluator(
                    self._expression_context(), variable_sink=self.variables
                ).evaluate(expression)
            except YamlPocError as exc:
                # dt 同时允许变量值为字面量和函数表达式；无法解析的纯字面量
                # 保留原值，真正含有函数/运算的错误继续隔离并记录。
                if "(" in text or ")" in text or any(operator in text for operator in ("&&", "||", "==", "!=")):
                    lines = [line.strip() for line in text.splitlines() if line.strip()]
                    if len(lines) > 1:
                        try:
                            values = []
                            for line in lines:
                                if _looks_like_variable_expression(line, self.variables):
                                    value = _ExpressionEvaluator(
                                        self._expression_context(), variable_sink=self.variables
                                    ).evaluate(line)
                                else:
                                    value = line
                                values.append(value)
                            value = "\n".join(
                                item.decode("latin1", errors="replace") if isinstance(item, bytes) else str(item)
                                for item in values
                            )
                            self.variables[str(name)] = value
                            continue
                        except YamlPocError:
                            raise
                    raise
                if "表达式名称不存在" not in str(exc):
                    raise
                value = expression
            self.variables[str(name)] = value

    def _expression_context(self, response=None, conn=None):
        context = dict(self.variables)
        if response is not None:
            context.update(response.as_context())
        if conn is not None:
            context["conn"] = conn
        context.update(self._dns_contexts)
        return context

    def _execute_request(self, target, request, label):
        if not isinstance(request, dict):
            raise YamlPocError("{} 请求格式错误".format(label))
        if request.get("rawTCP"):
            response, evidence = self._execute_raw_tcp(target, request)
            matched = self._evaluate_expressions(request, response, evidence)
            self._capture_output(request, response)
            evidence.pop("conn", None)
            return {
                "matched": matched,
                "evidence": evidence,
                "expression": _limited_text(request.get("expression") or "", 900),
            } if matched else None
        elif isinstance(request.get("expression"), list) and not request.get("rawTCP"):
            response, evidence, matched = self._execute_tcp_sequence(target, request)
            evidence.pop("conn", None)
            return {
                "matched": matched,
                "evidence": evidence,
                "expression": _limited_text(
                    request.get("expression")[-1] if request.get("expression") else "", 900
                ),
            } if matched else None
        else:
            response, evidence, expression = self._execute_http(target, request)
            if not expression:
                return None
            return {
                "matched": True,
                "evidence": evidence,
                "expression": expression,
            }

    def _evaluate_expressions(self, request, response, evidence=None):
        expression = request.get("expression")
        expressions = expression if isinstance(expression, list) else [expression]
        for expression_item in expressions:
            if isinstance(expression_item, str) and expression_item.strip().startswith(("conn.", "#")):
                continue
            if expression_item is None or not str(expression_item).strip():
                continue
            evaluator = _ExpressionEvaluator(
                self._expression_context(response=response, conn=(evidence or {}).get("conn")),
                variable_sink=self.variables,
            )
            result = evaluator.evaluate(expression_item)
            if isinstance(result, dict):
                self.variables.update(result)
            if not bool(result):
                return False
        return True

    def _base_url(self, target):
        return target if "://" in target else "http://" + target

    def _build_url(self, target, path):
        base = self._base_url(target)
        path = str(path or "")
        if not path.startswith("/"):
            path = "/" + path
        base_parts = urlsplit(base)
        return urlunsplit((base_parts.scheme, base_parts.netloc, path, "", ""))

    def _execute_http(self, target, request):
        method = str(request.get("method", "GET") or "GET").upper()
        if method not in HTTP_METHODS:
            raise YamlPocError("HTTP method 不支持: {}".format(method))
        path_key = "rawPath" if request.get("rawPath") is not None else "path"
        path_value = request.get(path_key)
        if path_value is None:
            path_value = request.get("paths", "")
        paths = _render(path_value, self.variables)
        if isinstance(paths, (list, tuple)):
            path_candidates = [str(item).strip() for item in paths if str(item).strip()]
        elif isinstance(paths, str) and "\n" in paths and request.get("paths") is not None:
            path_candidates = [item.strip() for item in paths.splitlines() if item.strip()]
        else:
            path_candidates = [paths]
        last_response = None
        last_evidence = {}
        for path in path_candidates:
            url = self._build_url(target, path)
            headers = _render(request.get("headers") or {}, self.variables)
            data = _render(request.get("data"), self.variables)
            kwargs = {
                "headers": headers,
                "allow_redirects": bool(request.get("redirect", False)),
            }
            if request.get("disable_normal"):
                kwargs["disable_normal"] = True
                kwargs.pop("allow_redirects", None)
            if request.get("timeout"):
                kwargs["timeout"] = float(request["timeout"])
            if request.get("verify") is not None:
                kwargs["verify"] = bool(request["verify"])
            if request.get("files"):
                kwargs["files"] = self._render_files(_render(request["files"], self.variables))
            elif data is not None:
                kwargs["data"] = data
            if request.get("raw"):
                raw_method, raw_path, raw_headers, raw_body = self._parse_raw_http(_render(request["raw"], self.variables))
                method = raw_method
                url = self._build_url(target, raw_path)
                headers.update(raw_headers)
                kwargs["headers"] = headers
                kwargs["data"] = raw_body
            if path_key == "rawPath":
                kwargs["disable_normal"] = True
                kwargs.pop("allow_redirects", None)
                kwargs.pop("verify", None)
            started = time.monotonic()
            last_response = http_req(url, method=method.lower(), **kwargs)
            duration = time.monotonic() - started
            last_evidence = self._http_evidence(method, url, last_response, duration)
            response = _ResponseContext(last_response, request=request, duration=duration)
            if self._evaluate_expressions(request, response, last_evidence):
                self._capture_output(request, response)
                expression = request.get("expression")
                expressions = expression if isinstance(expression, list) else [expression]
                return response, last_evidence, _limited_text(
                    expressions[-1] if expressions else "", 900
                )
            if request.get("stop-at-first-match"):
                break
        if last_response is None:
            raise YamlPocError("没有可执行 HTTP 路径")
        return response, last_evidence, ""

    @staticmethod
    def _parse_raw_http(raw):
        lines = raw.replace("\r\n", "\n").split("\n")
        if not lines or len(lines[0].split()) < 2:
            raise YamlPocError("raw HTTP 首行格式错误")
        method, path = lines[0].split()[:2]
        headers = {}
        separator = next((index for index, line in enumerate(lines[1:], 1) if not line.strip()), len(lines))
        for line in lines[1:separator]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip()] = value.strip()
        body = "\n".join(lines[separator + 1:]) if separator < len(lines) else ""
        return method.upper(), path, headers, body

    @staticmethod
    def _render_files(files):
        result = {}
        for field, value in (files or {}).items():
            if not isinstance(value, dict):
                raise YamlPocError("files 字段格式错误")
            filename = value.get("filename", value.get("name", "file.bin"))
            content = value.get("content", value.get("data", ""))
            content_type = value.get("content_type")
            result[field] = (filename, content, content_type) if content_type else (filename, content)
        return result

    def _execute_raw_tcp(self, target, request):
        host, port = self._target_host_port(target)
        raw = _render(request.get("rawTCP"), self.variables)
        context = current_request_context()
        tcp_url = "tcp://{}:{}".format(host, port)
        if context is not None:
            context.before_request(tcp_url)
            timeout = context.limit_timeout(self.timeout)
        else:
            timeout = self.timeout
        conn = None
        try:
            conn = _TcpConnection(
                host,
                port,
                timeout,
                use_tls=urlsplit(self._base_url(target)).scheme == "https",
                request_context=context,
                request_url=tcp_url,
            )
            conn.WriteStr(raw)
            response_text = conn.ReadStr()
            status_code = _status_from_raw(response_text)
            response = _ResponseContext(request=request, duration=0.0, raw_text=response_text, status_code=status_code)
            evidence = self._tcp_evidence(raw, response_text, status_code)
            evidence["conn"] = conn
            return response, evidence
        except NPoCRequestSkipped:
            raise
        except Exception as exc:
            if context is not None:
                context.observe_error(tcp_url, exc)
            raise
        finally:
            if conn is not None:
                conn.Close()

    def _execute_tcp_sequence(self, target, request):
        host, port = self._target_host_port(target)
        context = current_request_context()
        tcp_url = "tcp://{}:{}".format(host, port)
        if context is not None:
            context.before_request(tcp_url)
            timeout = context.limit_timeout(self.timeout)
        else:
            timeout = self.timeout
        conn = None
        response_text = ""
        matched = True
        try:
            conn = _TcpConnection(
                host,
                port,
                timeout,
                use_tls=urlsplit(self._base_url(target)).scheme == "https",
                request_context=context,
                request_url=tcp_url,
            )
            expressions = request.get("expression") or []
            for command in expressions:
                if not isinstance(command, str):
                    continue
                command = _render(command, self.variables)
                evaluator = _ExpressionEvaluator(
                    self._expression_context(
                        conn=conn,
                        response=_ResponseContext(
                            raw_text=response_text,
                            status_code=_status_from_raw(response_text),
                        ),
                    ),
                    variable_sink=self.variables,
                )
                result = evaluator.evaluate(command)
                if isinstance(result, dict):
                    self.variables.update(result)
                if isinstance(result, str) and result:
                    response_text = result
                if re.match(r"\s*(?:conn\.|set_var\s*\()", command):
                    continue
                if not bool(result):
                    matched = False
                    break
            status_code = _status_from_raw(response_text)
            response = _ResponseContext(request=request, raw_text=response_text, status_code=status_code)
            evidence = self._tcp_evidence("", response_text, status_code)
            evidence["conn"] = conn
            return response, evidence, matched
        except NPoCRequestSkipped:
            raise
        except Exception as exc:
            if context is not None:
                context.observe_error(tcp_url, exc)
            raise
        finally:
            if conn is not None:
                conn.Close()

    def _target_host_port(self, target):
        candidate = self._base_url(target)
        parsed = urlsplit(candidate)
        if not parsed.hostname:
            raise YamlPocError("目标主机为空")
        default_port = self.rule.get("port")
        if default_port:
            try:
                default_port = int(default_port)
            except (TypeError, ValueError) as exc:
                raise YamlPocError("规则 port 无效") from exc
        return parsed.hostname, parsed.port or default_port or (443 if parsed.scheme == "https" else 80)

    @staticmethod
    def _http_evidence(method, url, response, duration):
        return {
            "request": {"method": method, "url": _limited_text(url, 400)},
            "response": {
                "status_code": getattr(response, "status_code", -1),
                "headers": _safe_headers(getattr(response, "headers", {})),
                "duration": round(duration, 3),
                "body": _limited_text(getattr(response, "text", "")),
            },
        }

    @staticmethod
    def _tcp_evidence(request, body, status_code):
        return {
            "request": {"raw": _limited_text(request, 600)},
            "response": {"status_code": status_code, "body": _limited_text(body)},
        }

    def _capture_output(self, request, response):
        for output in request.get("output") or []:
            if not isinstance(output, str):
                continue
            try:
                result = _ExpressionEvaluator(
                    self._expression_context(response=response),
                    variable_sink=self.variables,
                ).evaluate(output)
            except YamlPocError:
                raise
            if isinstance(result, dict):
                self.variables.update(result)


def _status_from_raw(raw):
    match = re.search(r"HTTP/\d(?:\.\d)?\s+(\d{3})", str(raw or ""), re.I)
    return int(match.group(1)) if match else -1


def _parse_raw_response(raw):
    text = str(raw or "")
    separator = "\r\n\r\n" if "\r\n\r\n" in text else "\n\n"
    head, body = text.split(separator, 1) if separator in text else (text, "")
    lines = head.splitlines()
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()
    return _status_from_raw(text), headers, body


class YamlPocPlugin(BasePlugin):
    """使 YAML 规则兼容现有 PluginRunner 的 POC 插件接口。"""

    def __init__(self, rule_path=None):
        super().__init__()
        self.plugin_type = PluginType.POC
        self._rule_path = str(rule_path or "")
        self.poc_engine = "yaml"
        self.poc_source = "dt"
        self.status = "ready"
        self._rule = None
        if self._rule_path:
            self._load_metadata()

    def _load_rule(self):
        if self._rule is not None:
            return self._rule
        if not self._rule_path:
            raise YamlPocError("YAML 规则路径为空")
        self._rule = yaml.safe_load(Path(self._rule_path).read_text(encoding="utf-8"))
        if not isinstance(self._rule, dict):
            raise YamlPocError("YAML 规则根节点不是对象")
        return self._rule

    def _load_metadata(self):
        rule = self._load_rule()
        info = rule.get("info") or {}
        self._plugin_name = str(rule.get("id") or Path(self._rule_path).stem)
        self.app_name = str(info.get("finger") or "")
        self.vul_name = str(info.get("name") or self._plugin_name)
        transport = str(rule.get("transport") or "http").lower()
        rule_scheme = str(rule.get("scheme") or "").strip().lower()
        self.scheme = ["http", "https"] if transport == "http" else [rule_scheme or "tcp"]
        self.target_scheme = rule_scheme or transport
        self.severity = str(info.get("severity") or "info").lower()
        self.tags = list(info.get("tags") or []) if isinstance(info.get("tags"), list) else [str(info.get("tags"))]
        self.finger = info.get("finger", "")

    def set_target(self, target):
        self._target_info = None
        self.target = str(target or "").strip()

    def should_skip(self):
        return False

    def verify(self, target):
        try:
            executor = YamlPocExecutor(self._load_rule())
            matched = executor.execute(target)
            if not matched:
                return None
            return {
                "__yaml_result__": True,
                "result_status": "matched",
                "poc_engine": self.poc_engine,
                "poc_id": self._plugin_name,
                "poc_source": self.poc_source,
                "severity": self.severity,
                "tags": self.tags,
                "request_index": executor.last_request_index,
                "match_summary": executor.last_expression,
                "evidence": executor.last_evidence,
                "verify_data": executor.last_expression,
            }
        except NPoCRequestSkipped:
            # 熔断属于调度决策，不应被记录成某个 PoC 的误报或失败结果。
            return None
        except NPoCExecutionTimeout:
            # deadline 由上层汇总为 partial；保留当前规则的执行边界，避免继续发请求。
            return {
                "__yaml_result__": True,
                "result_status": "partial",
                "poc_engine": self.poc_engine,
                "poc_id": self._plugin_name,
                "poc_source": self.poc_source,
                "severity": self.severity,
                "tags": self.tags,
                "request_index": getattr(locals().get("executor"), "last_request_index", -1),
                "match_summary": "",
                "evidence": {},
                "error_type": "NPoCExecutionTimeout",
                "error": "NPoC execution deadline exceeded",
                "verify_data": None,
            }
        except Exception as exc:
            return {
                "__yaml_result__": True,
                "result_status": "partial",
                "poc_engine": self.poc_engine,
                "poc_id": self._plugin_name,
                "poc_source": self.poc_source,
                "severity": self.severity,
                "tags": self.tags,
                "request_index": getattr(locals().get("executor"), "last_request_index", -1),
                "match_summary": "",
                "evidence": {},
                "error_type": type(exc).__name__,
                "error": _limited_text(exc, 500),
                "verify_data": None,
            }


def load_yaml_plugins():
    """只加载主清单 ready 和旧插件迁移清单 verified 的 YAML。"""
    root = Path(getattr(Conf, "YAML_POC_ROOT", Path(Conf.PROJECT_DIRECTORY) / "pocs")).resolve()
    yaml_root = (root / "yaml").resolve()
    plugins = []
    manifests = (
        (root / "manifest.json", {"ready"}),
        (root / "legacy_manifest.json", {"verified"}),
    )
    for manifest_path, accepted_statuses in manifests:
        if not manifest_path.is_file():
            continue
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            get_logger().warning("load YAML POC manifest error: {}".format(_limited_text(exc, 300)))
            continue
        for entry in manifest.get("entries", []):
            if entry.get("status") not in accepted_statuses:
                continue
            relative = Path(str(entry.get("canonical_path") or ""))
            path = (root / relative).resolve()
            if yaml_root not in path.parents or path.suffix not in {".yaml", ".yml"}:
                continue
            try:
                plugin = YamlPocPlugin(str(path))
                expected_hash = str(entry.get("canonical_sha256") or "").strip()
                if expected_hash and expected_hash != sha256_bytes(canonical_bytes(plugin._load_rule())):
                    raise YamlPocError("规范化内容哈希不匹配")
                if entry.get("rule_id") and entry.get("rule_id") != plugin._plugin_name:
                    raise YamlPocError("manifest rule_id 与 YAML id 不一致")
                plugin.poc_source = str(entry.get("source") or plugin.poc_source)
                plugins.append(plugin)
            except (OSError, ValueError, YamlPocError, yaml.YAMLError) as exc:
                get_logger().warning("load YAML POC error rule:{} reason:{}".format(
                    entry.get("rule_id", "-"), _limited_text(exc, 240)
                ))
                continue
    return plugins


def load_yaml_aliases():
    """读取规范化内容去重后保留的旧 ID，供历史任务解析到主执行实体。"""
    root = Path(getattr(Conf, "YAML_POC_ROOT", Path(Conf.PROJECT_DIRECTORY) / "pocs")).resolve()
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file():
        return {}
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        get_logger().warning("load YAML POC alias manifest error: {}".format(_limited_text(exc, 300)))
        return {}
    aliases = {}
    for entry in manifest.get("entries", []):
        if entry.get("status") != "duplicate":
            continue
        alias = str(entry.get("rule_id") or "").strip()
        target = str(entry.get("alias_of") or "").strip()
        if alias and target and alias != target:
            aliases[alias] = target
    return aliases
