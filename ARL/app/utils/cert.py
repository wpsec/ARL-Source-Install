"""
证书处理工具
"""
import ssl
import OpenSSL
import socket
import shutil
import subprocess
import re
import ipaddress
from collections import Counter
from datetime import datetime

socket.setdefaulttimeout(6)


def _safe_text(value):
    """
    将各种输入安全转为字符串，避免后续拼接异常。
    """
    if value is None:
        return ""
    return str(value).strip()


def _is_ip_address(value):
    """
    判断输入是否是 IP 地址（v4/v6）。
    """
    text = _safe_text(value)
    if not text:
        return False

    try:
        ipaddress.ip_address(text)
        return True
    except Exception:
        return False


def _normalize_server_hostname(value):
    """
    归一化 SNI 主机名，IP/空值返回空字符串。
    """
    hostname = _safe_text(value).strip(".").lower()
    if not hostname:
        return ""
    if _is_ip_address(hostname):
        return ""
    return hostname


def _fetch_server_certificate(connect_host, port, server_hostname=""):
    """
    获取远端证书 PEM：
    - 支持 connect_host 与 server_hostname 分离（SNI）
    - 失败时回退 ssl.get_server_certificate
    """
    connect_host = _safe_text(connect_host)
    if not connect_host:
        return ""

    try:
        port = int(port)
    except Exception:
        return ""

    if port <= 0:
        return ""

    normalized_sni = _normalize_server_hostname(server_hostname)
    if not normalized_sni and not _is_ip_address(connect_host):
        normalized_sni = _normalize_server_hostname(connect_host)

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((connect_host, port), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=normalized_sni or None) as tls_sock:
                cert_der = tls_sock.getpeercert(binary_form=True)
                if cert_der:
                    return ssl.DER_cert_to_PEM_cert(cert_der)
    except Exception:
        pass

    try:
        return ssl.get_server_certificate((connect_host, port))
    except Exception:
        return ""


def _normalize_protocol_name(name):
    """
    统一协议名称格式，便于展示与导出聚合。
    """
    value = _safe_text(name).replace(" ", "")
    if not value:
        return ""

    lower = value.lower()
    if lower.startswith("tlsv"):
        suffix = value[4:]
        return "TLSv{}".format(suffix)
    if lower.startswith("sslv"):
        suffix = value[4:]
        return "SSLv{}".format(suffix)
    return value


def _parse_cipher_line(line):
    """
    解析 nmap ssl-enum-ciphers 中的单行套件信息。

    样例：
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (secp256r1) - A
    """
    text = _safe_text(line)
    if not text:
        return "", ""

    strength = ""
    cipher_name = text

    if " - " in text:
        left, right = text.rsplit(" - ", 1)
        right = _safe_text(right).upper()
        if right in {"A", "B", "C", "D", "E", "F"}:
            cipher_name = _safe_text(left)
            strength = right

    return cipher_name, strength


def _parse_ssl_enum_ciphers_output(raw_text):
    """
    解析 nmap ssl-enum-ciphers 原始输出，提取协议/套件/强度。
    """
    if not _safe_text(raw_text):
        return {}

    protocol_pattern = re.compile(r"^(SSLv[0-9.]+|TLSv[0-9.]+)\s*:\s*$", re.IGNORECASE)
    protocol_map = {}
    cipher_suites = []
    current_protocol = ""
    in_cipher_block = False
    least_strength = ""

    for raw_line in raw_text.splitlines():
        line = _safe_text(raw_line)
        if not line:
            continue

        # nmap 脚本输出以 | / |_ 开头，先统一清洗。
        line = line.lstrip("|").lstrip("_").strip()
        if not line:
            continue

        low = line.lower()
        if low.startswith("ssl-enum-ciphers"):
            continue

        protocol_match = protocol_pattern.match(line)
        if protocol_match:
            current_protocol = _normalize_protocol_name(protocol_match.group(1))
            if current_protocol and current_protocol not in protocol_map:
                protocol_map[current_protocol] = {
                    "name": current_protocol,
                    "supported": True,
                    "cipher_count": 0,
                }
            in_cipher_block = False
            continue

        if low.startswith("ciphers:"):
            in_cipher_block = bool(current_protocol)
            continue

        if low.startswith("compressors:") or low.startswith("compressor:"):
            in_cipher_block = False
            continue

        if low.startswith("cipher preference"):
            in_cipher_block = False
            continue

        if low.startswith("least strength"):
            _, _, right = line.partition(":")
            least_strength = _safe_text(right).upper()
            continue

        if not in_cipher_block or not current_protocol:
            continue

        cipher_name, strength = _parse_cipher_line(line)
        if not cipher_name:
            continue

        cipher_suites.append(
            {
                "protocol": current_protocol,
                "name": cipher_name,
                "strength": strength,
            }
        )
        protocol_map[current_protocol]["cipher_count"] += 1

    if not protocol_map and not cipher_suites and not least_strength:
        return {}

    protocol_names = sorted(protocol_map.keys())
    strength_counter = Counter(
        [item.get("strength", "") for item in cipher_suites if _safe_text(item.get("strength", ""))]
    )
    ecdhe_count = 0
    for item in cipher_suites:
        name = _safe_text(item.get("name", "")).upper()
        if "ECDHE" in name:
            ecdhe_count += 1

    strength_stat = {}
    for key in sorted(strength_counter.keys()):
        strength_stat[key] = strength_counter[key]

    return {
        "source": "nmap_ssl_enum_ciphers",
        "scan_time": str(datetime.utcnow()),
        "protocols": [protocol_map[name] for name in protocol_names],
        "protocol_names": protocol_names,
        "cipher_suites": cipher_suites,
        "cipher_total": len(cipher_suites),
        "ecdhe_count": ecdhe_count,
        "strength_stat": strength_stat,
        "least_strength": least_strength,
    }


def _scan_ssl_security_with_nmap(host, port):
    """
    调用 nmap ssl-enum-ciphers 脚本扫描协议与加密套件。
    """
    nmap_bin = shutil.which("nmap")
    if not nmap_bin:
        return {}

    try:
        port = int(port)
    except Exception:
        return {}

    cmd = [
        nmap_bin,
        "-n",
        "-Pn",
        "--max-retries",
        "1",
        "--host-timeout",
        "20s",
        "--script-timeout",
        "15s",
        "-p",
        str(port),
        "--script",
        "ssl-enum-ciphers",
        str(host),
    ]

    try:
        # nmap 在目标无响应时可能返回非0，但 stdout 仍有可解析信息，因此不使用 check=True。
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=28,
            check=False,
        )
        parsed = _parse_ssl_enum_ciphers_output(result.stdout or "")
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def parse_certs(certs):
    result = {}
    ospj = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certs)

    subject = ospj.get_subject()
    subject_dn = "C={C}, CN={CN}".format(C=subject.C,CN=subject.CN)
    if subject.O:
        subject_dn += " ,O={O}".format(O = subject.O)

    issuer = ospj.get_issuer()
    issuser_obj = {}
    issuser_obj['country'] = issuer.C
    issuser_obj['province'] = issuer.ST
    issuser_obj['locality'] = issuer.L
    issuser_obj['organizational'] = issuer.O
    issuser_obj['organizational_unit'] = issuer.OU
    issuser_obj['common_name'] = issuer.CN
    issuser_obj['email'] = issuer.emailAddress

    issuer_dn = "C={C}, O={O}, OU={OU}, CN={CN}".format(C=issuer.CN, O=issuer.O, OU=issuer.OU, CN=issuer.CN)

    signature_algorithm = bytes.decode(ospj.get_signature_algorithm()) # 返回证书使用的签名算法
    serial_number = ospj.get_serial_number() # 证书序列号
    validity_obj = {}
    start_date = str(datetime.strptime(ospj.get_notBefore().decode("UTF-8"), '%Y%m%d%H%M%SZ'))
    end_date = str(datetime.strptime(ospj.get_notAfter().decode("UTF-8"), '%Y%m%d%H%M%SZ'))

    validity_obj['start'] = start_date
    validity_obj['end'] = end_date
    validity_obj['expired'] = ospj.has_expired()

    version = ospj.get_version() + 1


    subject_key_info = {}
    subject_key_info['key_algorithm'] = signature_algorithm
    subject_key_info['public_key'] = {}
    subject_key_info['public_key']['length'] = ospj.get_pubkey().bits()
    subject_key_info['public_key']['key'] = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, ospj.get_pubkey()).decode("utf-8")

    subject_obj = {}
    subject_obj['country'] =  subject.C
    subject_obj['province'] = subject.ST
    subject_obj['locality'] = subject.L
    subject_obj['organizational'] = subject.O
    subject_obj['organizational_unit'] = subject.OU
    subject_obj['common_name'] = subject.CN
    subject_obj['email'] = subject.emailAddress

    fingerprint_obj = {}
    fingerprint_obj['sha1'] = bytes.decode(ospj.digest('sha1')).replace(":", "").lower()
    fingerprint_obj['sha256'] = bytes.decode(ospj.digest('sha256')).replace(":", "").lower()
    fingerprint_obj['md5'] = bytes.decode(ospj.digest('md5')).replace(":", "").lower()

    extensions = {}
    exn_num = 0
    while exn_num < ospj.get_extension_count():
        ext_name = bytes.decode(ospj.get_extension(exn_num).get_short_name())
        ext_val = str(ospj.get_extension(exn_num))
        extensions[ext_name] = ext_val
        exn_num += 1

    result['subject_dn'] = subject_dn
    result['issuer'] = issuser_obj
    result['signature_algorithm'] = signature_algorithm
    result['serial_number'] = str(serial_number) # 转换为 str模式 MongoDB can only handle up to 8-byte ints
    result['validity'] = validity_obj
    result['issuer_dn'] = issuer_dn
    result['version'] = version
    result['extensions'] = extensions
    #这个太长了，省点
    #result['subject_key_info'] = subject_key_info
    result['subject'] = subject_obj
    result['fingerprint'] = fingerprint_obj

    return result



def get_cert(host, port, server_hostname=""):
    from . import get_logger
    logger = get_logger()
    try:
        certs = _fetch_server_certificate(connect_host=host, port=port, server_hostname=server_hostname)
        if not certs and _safe_text(server_hostname):
            # SNI 失败时回退无 SNI，避免漏采
            certs = _fetch_server_certificate(connect_host=host, port=port, server_hostname="")
        if not certs:
            return {}
        parsed_cert = parse_certs(certs)
        ssl_security = _scan_ssl_security_with_nmap(host, port)
        if ssl_security:
            parsed_cert["ssl_security"] = ssl_security
        return parsed_cert
    except Exception as e:
        logger.debug("get cert error {}:{} {}".format(host,port, e))









